#include "src/quic/http3_protocol.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <set>
#include <string_view>
#include <type_traits>

#include "src/quic/buffer.h"

namespace coquic::quic {

namespace {

template <typename T> Http3Result<T> failure(Http3ErrorCode code, std::string reason = {}) {
    return Http3Result<T>::failure(code, std::move(reason));
}

CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value()) {
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);
    }
    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

Http3Result<std::vector<std::byte>> serialize_frame_bytes(std::uint64_t type,
                                                          std::span<const std::byte> payload) {
    const auto encoded_type = encode_varint(type);
    if (!encoded_type.has_value()) {
        return failure<std::vector<std::byte>>(Http3ErrorCode::internal_error,
                                               "invalid frame type");
    }

    const auto encoded_length = encode_varint(payload.size());
    if (!encoded_length.has_value()) {
        return failure<std::vector<std::byte>>(Http3ErrorCode::internal_error,
                                               "invalid frame length");
    }

    BufferWriter writer;
    writer.write_bytes(encoded_type.value());
    writer.write_bytes(encoded_length.value());
    writer.write_bytes(payload);
    return Http3Result<std::vector<std::byte>>::success(writer.bytes());
}

Http3Result<bool> validate_header_block(const Http3Headers &headers,
                                        std::span<const std::string_view> required_pseudo_headers,
                                        std::span<const std::string_view> allowed_pseudo_headers,
                                        Http3ErrorCode error_code) {
    bool saw_regular_header = false;
    std::set<std::string> seen_pseudo_headers;

    for (const auto &field : headers) {
        if (field.name.empty()) {
            return failure<bool>(error_code, "empty header field name");
        }

        if (field.name.front() == ':') {
            if (saw_regular_header) {
                return failure<bool>(error_code, "pseudo-header after regular header");
            }

            const auto allowed =
                std::find(allowed_pseudo_headers.begin(), allowed_pseudo_headers.end(),
                          std::string_view(field.name));
            if (allowed == allowed_pseudo_headers.end()) {
                return failure<bool>(error_code, "unexpected pseudo-header");
            }
            if (!seen_pseudo_headers.insert(field.name).second) {
                return failure<bool>(error_code, "duplicate pseudo-header");
            }
            continue;
        }

        saw_regular_header = true;
    }

    for (const auto required : required_pseudo_headers) {
        if (!seen_pseudo_headers.contains(std::string(required))) {
            return failure<bool>(error_code, "missing required pseudo-header");
        }
    }

    return Http3Result<bool>::success(true);
}

Http3Result<std::vector<std::byte>> serialize_settings_payload(const Http3SettingsFrame &frame) {
    BufferWriter writer;
    for (const auto &setting : frame.settings) {
        const auto encoded_id = encode_varint(setting.id);
        const auto encoded_value = encode_varint(setting.value);
        if (!encoded_id.has_value() || !encoded_value.has_value()) {
            return failure<std::vector<std::byte>>(Http3ErrorCode::internal_error,
                                                   "invalid setting");
        }
        writer.write_bytes(encoded_id.value());
        writer.write_bytes(encoded_value.value());
    }
    return Http3Result<std::vector<std::byte>>::success(writer.bytes());
}

} // namespace

Http3Result<std::vector<std::byte>> serialize_http3_frame(const Http3Frame &frame) {
    return std::visit(
        [](const auto &typed_frame) -> Http3Result<std::vector<std::byte>> {
            using T = std::decay_t<decltype(typed_frame)>;
            if constexpr (std::is_same_v<T, Http3DataFrame>) {
                return serialize_frame_bytes(kHttp3FrameData, typed_frame.payload);
            } else if constexpr (std::is_same_v<T, Http3HeadersFrame>) {
                return serialize_frame_bytes(kHttp3FrameHeaders, typed_frame.payload);
            } else if constexpr (std::is_same_v<T, Http3SettingsFrame>) {
                const auto payload = serialize_settings_payload(typed_frame);
                if (!payload.has_value()) {
                    return payload;
                }
                return serialize_frame_bytes(kHttp3FrameSettings, payload.value());
            } else {
                const auto encoded_id = encode_varint(typed_frame.id);
                if (!encoded_id.has_value()) {
                    return failure<std::vector<std::byte>>(Http3ErrorCode::internal_error,
                                                           "invalid GOAWAY id");
                }
                return serialize_frame_bytes(kHttp3FrameGoaway, encoded_id.value());
            }
        },
        frame);
}

Http3Result<Http3DecodedFrame> parse_http3_frame(std::span<const std::byte> bytes) {
    BufferReader reader(bytes);

    const auto frame_type = read_varint(reader);
    if (!frame_type.has_value()) {
        return failure<Http3DecodedFrame>(Http3ErrorCode::frame_error, "invalid frame type");
    }

    const auto frame_length = read_varint(reader);
    if (!frame_length.has_value()) {
        return failure<Http3DecodedFrame>(Http3ErrorCode::frame_error, "invalid frame length");
    }

    if (frame_length.value() > reader.remaining()) {
        return failure<Http3DecodedFrame>(Http3ErrorCode::frame_error, "truncated frame payload");
    }

    const auto payload = reader.read_exact(static_cast<std::size_t>(frame_length.value()));
    if (!payload.has_value()) {
        return failure<Http3DecodedFrame>(Http3ErrorCode::frame_error, "truncated frame payload");
    }

    Http3Frame frame;
    if (frame_type.value() == kHttp3FrameData) {
        frame = Http3DataFrame{
            .payload = std::vector<std::byte>(payload.value().begin(), payload.value().end()),
        };
    } else if (frame_type.value() == kHttp3FrameHeaders) {
        frame = Http3HeadersFrame{
            .payload = std::vector<std::byte>(payload.value().begin(), payload.value().end()),
        };
    } else if (frame_type.value() == kHttp3FrameSettings) {
        BufferReader payload_reader(payload.value());
        Http3SettingsFrame settings{};
        while (payload_reader.remaining() > 0) {
            const auto setting_id = read_varint(payload_reader);
            const auto setting_value = read_varint(payload_reader);
            if (!setting_id.has_value() || !setting_value.has_value()) {
                return failure<Http3DecodedFrame>(Http3ErrorCode::settings_error,
                                                  "invalid settings payload");
            }
            settings.settings.push_back(Http3Setting{
                .id = setting_id.value(),
                .value = setting_value.value(),
            });
        }
        frame = std::move(settings);
    } else if (frame_type.value() == kHttp3FrameGoaway) {
        BufferReader payload_reader(payload.value());
        const auto id = read_varint(payload_reader);
        if (!id.has_value() || payload_reader.remaining() != 0) {
            return failure<Http3DecodedFrame>(Http3ErrorCode::frame_error,
                                              "invalid GOAWAY payload");
        }
        frame = Http3GoawayFrame{
            .id = id.value(),
        };
    } else {
        return failure<Http3DecodedFrame>(Http3ErrorCode::frame_unexpected,
                                          "unsupported frame type");
    }

    return Http3Result<Http3DecodedFrame>::success(Http3DecodedFrame{
        .frame = std::move(frame),
        .bytes_consumed = reader.offset(),
    });
}

Http3Result<Http3UniStreamType> parse_http3_uni_stream_type(std::span<const std::byte> bytes,
                                                            std::size_t &bytes_consumed) {
    const auto decoded = decode_varint_bytes(bytes);
    if (!decoded.has_value()) {
        return failure<Http3UniStreamType>(Http3ErrorCode::stream_creation_error,
                                           "invalid stream type");
    }

    bytes_consumed = decoded.value().bytes_consumed;
    switch (decoded.value().value) {
    case static_cast<std::uint64_t>(Http3UniStreamType::control):
        return Http3Result<Http3UniStreamType>::success(Http3UniStreamType::control);
    case static_cast<std::uint64_t>(Http3UniStreamType::push):
        return Http3Result<Http3UniStreamType>::success(Http3UniStreamType::push);
    case static_cast<std::uint64_t>(Http3UniStreamType::qpack_encoder):
        return Http3Result<Http3UniStreamType>::success(Http3UniStreamType::qpack_encoder);
    case static_cast<std::uint64_t>(Http3UniStreamType::qpack_decoder):
        return Http3Result<Http3UniStreamType>::success(Http3UniStreamType::qpack_decoder);
    default:
        return failure<Http3UniStreamType>(Http3ErrorCode::stream_creation_error,
                                           "unsupported stream type");
    }
}

Http3Result<std::vector<std::byte>> serialize_http3_uni_stream_prefix(Http3UniStreamType type) {
    const auto encoded = encode_varint(static_cast<std::uint64_t>(type));
    if (!encoded.has_value()) {
        return failure<std::vector<std::byte>>(Http3ErrorCode::internal_error,
                                               "invalid stream type");
    }
    return Http3Result<std::vector<std::byte>>::success(encoded.value());
}

Http3Result<std::vector<std::byte>>
serialize_http3_control_stream(const Http3SettingsFrame &settings,
                               const std::optional<Http3GoawayFrame> &goaway) {
    const auto validated = validate_http3_settings_frame(settings);
    if (!validated.has_value()) {
        return failure<std::vector<std::byte>>(validated.error().code, validated.error().reason);
    }

    const auto prefix = serialize_http3_uni_stream_prefix(Http3UniStreamType::control);
    if (!prefix.has_value()) {
        return prefix;
    }

    const auto settings_frame = serialize_http3_frame(Http3Frame{settings});
    if (!settings_frame.has_value()) {
        return settings_frame;
    }

    auto output = prefix.value();
    output.insert(output.end(), settings_frame.value().begin(), settings_frame.value().end());

    if (goaway.has_value()) {
        const auto goaway_frame = serialize_http3_frame(Http3Frame{*goaway});
        if (!goaway_frame.has_value()) {
            return goaway_frame;
        }
        output.insert(output.end(), goaway_frame.value().begin(), goaway_frame.value().end());
    }

    return Http3Result<std::vector<std::byte>>::success(std::move(output));
}

Http3Result<Http3SettingsFrame> validate_http3_settings_frame(const Http3SettingsFrame &settings) {
    std::set<std::uint64_t> seen_ids;
    for (const auto &setting : settings.settings) {
        if (!seen_ids.insert(setting.id).second) {
            return failure<Http3SettingsFrame>(Http3ErrorCode::settings_error,
                                               "duplicate setting id");
        }
    }
    return Http3Result<Http3SettingsFrame>::success(settings);
}

Http3Result<Http3RequestHead> validate_http3_request_headers(const Http3Headers &headers) {
    static constexpr std::array required = {
        std::string_view(":method"), std::string_view(":scheme"), std::string_view(":authority"),
        std::string_view(":path")};
    static constexpr std::array allowed = {std::string_view(":method"), std::string_view(":scheme"),
                                           std::string_view(":authority"),
                                           std::string_view(":path")};

    const auto validation =
        validate_header_block(headers, required, allowed, Http3ErrorCode::message_error);
    if (!validation.has_value()) {
        return failure<Http3RequestHead>(validation.error().code, validation.error().reason);
    }

    Http3RequestHead request{};
    request.headers = headers;
    for (const auto &field : headers) {
        if (field.name == ":method") {
            request.method = field.value;
        } else if (field.name == ":scheme") {
            request.scheme = field.value;
        } else if (field.name == ":authority") {
            request.authority = field.value;
        } else if (field.name == ":path") {
            request.path = field.value;
        }
    }

    return Http3Result<Http3RequestHead>::success(std::move(request));
}

Http3Result<Http3ResponseHead> validate_http3_response_headers(const Http3Headers &headers) {
    static constexpr std::array required = {std::string_view(":status")};
    static constexpr std::array allowed = {std::string_view(":status")};

    const auto validation =
        validate_header_block(headers, required, allowed, Http3ErrorCode::message_error);
    if (!validation.has_value()) {
        return failure<Http3ResponseHead>(validation.error().code, validation.error().reason);
    }

    Http3ResponseHead response{};
    response.headers = headers;
    for (const auto &field : headers) {
        if (field.name != ":status") {
            continue;
        }

        unsigned int status = 0;
        const auto *begin = field.value.data();
        const auto *end = begin + field.value.size();
        const auto parsed = std::from_chars(begin, end, status);
        if (field.value.size() != 3 || parsed.ec != std::errc{} || parsed.ptr != end ||
            status < 100 || status > 999) {
            return failure<Http3ResponseHead>(Http3ErrorCode::message_error, "invalid :status");
        }
        response.status = static_cast<std::uint16_t>(status);
    }

    return Http3Result<Http3ResponseHead>::success(std::move(response));
}

Http3Result<Http3Headers> validate_http3_trailers(const Http3Headers &headers) {
    for (const auto &field : headers) {
        if (field.name.empty() || field.name.front() == ':') {
            return failure<Http3Headers>(Http3ErrorCode::message_error,
                                         "trailers must not contain pseudo-headers");
        }
    }
    return Http3Result<Http3Headers>::success(headers);
}

bool http3_frame_allowed_on_control_stream(const Http3Frame &frame) {
    return std::holds_alternative<Http3SettingsFrame>(frame) ||
           std::holds_alternative<Http3GoawayFrame>(frame);
}

bool http3_frame_allowed_on_request_stream(const Http3Frame &frame) {
    return std::holds_alternative<Http3DataFrame>(frame) ||
           std::holds_alternative<Http3HeadersFrame>(frame);
}

} // namespace coquic::quic

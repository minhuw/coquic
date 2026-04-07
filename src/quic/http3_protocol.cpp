#include "src/quic/http3_protocol.h"

#include <charconv>
#include <cctype>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include "src/quic/buffer.h"

namespace coquic::quic {

namespace {

template <typename T>
Http3Result<T> http3_failure(Http3ErrorCode code, std::string detail,
                             std::optional<std::uint64_t> stream_id = std::nullopt) {
    return Http3Result<T>::failure(Http3Error{
        .code = code,
        .detail = std::move(detail),
        .stream_id = stream_id,
    });
}

template <typename T> CodecResult<T> codec_failure(CodecErrorCode code, std::size_t offset) {
    return CodecResult<T>::failure(code, offset);
}

CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value()) {
        return codec_failure<std::uint64_t>(decoded.error().code, decoded.error().offset);
    }

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

CodecResult<std::vector<std::byte>>
serialize_http3_payload_frame(std::uint64_t type, std::span<const std::byte> payload) {
    const auto encoded_type = encode_varint(type);
    if (!encoded_type.has_value()) {
        return codec_failure<std::vector<std::byte>>(encoded_type.error().code,
                                                     encoded_type.error().offset);
    }

    const auto encoded_length = encode_varint(payload.size());
    if (!encoded_length.has_value()) {
        return codec_failure<std::vector<std::byte>>(encoded_length.error().code,
                                                     encoded_length.error().offset);
    }

    BufferWriter writer;
    writer.write_bytes(encoded_type.value());
    writer.write_bytes(encoded_length.value());
    writer.write_bytes(payload);
    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

bool header_name_has_uppercase(std::string_view name) {
    for (const unsigned char ch : name) {
        if (std::isupper(ch) != 0) {
            return true;
        }
    }

    return false;
}

} // namespace

CodecResult<std::vector<std::byte>> serialize_http3_frame(const Http3Frame &frame) {
    return std::visit(
        [](const auto &typed_frame) -> CodecResult<std::vector<std::byte>> {
            using T = std::decay_t<decltype(typed_frame)>;
            if constexpr (std::is_same_v<T, Http3DataFrame>) {
                return serialize_http3_payload_frame(kHttp3FrameTypeData, typed_frame.payload);
            } else if constexpr (std::is_same_v<T, Http3HeadersFrame>) {
                return serialize_http3_payload_frame(kHttp3FrameTypeHeaders,
                                                     typed_frame.field_section);
            } else if constexpr (std::is_same_v<T, Http3SettingsFrame>) {
                BufferWriter writer;
                for (const auto &setting : typed_frame.settings) {
                    const auto encoded_id = encode_varint(setting.id);
                    if (!encoded_id.has_value()) {
                        return codec_failure<std::vector<std::byte>>(encoded_id.error().code,
                                                                     encoded_id.error().offset);
                    }

                    const auto encoded_value = encode_varint(setting.value);
                    if (!encoded_value.has_value()) {
                        return codec_failure<std::vector<std::byte>>(encoded_value.error().code,
                                                                     encoded_value.error().offset);
                    }

                    writer.write_bytes(encoded_id.value());
                    writer.write_bytes(encoded_value.value());
                }

                return serialize_http3_payload_frame(kHttp3FrameTypeSettings, writer.bytes());
            } else {
                const auto encoded_id = encode_varint(typed_frame.id);
                if (!encoded_id.has_value()) {
                    return codec_failure<std::vector<std::byte>>(encoded_id.error().code,
                                                                 encoded_id.error().offset);
                }

                return serialize_http3_payload_frame(kHttp3FrameTypeGoaway, encoded_id.value());
            }
        },
        frame);
}

CodecResult<Http3DecodedFrame> parse_http3_frame(std::span<const std::byte> bytes) {
    BufferReader reader(bytes);

    const auto frame_type = read_varint(reader);
    if (!frame_type.has_value()) {
        return codec_failure<Http3DecodedFrame>(frame_type.error().code, frame_type.error().offset);
    }

    const auto frame_length = read_varint(reader);
    if (!frame_length.has_value()) {
        return codec_failure<Http3DecodedFrame>(frame_length.error().code,
                                                frame_length.error().offset);
    }

    if (frame_length.value() > reader.remaining()) {
        return codec_failure<Http3DecodedFrame>(CodecErrorCode::http3_parse_error, reader.offset());
    }

    const auto payload = reader.read_exact(static_cast<std::size_t>(frame_length.value()));
    if (!payload.has_value()) {
        return codec_failure<Http3DecodedFrame>(payload.error().code, payload.error().offset);
    }

    Http3Frame frame;
    if (frame_type.value() == kHttp3FrameTypeData) {
        frame = Http3DataFrame{
            .payload = std::vector<std::byte>(payload.value().begin(), payload.value().end()),
        };
    } else if (frame_type.value() == kHttp3FrameTypeHeaders) {
        frame = Http3HeadersFrame{
            .field_section = std::vector<std::byte>(payload.value().begin(), payload.value().end()),
        };
    } else if (frame_type.value() == kHttp3FrameTypeSettings) {
        BufferReader payload_reader(payload.value());
        Http3SettingsFrame settings{};
        while (payload_reader.remaining() > 0) {
            const auto setting_id = read_varint(payload_reader);
            if (!setting_id.has_value()) {
                return codec_failure<Http3DecodedFrame>(setting_id.error().code,
                                                        setting_id.error().offset);
            }

            const auto setting_value = read_varint(payload_reader);
            if (!setting_value.has_value()) {
                return codec_failure<Http3DecodedFrame>(setting_value.error().code,
                                                        setting_value.error().offset);
            }

            settings.settings.push_back(Http3Setting{
                .id = setting_id.value(),
                .value = setting_value.value(),
            });
        }
        frame = std::move(settings);
    } else if (frame_type.value() == kHttp3FrameTypeGoaway) {
        BufferReader payload_reader(payload.value());
        const auto id = read_varint(payload_reader);
        if (!id.has_value()) {
            return codec_failure<Http3DecodedFrame>(id.error().code, id.error().offset);
        }
        if (payload_reader.remaining() != 0) {
            return codec_failure<Http3DecodedFrame>(CodecErrorCode::http3_parse_error,
                                                    payload_reader.offset());
        }
        frame = Http3GoawayFrame{
            .id = id.value(),
        };
    } else {
        return codec_failure<Http3DecodedFrame>(CodecErrorCode::http3_parse_error, reader.offset());
    }

    return CodecResult<Http3DecodedFrame>::success(Http3DecodedFrame{
        .frame = std::move(frame),
        .bytes_consumed = reader.offset(),
    });
}

CodecResult<VarIntDecoded> parse_http3_uni_stream_type(std::span<const std::byte> bytes) {
    return decode_varint_bytes(bytes);
}

CodecResult<std::vector<std::byte>> serialize_http3_uni_stream_prefix(Http3UniStreamType type) {
    return encode_varint(static_cast<std::uint64_t>(type));
}

CodecResult<std::vector<std::byte>>
serialize_http3_control_stream(std::span<const Http3Setting> settings) {
    auto prefix = serialize_http3_uni_stream_prefix(Http3UniStreamType::control);
    if (!prefix.has_value()) {
        return codec_failure<std::vector<std::byte>>(prefix.error().code, prefix.error().offset);
    }

    auto frame = serialize_http3_frame(Http3Frame{Http3SettingsFrame{
        .settings = std::vector<Http3Setting>(settings.begin(), settings.end()),
    }});
    if (!frame.has_value()) {
        return codec_failure<std::vector<std::byte>>(frame.error().code, frame.error().offset);
    }

    auto output = prefix.value();
    output.insert(output.end(), frame.value().begin(), frame.value().end());
    return CodecResult<std::vector<std::byte>>::success(std::move(output));
}

Http3Result<bool> validate_http3_settings_frame(const Http3SettingsFrame &frame) {
    std::unordered_set<std::uint64_t> ids;
    for (const auto &setting : frame.settings) {
        if (!ids.insert(setting.id).second) {
            return http3_failure<bool>(Http3ErrorCode::settings_error, "duplicate setting");
        }
    }

    return Http3Result<bool>::success(true);
}

Http3Result<Http3RequestHead> validate_http3_request_headers(std::span<const Http3Field> fields) {
    Http3RequestHead head;
    bool saw_regular_header = false;
    bool saw_method = false;
    bool saw_scheme = false;
    bool saw_authority = false;
    bool saw_path = false;

    for (const auto &field : fields) {
        if (field.name.empty()) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "empty header name");
        }
        const bool is_pseudo = !field.name.empty() && field.name.front() == ':';
        if (is_pseudo && saw_regular_header) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "pseudo header after regular header");
        }
        if (header_name_has_uppercase(field.name)) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "uppercase header name");
        }

        if (!is_pseudo) {
            saw_regular_header = true;
            head.headers.push_back(field);
            continue;
        }

        if (field.name == ":method") {
            if (saw_method) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "duplicate request pseudo header");
            }
            saw_method = true;
            head.method = field.value;
            continue;
        }
        if (field.name == ":scheme") {
            if (saw_scheme) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "duplicate request pseudo header");
            }
            saw_scheme = true;
            head.scheme = field.value;
            continue;
        }
        if (field.name == ":authority") {
            if (saw_authority) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "duplicate request pseudo header");
            }
            saw_authority = true;
            head.authority = field.value;
            continue;
        }
        if (field.name == ":path") {
            if (saw_path) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "duplicate request pseudo header");
            }
            saw_path = true;
            head.path = field.value;
            continue;
        }

        return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                               "unexpected request pseudo header");
    }

    if (head.method.empty() || head.scheme.empty() || head.path.empty()) {
        return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                               "missing required request pseudo header");
    }

    return Http3Result<Http3RequestHead>::success(std::move(head));
}

Http3Result<Http3ResponseHead> validate_http3_response_headers(std::span<const Http3Field> fields) {
    Http3ResponseHead head;
    bool saw_regular_header = false;
    bool saw_status = false;

    for (const auto &field : fields) {
        if (field.name.empty()) {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "empty header name");
        }
        const bool is_pseudo = !field.name.empty() && field.name.front() == ':';
        if (is_pseudo && saw_regular_header) {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "pseudo header after regular header");
        }
        if (header_name_has_uppercase(field.name)) {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "uppercase header name");
        }

        if (!is_pseudo) {
            saw_regular_header = true;
            head.headers.push_back(field);
            continue;
        }

        if (field.name != ":status") {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "unexpected response pseudo header");
        }
        if (saw_status) {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "duplicate response pseudo header");
        }
        saw_status = true;

        unsigned int status = 0;
        const auto *begin = field.value.data();
        const auto *end = begin + field.value.size();
        const auto parsed = std::from_chars(begin, end, status);
        if (field.value.size() != 3 || parsed.ec != std::errc{} || parsed.ptr != end ||
            status < 100 || status > 999) {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "invalid :status");
        }

        head.status = static_cast<std::uint16_t>(status);
    }

    if (!saw_status) {
        return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                "missing required response pseudo header");
    }

    return Http3Result<Http3ResponseHead>::success(std::move(head));
}

Http3Result<Http3Headers> validate_http3_trailers(std::span<const Http3Field> fields) {
    Http3Headers trailers;
    trailers.reserve(fields.size());
    for (const auto &field : fields) {
        if (field.name.empty() || field.name.front() == ':') {
            return http3_failure<Http3Headers>(Http3ErrorCode::message_error,
                                               "trailers must not contain pseudo headers");
        }
        if (header_name_has_uppercase(field.name)) {
            return http3_failure<Http3Headers>(Http3ErrorCode::message_error,
                                               "uppercase header name");
        }
        trailers.push_back(field);
    }

    return Http3Result<Http3Headers>::success(std::move(trailers));
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

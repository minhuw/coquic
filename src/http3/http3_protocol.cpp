#include "src/http3/http3_protocol.h"
#include "src/http3/http3_protocol_test_hooks.h"

#include <charconv>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include "src/quic/buffer.h"

namespace coquic::http3 {

using quic::BufferReader;
using quic::BufferWriter;
using quic::CodecErrorCode;
using quic::CodecResult;
using quic::decode_varint;
using quic::decode_varint_bytes;
using quic::encode_varint;
using quic::VarIntDecoded;

namespace {

bool is_reserved_http2_derived_frame_type(std::uint64_t type) {
    return type == 0x02u || type == 0x06u || type == 0x08u || type == 0x09u;
}

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

std::string_view trim_ows(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool is_connection_specific_header(std::string_view name) {
    return name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
           name == "upgrade" || name == "transfer-encoding";
}

bool iequals_ascii(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    for (std::size_t index = 0; index < lhs.size(); ++index) {
        if (std::tolower(static_cast<unsigned char>(lhs[index])) !=
            std::tolower(static_cast<unsigned char>(rhs[index]))) {
            return false;
        }
    }
    return true;
}

Http3Result<std::uint64_t> parse_content_length_value(std::string_view value) {
    std::optional<std::uint64_t> parsed_value;

    while (true) {
        const auto comma = value.find(',');
        const auto token = trim_ows(value.substr(0, comma));
        if (token.empty()) {
            return http3_failure<std::uint64_t>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
        }

        std::uint64_t current = 0;
        const auto *begin = token.data();
        const auto *end = begin + token.size();
        const auto parsed = std::from_chars(begin, end, current);
        if (parsed.ec != std::errc{} || parsed.ptr != end) {
            return http3_failure<std::uint64_t>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
        }

        if (parsed_value.has_value() && *parsed_value != current) {
            return http3_failure<std::uint64_t>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
        }
        parsed_value = current;

        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }

    return Http3Result<std::uint64_t>::success(*parsed_value);
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
            } else if constexpr (std::is_same_v<T, Http3GoawayFrame>) {
                const auto encoded_id = encode_varint(typed_frame.id);
                if (!encoded_id.has_value()) {
                    return codec_failure<std::vector<std::byte>>(encoded_id.error().code,
                                                                 encoded_id.error().offset);
                }

                return serialize_http3_payload_frame(kHttp3FrameTypeGoaway, encoded_id.value());
            } else if constexpr (std::is_same_v<T, Http3MaxPushIdFrame>) {
                const auto encoded_push_id = encode_varint(typed_frame.push_id);
                if (!encoded_push_id.has_value()) {
                    return codec_failure<std::vector<std::byte>>(encoded_push_id.error().code,
                                                                 encoded_push_id.error().offset);
                }

                return serialize_http3_payload_frame(kHttp3FrameTypeMaxPushId,
                                                     encoded_push_id.value());
            } else {
                return serialize_http3_payload_frame(typed_frame.type, typed_frame.payload);
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

    const auto payload = reader.read_exact(static_cast<std::size_t>(frame_length.value())).value();

    Http3Frame frame;
    if (frame_type.value() == kHttp3FrameTypeData) {
        frame = Http3DataFrame{
            .payload = std::vector<std::byte>(payload.begin(), payload.end()),
        };
    } else if (frame_type.value() == kHttp3FrameTypeHeaders) {
        frame = Http3HeadersFrame{
            .field_section = std::vector<std::byte>(payload.begin(), payload.end()),
        };
    } else if (frame_type.value() == kHttp3FrameTypeSettings) {
        BufferReader payload_reader(payload);
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
        BufferReader payload_reader(payload);
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
    } else if (frame_type.value() == kHttp3FrameTypeMaxPushId) {
        BufferReader payload_reader(payload);
        const auto push_id = read_varint(payload_reader);
        if (!push_id.has_value()) {
            return codec_failure<Http3DecodedFrame>(push_id.error().code, push_id.error().offset);
        }
        if (payload_reader.remaining() != 0) {
            return codec_failure<Http3DecodedFrame>(CodecErrorCode::http3_parse_error,
                                                    payload_reader.offset());
        }
        frame = Http3MaxPushIdFrame{
            .push_id = push_id.value(),
        };
    } else {
        frame = Http3UnknownFrame{
            .type = frame_type.value(),
            .payload = std::vector<std::byte>(payload.begin(), payload.end()),
        };
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
    auto prefix = serialize_http3_uni_stream_prefix(Http3UniStreamType::control).value();

    auto frame = serialize_http3_frame(Http3Frame{Http3SettingsFrame{
        .settings = std::vector<Http3Setting>(settings.begin(), settings.end()),
    }});
    if (!frame.has_value()) {
        return codec_failure<std::vector<std::byte>>(frame.error().code, frame.error().offset);
    }

    auto output = std::move(prefix);
    output.insert(output.end(), frame.value().begin(), frame.value().end());
    return CodecResult<std::vector<std::byte>>::success(std::move(output));
}

Http3Result<bool> validate_http3_settings_frame(const Http3SettingsFrame &frame) {
    static const std::unordered_set<std::uint64_t> kReservedHttp2Settings = {
        0x02,
        0x03,
        0x04,
        0x05,
    };

    std::unordered_set<std::uint64_t> ids;
    for (const auto &setting : frame.settings) {
        if (!ids.insert(setting.id).second) {
            return http3_failure<bool>(Http3ErrorCode::settings_error, "duplicate setting");
        }
        if (kReservedHttp2Settings.contains(setting.id)) {
            return http3_failure<bool>(Http3ErrorCode::settings_error,
                                       "reserved setting identifier");
        }
    }

    return Http3Result<bool>::success(true);
}

Http3Result<bool> validate_http3_goaway_id(Http3ConnectionRole role, std::uint64_t id) {
    if (role == Http3ConnectionRole::client && ((id & 0x03u) != 0u)) {
        return http3_failure<bool>(Http3ErrorCode::id_error, "invalid server goaway stream id");
    }

    return Http3Result<bool>::success(true);
}

Http3Result<Http3RequestHead> validate_http3_request_headers(std::span<const Http3Field> fields) {
    Http3RequestHead head;
    std::optional<std::string_view> host_header;
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
        const bool is_pseudo = field.name.front() == ':';
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
            if (is_connection_specific_header(field.name)) {
                return http3_failure<Http3RequestHead>(
                    Http3ErrorCode::message_error, "connection-specific header is not permitted");
            }
            if (field.name == "host") {
                if (field.value.empty()) {
                    return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                           "empty host header");
                }
                host_header = field.value;
            }
            if (field.name == "te" && !iequals_ascii(trim_ows(field.value), "trailers")) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "invalid te header");
            }
            if (field.name == "content-length") {
                const auto content_length = parse_content_length_value(field.value);
                if (!content_length.has_value()) {
                    return http3_failure<Http3RequestHead>(content_length.error().code,
                                                           content_length.error().detail);
                }
                if (head.content_length.has_value() &&
                    *head.content_length != content_length.value()) {
                    return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                           "invalid content-length header");
                }
                head.content_length = content_length.value();
            }
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
            if (field.value.empty()) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "empty :authority pseudo header");
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
    if ((head.scheme == "http" || head.scheme == "https") && head.authority.empty() &&
        !host_header.has_value()) {
        return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                               "missing required authority information");
    }
    if (saw_authority && host_header.has_value() && *host_header != head.authority) {
        return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                               "mismatched :authority and host");
    }
    if (head.authority.empty() && host_header.has_value()) {
        head.authority = std::string(*host_header);
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
        const bool is_pseudo = field.name.front() == ':';
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
            if (is_connection_specific_header(field.name)) {
                return http3_failure<Http3ResponseHead>(
                    Http3ErrorCode::message_error, "connection-specific header is not permitted");
            }
            if (field.name == "te") {
                return http3_failure<Http3ResponseHead>(
                    Http3ErrorCode::message_error, "connection-specific header is not permitted");
            }
            if (field.name == "content-length") {
                const auto content_length = parse_content_length_value(field.value);
                if (!content_length.has_value()) {
                    return http3_failure<Http3ResponseHead>(content_length.error().code,
                                                            content_length.error().detail);
                }
                if (head.content_length.has_value() &&
                    *head.content_length != content_length.value()) {
                    return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                            "invalid content-length header");
                }
                head.content_length = content_length.value();
            }
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
            status < 100) {
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

bool http3_frame_allowed_on_control_stream(Http3ConnectionRole role, const Http3Frame &frame) {
    if (std::holds_alternative<Http3SettingsFrame>(frame) ||
        std::holds_alternative<Http3GoawayFrame>(frame)) {
        return true;
    }
    if (std::holds_alternative<Http3MaxPushIdFrame>(frame)) {
        return role == Http3ConnectionRole::server;
    }
    if (const auto *unknown = std::get_if<Http3UnknownFrame>(&frame)) {
        return !is_reserved_http2_derived_frame_type(unknown->type);
    }
    return false;
}

bool http3_frame_allowed_on_request_stream(const Http3Frame &frame) {
    if (std::holds_alternative<Http3DataFrame>(frame) ||
        std::holds_alternative<Http3HeadersFrame>(frame)) {
        return true;
    }
    if (const auto *unknown = std::get_if<Http3UnknownFrame>(&frame)) {
        return !is_reserved_http2_derived_frame_type(unknown->type);
    }
    return false;
}

} // namespace coquic::http3

namespace coquic::http3::test {

quic::CodecResult<std::vector<std::byte>>
serialize_http3_payload_frame_with_synthetic_length_for_tests(std::uint64_t type,
                                                              std::size_t payload_size) {
    const std::byte sentinel{0x00};
    return serialize_http3_payload_frame(type, std::span<const std::byte>(&sentinel, payload_size));
}

} // namespace coquic::http3::test

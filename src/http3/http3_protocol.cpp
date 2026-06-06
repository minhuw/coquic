#include "src/http3/http3_protocol.h"
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include "src/quic/codec/buffer.h"

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

std::optional<quic::CodecError> write_http3_payload_frame(BufferWriter &frame_writer,
                                                          std::uint64_t type,
                                                          std::span<const std::byte> payload) {
    const auto encoded_type = encode_varint(type);
    if (!encoded_type.has_value()) {
        return encoded_type.error();
    }

    const auto encoded_length = encode_varint(payload.size());
    if (!encoded_length.has_value()) {
        return encoded_length.error();
    }

    frame_writer.write_bytes(encoded_type.value());
    frame_writer.write_bytes(encoded_length.value());
    frame_writer.write_bytes(payload);
    return std::nullopt;
}

CodecResult<std::vector<std::byte>>
serialize_http3_payload_frame(std::uint64_t type, std::span<const std::byte> payload) {
    BufferWriter frame_writer;
    if (const auto error = write_http3_payload_frame(frame_writer, type, payload);
        error.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(*error);
    }
    return CodecResult<std::vector<std::byte>>::success(frame_writer.bytes());
}

CodecResult<std::vector<std::byte>>
serialize_http3_data_payload_frame(std::span<const std::byte> payload) {
    BufferWriter writer;
    if (const auto error = write_http3_payload_frame(writer, kHttp3FrameTypeData, payload);
        error.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(*error);
    }
    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<std::vector<std::byte>>
serialize_http3_headers_payload_frame(std::span<const std::byte> field_section) {
    BufferWriter writer;
    if (const auto error = write_http3_payload_frame(writer, kHttp3FrameTypeHeaders, field_section);
        error.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(*error);
    }
    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
CodecResult<std::vector<std::byte>> serialize_http3_varint_payload_frame(std::uint64_t type,
                                                                         std::uint64_t value) {
    const auto encoded_value = encode_varint(value);
    if (!encoded_value.has_value()) {
        return codec_failure<std::vector<std::byte>>(encoded_value.error().code,
                                                     encoded_value.error().offset);
    }

    return serialize_http3_payload_frame(type, encoded_value.value());
}

CodecResult<std::vector<std::byte>>
serialize_http3_push_promise_frame(const Http3PushPromiseFrame &frame) {
    const auto encoded_push_id = encode_varint(frame.push_id);
    if (!encoded_push_id.has_value()) {
        return codec_failure<std::vector<std::byte>>(encoded_push_id.error().code,
                                                     encoded_push_id.error().offset);
    }

    BufferWriter writer;
    writer.write_bytes(encoded_push_id.value());
    writer.write_bytes(frame.field_section);
    return serialize_http3_payload_frame(kHttp3FrameTypePushPromise, writer.bytes());
}

bool header_name_has_uppercase(std::string_view name) {
    for (const unsigned char ch : name) {
        if (std::isupper(ch) != 0) {
            return true;
        }
    }

    return false;
}

bool is_http_token_char(unsigned char ch) {
    if (std::isalnum(ch) != 0) {
        return true;
    }

    switch (ch) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '=':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
        return true;
    default:
        return false;
    }
}

bool header_name_is_valid(std::string_view name) {
    if (name.empty()) {
        return false;
    }

    const bool is_pseudo = name.front() == ':';
    if (is_pseudo) {
        if (name.size() == 1) {
            return false;
        }
        name.remove_prefix(1);
        if (std::memchr(name.data(), ':', name.size()) != nullptr) {
            return false;
        }
    }

    for (const unsigned char ch : name) {
        if (!is_http_token_char(ch)) {
            return false;
        }
    }
    return true;
}

bool header_value_is_valid(std::string_view value) {
    for (const unsigned char ch : value) {
        if (ch < 0x20u && ch != '\t') {
            return false;
        }
        if (ch == 0x7fu) {
            return false;
        }
    }
    return true;
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

bool is_alpha_ascii(unsigned char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

bool is_uri_scheme_char(unsigned char ch) {
    return std::isalnum(ch) != 0 || ch == '+' || ch == '-' || ch == '.';
}

bool uri_scheme_is_valid(std::string_view scheme) {
    if (scheme.empty() || !is_alpha_ascii(static_cast<unsigned char>(scheme.front()))) {
        return false;
    }
    for (const unsigned char ch : scheme.substr(1)) {
        if (!is_uri_scheme_char(ch)) {
            return false;
        }
    }
    return true;
}

bool is_uri_pchar_or_query_char(unsigned char ch) {
    if (std::isalnum(ch) != 0) {
        return true;
    }

    switch (ch) {
    case '-':
    case '.':
    case '_':
    case '~':
    case ':':
    case '@':
    case '!':
    case '$':
    case '&':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '+':
    case ',':
    case ';':
    case '=':
    case '%':
    case '/':
    case '?':
        return true;
    default:
        return false;
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool path_is_valid(std::string_view path, std::string_view method) {
    if (path == "*") {
        return method == "OPTIONS";
    }
    if (path.empty() || path.front() != '/') {
        return false;
    }
    for (const unsigned char ch : path) {
        if (!is_uri_pchar_or_query_char(ch)) {
            return false;
        }
    }
    return true;
}

bool authority_contains_userinfo(std::string_view authority) {
    return authority.find('@') != std::string_view::npos;
}

bool authority_is_valid(std::string_view authority) {
    if (authority.empty()) {
        return false;
    }
    for (const unsigned char ch : authority) {
        if (ch <= 0x20u || ch == 0x7fu || ch == '/' || ch == '?' || ch == '#') {
            return false;
        }
    }
    return true;
}

bool later_field_named(std::span<const Http3Field> fields, std::size_t start,
                       std::string_view name) {
    for (std::size_t index = start; index < fields.size(); ++index) {
        if (fields[index].name == name) {
            return true;
        }
    }
    return false;
}

Http3Result<std::uint64_t> parse_content_length_value(std::string_view value) {
    std::optional<std::uint64_t> parsed_value;

    bool parsing = true;
    while (parsing) {
        const auto comma = value.find(',');
        const auto token = trim_ows(value.substr(0, comma));
        if (token.empty()) {
            return http3_failure<std::uint64_t>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
        }

        std::uint64_t current = 0;
        const auto *field_begin = token.data();
        const auto *field_end = field_begin + token.size();
        const auto parsed_number = std::from_chars(field_begin, field_end, current);
        if (parsed_number.ec != std::errc{} || parsed_number.ptr != field_end) {
            return http3_failure<std::uint64_t>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
        }

        if (parsed_value.has_value() && *parsed_value != current) {
            return http3_failure<std::uint64_t>(Http3ErrorCode::message_error,
                                                "invalid content-length header");
        }
        parsed_value = current;

        if (comma == std::string_view::npos) {
            parsing = false;
        } else {
            value.remove_prefix(comma + 1);
        }
    }

    return Http3Result<std::uint64_t>::success(*parsed_value);
}

template <typename T> Http3Result<T> validate_field_wire_syntax(const Http3Field &field) {
    if (field.name.empty()) {
        return http3_failure<T>(Http3ErrorCode::message_error, "empty header name");
    }
    if (!header_name_is_valid(field.name)) {
        return http3_failure<T>(Http3ErrorCode::message_error, "invalid header name");
    }
    if (header_name_has_uppercase(field.name)) {
        return http3_failure<T>(Http3ErrorCode::message_error, "uppercase header name");
    }
    if (!header_value_is_valid(field.value)) {
        return http3_failure<T>(Http3ErrorCode::message_error, "invalid header value");
    }
    return Http3Result<T>::success(T{});
}

} // namespace

CodecResult<std::vector<std::byte>> serialize_http3_frame(const Http3Frame &frame) {
    struct FrameSerializer {
        CodecResult<std::vector<std::byte>> operator()(const Http3DataFrame &typed_frame) const {
            return serialize_http3_data_payload_frame(typed_frame.payload);
        }

        CodecResult<std::vector<std::byte>> operator()(const Http3HeadersFrame &typed_frame) const {
            return serialize_http3_headers_payload_frame(typed_frame.field_section);
        }

        CodecResult<std::vector<std::byte>>
        operator()(const Http3CancelPushFrame &typed_frame) const {
            return serialize_http3_varint_payload_frame(kHttp3FrameTypeCancelPush,
                                                        typed_frame.push_id);
        }

        CodecResult<std::vector<std::byte>>
        operator()(const Http3SettingsFrame &typed_frame) const {
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
        }

        CodecResult<std::vector<std::byte>>
        operator()(const Http3PushPromiseFrame &typed_frame) const {
            return serialize_http3_push_promise_frame(typed_frame);
        }

        CodecResult<std::vector<std::byte>> operator()(const Http3GoawayFrame &typed_frame) const {
            return serialize_http3_varint_payload_frame(kHttp3FrameTypeGoaway, typed_frame.id);
        }

        CodecResult<std::vector<std::byte>>
        operator()(const Http3MaxPushIdFrame &typed_frame) const {
            return serialize_http3_varint_payload_frame(kHttp3FrameTypeMaxPushId,
                                                        typed_frame.push_id);
        }

        CodecResult<std::vector<std::byte>> operator()(const Http3UnknownFrame &typed_frame) const {
            BufferWriter writer;
            if (const auto error =
                    write_http3_payload_frame(writer, typed_frame.type, typed_frame.payload);
                error.has_value()) {
                return CodecResult<std::vector<std::byte>>::failure(*error);
            }
            return CodecResult<std::vector<std::byte>>::success(writer.bytes());
        }
    };

    return std::visit(FrameSerializer{}, frame);
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
    } else if (frame_type.value() == kHttp3FrameTypeCancelPush) {
        BufferReader payload_reader(payload);
        const auto push_id = read_varint(payload_reader);
        if (!push_id.has_value()) {
            return codec_failure<Http3DecodedFrame>(push_id.error().code, push_id.error().offset);
        }
        if (payload_reader.remaining() != 0) {
            return codec_failure<Http3DecodedFrame>(CodecErrorCode::http3_parse_error,
                                                    payload_reader.offset());
        }
        frame = Http3CancelPushFrame{
            .push_id = push_id.value(),
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
    } else if (frame_type.value() == kHttp3FrameTypePushPromise) {
        BufferReader payload_reader(payload);
        const auto push_id = read_varint(payload_reader);
        if (!push_id.has_value()) {
            return codec_failure<Http3DecodedFrame>(push_id.error().code, push_id.error().offset);
        }
        const auto field_section = payload.subspan(payload_reader.offset());
        frame = Http3PushPromiseFrame{
            .push_id = push_id.value(),
            .field_section = std::vector<std::byte>(field_section.begin(), field_section.end()),
        };
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

std::optional<std::uint64_t> http3_field_section_size(std::span<const Http3Field> fields) {
    std::uint64_t size = 0;
    for (std::size_t field_index = 0; field_index < fields.size(); ++field_index) {
        const auto &field = fields[field_index];
        const auto name_size = static_cast<std::uint64_t>(field.name.size());
        const auto value_size = static_cast<std::uint64_t>(field.value.size());
        constexpr std::uint64_t kFieldOverhead = 32;

        if (size > std::numeric_limits<std::uint64_t>::max() - name_size) {
            return std::nullopt;
        }
        size += name_size;
        if (size > std::numeric_limits<std::uint64_t>::max() - value_size) {
            return std::nullopt;
        }
        size += value_size;
        if (size > std::numeric_limits<std::uint64_t>::max() - kFieldOverhead) {
            return std::nullopt;
        }
        size += kFieldOverhead;
    }
    return size;
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

    for (std::size_t field_index = 0; field_index < fields.size(); ++field_index) {
        const auto &field = fields[field_index];
        if (const auto syntax = validate_field_wire_syntax<Http3RequestHead>(field);
            !syntax.has_value()) {
            return syntax;
        }
        const bool is_pseudo = field.name.front() == ':';
        if (is_pseudo && saw_regular_header) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "pseudo header after regular header");
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
            if (field.value.empty()) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "empty :method pseudo header");
            }
            head.method = field.value;
            continue;
        }
        if (field.name == ":scheme") {
            if (saw_scheme) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "duplicate request pseudo header");
            }
            saw_scheme = true;
            if (!uri_scheme_is_valid(field.value)) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "invalid :scheme pseudo header");
            }
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
            if (!authority_is_valid(field.value)) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "invalid :authority pseudo header");
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
            if (!saw_method && later_field_named(fields, field_index + 1, ":method")) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       ":path before :method");
            }
            saw_path = true;
            if (!path_is_valid(field.value, head.method)) {
                return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                       "invalid :path pseudo header");
            }
            head.path = field.value;
            continue;
        }

        return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                               "unexpected request pseudo header");
    }

    if (head.method == "CONNECT") {
        if (!saw_authority || head.authority.empty() || saw_scheme || saw_path) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "malformed connect request pseudo headers");
        }
        if (!authority_is_valid(head.authority)) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "invalid :authority pseudo header");
        }
        if (host_header.has_value() && *host_header != head.authority) {
            return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                                   "mismatched :authority and host");
        }
        return Http3Result<Http3RequestHead>::success(std::move(head));
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
    if ((head.scheme == "http" || head.scheme == "https") &&
        ((!head.authority.empty() && authority_contains_userinfo(head.authority)) ||
         (host_header.has_value() && authority_contains_userinfo(*host_header)))) {
        return http3_failure<Http3RequestHead>(Http3ErrorCode::message_error,
                                               "userinfo is not permitted in authority");
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
        if (const auto syntax = validate_field_wire_syntax<Http3ResponseHead>(field);
            !syntax.has_value()) {
            return syntax;
        }
        const bool is_pseudo = field.name.front() == ':';
        if (is_pseudo && saw_regular_header) {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "pseudo header after regular header");
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

        if (field.value.size() != 3 || field.value[0] < '1' || field.value[0] > '9' ||
            field.value[1] < '0' || field.value[1] > '9' || field.value[2] < '0' ||
            field.value[2] > '9') {
            return http3_failure<Http3ResponseHead>(Http3ErrorCode::message_error,
                                                    "invalid :status");
        }

        const auto status = static_cast<unsigned int>(
            (field.value[0] - '0') * 100 + (field.value[1] - '0') * 10 + (field.value[2] - '0'));
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
        if (const auto syntax = validate_field_wire_syntax<Http3Headers>(field);
            !syntax.has_value()) {
            return syntax;
        }
        if (field.name.front() == ':') {
            return http3_failure<Http3Headers>(Http3ErrorCode::message_error,
                                               "trailers must not contain pseudo headers");
        }
        if (is_connection_specific_header(field.name) || field.name == "te") {
            return http3_failure<Http3Headers>(Http3ErrorCode::message_error,
                                               "connection-specific header is not permitted");
        }
        trailers.push_back(field);
    }

    return Http3Result<Http3Headers>::success(std::move(trailers));
}

bool http3_frame_allowed_on_control_stream(Http3ConnectionRole role, const Http3Frame &frame) {
    if (std::holds_alternative<Http3SettingsFrame>(frame) ||
        std::holds_alternative<Http3GoawayFrame>(frame) ||
        std::holds_alternative<Http3CancelPushFrame>(frame)) {
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
        std::holds_alternative<Http3HeadersFrame>(frame) ||
        std::holds_alternative<Http3PushPromiseFrame>(frame)) {
        return true;
    }
    if (const auto *unknown = std::get_if<Http3UnknownFrame>(&frame)) {
        return !is_reserved_http2_derived_frame_type(unknown->type);
    }
    return false;
}

} // namespace coquic::http3

#include "src/http3/http3_qpack.h"

#include <array>
#include <optional>
#include <string_view>

namespace {

struct StaticTableEntry {
    std::string_view name;
    std::string_view value;
};

constexpr std::array<StaticTableEntry, 10> kStaticTable = {{
    {":authority", ""},
    {":path", "/"},
    {"content-length", "0"},
    {":method", "GET"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "404"},
    {"content-type", "text/plain"},
    {"content-type", "text/html"},
    {"server", "coquic"},
}};

std::optional<std::size_t> lookup_http3_qpack_static_entry(const coquic::http3::Http3Field &field) {
    for (std::size_t index = 0; index < kStaticTable.size(); ++index) {
        if (kStaticTable[index].name == field.name && kStaticTable[index].value == field.value) {
            return index;
        }
    }
    return std::nullopt;
}

void append_indexed_field(std::vector<std::byte> &out, std::size_t index) {
    const auto encoded = coquic::quic::encode_varint(index);
    out.push_back(std::byte{0x80});
    out.insert(out.end(), encoded.value().begin(), encoded.value().end());
}

void append_literal_field(std::vector<std::byte> &out, const coquic::http3::Http3Field &field) {
    out.push_back(std::byte{0x20});
    out.push_back(static_cast<std::byte>(field.name.size()));
    out.insert(out.end(), reinterpret_cast<const std::byte *>(field.name.data()),
               reinterpret_cast<const std::byte *>(field.name.data()) + field.name.size());
    out.push_back(static_cast<std::byte>(field.value.size()));
    out.insert(out.end(), reinterpret_cast<const std::byte *>(field.value.data()),
               reinterpret_cast<const std::byte *>(field.value.data()) + field.value.size());
}

} // namespace

namespace coquic::http3 {

using quic::CodecErrorCode;
using quic::CodecResult;
using quic::decode_varint_bytes;

CodecResult<std::vector<std::byte>> encode_http3_field_section(std::span<const Http3Field> fields) {
    std::vector<std::byte> out;
    for (const auto &field : fields) {
        const auto static_index = lookup_http3_qpack_static_entry(field);
        if (static_index.has_value()) {
            append_indexed_field(out, *static_index);
            continue;
        }
        if (field.name.size() > 0xff || field.value.size() > 0xff) {
            return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::http3_parse_error,
                                                                0);
        }
        append_literal_field(out, field);
    }
    return CodecResult<std::vector<std::byte>>::success(std::move(out));
}

Http3Result<Http3Headers> decode_http3_field_section(std::span<const std::byte> bytes) {
    Http3Headers headers;
    for (std::size_t index = 0; index < bytes.size();) {
        const auto prefix = std::to_integer<std::uint8_t>(bytes[index]);
        if ((prefix & 0x80u) != 0u) {
            const auto decoded = decode_varint_bytes(bytes.subspan(index + 1));
            if (!decoded.has_value() || decoded.value().value >= kStaticTable.size()) {
                return Http3Result<Http3Headers>::failure(Http3Error{
                    .code = Http3ErrorCode::qpack_decompression_failed,
                    .detail = "invalid static table index",
                });
            }
            const auto &entry = kStaticTable[decoded.value().value];
            headers.push_back(Http3Field{
                .name = std::string(entry.name),
                .value = std::string(entry.value),
            });
            index += 1 + decoded.value().bytes_consumed;
            continue;
        }

        if (prefix != 0x20u || index + 2 >= bytes.size()) {
            return Http3Result<Http3Headers>::failure(Http3Error{
                .code = Http3ErrorCode::qpack_decompression_failed,
                .detail = "malformed literal field",
            });
        }

        const auto name_length = std::to_integer<std::uint8_t>(bytes[index + 1]);
        if (index + 2 + name_length >= bytes.size()) {
            return Http3Result<Http3Headers>::failure(Http3Error{
                .code = Http3ErrorCode::qpack_decompression_failed,
                .detail = "truncated literal field name",
            });
        }
        const auto name_begin = reinterpret_cast<const char *>(bytes.data() + index + 2);
        const auto value_length_index = index + 2 + name_length;
        const auto value_length = std::to_integer<std::uint8_t>(bytes[value_length_index]);
        if (value_length_index + 1 + value_length > bytes.size()) {
            return Http3Result<Http3Headers>::failure(Http3Error{
                .code = Http3ErrorCode::qpack_decompression_failed,
                .detail = "truncated literal field value",
            });
        }
        const auto value_begin =
            reinterpret_cast<const char *>(bytes.data() + value_length_index + 1);
        headers.push_back(Http3Field{
            .name = std::string(name_begin, name_length),
            .value = std::string(value_begin, value_length),
        });
        index = value_length_index + 1 + value_length;
    }
    return Http3Result<Http3Headers>::success(std::move(headers));
}

Http3Result<bool> validate_http3_qpack_encoder_stream(std::span<const std::byte> bytes,
                                                      const Http3QpackSettings &settings) {
    if (settings.max_table_capacity == 0 && !bytes.empty()) {
        return Http3Result<bool>::failure(Http3Error{
            .code = Http3ErrorCode::qpack_encoder_stream_error,
            .detail = "dynamic table instructions disabled",
        });
    }
    return Http3Result<bool>::success(true);
}

Http3Result<bool> validate_http3_qpack_decoder_stream(std::span<const std::byte> bytes,
                                                      const Http3QpackSettings &settings) {
    if (settings.blocked_streams == 0 && !bytes.empty()) {
        return Http3Result<bool>::failure(Http3Error{
            .code = Http3ErrorCode::qpack_decoder_stream_error,
            .detail = "decoder instructions disabled",
        });
    }
    return Http3Result<bool>::success(true);
}

} // namespace coquic::http3

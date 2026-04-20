#include "src/http3/http3_qpack.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "src/quic/buffer.h"

namespace {

using coquic::http3::Http3DecodedFieldSection;
using coquic::http3::Http3EncodedFieldSection;
using coquic::http3::Http3Error;
using coquic::http3::Http3ErrorCode;
using coquic::http3::Http3Field;
using coquic::http3::Http3Headers;
using coquic::http3::Http3QpackDecoderContext;
using coquic::http3::Http3QpackDecodeStatus;
using coquic::http3::Http3QpackEncoderContext;
using coquic::http3::Http3QpackEntry;
using coquic::http3::Http3QpackOutstandingFieldSection;
using coquic::http3::Http3QpackPendingFieldSection;
using coquic::http3::Http3QpackSectionAcknowledgment;
using coquic::http3::Http3Result;
namespace quic = coquic::quic;

struct StaticTableEntry {
    std::string_view name;
    std::string_view value;
};

struct ParsedFieldSectionPrefix {
    std::uint64_t required_insert_count = 0;
    std::uint64_t base = 0;
};

struct HuffmanNode {
    int zero = -1;
    int one = -1;
    int symbol = -1;
};

constexpr std::array<StaticTableEntry, 99> kStaticTable = {{
    {":authority", ""},
    {":path", "/"},
    {"age", "0"},
    {"content-disposition", ""},
    {"content-length", "0"},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"referer", ""},
    {"set-cookie", ""},
    {":method", "CONNECT"},
    {":method", "DELETE"},
    {":method", "GET"},
    {":method", "HEAD"},
    {":method", "OPTIONS"},
    {":method", "POST"},
    {":method", "PUT"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "304"},
    {":status", "404"},
    {":status", "503"},
    {"accept", "*/*"},
    {"accept", "application/dns-message"},
    {"accept-encoding", "gzip, deflate, br"},
    {"accept-ranges", "bytes"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"cache-control", "max-age=0"},
    {"cache-control", "max-age=2592000"},
    {"cache-control", "max-age=604800"},
    {"cache-control", "no-cache"},
    {"cache-control", "no-store"},
    {"cache-control", "public, max-age=31536000"},
    {"content-encoding", "br"},
    {"content-encoding", "gzip"},
    {"content-type", "application/dns-message"},
    {"content-type", "application/javascript"},
    {"content-type", "application/json"},
    {"content-type", "application/x-www-form-urlencoded"},
    {"content-type", "image/gif"},
    {"content-type", "image/jpeg"},
    {"content-type", "image/png"},
    {"content-type", "text/css"},
    {"content-type", "text/html; charset=utf-8"},
    {"content-type", "text/plain"},
    {"content-type", "text/plain;charset=utf-8"},
    {"range", "bytes=0-"},
    {"strict-transport-security", "max-age=31536000"},
    {"strict-transport-security", "max-age=31536000; includesubdomains"},
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
    {"vary", "accept-encoding"},
    {"vary", "origin"},
    {"x-content-type-options", "nosniff"},
    {"x-xss-protection", "1; mode=block"},
    {":status", "100"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "400"},
    {":status", "403"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {"accept-language", ""},
    {"access-control-allow-credentials", "FALSE"},
    {"access-control-allow-credentials", "TRUE"},
    {"access-control-allow-headers", "*"},
    {"access-control-allow-methods", "get"},
    {"access-control-allow-methods", "get, post, options"},
    {"access-control-allow-methods", "options"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", ""},
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", ""},
    {"forwarded", ""},
    {"if-range", ""},
    {"origin", ""},
    {"purpose", "prefetch"},
    {"server", ""},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", ""},
    {"x-forwarded-for", ""},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"},
}};

constexpr std::string_view kHpackHuffmanCodes = R"(1ff8 13
7fffd8 23
fffffe2 28
fffffe3 28
fffffe4 28
fffffe5 28
fffffe6 28
fffffe7 28
fffffe8 28
ffffea 24
3ffffffc 30
fffffe9 28
fffffea 28
3ffffffd 30
fffffeb 28
fffffec 28
fffffed 28
fffffee 28
fffffef 28
ffffff0 28
ffffff1 28
ffffff2 28
3ffffffe 30
ffffff3 28
ffffff4 28
ffffff5 28
ffffff6 28
ffffff7 28
ffffff8 28
ffffff9 28
ffffffa 28
ffffffb 28
14 6
3f8 10
3f9 10
ffa 12
1ff9 13
15 6
f8 8
7fa 11
3fa 10
3fb 10
f9 8
7fb 11
fa 8
16 6
17 6
18 6
0 5
1 5
2 5
19 6
1a 6
1b 6
1c 6
1d 6
1e 6
1f 6
5c 7
fb 8
7ffc 15
20 6
ffb 12
3fc 10
1ffa 13
21 6
5d 7
5e 7
5f 7
60 7
61 7
62 7
63 7
64 7
65 7
66 7
67 7
68 7
69 7
6a 7
6b 7
6c 7
6d 7
6e 7
6f 7
70 7
71 7
72 7
fc 8
73 7
fd 8
1ffb 13
7fff0 19
1ffc 13
3ffc 14
22 6
7ffd 15
3 5
23 6
4 5
24 6
5 5
25 6
26 6
27 6
6 5
74 7
75 7
28 6
29 6
2a 6
7 5
2b 6
76 7
2c 6
8 5
9 5
2d 6
77 7
78 7
79 7
7a 7
7b 7
7ffe 15
7fc 11
3ffd 14
1ffd 13
ffffffc 28
fffe6 20
3fffd2 22
fffe7 20
fffe8 20
3fffd3 22
3fffd4 22
3fffd5 22
7fffd9 23
3fffd6 22
7fffda 23
7fffdb 23
7fffdc 23
7fffdd 23
7fffde 23
ffffeb 24
7fffdf 23
ffffec 24
ffffed 24
3fffd7 22
7fffe0 23
ffffee 24
7fffe1 23
7fffe2 23
7fffe3 23
7fffe4 23
1fffdc 21
3fffd8 22
7fffe5 23
3fffd9 22
7fffe6 23
7fffe7 23
ffffef 24
3fffda 22
1fffdd 21
fffe9 20
3fffdb 22
3fffdc 22
7fffe8 23
7fffe9 23
1fffde 21
7fffea 23
3fffdd 22
3fffde 22
fffff0 24
1fffdf 21
3fffdf 22
7fffeb 23
7fffec 23
1fffe0 21
1fffe1 21
3fffe0 22
1fffe2 21
7fffed 23
3fffe1 22
7fffee 23
7fffef 23
fffea 20
3fffe2 22
3fffe3 22
3fffe4 22
7ffff0 23
3fffe5 22
3fffe6 22
7ffff1 23
3ffffe0 26
3ffffe1 26
fffeb 20
7fff1 19
3fffe7 22
7ffff2 23
3fffe8 22
1ffffec 25
3ffffe2 26
3ffffe3 26
3ffffe4 26
7ffffde 27
7ffffdf 27
3ffffe5 26
fffff1 24
1ffffed 25
7fff2 19
1fffe3 21
3ffffe6 26
7ffffe0 27
7ffffe1 27
3ffffe7 26
7ffffe2 27
fffff2 24
1fffe4 21
1fffe5 21
3ffffe8 26
3ffffe9 26
ffffffd 28
7ffffe3 27
7ffffe4 27
7ffffe5 27
fffec 20
fffff3 24
fffed 20
1fffe6 21
3fffe9 22
1fffe7 21
1fffe8 21
7ffff3 23
3fffea 22
3fffeb 22
1ffffee 25
1ffffef 25
fffff4 24
fffff5 24
3ffffea 26
7ffff4 23
3ffffeb 26
7ffffe6 27
3ffffec 26
3ffffed 26
7ffffe7 27
7ffffe8 27
7ffffe9 27
7ffffea 27
7ffffeb 27
ffffffe 28
7ffffec 27
7ffffed 27
7ffffee 27
7ffffef 27
7fffff0 27
3ffffee 26
3fffffff 30
)";

template <typename T>
Http3Result<T> qpack_failure(Http3ErrorCode code, std::string detail,
                             std::optional<std::uint64_t> stream_id = std::nullopt) {
    return Http3Result<T>::failure(Http3Error{
        .code = code,
        .detail = std::move(detail),
        .stream_id = stream_id,
    });
}

template <typename T> quic::CodecResult<T> qpack_encode_failure(std::size_t offset = 0) {
    return quic::CodecResult<T>::failure(quic::CodecErrorCode::http3_parse_error, offset);
}

constexpr bool kNeedUint64SizeCheck = std::numeric_limits<std::uint64_t>::max() >
                                      std::numeric_limits<std::size_t>::max();

template <typename T> std::size_t unchecked_size(T value) {
    return static_cast<std::size_t>(value);
}

std::size_t qpack_entry_size(const Http3Field &field) {
    return 32 + field.name.size() + field.value.size();
}

std::uint64_t max_entries_for_capacity(std::uint64_t capacity) {
    return capacity / 32;
}

std::string bytes_to_string(std::span<const std::byte> bytes) {
    return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void append_prefixed_integer(std::vector<std::byte> &out, std::uint8_t leading_bits,
                             std::uint8_t prefix_bits, std::uint64_t value) {
    const auto max_in_prefix = (static_cast<std::uint64_t>(1) << prefix_bits) - 1;
    if (value < max_in_prefix) {
        out.push_back(static_cast<std::byte>(leading_bits | static_cast<std::uint8_t>(value)));
        return;
    }

    out.push_back(static_cast<std::byte>(leading_bits | static_cast<std::uint8_t>(max_in_prefix)));
    value -= max_in_prefix;
    while (value >= 128) {
        out.push_back(static_cast<std::byte>(0x80u | static_cast<std::uint8_t>(value & 0x7fu)));
        value >>= 7u;
    }
    out.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value)));
}

std::optional<std::uint64_t> decode_prefixed_integer(quic::BufferReader &reader, std::uint8_t first,
                                                     std::uint8_t prefix_bits) {
    const auto max_in_prefix = (static_cast<std::uint64_t>(1) << prefix_bits) - 1;
    std::uint64_t value = first & static_cast<std::uint8_t>(max_in_prefix);
    if (value < max_in_prefix) {
        return value;
    }

    std::uint64_t shift = 0;
    while (true) {
        const auto next = reader.read_byte();
        if (!next.has_value()) {
            return std::nullopt;
        }
        const auto byte = std::to_integer<std::uint8_t>(next.value());
        const auto chunk = static_cast<std::uint64_t>(byte & 0x7fu);
        if (shift >= 63) {
            return std::nullopt;
        }
        value += chunk << shift;
        if ((byte & 0x80u) == 0u) {
            return value;
        }
        shift += 7;
    }
}

const std::vector<HuffmanNode> &hpack_huffman_trie() {
    static const auto trie = [] {
        std::vector<HuffmanNode> nodes(1);
        std::string_view remaining = kHpackHuffmanCodes;

        for (std::uint16_t symbol = 0; symbol <= 256; ++symbol) {
            const auto newline = remaining.find('\n');
            const auto line = remaining.substr(0, newline);
            remaining.remove_prefix(newline + 1);

            const auto separator = line.find(' ');
            std::uint32_t bits = 0;
            std::uint32_t length = 0;
            std::from_chars(line.begin(), line.begin() + separator, bits, 16);
            std::from_chars(line.begin() + separator + 1, line.end(), length, 10);

            int node = 0;
            for (int bit_index = static_cast<int>(length) - 1; bit_index >= 0; --bit_index) {
                const bool bit = ((bits >> bit_index) & 1u) != 0u;
                int child = bit ? nodes[static_cast<std::size_t>(node)].one
                                : nodes[static_cast<std::size_t>(node)].zero;
                if (child == -1) {
                    child = static_cast<int>(nodes.size());
                    nodes.push_back(HuffmanNode{});
                    if (bit) {
                        nodes[static_cast<std::size_t>(node)].one = child;
                    } else {
                        nodes[static_cast<std::size_t>(node)].zero = child;
                    }
                }
                node = child;
            }
            nodes[static_cast<std::size_t>(node)].symbol = symbol;
        }

        return nodes;
    }();

    return trie;
}

Http3Result<std::string> decode_hpack_huffman(std::span<const std::byte> bytes,
                                              std::string_view context, Http3ErrorCode code,
                                              std::optional<std::uint64_t> stream_id) {
    const auto &trie = hpack_huffman_trie();
    std::string decoded;
    int node = 0;
    int bits_since_symbol = 0;
    bool pending_bits_all_ones = true;

    for (const auto byte : bytes) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        for (int shift = 7; shift >= 0; --shift) {
            const bool bit = ((value >> shift) & 0x01u) != 0u;
            ++bits_since_symbol;
            pending_bits_all_ones = pending_bits_all_ones && bit;

            node = bit ? trie[static_cast<std::size_t>(node)].one
                       : trie[static_cast<std::size_t>(node)].zero;
            const int symbol = trie[static_cast<std::size_t>(node)].symbol;
            if (symbol < 0) {
                continue;
            }
            if (symbol == 256) {
                return qpack_failure<std::string>(
                    code, "invalid " + std::string(context) + " huffman encoding", stream_id);
            }

            decoded.push_back(static_cast<char>(symbol));
            node = 0;
            bits_since_symbol = 0;
            pending_bits_all_ones = true;
        }
    }

    if (node == 0) {
        return Http3Result<std::string>::success(std::move(decoded));
    }

    if (bits_since_symbol > 7 || !pending_bits_all_ones) {
        return qpack_failure<std::string>(
            code, "invalid " + std::string(context) + " huffman encoding", stream_id);
    }

    return Http3Result<std::string>::success(std::move(decoded));
}

void append_string_literal(std::vector<std::byte> &out, std::uint8_t leading_bits,
                           std::uint8_t prefix_bits, std::string_view value) {
    append_prefixed_integer(out, leading_bits, prefix_bits, value.size());
    out.insert(out.end(), reinterpret_cast<const std::byte *>(value.data()),
               reinterpret_cast<const std::byte *>(value.data()) + value.size());
}

Http3Result<std::string> decode_string_literal(quic::BufferReader &reader, std::uint8_t first,
                                               std::uint8_t prefix_bits, std::string_view context,
                                               Http3ErrorCode code,
                                               std::optional<std::uint64_t> stream_id) {
    const auto length = decode_prefixed_integer(reader, first, prefix_bits);
    if (!length.has_value()) {
        return qpack_failure<std::string>(code, "malformed " + std::string(context) + " length",
                                          stream_id);
    }

    auto size = unchecked_size(length.value());
    if constexpr (kNeedUint64SizeCheck) {
        if (length.value() > std::numeric_limits<std::size_t>::max()) {
            return qpack_failure<std::string>(code, std::string(context) + " is too large",
                                              stream_id);
        }
    }

    const auto bytes = reader.read_exact(size);
    if (!bytes.has_value()) {
        return qpack_failure<std::string>(code, "truncated " + std::string(context), stream_id);
    }

    const auto huffman_flag = static_cast<std::uint8_t>(1u << prefix_bits);
    if ((first & huffman_flag) == 0u) {
        return Http3Result<std::string>::success(bytes_to_string(bytes.value()));
    }

    return decode_hpack_huffman(bytes.value(), context, code, stream_id);
}

std::optional<std::size_t> lookup_static_field(const Http3Field &field) {
    for (std::size_t index = 0; index < kStaticTable.size(); ++index) {
        if (kStaticTable[index].name == field.name && kStaticTable[index].value == field.value) {
            return index;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> lookup_static_name(std::string_view name) {
    for (std::size_t index = 0; index < kStaticTable.size(); ++index) {
        if (kStaticTable[index].name == name) {
            return index;
        }
    }
    return std::nullopt;
}

std::optional<std::uint64_t>
find_dynamic_field_absolute_index(const std::deque<Http3QpackEntry> &table,
                                  const Http3Field &field) {
    for (const auto &entry : table) {
        if (entry.field == field) {
            return entry.absolute_index;
        }
    }
    return std::nullopt;
}

std::optional<std::uint64_t>
find_dynamic_name_absolute_index(const std::deque<Http3QpackEntry> &table, std::string_view name) {
    for (const auto &entry : table) {
        if (entry.field.name == name) {
            return entry.absolute_index;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t>
find_encoder_stream_name_relative_index(const std::deque<Http3QpackEntry> &table,
                                        std::string_view name) {
    for (std::size_t index = 0; index < table.size(); ++index) {
        if (table[index].field.name == name) {
            return index;
        }
    }
    return std::nullopt;
}

const Http3QpackEntry *
find_dynamic_entry_by_absolute_index(const std::deque<Http3QpackEntry> &table,
                                     std::uint64_t absolute_index) {
    for (const auto &entry : table) {
        if (entry.absolute_index == absolute_index) {
            return &entry;
        }
    }
    return nullptr;
}

Http3QpackEntry &find_dynamic_entry_by_absolute_index(std::deque<Http3QpackEntry> &table,
                                                      std::uint64_t absolute_index) {
    return const_cast<Http3QpackEntry &>(*find_dynamic_entry_by_absolute_index(
        static_cast<const std::deque<Http3QpackEntry> &>(table), absolute_index));
}

std::size_t count_blocked_streams(const Http3QpackEncoderContext &encoder) {
    std::unordered_set<std::uint64_t> blocked_streams;
    for (const auto &section : encoder.outstanding_field_sections) {
        if (section.required_insert_count > encoder.known_received_count) {
            blocked_streams.insert(section.stream_id);
        }
    }
    return blocked_streams.size();
}

void refresh_blocked_stream_count(Http3QpackDecoderContext &decoder) {
    std::unordered_set<std::uint64_t> blocked_streams;
    for (const auto &pending : decoder.pending_field_sections) {
        blocked_streams.insert(pending.stream_id);
    }
    decoder.blocked_streams = blocked_streams.size();
}

bool pending_field_sections_reference(const Http3QpackDecoderContext &decoder,
                                      std::uint64_t absolute_index) {
    for (const auto &pending : decoder.pending_field_sections) {
        if (std::find(pending.referenced_entries.begin(), pending.referenced_entries.end(),
                      absolute_index) != pending.referenced_entries.end()) {
            return true;
        }
    }
    return false;
}

bool stream_is_already_blocked(const Http3QpackEncoderContext &encoder, std::uint64_t stream_id) {
    for (const auto &section : encoder.outstanding_field_sections) {
        if (section.stream_id == stream_id &&
            section.required_insert_count > encoder.known_received_count) {
            return true;
        }
    }
    return false;
}

bool append_unique_reference(std::vector<std::uint64_t> &references, std::uint64_t absolute_index) {
    if (std::find(references.begin(), references.end(), absolute_index) != references.end()) {
        return false;
    }
    references.push_back(absolute_index);
    return true;
}

bool can_reference_dynamic_state(const Http3QpackEncoderContext &encoder,
                                 std::uint64_t candidate_required_insert_count,
                                 bool stream_already_blocked, std::size_t blocked_stream_count) {
    if (candidate_required_insert_count <= encoder.known_received_count) {
        return true;
    }
    if (encoder.peer_settings.blocked_streams == 0) {
        return false;
    }
    if (stream_already_blocked) {
        return true;
    }
    return blocked_stream_count < encoder.peer_settings.blocked_streams;
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
void note_dynamic_reference(const Http3QpackEncoderContext &encoder, std::uint64_t absolute_index,
                            std::vector<std::uint64_t> &references,
                            std::uint64_t &required_insert_count, bool &stream_already_blocked,
                            std::size_t &blocked_stream_count) {
    append_unique_reference(references, absolute_index);
    required_insert_count = std::max(required_insert_count, absolute_index + 1);
    if (absolute_index + 1 > encoder.known_received_count && !stream_already_blocked) {
        stream_already_blocked = true;
        ++blocked_stream_count;
    }
}
// NOLINTEND(bugprone-easily-swappable-parameters)

bool insert_encoder_entry(Http3QpackEncoderContext &encoder, const Http3Field &field,
                          std::uint64_t &absolute_index_out) {
    const auto size = qpack_entry_size(field);

    while (encoder.dynamic_table_size + size > encoder.dynamic_table_capacity) {
        const auto &oldest = encoder.dynamic_table.back();
        if (oldest.outstanding_references != 0 ||
            oldest.absolute_index >= encoder.known_received_count) {
            return false;
        }
        encoder.dynamic_table_size -= oldest.size;
        encoder.dynamic_table.pop_back();
    }

    absolute_index_out = encoder.insert_count;
    encoder.dynamic_table.push_front(Http3QpackEntry{
        .field = field,
        .size = size,
        .absolute_index = absolute_index_out,
    });
    encoder.dynamic_table_size += size;
    ++encoder.insert_count;
    return true;
}

Http3Result<bool> insert_decoder_entry(Http3QpackDecoderContext &decoder, Http3Field field) {
    if (decoder.dynamic_table_capacity == 0) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "dynamic table insertion without capacity");
    }

    const auto size = qpack_entry_size(field);
    if (size > decoder.dynamic_table_capacity) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "dynamic table entry exceeds capacity");
    }

    while (decoder.dynamic_table_size + size > decoder.dynamic_table_capacity) {
        if (pending_field_sections_reference(decoder,
                                             decoder.dynamic_table.back().absolute_index)) {
            return qpack_failure<bool>(
                Http3ErrorCode::qpack_encoder_stream_error,
                "dynamic table eviction would invalidate blocked field section");
        }
        decoder.dynamic_table_size -= decoder.dynamic_table.back().size;
        decoder.dynamic_table.pop_back();
    }

    decoder.dynamic_table.push_front(Http3QpackEntry{
        .field = std::move(field),
        .size = size,
        .absolute_index = decoder.insert_count,
    });
    decoder.dynamic_table_size += size;
    ++decoder.insert_count;
    return Http3Result<bool>::success(true);
}

void append_set_dynamic_table_capacity(std::vector<std::byte> &out, std::size_t capacity) {
    append_prefixed_integer(out, 0x20u, 5, capacity);
}

void append_insert_with_name_reference(std::vector<std::byte> &out, bool is_static,
                                       std::size_t name_index, std::string_view value) {
    append_prefixed_integer(out, is_static ? 0xc0u : 0x80u, 6, name_index);
    append_string_literal(out, 0x00u, 7, value);
}

void append_insert_with_literal_name(std::vector<std::byte> &out, const Http3Field &field) {
    append_string_literal(out, 0x40u, 5, field.name);
    append_string_literal(out, 0x00u, 7, field.value);
}

void append_indexed_field_line(std::vector<std::byte> &out, std::uint64_t absolute_index,
                               std::uint64_t base) {
    if (absolute_index < base) {
        append_prefixed_integer(out, 0x80u, 6, base - absolute_index - 1);
        return;
    }
    append_prefixed_integer(out, 0x10u, 4, absolute_index - base);
}

void append_static_indexed_field_line(std::vector<std::byte> &out, std::size_t static_index) {
    append_prefixed_integer(out, 0xc0u, 6, static_index);
}

void append_literal_with_static_name_reference(std::vector<std::byte> &out, std::size_t name_index,
                                               std::string_view value) {
    append_prefixed_integer(out, 0x50u, 4, name_index);
    append_string_literal(out, 0x00u, 7, value);
}

void append_literal_with_dynamic_name_reference(std::vector<std::byte> &out,
                                                std::uint64_t absolute_index, std::uint64_t base,
                                                std::string_view value) {
    if (absolute_index < base) {
        append_prefixed_integer(out, 0x40u, 4, base - absolute_index - 1);
    } else {
        append_prefixed_integer(out, 0x00u, 3, absolute_index - base);
    }
    append_string_literal(out, 0x00u, 7, value);
}

void append_literal_with_literal_name(std::vector<std::byte> &out, const Http3Field &field) {
    append_string_literal(out, 0x20u, 3, field.name);
    append_string_literal(out, 0x00u, 7, field.value);
}

Http3Result<std::uint64_t> decode_required_insert_count(const Http3QpackDecoderContext &decoder,
                                                        std::uint64_t encoded_insert_count,
                                                        std::optional<std::uint64_t> stream_id) {
    const auto max_entries = max_entries_for_capacity(decoder.local_settings.max_table_capacity);
    if (max_entries == 0) {
        if (encoded_insert_count != 0) {
            return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                                "invalid required insert count", stream_id);
        }
        return Http3Result<std::uint64_t>::success(0);
    }

    const auto full_range = max_entries * 2;
    if (encoded_insert_count == 0) {
        return Http3Result<std::uint64_t>::success(0);
    }
    if (encoded_insert_count > full_range) {
        return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                            "invalid required insert count", stream_id);
    }

    const auto max_value = decoder.insert_count + max_entries;
    const auto max_wrapped = (max_value / full_range) * full_range;
    std::uint64_t required_insert_count = max_wrapped + encoded_insert_count - 1;
    if (required_insert_count > max_value) {
        if (required_insert_count <= full_range) {
            return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                                "invalid required insert count", stream_id);
        }
        required_insert_count -= full_range;
    }
    if (required_insert_count == 0) {
        return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                            "invalid required insert count", stream_id);
    }

    return Http3Result<std::uint64_t>::success(required_insert_count);
}

Http3Result<ParsedFieldSectionPrefix>
decode_field_section_prefix(const Http3QpackDecoderContext &decoder,
                            std::span<const std::byte> prefix,
                            std::optional<std::uint64_t> stream_id) {
    quic::BufferReader reader(prefix);
    const auto first = reader.read_byte();
    if (!first.has_value()) {
        return qpack_failure<ParsedFieldSectionPrefix>(Http3ErrorCode::qpack_decompression_failed,
                                                       "truncated field section prefix", stream_id);
    }
    const auto encoded_insert_count =
        decode_prefixed_integer(reader, std::to_integer<std::uint8_t>(first.value()), 8);
    if (!encoded_insert_count.has_value()) {
        return qpack_failure<ParsedFieldSectionPrefix>(Http3ErrorCode::qpack_decompression_failed,
                                                       "malformed field section prefix", stream_id);
    }

    const auto second = reader.read_byte();
    if (!second.has_value()) {
        return qpack_failure<ParsedFieldSectionPrefix>(Http3ErrorCode::qpack_decompression_failed,
                                                       "truncated field section prefix", stream_id);
    }

    const auto second_value = std::to_integer<std::uint8_t>(second.value());
    const auto delta_base = decode_prefixed_integer(reader, second_value, 7);
    if (!delta_base.has_value() || reader.remaining() != 0) {
        return qpack_failure<ParsedFieldSectionPrefix>(Http3ErrorCode::qpack_decompression_failed,
                                                       "malformed field section prefix", stream_id);
    }

    const auto required_insert_count =
        decode_required_insert_count(decoder, encoded_insert_count.value(), stream_id);
    if (!required_insert_count.has_value()) {
        return qpack_failure<ParsedFieldSectionPrefix>(required_insert_count.error().code,
                                                       required_insert_count.error().detail,
                                                       required_insert_count.error().stream_id);
    }

    std::uint64_t base = 0;
    if ((second_value & 0x80u) == 0u) {
        if (required_insert_count.value() >
            std::numeric_limits<std::uint64_t>::max() - delta_base.value()) {
            return qpack_failure<ParsedFieldSectionPrefix>(
                Http3ErrorCode::qpack_decompression_failed, "invalid field section base",
                stream_id);
        }
        base = required_insert_count.value() + delta_base.value();
    } else {
        if (required_insert_count.value() <= delta_base.value()) {
            return qpack_failure<ParsedFieldSectionPrefix>(
                Http3ErrorCode::qpack_decompression_failed, "invalid field section base",
                stream_id);
        }
        base = required_insert_count.value() - delta_base.value() - 1;
    }

    return Http3Result<ParsedFieldSectionPrefix>::success(ParsedFieldSectionPrefix{
        .required_insert_count = required_insert_count.value(),
        .base = base,
    });
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
Http3Result<std::uint64_t> resolve_relative_absolute_index(std::uint64_t base, std::uint64_t index,
                                                           std::uint64_t required_insert_count,
                                                           std::optional<std::uint64_t> stream_id) {
    if (base == 0 || index >= base) {
        return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                            "invalid dynamic table index", stream_id);
    }
    const auto absolute_index = base - index - 1;
    if (absolute_index + 1 > required_insert_count) {
        return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                            "dynamic table reference exceeds required insert count",
                                            stream_id);
    }
    return Http3Result<std::uint64_t>::success(absolute_index);
}

Http3Result<std::uint64_t>
resolve_post_base_absolute_index(std::uint64_t base, std::uint64_t index,
                                 std::uint64_t required_insert_count,
                                 std::optional<std::uint64_t> stream_id) {
    if (index > std::numeric_limits<std::uint64_t>::max() - base) {
        return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                            "invalid post-base index", stream_id);
    }
    const auto absolute_index = base + index;
    if (absolute_index + 1 > required_insert_count) {
        return qpack_failure<std::uint64_t>(Http3ErrorCode::qpack_decompression_failed,
                                            "dynamic table reference exceeds required insert count",
                                            stream_id);
    }
    return Http3Result<std::uint64_t>::success(absolute_index);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

Http3Result<std::vector<std::uint64_t>>
collect_field_section_references(std::uint64_t stream_id, std::uint64_t required_insert_count,
                                 std::uint64_t base, std::span<const std::byte> payload) {
    quic::BufferReader reader(payload);
    std::vector<std::uint64_t> references;

    while (reader.remaining() > 0) {
        const auto first_value = std::to_integer<std::uint8_t>(reader.read_byte().value());
        if ((first_value & 0x80u) == 0x80u) {
            const auto index = decode_prefixed_integer(reader, first_value, 6);
            if (!index.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(
                    Http3ErrorCode::qpack_decompression_failed, "malformed indexed field line",
                    stream_id);
            }

            if ((first_value & 0x40u) == 0u) {
                const auto absolute_index = resolve_relative_absolute_index(
                    base, index.value(), required_insert_count, stream_id);
                if (!absolute_index.has_value()) {
                    return qpack_failure<std::vector<std::uint64_t>>(
                        absolute_index.error().code, absolute_index.error().detail,
                        absolute_index.error().stream_id);
                }
                append_unique_reference(references, absolute_index.value());
            }
            continue;
        }

        if ((first_value & 0xf0u) == 0x10u) {
            const auto index = decode_prefixed_integer(reader, first_value, 4);
            if (!index.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(
                    Http3ErrorCode::qpack_decompression_failed,
                    "malformed post-base indexed field line", stream_id);
            }

            const auto absolute_index = resolve_post_base_absolute_index(
                base, index.value(), required_insert_count, stream_id);
            if (!absolute_index.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(absolute_index.error().code,
                                                                 absolute_index.error().detail,
                                                                 absolute_index.error().stream_id);
            }
            append_unique_reference(references, absolute_index.value());
            continue;
        }

        if ((first_value & 0xc0u) == 0x40u) {
            const auto name_index = decode_prefixed_integer(reader, first_value, 4);
            if (!name_index.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(
                    Http3ErrorCode::qpack_decompression_failed,
                    "malformed literal-with-name-reference", stream_id);
            }

            if ((first_value & 0x10u) == 0u) {
                const auto absolute_index = resolve_relative_absolute_index(
                    base, name_index.value(), required_insert_count, stream_id);
                if (!absolute_index.has_value()) {
                    return qpack_failure<std::vector<std::uint64_t>>(
                        absolute_index.error().code, absolute_index.error().detail,
                        absolute_index.error().stream_id);
                }
                append_unique_reference(references, absolute_index.value());
            }

            const auto value_first = reader.read_byte();
            if (!value_first.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(
                    Http3ErrorCode::qpack_decompression_failed, "truncated literal field value",
                    stream_id);
            }
            const auto value = decode_string_literal(
                reader, std::to_integer<std::uint8_t>(value_first.value()), 7,
                "literal field value", Http3ErrorCode::qpack_decompression_failed, stream_id);
            if (!value.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(value.error().code,
                                                                 value.error().detail, stream_id);
            }
            continue;
        }

        if ((first_value & 0xf0u) == 0x00u) {
            const auto name_index = decode_prefixed_integer(reader, first_value, 3);
            if (!name_index.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(
                    Http3ErrorCode::qpack_decompression_failed,
                    "malformed literal-with-post-base-name-reference", stream_id);
            }

            const auto absolute_index = resolve_post_base_absolute_index(
                base, name_index.value(), required_insert_count, stream_id);
            if (!absolute_index.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(absolute_index.error().code,
                                                                 absolute_index.error().detail,
                                                                 absolute_index.error().stream_id);
            }
            append_unique_reference(references, absolute_index.value());

            const auto value_first = reader.read_byte();
            if (!value_first.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(
                    Http3ErrorCode::qpack_decompression_failed, "truncated literal field value",
                    stream_id);
            }
            const auto value = decode_string_literal(
                reader, std::to_integer<std::uint8_t>(value_first.value()), 7,
                "literal field value", Http3ErrorCode::qpack_decompression_failed, stream_id);
            if (!value.has_value()) {
                return qpack_failure<std::vector<std::uint64_t>>(value.error().code,
                                                                 value.error().detail, stream_id);
            }
            continue;
        }

        const auto name =
            decode_string_literal(reader, first_value, 3, "literal field name",
                                  Http3ErrorCode::qpack_decompression_failed, stream_id);
        if (!name.has_value()) {
            return qpack_failure<std::vector<std::uint64_t>>(name.error().code, name.error().detail,
                                                             stream_id);
        }

        const auto value_first = reader.read_byte();
        if (!value_first.has_value()) {
            return qpack_failure<std::vector<std::uint64_t>>(
                Http3ErrorCode::qpack_decompression_failed, "truncated literal field value",
                stream_id);
        }
        const auto value = decode_string_literal(
            reader, std::to_integer<std::uint8_t>(value_first.value()), 7, "literal field value",
            Http3ErrorCode::qpack_decompression_failed, stream_id);
        if (!value.has_value()) {
            return qpack_failure<std::vector<std::uint64_t>>(value.error().code,
                                                             value.error().detail, stream_id);
        }
    }

    return Http3Result<std::vector<std::uint64_t>>::success(std::move(references));
}

Http3Result<Http3Headers> decode_field_section_payload(const Http3QpackDecoderContext &decoder,
                                                       std::uint64_t stream_id,
                                                       std::uint64_t required_insert_count,
                                                       std::uint64_t base,
                                                       std::span<const std::byte> payload) {
    quic::BufferReader reader(payload);
    Http3Headers headers;

    while (reader.remaining() > 0) {
        const auto first_value = std::to_integer<std::uint8_t>(reader.read_byte().value());
        if ((first_value & 0x80u) == 0x80u) {
            const auto index = decode_prefixed_integer(reader, first_value, 6);
            if (!index.has_value()) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "malformed indexed field line", stream_id);
            }

            if ((first_value & 0x40u) != 0u) {
                if (index.value() >= kStaticTable.size()) {
                    return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                       "invalid static table index", stream_id);
                }
                headers.push_back(Http3Field{
                    .name = std::string(kStaticTable[static_cast<std::size_t>(index.value())].name),
                    .value =
                        std::string(kStaticTable[static_cast<std::size_t>(index.value())].value),
                });
                continue;
            }

            const auto absolute_index = resolve_relative_absolute_index(
                base, index.value(), required_insert_count, stream_id);
            if (!absolute_index.has_value()) {
                return qpack_failure<Http3Headers>(absolute_index.error().code,
                                                   absolute_index.error().detail,
                                                   absolute_index.error().stream_id);
            }
            const auto *entry =
                find_dynamic_entry_by_absolute_index(decoder.dynamic_table, absolute_index.value());
            if (entry == nullptr) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "invalid dynamic table index", stream_id);
            }
            headers.push_back(entry->field);
            continue;
        }

        if ((first_value & 0xf0u) == 0x10u) {
            const auto index = decode_prefixed_integer(reader, first_value, 4);
            if (!index.has_value()) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "malformed post-base indexed field line",
                                                   stream_id);
            }

            const auto absolute_index = resolve_post_base_absolute_index(
                base, index.value(), required_insert_count, stream_id);
            if (!absolute_index.has_value()) {
                return qpack_failure<Http3Headers>(absolute_index.error().code,
                                                   absolute_index.error().detail,
                                                   absolute_index.error().stream_id);
            }
            const auto *entry =
                find_dynamic_entry_by_absolute_index(decoder.dynamic_table, absolute_index.value());
            if (entry == nullptr) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "invalid post-base index", stream_id);
            }
            headers.push_back(entry->field);
            continue;
        }

        if ((first_value & 0xc0u) == 0x40u) {
            const auto name_index = decode_prefixed_integer(reader, first_value, 4);
            if (!name_index.has_value()) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "malformed literal-with-name-reference",
                                                   stream_id);
            }

            std::string name;
            if ((first_value & 0x10u) != 0u) {
                if (name_index.value() >= kStaticTable.size()) {
                    return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                       "invalid static table name reference",
                                                       stream_id);
                }
                name = std::string(kStaticTable[static_cast<std::size_t>(name_index.value())].name);
            } else {
                const auto absolute_index = resolve_relative_absolute_index(
                    base, name_index.value(), required_insert_count, stream_id);
                if (!absolute_index.has_value()) {
                    return qpack_failure<Http3Headers>(absolute_index.error().code,
                                                       absolute_index.error().detail,
                                                       absolute_index.error().stream_id);
                }
                const auto *entry = find_dynamic_entry_by_absolute_index(decoder.dynamic_table,
                                                                         absolute_index.value());
                if (entry == nullptr) {
                    return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                       "invalid dynamic table name reference",
                                                       stream_id);
                }
                name = entry->field.name;
            }

            const auto value_first = reader.read_byte();
            if (!value_first.has_value()) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "truncated literal field value", stream_id);
            }
            const auto value = decode_string_literal(
                reader, std::to_integer<std::uint8_t>(value_first.value()), 7,
                "literal field value", Http3ErrorCode::qpack_decompression_failed, stream_id);
            if (!value.has_value()) {
                return qpack_failure<Http3Headers>(value.error().code, value.error().detail,
                                                   stream_id);
            }

            headers.push_back(Http3Field{
                .name = std::move(name),
                .value = value.value(),
            });
            continue;
        }

        if ((first_value & 0xf0u) == 0x00u) {
            const auto name_index = decode_prefixed_integer(reader, first_value, 3);
            if (!name_index.has_value()) {
                return qpack_failure<Http3Headers>(
                    Http3ErrorCode::qpack_decompression_failed,
                    "malformed literal-with-post-base-name-reference", stream_id);
            }

            const auto absolute_index = resolve_post_base_absolute_index(
                base, name_index.value(), required_insert_count, stream_id);
            if (!absolute_index.has_value()) {
                return qpack_failure<Http3Headers>(absolute_index.error().code,
                                                   absolute_index.error().detail,
                                                   absolute_index.error().stream_id);
            }
            const auto *entry =
                find_dynamic_entry_by_absolute_index(decoder.dynamic_table, absolute_index.value());
            if (entry == nullptr) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "invalid post-base name reference", stream_id);
            }

            const auto value_first = reader.read_byte();
            if (!value_first.has_value()) {
                return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                                   "truncated literal field value", stream_id);
            }
            const auto value = decode_string_literal(
                reader, std::to_integer<std::uint8_t>(value_first.value()), 7,
                "literal field value", Http3ErrorCode::qpack_decompression_failed, stream_id);
            if (!value.has_value()) {
                return qpack_failure<Http3Headers>(value.error().code, value.error().detail,
                                                   stream_id);
            }

            headers.push_back(Http3Field{
                .name = entry->field.name,
                .value = value.value(),
            });
            continue;
        }

        const auto name =
            decode_string_literal(reader, first_value, 3, "literal field name",
                                  Http3ErrorCode::qpack_decompression_failed, stream_id);
        if (!name.has_value()) {
            return qpack_failure<Http3Headers>(name.error().code, name.error().detail, stream_id);
        }

        const auto value_first = reader.read_byte();
        if (!value_first.has_value()) {
            return qpack_failure<Http3Headers>(Http3ErrorCode::qpack_decompression_failed,
                                               "truncated literal field value", stream_id);
        }
        const auto value = decode_string_literal(
            reader, std::to_integer<std::uint8_t>(value_first.value()), 7, "literal field value",
            Http3ErrorCode::qpack_decompression_failed, stream_id);
        if (!value.has_value()) {
            return qpack_failure<Http3Headers>(value.error().code, value.error().detail, stream_id);
        }

        headers.push_back(Http3Field{
            .name = name.value(),
            .value = value.value(),
        });
    }

    return Http3Result<Http3Headers>::success(std::move(headers));
}

Http3Result<std::vector<Http3DecodedFieldSection>>
decode_unblocked_field_sections(Http3QpackDecoderContext &decoder) {
    std::vector<Http3DecodedFieldSection> decoded_sections;
    std::vector<Http3QpackPendingFieldSection> still_blocked;
    std::unordered_set<std::uint64_t> streams_with_prior_blocked_section;

    for (const auto &pending : decoder.pending_field_sections) {
        if (streams_with_prior_blocked_section.contains(pending.stream_id) ||
            pending.required_insert_count > decoder.insert_count) {
            streams_with_prior_blocked_section.insert(pending.stream_id);
            still_blocked.push_back(pending);
            continue;
        }

        auto headers =
            decode_field_section_payload(decoder, pending.stream_id, pending.required_insert_count,
                                         pending.base, pending.payload);
        if (!headers.has_value()) {
            return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                headers.error().code, headers.error().detail, headers.error().stream_id);
        }

        decoder.pending_section_acknowledgments.push_back(Http3QpackSectionAcknowledgment{
            .stream_id = pending.stream_id,
            .required_insert_count = pending.required_insert_count,
        });

        decoded_sections.push_back(Http3DecodedFieldSection{
            .stream_id = pending.stream_id,
            .required_insert_count = pending.required_insert_count,
            .base = pending.base,
            .status = Http3QpackDecodeStatus::complete,
            .headers = std::move(headers.value()),
        });
    }

    decoder.pending_field_sections = std::move(still_blocked);
    refresh_blocked_stream_count(decoder);
    return Http3Result<std::vector<Http3DecodedFieldSection>>::success(std::move(decoded_sections));
}

void release_section_references(Http3QpackEncoderContext &encoder,
                                const Http3QpackOutstandingFieldSection &section) {
    for (const auto absolute_index : section.referenced_entries) {
        auto &entry = find_dynamic_entry_by_absolute_index(encoder.dynamic_table, absolute_index);
        --entry.outstanding_references;
    }
}

Http3Result<bool> decode_insert_with_name_reference(quic::BufferReader &reader,
                                                    Http3QpackDecoderContext &decoder,
                                                    std::uint8_t first) {
    const auto name_index = decode_prefixed_integer(reader, first, 6);
    if (!name_index.has_value()) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "malformed insert-with-name-reference instruction");
    }

    std::string name;
    if ((first & 0x40u) != 0u) {
        if (name_index.value() >= kStaticTable.size()) {
            return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                       "invalid static table name reference");
        }
        name = std::string(kStaticTable[static_cast<std::size_t>(name_index.value())].name);
    } else {
        auto dynamic_index = unchecked_size(name_index.value());
        if constexpr (kNeedUint64SizeCheck) {
            if (name_index.value() > std::numeric_limits<std::size_t>::max()) {
                return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                           "invalid dynamic table name reference");
            }
        }
        if (dynamic_index >= decoder.dynamic_table.size()) {
            return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                       "invalid dynamic table name reference");
        }
        name = decoder.dynamic_table[dynamic_index].field.name;
    }

    const auto value_first = reader.read_byte();
    if (!value_first.has_value()) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "truncated insert value");
    }
    const auto value = decode_string_literal(
        reader, std::to_integer<std::uint8_t>(value_first.value()), 7, "insert value",
        Http3ErrorCode::qpack_encoder_stream_error, std::nullopt);
    if (!value.has_value()) {
        return qpack_failure<bool>(value.error().code, value.error().detail);
    }

    return insert_decoder_entry(decoder, Http3Field{
                                             .name = std::move(name),
                                             .value = value.value(),
                                         });
}

Http3Result<bool> decode_insert_with_literal_name(quic::BufferReader &reader,
                                                  Http3QpackDecoderContext &decoder,
                                                  std::uint8_t first) {
    const auto name = decode_string_literal(
        reader, first, 5, "insert name", Http3ErrorCode::qpack_encoder_stream_error, std::nullopt);
    if (!name.has_value()) {
        return qpack_failure<bool>(name.error().code, name.error().detail);
    }

    const auto value_first = reader.read_byte();
    if (!value_first.has_value()) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "truncated insert value");
    }
    const auto value = decode_string_literal(
        reader, std::to_integer<std::uint8_t>(value_first.value()), 7, "insert value",
        Http3ErrorCode::qpack_encoder_stream_error, std::nullopt);
    if (!value.has_value()) {
        return qpack_failure<bool>(value.error().code, value.error().detail);
    }

    return insert_decoder_entry(decoder, Http3Field{
                                             .name = name.value(),
                                             .value = value.value(),
                                         });
}

Http3Result<bool> decode_duplicate_instruction(quic::BufferReader &reader,
                                               Http3QpackDecoderContext &decoder,
                                               std::uint8_t first) {
    const auto index = decode_prefixed_integer(reader, first, 5);
    if (!index.has_value()) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "malformed duplicate instruction");
    }
    auto dynamic_index = unchecked_size(index.value());
    if constexpr (kNeedUint64SizeCheck) {
        if (index.value() > std::numeric_limits<std::size_t>::max()) {
            return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                       "invalid duplicate instruction index");
        }
    }
    if (dynamic_index >= decoder.dynamic_table.size()) {
        return qpack_failure<bool>(Http3ErrorCode::qpack_encoder_stream_error,
                                   "invalid duplicate instruction index");
    }

    return insert_decoder_entry(decoder, decoder.dynamic_table[dynamic_index].field);
}

} // namespace

namespace coquic::http3 {

quic::CodecResult<Http3EncodedFieldSection>
encode_http3_field_section(Http3QpackEncoderContext &encoder, std::uint64_t stream_id,
                           std::span<const Http3Field> fields) {
    Http3EncodedFieldSection encoded{};
    auto peer_capacity = unchecked_size(encoder.peer_settings.max_table_capacity);
    if constexpr (kNeedUint64SizeCheck) {
        if (encoder.peer_settings.max_table_capacity > std::numeric_limits<std::size_t>::max()) {
            return qpack_encode_failure<Http3EncodedFieldSection>();
        }
    }

    const std::uint64_t base = encoder.insert_count;
    std::uint64_t required_insert_count = 0;
    std::vector<std::uint64_t> referenced_entries;
    auto blocked_stream_count = count_blocked_streams(encoder);
    auto stream_already_blocked = stream_is_already_blocked(encoder, stream_id);

    for (const auto &field : fields) {
        if (const auto static_index = lookup_static_field(field); static_index.has_value()) {
            append_static_indexed_field_line(encoded.payload, static_index.value());
            continue;
        }

        if (const auto dynamic_index =
                find_dynamic_field_absolute_index(encoder.dynamic_table, field);
            dynamic_index.has_value() &&
            can_reference_dynamic_state(encoder, dynamic_index.value() + 1, stream_already_blocked,
                                        blocked_stream_count)) {
            append_indexed_field_line(encoded.payload, dynamic_index.value(), base);
            note_dynamic_reference(encoder, dynamic_index.value(), referenced_entries,
                                   required_insert_count, stream_already_blocked,
                                   blocked_stream_count);
            continue;
        }

        const auto static_name_index = lookup_static_name(field.name);
        const auto dynamic_name_absolute_index =
            find_dynamic_name_absolute_index(encoder.dynamic_table, field.name);

        const auto entry_size = qpack_entry_size(field);
        if (peer_capacity > 0 && entry_size <= peer_capacity &&
            can_reference_dynamic_state(encoder, encoder.insert_count + 1, stream_already_blocked,
                                        blocked_stream_count)) {
            const auto dynamic_name_relative_index =
                find_encoder_stream_name_relative_index(encoder.dynamic_table, field.name);

            if (encoder.dynamic_table_capacity == 0) {
                encoder.dynamic_table_capacity = peer_capacity;
                append_set_dynamic_table_capacity(encoded.encoder_instructions,
                                                  encoder.dynamic_table_capacity);
            }

            std::uint64_t inserted_absolute_index = 0;
            if (insert_encoder_entry(encoder, field, inserted_absolute_index)) {
                if (static_name_index.has_value()) {
                    append_insert_with_name_reference(encoded.encoder_instructions, true,
                                                      static_name_index.value(), field.value);
                } else if (dynamic_name_relative_index.has_value()) {
                    append_insert_with_name_reference(encoded.encoder_instructions, false,
                                                      dynamic_name_relative_index.value(),
                                                      field.value);
                } else {
                    append_insert_with_literal_name(encoded.encoder_instructions, field);
                }

                append_indexed_field_line(encoded.payload, inserted_absolute_index, base);
                note_dynamic_reference(encoder, inserted_absolute_index, referenced_entries,
                                       required_insert_count, stream_already_blocked,
                                       blocked_stream_count);
                continue;
            }
        }

        if (static_name_index.has_value()) {
            append_literal_with_static_name_reference(encoded.payload, static_name_index.value(),
                                                      field.value);
            continue;
        }

        if (dynamic_name_absolute_index.has_value() &&
            can_reference_dynamic_state(encoder, dynamic_name_absolute_index.value() + 1,
                                        stream_already_blocked, blocked_stream_count)) {
            append_literal_with_dynamic_name_reference(
                encoded.payload, dynamic_name_absolute_index.value(), base, field.value);
            note_dynamic_reference(encoder, dynamic_name_absolute_index.value(), referenced_entries,
                                   required_insert_count, stream_already_blocked,
                                   blocked_stream_count);
            continue;
        }

        append_literal_with_literal_name(encoded.payload, field);
    }

    encoded.prefix.clear();
    if (required_insert_count == 0) {
        append_prefixed_integer(encoded.prefix, 0x00u, 8, 0);
        append_prefixed_integer(encoded.prefix, 0x00u, 7, 0);
    } else {
        const auto max_entries = max_entries_for_capacity(encoder.peer_settings.max_table_capacity);
        if (max_entries == 0) {
            return qpack_encode_failure<Http3EncodedFieldSection>();
        }
        const auto encoded_insert_count = (required_insert_count % (2 * max_entries)) + 1;
        append_prefixed_integer(encoded.prefix, 0x00u, 8, encoded_insert_count);
        if (base >= required_insert_count) {
            append_prefixed_integer(encoded.prefix, 0x00u, 7, base - required_insert_count);
        } else {
            append_prefixed_integer(encoded.prefix, 0x80u, 7, required_insert_count - base - 1);
        }
    }

    if (!referenced_entries.empty()) {
        for (const auto absolute_index : referenced_entries) {
            auto &entry =
                find_dynamic_entry_by_absolute_index(encoder.dynamic_table, absolute_index);
            ++entry.outstanding_references;
        }
        encoder.outstanding_field_sections.push_back(Http3QpackOutstandingFieldSection{
            .stream_id = stream_id,
            .required_insert_count = required_insert_count,
            .referenced_entries = std::move(referenced_entries),
        });
    }

    return quic::CodecResult<Http3EncodedFieldSection>::success(std::move(encoded));
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
Http3Result<Http3DecodedFieldSection>
decode_http3_field_section(Http3QpackDecoderContext &decoder, std::uint64_t stream_id,
                           std::span<const std::byte> prefix, std::span<const std::byte> payload) {
    const auto parsed_prefix = decode_field_section_prefix(decoder, prefix, stream_id);
    if (!parsed_prefix.has_value()) {
        return qpack_failure<Http3DecodedFieldSection>(parsed_prefix.error().code,
                                                       parsed_prefix.error().detail,
                                                       parsed_prefix.error().stream_id);
    }

    if (parsed_prefix.value().required_insert_count > decoder.insert_count) {
        if (std::find_if(decoder.pending_field_sections.begin(),
                         decoder.pending_field_sections.end(),
                         [&](const Http3QpackPendingFieldSection &pending) {
                             return pending.stream_id == stream_id;
                         }) != decoder.pending_field_sections.end()) {
            return qpack_failure<Http3DecodedFieldSection>(
                Http3ErrorCode::qpack_decompression_failed,
                "stream already has blocked field section", stream_id);
        }

        std::unordered_set<std::uint64_t> blocked_streams;
        for (const auto &pending : decoder.pending_field_sections) {
            blocked_streams.insert(pending.stream_id);
        }
        blocked_streams.insert(stream_id);
        if (blocked_streams.size() > decoder.local_settings.blocked_streams) {
            return qpack_failure<Http3DecodedFieldSection>(
                Http3ErrorCode::qpack_decompression_failed, "too many blocked streams", stream_id);
        }

        auto references =
            collect_field_section_references(stream_id, parsed_prefix.value().required_insert_count,
                                             parsed_prefix.value().base, payload);
        if (!references.has_value()) {
            return qpack_failure<Http3DecodedFieldSection>(
                references.error().code, references.error().detail, references.error().stream_id);
        }

        decoder.pending_field_sections.push_back(Http3QpackPendingFieldSection{
            .stream_id = stream_id,
            .required_insert_count = parsed_prefix.value().required_insert_count,
            .base = parsed_prefix.value().base,
            .payload = std::vector<std::byte>(payload.begin(), payload.end()),
            .referenced_entries = std::move(references.value()),
        });
        refresh_blocked_stream_count(decoder);
        return Http3Result<Http3DecodedFieldSection>::success(Http3DecodedFieldSection{
            .stream_id = stream_id,
            .required_insert_count = parsed_prefix.value().required_insert_count,
            .base = parsed_prefix.value().base,
            .status = Http3QpackDecodeStatus::blocked,
        });
    }

    auto headers = decode_field_section_payload(decoder, stream_id,
                                                parsed_prefix.value().required_insert_count,
                                                parsed_prefix.value().base, payload);
    if (!headers.has_value()) {
        return qpack_failure<Http3DecodedFieldSection>(headers.error().code, headers.error().detail,
                                                       headers.error().stream_id);
    }

    if (parsed_prefix.value().required_insert_count != 0) {
        decoder.pending_section_acknowledgments.push_back(Http3QpackSectionAcknowledgment{
            .stream_id = stream_id,
            .required_insert_count = parsed_prefix.value().required_insert_count,
        });
    }

    return Http3Result<Http3DecodedFieldSection>::success(Http3DecodedFieldSection{
        .stream_id = stream_id,
        .required_insert_count = parsed_prefix.value().required_insert_count,
        .base = parsed_prefix.value().base,
        .status = Http3QpackDecodeStatus::complete,
        .headers = std::move(headers.value()),
    });
}
// NOLINTEND(bugprone-easily-swappable-parameters)

Http3Result<std::vector<Http3DecodedFieldSection>>
process_http3_qpack_encoder_instructions(Http3QpackDecoderContext &decoder,
                                         std::span<const std::byte> bytes) {
    quic::BufferReader reader(bytes);
    while (reader.remaining() > 0) {
        const auto first_value = std::to_integer<std::uint8_t>(reader.read_byte().value());
        if ((first_value & 0xe0u) == 0x20u) {
            const auto capacity = decode_prefixed_integer(reader, first_value, 5);
            if (!capacity.has_value()) {
                return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                    Http3ErrorCode::qpack_encoder_stream_error, "malformed capacity update");
            }
            if (capacity.value() > decoder.local_settings.max_table_capacity) {
                return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                    Http3ErrorCode::qpack_encoder_stream_error,
                    "encoder capacity exceeds peer setting");
            }
            auto new_capacity = unchecked_size(capacity.value());
            if constexpr (kNeedUint64SizeCheck) {
                if (capacity.value() > std::numeric_limits<std::size_t>::max()) {
                    return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                        Http3ErrorCode::qpack_encoder_stream_error,
                        "encoder capacity is too large");
                }
            }

            decoder.dynamic_table_capacity = new_capacity;
            while (decoder.dynamic_table_size > decoder.dynamic_table_capacity) {
                if (pending_field_sections_reference(decoder,
                                                     decoder.dynamic_table.back().absolute_index)) {
                    return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                        Http3ErrorCode::qpack_encoder_stream_error,
                        "dynamic table eviction would invalidate blocked field section");
                }
                decoder.dynamic_table_size -= decoder.dynamic_table.back().size;
                decoder.dynamic_table.pop_back();
            }
            continue;
        }

        if ((first_value & 0x80u) == 0x80u) {
            const auto inserted = decode_insert_with_name_reference(reader, decoder, first_value);
            if (!inserted.has_value()) {
                return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                    inserted.error().code, inserted.error().detail);
            }
            continue;
        }

        if ((first_value & 0x40u) == 0x40u) {
            const auto inserted = decode_insert_with_literal_name(reader, decoder, first_value);
            if (!inserted.has_value()) {
                return qpack_failure<std::vector<Http3DecodedFieldSection>>(
                    inserted.error().code, inserted.error().detail);
            }
            continue;
        }

        const auto duplicated = decode_duplicate_instruction(reader, decoder, first_value);
        if (!duplicated.has_value()) {
            return qpack_failure<std::vector<Http3DecodedFieldSection>>(duplicated.error().code,
                                                                        duplicated.error().detail);
        }
    }

    return decode_unblocked_field_sections(decoder);
}

Http3Result<std::vector<std::byte>>
take_http3_qpack_decoder_instructions(Http3QpackDecoderContext &decoder) {
    std::vector<std::byte> instructions;
    auto feedback_insert_count = decoder.feedback_insert_count;

    for (const auto &ack : decoder.pending_section_acknowledgments) {
        append_prefixed_integer(instructions, 0x80u, 7, ack.stream_id);
        feedback_insert_count = std::max(feedback_insert_count, ack.required_insert_count);
    }
    decoder.pending_section_acknowledgments.clear();

    for (const auto stream_id : decoder.pending_stream_cancellations) {
        append_prefixed_integer(instructions, 0x40u, 6, stream_id);
    }
    decoder.pending_stream_cancellations.clear();

    if (decoder.insert_count > feedback_insert_count) {
        append_prefixed_integer(instructions, 0x00u, 6,
                                decoder.insert_count - feedback_insert_count);
        feedback_insert_count = decoder.insert_count;
    }

    decoder.feedback_insert_count = feedback_insert_count;
    return Http3Result<std::vector<std::byte>>::success(std::move(instructions));
}

Http3Result<bool> process_http3_qpack_decoder_instructions(Http3QpackEncoderContext &encoder,
                                                           std::span<const std::byte> bytes) {
    quic::BufferReader reader(bytes);
    while (reader.remaining() > 0) {
        const auto first_value = std::to_integer<std::uint8_t>(reader.read_byte().value());
        if ((first_value & 0x80u) == 0x80u) {
            const auto stream_id = decode_prefixed_integer(reader, first_value, 7);
            if (!stream_id.has_value()) {
                return qpack_failure<bool>(Http3ErrorCode::qpack_decoder_stream_error,
                                           "malformed section acknowledgment");
            }

            const auto section_it =
                std::find_if(encoder.outstanding_field_sections.begin(),
                             encoder.outstanding_field_sections.end(),
                             [&](const Http3QpackOutstandingFieldSection &section) {
                                 return section.stream_id == stream_id.value();
                             });
            if (section_it == encoder.outstanding_field_sections.end()) {
                return qpack_failure<bool>(Http3ErrorCode::qpack_decoder_stream_error,
                                           "unknown section acknowledgment");
            }

            release_section_references(encoder, *section_it);
            encoder.known_received_count =
                std::max(encoder.known_received_count, section_it->required_insert_count);
            encoder.outstanding_field_sections.erase(section_it);
            continue;
        }

        if ((first_value & 0x40u) == 0x40u) {
            const auto stream_id = decode_prefixed_integer(reader, first_value, 6);
            if (!stream_id.has_value()) {
                return qpack_failure<bool>(Http3ErrorCode::qpack_decoder_stream_error,
                                           "malformed stream cancellation");
            }

            auto write_it = encoder.outstanding_field_sections.begin();
            for (auto read_it = encoder.outstanding_field_sections.begin();
                 read_it != encoder.outstanding_field_sections.end(); ++read_it) {
                if (read_it->stream_id == stream_id.value()) {
                    release_section_references(encoder, *read_it);
                    continue;
                }
                if (write_it != read_it) {
                    *write_it = std::move(*read_it);
                }
                ++write_it;
            }
            encoder.outstanding_field_sections.erase(write_it,
                                                     encoder.outstanding_field_sections.end());
            continue;
        }

        const auto increment = decode_prefixed_integer(reader, first_value, 6);
        if (!increment.has_value() || increment.value() == 0) {
            return qpack_failure<bool>(Http3ErrorCode::qpack_decoder_stream_error,
                                       "invalid insert count increment");
        }
        if (encoder.known_received_count >
                std::numeric_limits<std::uint64_t>::max() - increment.value() ||
            encoder.known_received_count + increment.value() > encoder.insert_count) {
            return qpack_failure<bool>(Http3ErrorCode::qpack_decoder_stream_error,
                                       "insert count increment exceeds sent state");
        }
        encoder.known_received_count += increment.value();
    }

    return Http3Result<bool>::success(true);
}

Http3Result<bool> cancel_http3_qpack_stream(Http3QpackDecoderContext &decoder,
                                            std::uint64_t stream_id) {
    bool removed_any = false;

    auto pending_write = decoder.pending_field_sections.begin();
    for (auto pending_read = decoder.pending_field_sections.begin();
         pending_read != decoder.pending_field_sections.end(); ++pending_read) {
        if (pending_read->stream_id == stream_id) {
            removed_any = true;
            continue;
        }
        if (pending_write != pending_read) {
            *pending_write = std::move(*pending_read);
        }
        ++pending_write;
    }
    decoder.pending_field_sections.erase(pending_write, decoder.pending_field_sections.end());
    refresh_blocked_stream_count(decoder);

    auto ack_write = decoder.pending_section_acknowledgments.begin();
    for (auto ack_read = decoder.pending_section_acknowledgments.begin();
         ack_read != decoder.pending_section_acknowledgments.end(); ++ack_read) {
        if (ack_read->stream_id == stream_id) {
            removed_any = true;
            continue;
        }
        if (ack_write != ack_read) {
            *ack_write = *ack_read;
        }
        ++ack_write;
    }
    decoder.pending_section_acknowledgments.erase(ack_write,
                                                  decoder.pending_section_acknowledgments.end());

    if (removed_any && std::find(decoder.pending_stream_cancellations.begin(),
                                 decoder.pending_stream_cancellations.end(),
                                 stream_id) == decoder.pending_stream_cancellations.end()) {
        decoder.pending_stream_cancellations.push_back(stream_id);
    }

    return Http3Result<bool>::success(true);
}

} // namespace coquic::http3

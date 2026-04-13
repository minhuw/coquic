#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <vector>

#include "src/http3/http3.h"
#include "src/quic/varint.h"

namespace coquic::http3 {

struct Http3QpackSettings {
    std::uint64_t max_table_capacity = 0;
    std::uint64_t blocked_streams = 0;
};

enum class Http3QpackDecodeStatus : std::uint8_t {
    complete,
    blocked,
};

struct Http3QpackEntry {
    Http3Field field;
    std::size_t size = 0;
    std::uint64_t absolute_index = 0;
    std::size_t outstanding_references = 0;
};

struct Http3QpackOutstandingFieldSection {
    std::uint64_t stream_id = 0;
    std::uint64_t required_insert_count = 0;
    std::vector<std::uint64_t> referenced_entries;
};

struct Http3QpackPendingFieldSection {
    std::uint64_t stream_id = 0;
    std::uint64_t required_insert_count = 0;
    std::uint64_t base = 0;
    std::vector<std::byte> payload;
    std::vector<std::uint64_t> referenced_entries;
};

struct Http3QpackSectionAcknowledgment {
    std::uint64_t stream_id = 0;
    std::uint64_t required_insert_count = 0;
};

struct Http3QpackEncoderContext {
    Http3QpackSettings peer_settings;
    std::deque<Http3QpackEntry> dynamic_table;
    std::size_t dynamic_table_capacity = 0;
    std::size_t dynamic_table_size = 0;
    std::uint64_t insert_count = 0;
    std::uint64_t known_received_count = 0;
    std::vector<Http3QpackOutstandingFieldSection> outstanding_field_sections;
};

struct Http3QpackDecoderContext {
    Http3QpackSettings local_settings;
    std::deque<Http3QpackEntry> dynamic_table;
    std::size_t dynamic_table_capacity = 0;
    std::size_t dynamic_table_size = 0;
    std::uint64_t insert_count = 0;
    std::uint64_t blocked_streams = 0;
    std::uint64_t feedback_insert_count = 0;
    std::vector<Http3QpackPendingFieldSection> pending_field_sections;
    std::vector<Http3QpackSectionAcknowledgment> pending_section_acknowledgments;
    std::vector<std::uint64_t> pending_stream_cancellations;
};

struct Http3EncodedFieldSection {
    std::vector<std::byte> prefix;
    std::vector<std::byte> payload;
    std::vector<std::byte> encoder_instructions;
};

struct Http3DecodedFieldSection {
    std::uint64_t stream_id = 0;
    std::uint64_t required_insert_count = 0;
    std::uint64_t base = 0;
    Http3QpackDecodeStatus status = Http3QpackDecodeStatus::complete;
    Http3Headers headers;
};

quic::CodecResult<Http3EncodedFieldSection>
encode_http3_field_section(Http3QpackEncoderContext &encoder, std::uint64_t stream_id,
                           std::span<const Http3Field> fields);
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
Http3Result<Http3DecodedFieldSection>
decode_http3_field_section(Http3QpackDecoderContext &decoder, std::uint64_t stream_id,
                           std::span<const std::byte> prefix, std::span<const std::byte> payload);
// NOLINTEND(bugprone-easily-swappable-parameters)
Http3Result<std::vector<Http3DecodedFieldSection>>
process_http3_qpack_encoder_instructions(Http3QpackDecoderContext &decoder,
                                         std::span<const std::byte> bytes);
Http3Result<std::vector<std::byte>>
take_http3_qpack_decoder_instructions(Http3QpackDecoderContext &decoder);
Http3Result<bool> process_http3_qpack_decoder_instructions(Http3QpackEncoderContext &encoder,
                                                           std::span<const std::byte> bytes);
Http3Result<bool> cancel_http3_qpack_stream(Http3QpackDecoderContext &decoder,
                                            std::uint64_t stream_id);

} // namespace coquic::http3

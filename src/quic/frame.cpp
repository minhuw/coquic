#include "src/quic/frame.h"

#include <array>
#include <limits>
#include <type_traits>

#include "src/quic/buffer.h"

namespace coquic::quic {

namespace {

constexpr std::uint64_t kMaxVarInt = 4611686018427387903ull;
constexpr std::uint64_t kMaxStreamsLimit = 1ull << 60;

CodecResult<std::vector<std::byte>> failure_result(CodecErrorCode code, std::size_t offset) {
    return CodecResult<std::vector<std::byte>>::failure(code, offset);
}

CodecResult<FrameDecodeResult> decode_failure(CodecErrorCode code, std::size_t offset) {
    return CodecResult<FrameDecodeResult>::failure(code, offset);
}

template <typename Writer> std::optional<CodecError> append_byte(Writer &writer, std::byte value) {
    if constexpr (std::is_void_v<decltype(writer.write_byte(value))>) {
        writer.write_byte(value);
        return std::nullopt;
    } else {
        return writer.write_byte(value);
    }
}

template <typename Writer>
std::optional<CodecError> append_bytes(Writer &writer, std::span<const std::byte> bytes) {
    if constexpr (std::is_void_v<decltype(writer.write_bytes(bytes))>) {
        writer.write_bytes(bytes);
        return std::nullopt;
    } else {
        return writer.write_bytes(bytes);
    }
}

template <typename Writer>
std::optional<CodecError> append_varint(Writer &writer, std::uint64_t value) {
    auto error = writer.write_varint(value);
    if (error.has_value() && error->code == CodecErrorCode::invalid_varint) {
        error->offset = 0;
    }
    return error;
}

template <typename Writer>
std::optional<CodecError> append_exact_length_bytes(Writer &writer,
                                                    const std::vector<std::byte> &bytes) {
    if (const auto error = append_varint(writer, bytes.size())) {
        return error;
    }
    if (const auto error = append_bytes(writer, bytes)) {
        return error;
    }
    return std::nullopt;
}

template <typename Writer>
std::optional<CodecError> append_single_varint_frame(Writer &writer, std::byte type,
                                                     std::uint64_t value) {
    if (const auto error = append_byte(writer, type)) {
        return error;
    }
    if (const auto error = append_varint(writer, value)) {
        return error;
    }

    return std::nullopt;
}
CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value()) {
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);
    }

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

CodecResult<std::vector<std::byte>> read_length_prefixed_bytes(BufferReader &reader) {
    const auto length = read_varint(reader);
    if (!length.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(length.error().code,
                                                            length.error().offset);
    }

    if (length.value() > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::truncated_input,
                                                            reader.offset());
    }

    const auto data = reader.read_exact(static_cast<std::size_t>(length.value())).value();

    return CodecResult<std::vector<std::byte>>::success(std::vector<std::byte>{
        data.begin(),
        data.end(),
    });
}

CodecResult<std::uint8_t> read_u8(BufferReader &reader) {
    const auto byte = reader.read_byte();
    if (!byte.has_value()) {
        return CodecResult<std::uint8_t>::failure(byte.error().code, byte.error().offset);
    }

    return CodecResult<std::uint8_t>::success(static_cast<std::uint8_t>(byte.value()));
}

CodecResult<std::array<std::byte, 16>> read_reset_token(BufferReader &reader) {
    const auto bytes = reader.read_exact(16);
    if (!bytes.has_value()) {
        return CodecResult<std::array<std::byte, 16>>::failure(bytes.error().code,
                                                               bytes.error().offset);
    }

    std::array<std::byte, 16> token{};
    for (std::size_t i = 0; i < token.size(); ++i) {
        token[i] = bytes.value()[i];
    }

    return CodecResult<std::array<std::byte, 16>>::success(token);
}

CodecResult<std::array<std::byte, 8>> read_path_bytes(BufferReader &reader) {
    const auto bytes = reader.read_exact(8);
    if (!bytes.has_value()) {
        return CodecResult<std::array<std::byte, 8>>::failure(bytes.error().code,
                                                              bytes.error().offset);
    }

    std::array<std::byte, 8> data{};
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = bytes.value()[i];
    }

    return CodecResult<std::array<std::byte, 8>>::success(data);
}

CodecResult<AckFrame> decode_ack_frame(BufferReader &reader, bool has_ecn_counts) {
    AckFrame frame{};

    const auto largest_acknowledged = read_varint(reader);
    if (!largest_acknowledged.has_value()) {
        return CodecResult<AckFrame>::failure(largest_acknowledged.error().code,
                                              largest_acknowledged.error().offset);
    }
    frame.largest_acknowledged = largest_acknowledged.value();

    const auto ack_delay = read_varint(reader);
    if (!ack_delay.has_value()) {
        return CodecResult<AckFrame>::failure(ack_delay.error().code, ack_delay.error().offset);
    }
    frame.ack_delay = ack_delay.value();

    const auto ack_range_count = read_varint(reader);
    if (!ack_range_count.has_value()) {
        return CodecResult<AckFrame>::failure(ack_range_count.error().code,
                                              ack_range_count.error().offset);
    }

    const auto first_ack_range = read_varint(reader);
    if (!first_ack_range.has_value()) {
        return CodecResult<AckFrame>::failure(first_ack_range.error().code,
                                              first_ack_range.error().offset);
    }
    frame.first_ack_range = first_ack_range.value();

    if (frame.largest_acknowledged < frame.first_ack_range) {
        return CodecResult<AckFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    std::uint64_t previous_smallest = frame.largest_acknowledged - frame.first_ack_range;

    for (std::uint64_t i = 0; i < ack_range_count.value(); ++i) {
        const auto gap = read_varint(reader);
        if (!gap.has_value()) {
            return CodecResult<AckFrame>::failure(gap.error().code, gap.error().offset);
        }

        const auto range_length = read_varint(reader);
        if (!range_length.has_value()) {
            return CodecResult<AckFrame>::failure(range_length.error().code,
                                                  range_length.error().offset);
        }

        if (previous_smallest < gap.value() + 2) {
            return CodecResult<AckFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
        }

        const auto largest = previous_smallest - gap.value() - 2;
        if (largest < range_length.value()) {
            return CodecResult<AckFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
        }

        frame.additional_ranges.push_back(AckRange{
            .gap = gap.value(),
            .range_length = range_length.value(),
        });
        previous_smallest = largest - range_length.value();
    }

    if (has_ecn_counts) {
        AckEcnCounts counts{};

        const auto ect0 = read_varint(reader);
        const auto ect1 = read_varint(reader);
        const auto ecn_ce = read_varint(reader);
        if (!ect0.has_value()) {
            return CodecResult<AckFrame>::failure(ect0.error().code, ect0.error().offset);
        }
        if (!ect1.has_value()) {
            return CodecResult<AckFrame>::failure(ect1.error().code, ect1.error().offset);
        }
        if (!ecn_ce.has_value()) {
            return CodecResult<AckFrame>::failure(ecn_ce.error().code, ecn_ce.error().offset);
        }

        counts.ect0 = ect0.value();
        counts.ect1 = ect1.value();
        counts.ecn_ce = ecn_ce.value();
        frame.ecn_counts = counts;
    }

    return CodecResult<AckFrame>::success(std::move(frame));
}

CodecResult<ResetStreamFrame> decode_reset_stream_frame(BufferReader &reader) {
    ResetStreamFrame frame{};

    const auto stream_id = read_varint(reader);
    const auto error_code = read_varint(reader);
    const auto final_size = read_varint(reader);
    if (!stream_id.has_value()) {
        return CodecResult<ResetStreamFrame>::failure(stream_id.error().code,
                                                      stream_id.error().offset);
    }
    if (!error_code.has_value()) {
        return CodecResult<ResetStreamFrame>::failure(error_code.error().code,
                                                      error_code.error().offset);
    }
    if (!final_size.has_value()) {
        return CodecResult<ResetStreamFrame>::failure(final_size.error().code,
                                                      final_size.error().offset);
    }

    frame.stream_id = stream_id.value();
    frame.application_protocol_error_code = error_code.value();
    frame.final_size = final_size.value();
    return CodecResult<ResetStreamFrame>::success(frame);
}

CodecResult<StopSendingFrame> decode_stop_sending_frame(BufferReader &reader) {
    StopSendingFrame frame{};

    const auto stream_id = read_varint(reader);
    const auto error_code = read_varint(reader);
    if (!stream_id.has_value()) {
        return CodecResult<StopSendingFrame>::failure(stream_id.error().code,
                                                      stream_id.error().offset);
    }
    if (!error_code.has_value()) {
        return CodecResult<StopSendingFrame>::failure(error_code.error().code,
                                                      error_code.error().offset);
    }

    frame.stream_id = stream_id.value();
    frame.application_protocol_error_code = error_code.value();
    return CodecResult<StopSendingFrame>::success(frame);
}

CodecResult<CryptoFrame> decode_crypto_frame(BufferReader &reader) {
    CryptoFrame frame{};

    const auto offset = read_varint(reader);
    if (!offset.has_value()) {
        return CodecResult<CryptoFrame>::failure(offset.error().code, offset.error().offset);
    }

    const auto crypto_data = read_length_prefixed_bytes(reader);
    if (!crypto_data.has_value()) {
        return CodecResult<CryptoFrame>::failure(crypto_data.error().code,
                                                 crypto_data.error().offset);
    }

    if (offset.value() > kMaxVarInt - crypto_data.value().size()) {
        return CodecResult<CryptoFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    frame.offset = offset.value();
    frame.crypto_data = crypto_data.value();
    return CodecResult<CryptoFrame>::success(std::move(frame));
}

CodecResult<NewTokenFrame> decode_new_token_frame(BufferReader &reader) {
    const auto token = read_length_prefixed_bytes(reader);
    if (!token.has_value()) {
        return CodecResult<NewTokenFrame>::failure(token.error().code, token.error().offset);
    }
    if (token.value().empty()) {
        return CodecResult<NewTokenFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    return CodecResult<NewTokenFrame>::success(NewTokenFrame{
        .token = token.value(),
    });
}

CodecResult<StreamFrame> decode_stream_frame(BufferReader &reader, std::uint64_t frame_type) {
    StreamFrame frame{};
    frame.fin = (frame_type & 0x01u) != 0;
    frame.has_length = (frame_type & 0x02u) != 0;
    frame.has_offset = (frame_type & 0x04u) != 0;

    const auto stream_id = read_varint(reader);
    if (!stream_id.has_value()) {
        return CodecResult<StreamFrame>::failure(stream_id.error().code, stream_id.error().offset);
    }
    frame.stream_id = stream_id.value();

    std::uint64_t offset_value = 0;
    if (frame.has_offset) {
        const auto offset = read_varint(reader);
        if (!offset.has_value()) {
            return CodecResult<StreamFrame>::failure(offset.error().code, offset.error().offset);
        }
        offset_value = offset.value();
        frame.offset = offset_value;
    }

    if (frame.has_length) {
        const auto stream_data = read_length_prefixed_bytes(reader);
        if (!stream_data.has_value()) {
            return CodecResult<StreamFrame>::failure(stream_data.error().code,
                                                     stream_data.error().offset);
        }
        frame.stream_data = stream_data.value();
    } else {
        const auto bytes = reader.read_exact(reader.remaining()).value();
        frame.stream_data.assign(bytes.begin(), bytes.end());
    }

    if (offset_value > kMaxVarInt - frame.stream_data.size()) {
        return CodecResult<StreamFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    return CodecResult<StreamFrame>::success(std::move(frame));
}

CodecResult<MaxStreamDataFrame> decode_max_stream_data_frame(BufferReader &reader) {
    MaxStreamDataFrame frame{};

    const auto stream_id = read_varint(reader);
    const auto maximum_stream_data = read_varint(reader);
    if (!stream_id.has_value()) {
        return CodecResult<MaxStreamDataFrame>::failure(stream_id.error().code,
                                                        stream_id.error().offset);
    }
    if (!maximum_stream_data.has_value()) {
        return CodecResult<MaxStreamDataFrame>::failure(maximum_stream_data.error().code,
                                                        maximum_stream_data.error().offset);
    }

    frame.stream_id = stream_id.value();
    frame.maximum_stream_data = maximum_stream_data.value();
    return CodecResult<MaxStreamDataFrame>::success(frame);
}

CodecResult<StreamDataBlockedFrame> decode_stream_data_blocked_frame(BufferReader &reader) {
    StreamDataBlockedFrame frame{};

    const auto stream_id = read_varint(reader);
    const auto maximum_stream_data = read_varint(reader);
    if (!stream_id.has_value()) {
        return CodecResult<StreamDataBlockedFrame>::failure(stream_id.error().code,
                                                            stream_id.error().offset);
    }
    if (!maximum_stream_data.has_value()) {
        return CodecResult<StreamDataBlockedFrame>::failure(maximum_stream_data.error().code,
                                                            maximum_stream_data.error().offset);
    }

    frame.stream_id = stream_id.value();
    frame.maximum_stream_data = maximum_stream_data.value();
    return CodecResult<StreamDataBlockedFrame>::success(frame);
}

CodecResult<MaxStreamsFrame> decode_max_streams_frame(BufferReader &reader,
                                                      StreamLimitType stream_type) {
    const auto maximum_streams = read_varint(reader);
    if (!maximum_streams.has_value()) {
        return CodecResult<MaxStreamsFrame>::failure(maximum_streams.error().code,
                                                     maximum_streams.error().offset);
    }
    if (maximum_streams.value() > kMaxStreamsLimit) {
        return CodecResult<MaxStreamsFrame>::failure(CodecErrorCode::invalid_varint,
                                                     reader.offset());
    }

    return CodecResult<MaxStreamsFrame>::success(MaxStreamsFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams.value(),
    });
}

CodecResult<StreamsBlockedFrame> decode_streams_blocked_frame(BufferReader &reader,
                                                              StreamLimitType stream_type) {
    const auto maximum_streams = read_varint(reader);
    if (!maximum_streams.has_value()) {
        return CodecResult<StreamsBlockedFrame>::failure(maximum_streams.error().code,
                                                         maximum_streams.error().offset);
    }
    if (maximum_streams.value() > kMaxStreamsLimit) {
        return CodecResult<StreamsBlockedFrame>::failure(CodecErrorCode::invalid_varint,
                                                         reader.offset());
    }

    return CodecResult<StreamsBlockedFrame>::success(StreamsBlockedFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams.value(),
    });
}

CodecResult<NewConnectionIdFrame> decode_new_connection_id_frame(BufferReader &reader) {
    NewConnectionIdFrame frame{};

    const auto sequence_number = read_varint(reader);
    const auto retire_prior_to = read_varint(reader);
    const auto length = read_u8(reader);
    if (!sequence_number.has_value()) {
        return CodecResult<NewConnectionIdFrame>::failure(sequence_number.error().code,
                                                          sequence_number.error().offset);
    }
    if (!retire_prior_to.has_value()) {
        return CodecResult<NewConnectionIdFrame>::failure(retire_prior_to.error().code,
                                                          retire_prior_to.error().offset);
    }
    if (!length.has_value()) {
        return CodecResult<NewConnectionIdFrame>::failure(length.error().code,
                                                          length.error().offset);
    }

    if (length.value() == 0 || length.value() > 20) {
        return CodecResult<NewConnectionIdFrame>::failure(CodecErrorCode::invalid_varint,
                                                          reader.offset());
    }
    if (retire_prior_to.value() > sequence_number.value()) {
        return CodecResult<NewConnectionIdFrame>::failure(CodecErrorCode::invalid_varint,
                                                          reader.offset());
    }

    const auto connection_id_bytes = reader.read_exact(length.value());
    if (!connection_id_bytes.has_value()) {
        return CodecResult<NewConnectionIdFrame>::failure(connection_id_bytes.error().code,
                                                          connection_id_bytes.error().offset);
    }

    const auto stateless_reset_token = read_reset_token(reader);
    if (!stateless_reset_token.has_value()) {
        return CodecResult<NewConnectionIdFrame>::failure(stateless_reset_token.error().code,
                                                          stateless_reset_token.error().offset);
    }

    frame.sequence_number = sequence_number.value();
    frame.retire_prior_to = retire_prior_to.value();
    frame.connection_id.assign(connection_id_bytes.value().begin(),
                               connection_id_bytes.value().end());
    frame.stateless_reset_token = stateless_reset_token.value();
    return CodecResult<NewConnectionIdFrame>::success(std::move(frame));
}

CodecResult<TransportConnectionCloseFrame>
decode_transport_connection_close_frame(BufferReader &reader) {
    TransportConnectionCloseFrame frame{};

    const auto error_code = read_varint(reader);
    const auto frame_type = read_varint(reader);
    const auto reason = read_length_prefixed_bytes(reader);
    if (!error_code.has_value()) {
        return CodecResult<TransportConnectionCloseFrame>::failure(error_code.error().code,
                                                                   error_code.error().offset);
    }
    if (!frame_type.has_value()) {
        return CodecResult<TransportConnectionCloseFrame>::failure(frame_type.error().code,
                                                                   frame_type.error().offset);
    }
    if (!reason.has_value()) {
        return CodecResult<TransportConnectionCloseFrame>::failure(reason.error().code,
                                                                   reason.error().offset);
    }

    frame.error_code = error_code.value();
    frame.frame_type = frame_type.value();
    frame.reason.bytes = reason.value();
    return CodecResult<TransportConnectionCloseFrame>::success(std::move(frame));
}

CodecResult<ApplicationConnectionCloseFrame>
decode_application_connection_close_frame(BufferReader &reader) {
    ApplicationConnectionCloseFrame frame{};

    const auto error_code = read_varint(reader);
    const auto reason = read_length_prefixed_bytes(reader);
    if (!error_code.has_value()) {
        return CodecResult<ApplicationConnectionCloseFrame>::failure(error_code.error().code,
                                                                     error_code.error().offset);
    }
    if (!reason.has_value()) {
        return CodecResult<ApplicationConnectionCloseFrame>::failure(reason.error().code,
                                                                     reason.error().offset);
    }

    frame.error_code = error_code.value();
    frame.reason.bytes = reason.value();
    return CodecResult<ApplicationConnectionCloseFrame>::success(std::move(frame));
}

template <typename Writer>
std::optional<CodecError> serialize_frame_into_writer(Writer &writer, const Frame &frame) {
    if (const auto *padding = std::get_if<PaddingFrame>(&frame)) {
        if (padding->length == 0) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        for (std::size_t i = 0; i < padding->length; ++i) {
            if (const auto error = append_byte(writer, std::byte{0x00})) {
                return error;
            }
        }
        return std::nullopt;
    }

    if (std::holds_alternative<PingFrame>(frame)) {
        if (const auto error = append_byte(writer, std::byte{0x01})) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *ack = std::get_if<AckFrame>(&frame)) {
        if (const auto error = append_byte(writer, ack->ecn_counts.has_value() ? std::byte{0x03}
                                                                               : std::byte{0x02})) {
            return error;
        }
        if (const auto error = append_varint(writer, ack->largest_acknowledged)) {
            return error;
        }
        if (const auto error = append_varint(writer, ack->ack_delay)) {
            return error;
        }
        if (const auto error = append_varint(writer, ack->additional_ranges.size())) {
            return error;
        }
        if (const auto error = append_varint(writer, ack->first_ack_range)) {
            return error;
        }

        if (ack->largest_acknowledged < ack->first_ack_range) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        std::uint64_t previous_smallest = ack->largest_acknowledged - ack->first_ack_range;
        for (const auto &range : ack->additional_ranges) {
            if (previous_smallest < range.gap + 2) {
                return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
            }
            const auto largest = previous_smallest - range.gap - 2;
            if (largest < range.range_length) {
                return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
            }

            if (const auto error = append_varint(writer, range.gap)) {
                return error;
            }
            if (const auto error = append_varint(writer, range.range_length)) {
                return error;
            }

            previous_smallest = largest - range.range_length;
        }

        if (ack->ecn_counts.has_value()) {
            if (const auto error = append_varint(writer, ack->ecn_counts->ect0)) {
                return error;
            }
            if (const auto error = append_varint(writer, ack->ecn_counts->ect1)) {
                return error;
            }
            if (const auto error = append_varint(writer, ack->ecn_counts->ecn_ce)) {
                return error;
            }
        }
        return std::nullopt;
    }

    if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x04})) {
            return error;
        }
        if (const auto error = append_varint(writer, reset_stream->stream_id)) {
            return error;
        }
        if (const auto error =
                append_varint(writer, reset_stream->application_protocol_error_code)) {
            return error;
        }
        if (const auto error = append_varint(writer, reset_stream->final_size)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x05})) {
            return error;
        }
        if (const auto error = append_varint(writer, stop_sending->stream_id)) {
            return error;
        }
        if (const auto error =
                append_varint(writer, stop_sending->application_protocol_error_code)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *crypto = std::get_if<CryptoFrame>(&frame)) {
        if (crypto->offset > kMaxVarInt - crypto->crypto_data.size()) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(writer, std::byte{0x06})) {
            return error;
        }
        if (const auto error = append_varint(writer, crypto->offset)) {
            return error;
        }
        if (const auto error = append_exact_length_bytes(writer, crypto->crypto_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *new_token = std::get_if<NewTokenFrame>(&frame)) {
        if (new_token->token.empty()) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(writer, std::byte{0x07})) {
            return error;
        }
        if (const auto error = append_exact_length_bytes(writer, new_token->token)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *stream = std::get_if<StreamFrame>(&frame)) {
        std::byte type = std::byte{0x08};
        if (stream->has_offset) {
            type |= std::byte{0x04};
        }
        if (stream->has_length) {
            type |= std::byte{0x02};
        }
        if (stream->fin) {
            type |= std::byte{0x01};
        }

        const auto offset = stream->offset.value_or(0);
        if (offset > kMaxVarInt - stream->stream_data.size()) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(writer, type)) {
            return error;
        }
        if (const auto error = append_varint(writer, stream->stream_id)) {
            return error;
        }
        if (stream->has_offset) {
            if (const auto error = append_varint(writer, offset)) {
                return error;
            }
        }
        if (stream->has_length) {
            if (const auto error = append_varint(writer, stream->stream_data.size())) {
                return error;
            }
        }
        if (const auto error = append_bytes(writer, stream->stream_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
        return append_single_varint_frame(writer, std::byte{0x10}, max_data->maximum_data);
    }

    if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x11})) {
            return error;
        }
        if (const auto error = append_varint(writer, max_stream_data->stream_id)) {
            return error;
        }
        if (const auto error = append_varint(writer, max_stream_data->maximum_stream_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
        if (max_streams->maximum_streams > kMaxStreamsLimit) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        if (const auto error =
                append_byte(writer, max_streams->stream_type == StreamLimitType::bidirectional
                                        ? std::byte{0x12}
                                        : std::byte{0x13})) {
            return error;
        }
        if (const auto error = append_varint(writer, max_streams->maximum_streams)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
        return append_single_varint_frame(writer, std::byte{0x14}, data_blocked->maximum_data);
    }

    if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x15})) {
            return error;
        }
        if (const auto error = append_varint(writer, stream_data_blocked->stream_id)) {
            return error;
        }
        if (const auto error = append_varint(writer, stream_data_blocked->maximum_stream_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *streams_blocked = std::get_if<StreamsBlockedFrame>(&frame)) {
        if (streams_blocked->maximum_streams > kMaxStreamsLimit) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        if (const auto error =
                append_byte(writer, streams_blocked->stream_type == StreamLimitType::bidirectional
                                        ? std::byte{0x16}
                                        : std::byte{0x17})) {
            return error;
        }
        if (const auto error = append_varint(writer, streams_blocked->maximum_streams)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
        const auto invalid_new_connection_id =
            new_connection_id->connection_id.empty() |
            (new_connection_id->connection_id.size() > 20) |
            (new_connection_id->retire_prior_to > new_connection_id->sequence_number);
        if (invalid_new_connection_id) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(writer, std::byte{0x18})) {
            return error;
        }
        if (const auto error = append_varint(writer, new_connection_id->sequence_number)) {
            return error;
        }
        if (const auto error = append_varint(writer, new_connection_id->retire_prior_to)) {
            return error;
        }
        if (const auto error = append_byte(
                writer, static_cast<std::byte>(new_connection_id->connection_id.size()))) {
            return error;
        }
        if (const auto error = append_bytes(writer, new_connection_id->connection_id)) {
            return error;
        }
        if (const auto error = append_bytes(writer, new_connection_id->stateless_reset_token)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *retire_connection_id = std::get_if<RetireConnectionIdFrame>(&frame)) {
        return append_single_varint_frame(writer, std::byte{0x19},
                                          retire_connection_id->sequence_number);
    }

    if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x1a})) {
            return error;
        }
        if (const auto error = append_bytes(writer, path_challenge->data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x1b})) {
            return error;
        }
        if (const auto error = append_bytes(writer, path_response->data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *transport_close = std::get_if<TransportConnectionCloseFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x1c})) {
            return error;
        }
        if (const auto error = append_varint(writer, transport_close->error_code)) {
            return error;
        }
        if (const auto error = append_varint(writer, transport_close->frame_type)) {
            return error;
        }
        if (const auto error = append_exact_length_bytes(writer, transport_close->reason.bytes)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *application_close = std::get_if<ApplicationConnectionCloseFrame>(&frame)) {
        if (const auto error = append_byte(writer, std::byte{0x1d})) {
            return error;
        }
        if (const auto error = append_varint(writer, application_close->error_code)) {
            return error;
        }
        if (const auto error = append_exact_length_bytes(writer, application_close->reason.bytes)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto error = append_byte(writer, std::byte{0x1e})) {
        return error;
    }
    return std::nullopt;
}

} // namespace

CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame) {
    BufferWriter writer;
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return failure_result(error->code, error->offset);
    }

    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<std::size_t> serialized_frame_size(const Frame &frame) {
    CountingBufferWriter writer;
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame) {
    const auto size = serialized_frame_size(frame);
    if (!size.has_value()) {
        return CodecResult<std::size_t>::failure(size.error().code, size.error().offset);
    }
    if (output.size() < size.value()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
    }

    SpanBufferWriter writer(output);
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes,
                                                 const Frame &frame) {
    const auto begin = bytes.size();
    BufferWriter writer(&bytes);
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        bytes.resize(begin);
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<FrameDecodeResult> deserialize_frame(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return decode_failure(CodecErrorCode::truncated_input, 0);
    }

    if (bytes.front() == std::byte{0x00}) {
        std::size_t length = 1;
        while (length < bytes.size() && bytes[length] == std::byte{0x00}) {
            ++length;
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame =
                PaddingFrame{
                    .length = length,
                },
            .bytes_consumed = length,
        });
    }

    BufferReader reader(bytes);
    const auto frame_type_result = decode_varint(reader);
    if (!frame_type_result.has_value()) {
        return decode_failure(frame_type_result.error().code, frame_type_result.error().offset);
    }

    const auto frame_type = frame_type_result.value().value;
    if (frame_type <= 0x1eu && frame_type_result.value().bytes_consumed != 1) {
        return decode_failure(CodecErrorCode::non_shortest_frame_type_encoding, 0);
    }

    if (frame_type >= 0x08 && frame_type <= 0x0f) {
        const auto frame = decode_stream_frame(reader, frame_type);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }

    switch (frame_type) {
    case 0x01:
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = PingFrame{},
            .bytes_consumed = reader.offset(),
        });
    case 0x02:
    case 0x03: {
        const auto ack = decode_ack_frame(reader, frame_type == 0x03);
        if (!ack.has_value()) {
            return decode_failure(ack.error().code, ack.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = ack.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x04: {
        const auto frame = decode_reset_stream_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x05: {
        const auto frame = decode_stop_sending_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x06: {
        const auto frame = decode_crypto_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x07: {
        const auto frame = decode_new_token_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x10: {
        const auto maximum_data = read_varint(reader);
        if (!maximum_data.has_value()) {
            return decode_failure(maximum_data.error().code, maximum_data.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame =
                MaxDataFrame{
                    .maximum_data = maximum_data.value(),
                },
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x11: {
        const auto frame = decode_max_stream_data_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x12:
    case 0x13: {
        const auto frame =
            decode_max_streams_frame(reader, frame_type == 0x12 ? StreamLimitType::bidirectional
                                                                : StreamLimitType::unidirectional);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x14: {
        const auto maximum_data = read_varint(reader);
        if (!maximum_data.has_value()) {
            return decode_failure(maximum_data.error().code, maximum_data.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame =
                DataBlockedFrame{
                    .maximum_data = maximum_data.value(),
                },
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x15: {
        const auto frame = decode_stream_data_blocked_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x16:
    case 0x17: {
        const auto frame = decode_streams_blocked_frame(
            reader,
            frame_type == 0x16 ? StreamLimitType::bidirectional : StreamLimitType::unidirectional);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x18: {
        const auto frame = decode_new_connection_id_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x19: {
        const auto sequence_number = read_varint(reader);
        if (!sequence_number.has_value()) {
            return decode_failure(sequence_number.error().code, sequence_number.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame =
                RetireConnectionIdFrame{
                    .sequence_number = sequence_number.value(),
                },
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x1a: {
        const auto data = read_path_bytes(reader);
        if (!data.has_value()) {
            return decode_failure(data.error().code, data.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame =
                PathChallengeFrame{
                    .data = data.value(),
                },
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x1b: {
        const auto data = read_path_bytes(reader);
        if (!data.has_value()) {
            return decode_failure(data.error().code, data.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame =
                PathResponseFrame{
                    .data = data.value(),
                },
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x1c: {
        const auto frame = decode_transport_connection_close_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x1d: {
        const auto frame = decode_application_connection_close_frame(reader);
        if (!frame.has_value()) {
            return decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = frame.value(),
            .bytes_consumed = reader.offset(),
        });
    }
    case 0x1e:
        return CodecResult<FrameDecodeResult>::success(FrameDecodeResult{
            .frame = HandshakeDoneFrame{},
            .bytes_consumed = reader.offset(),
        });
    default:
        return decode_failure(CodecErrorCode::unknown_frame_type, 0);
    }
}

CodecResult<std::vector<AckPacketNumberRange>> ack_frame_packet_number_ranges(const AckFrame &ack) {
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return CodecResult<std::vector<AckPacketNumberRange>>::failure(
            CodecErrorCode::invalid_varint, 0);
    }

    std::vector<AckPacketNumberRange> ranges;
    ranges.reserve(1 + ack.additional_ranges.size());

    auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
    ranges.push_back(AckPacketNumberRange{
        .smallest = range_smallest,
        .largest = ack.largest_acknowledged,
    });

    auto previous_smallest = range_smallest;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return CodecResult<std::vector<AckPacketNumberRange>>::failure(
                CodecErrorCode::invalid_varint, 0);
        }

        const auto range_largest = previous_smallest - range.gap - 2;
        if (range_largest < range.range_length) {
            return CodecResult<std::vector<AckPacketNumberRange>>::failure(
                CodecErrorCode::invalid_varint, 0);
        }

        range_smallest = range_largest - range.range_length;
        ranges.push_back(AckPacketNumberRange{
            .smallest = range_smallest,
            .largest = range_largest,
        });
        previous_smallest = range_smallest;
    }

    return CodecResult<std::vector<AckPacketNumberRange>>::success(std::move(ranges));
}

} // namespace coquic::quic

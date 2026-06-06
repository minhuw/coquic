#include "src/quic/codec/frame.h"

#include <array>
#include <limits>
#include <type_traits>
#include <utility>

#include "src/quic/codec/buffer.h"

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::quic {

namespace {

constexpr std::uint64_t kMaxVarInt = 4611686018427387903ull;
constexpr std::uint64_t kMaxStreamsLimit = 1ull << 60;
constexpr bool kCoquicFrameFaultHooksEnabled = COQUIC_PROFILE_HOOKS != 0;

CodecResult<std::vector<std::byte>> failure_result(CodecErrorCode code, std::size_t offset) {
    return CodecResult<std::vector<std::byte>>::failure(code, offset);
}

CodecResult<FrameDecodeResult> decode_failure(CodecErrorCode code, std::size_t offset) {
    return CodecResult<FrameDecodeResult>::failure(code, offset);
}

CodecResult<ReceivedFrameDecodeResult> received_decode_failure(CodecErrorCode code,
                                                               std::size_t offset) {
    return CodecResult<ReceivedFrameDecodeResult>::failure(code, offset);
}

CodecResult<ReceivedAckFrameDecodeResult> received_ack_decode_failure(CodecErrorCode code,
                                                                      std::size_t offset) {
    return CodecResult<ReceivedAckFrameDecodeResult>::failure(code, offset);
}

enum class FrameFaultPoint : std::uint8_t;
enum class FrameFaultPoint : std::uint8_t {
    append_byte,
    append_bytes,
    append_varint,
};

constexpr CodecError kFrameFaultError{
    .code = CodecErrorCode::truncated_input,
    .offset = 17,
};

struct FrameFaultState {
    std::optional<FrameFaultPoint> point;
    std::size_t occurrence = 0;
};

FrameFaultState &frame_fault_state() {
    static auto *state = new FrameFaultState();
    return *state;
}

void set_frame_fault_state(std::optional<FrameFaultPoint> point, std::size_t occurrence) {
    frame_fault_state() = FrameFaultState{
        .point = point,
        .occurrence = occurrence,
    };
}

std::optional<CodecError> consume_frame_fault(FrameFaultPoint point) {
    auto &state = frame_fault_state();
    const bool matches = state.point.has_value() && state.point.value() == point;
    const bool should_fire = matches && state.occurrence == 1;
    if (matches && state.occurrence > 0) {
        --state.occurrence;
    }
    if (should_fire) {
        return kFrameFaultError;
    }
    return std::nullopt;
}

class ScopedFrameFault {
  public:
    ScopedFrameFault(FrameFaultPoint point, std::size_t occurrence)
        : previous_point_(frame_fault_state().point),
          previous_occurrence_(frame_fault_state().occurrence) {
        set_frame_fault_state(point, occurrence);
    }

    ~ScopedFrameFault() {
        set_frame_fault_state(previous_point_, previous_occurrence_);
    }

    ScopedFrameFault(const ScopedFrameFault &) = delete;
    ScopedFrameFault &operator=(const ScopedFrameFault &) = delete;

  private:
    std::optional<FrameFaultPoint> previous_point_;
    std::size_t previous_occurrence_ = 0;
};

template <typename Writer>
std::optional<CodecError> append_byte(Writer &frame_writer, std::byte value) {
    if constexpr (kCoquicFrameFaultHooksEnabled) {
        if (const auto injected = consume_frame_fault(FrameFaultPoint::append_byte)) {
            return injected;
        }
    }
    if constexpr (std::is_void_v<decltype(frame_writer.write_byte(value))>) {
        frame_writer.write_byte(value);
        return std::nullopt;
    } else {
        return frame_writer.write_byte(value);
    }
}

template <typename Writer>
std::optional<CodecError> append_bytes(Writer &frame_writer, std::span<const std::byte> bytes) {
    if constexpr (kCoquicFrameFaultHooksEnabled) {
        if (const auto injected = consume_frame_fault(FrameFaultPoint::append_bytes)) {
            return injected;
        }
    }
    if constexpr (std::is_void_v<decltype(frame_writer.write_bytes(bytes))>) {
        frame_writer.write_bytes(bytes);
        return std::nullopt;
    } else {
        return frame_writer.write_bytes(bytes);
    }
}

template <typename Writer>
std::optional<CodecError> append_varint(Writer &frame_writer, std::uint64_t value) {
    if constexpr (kCoquicFrameFaultHooksEnabled) {
        if (const auto injected = consume_frame_fault(FrameFaultPoint::append_varint)) {
            return injected;
        }
    }
    auto error = frame_writer.write_varint(value);
    if (error.has_value()) {
        error->offset *= static_cast<std::size_t>(error->code != CodecErrorCode::invalid_varint);
    }
    return error;
}

template <typename Writer>
std::optional<CodecError> append_exact_length_bytes(Writer &frame_writer,
                                                    const std::vector<std::byte> &bytes) {
    if (const auto error = append_varint(frame_writer, bytes.size())) {
        return error;
    }
    if (const auto error = append_bytes(frame_writer, bytes)) {
        return error;
    }
    return std::nullopt;
}

template <typename Writer>
std::optional<CodecError> append_single_varint_frame(Writer &frame_writer, std::byte type,
                                                     std::uint64_t value) {
    if (const auto error = append_byte(frame_writer, type)) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, value)) {
        return error;
    }

    return std::nullopt;
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
template <typename Writer>
std::optional<CodecError>
write_ack_fields(Writer &frame_writer, std::uint64_t largest_acknowledged, std::uint64_t ack_delay,
                 std::size_t additional_range_count, std::uint64_t first_ack_range,
                 const std::optional<AckEcnCounts> &ecn_counts) {
    if (const auto error =
            append_byte(frame_writer, ecn_counts.has_value() ? std::byte{0x03} : std::byte{0x02})) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, largest_acknowledged)) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, ack_delay)) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, additional_range_count)) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, first_ack_range)) {
        return error;
    }
    return std::nullopt;
}
// NOLINTEND(bugprone-easily-swappable-parameters)

template <typename Writer>
std::optional<CodecError> write_ack_ranges(Writer &frame_writer, std::uint64_t largest_acknowledged,
                                           std::uint64_t first_ack_range,
                                           std::span<const AckRange> additional_ranges) {
    if (largest_acknowledged < first_ack_range) {
        return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
    }

    std::uint64_t previous_smallest = largest_acknowledged - first_ack_range;
    for (const auto &range : additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        const auto largest = previous_smallest - range.gap - 2;
        if (largest < range.range_length) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_varint(frame_writer, range.gap)) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, range.range_length)) {
            return error;
        }

        previous_smallest = largest - range.range_length;
    }

    return std::nullopt;
}

template <typename Writer>
std::optional<CodecError> write_ack_ecn_counts(Writer &frame_writer,
                                               const std::optional<AckEcnCounts> &ecn_counts) {
    if (!ecn_counts.has_value()) {
        return std::nullopt;
    }

    if (const auto error = append_varint(frame_writer, ecn_counts->ect0)) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, ecn_counts->ect1)) {
        return error;
    }
    if (const auto error = append_varint(frame_writer, ecn_counts->ecn_ce)) {
        return error;
    }
    return std::nullopt;
}

template <typename Writer>
std::optional<CodecError> write_ack_frame(Writer &frame_writer, const AckFrame &ack) {
    if (const auto error =
            write_ack_fields(frame_writer, ack.largest_acknowledged, ack.ack_delay,
                             ack.additional_ranges.size(), ack.first_ack_range, ack.ecn_counts)) {
        return error;
    }
    if (const auto error = write_ack_ranges(frame_writer, ack.largest_acknowledged,
                                            ack.first_ack_range, ack.additional_ranges)) {
        return error;
    }
    return write_ack_ecn_counts(frame_writer, ack.ecn_counts);
}

template <typename Writer>
std::optional<CodecError> write_outbound_ack_frame(Writer &frame_writer,
                                                   const OutboundAckFrame &ack) {
    if (const auto error =
            write_ack_fields(frame_writer, ack.header.largest_acknowledged, ack.header.ack_delay,
                             ack.header.additional_ranges.size(), ack.header.first_ack_range,
                             ack.header.ecn_counts)) {
        return error;
    }
    if (const auto error =
            write_ack_ranges(frame_writer, ack.header.largest_acknowledged,
                             ack.header.first_ack_range, ack.header.additional_ranges)) {
        return error;
    }
    return write_ack_ecn_counts(frame_writer, ack.header.ecn_counts);
}

CodecResult<AckFrame> materialize_outbound_ack_frame(const OutboundAckFrame &ack) {
    return CodecResult<AckFrame>::success(AckFrame{
        .largest_acknowledged = ack.header.largest_acknowledged,
        .ack_delay = ack.header.ack_delay,
        .first_ack_range = ack.header.first_ack_range,
        .additional_ranges = ack.header.additional_ranges,
        .ecn_counts = ack.header.ecn_counts,
    });
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

CodecResult<SharedBytes> read_length_prefixed_shared_bytes(BufferReader &reader,
                                                           const SharedBytes &bytes) {
    const auto length = read_varint(reader);
    if (!length.has_value()) {
        return CodecResult<SharedBytes>::failure(length.error().code, length.error().offset);
    }

    if (length.value() > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<SharedBytes>::failure(CodecErrorCode::truncated_input, reader.offset());
    }

    const auto begin = reader.offset();
    static_cast<void>(reader.read_exact(static_cast<std::size_t>(length.value())).value());
    return CodecResult<SharedBytes>::success(
        bytes.subspan(begin, static_cast<std::size_t>(length.value())));
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

struct DecodedAckHeader {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t additional_range_count = 0;
    std::uint64_t first_ack_range = 0;
    std::uint64_t first_range_smallest = 0;
};

CodecResult<DecodedAckHeader> decode_ack_header(BufferReader &reader) {
    const auto largest_acknowledged = read_varint(reader);
    if (!largest_acknowledged.has_value()) {
        return CodecResult<DecodedAckHeader>::failure(largest_acknowledged.error().code,
                                                      largest_acknowledged.error().offset);
    }

    const auto ack_delay = read_varint(reader);
    if (!ack_delay.has_value()) {
        return CodecResult<DecodedAckHeader>::failure(ack_delay.error().code,
                                                      ack_delay.error().offset);
    }

    const auto ack_range_count = read_varint(reader);
    if (!ack_range_count.has_value()) {
        return CodecResult<DecodedAckHeader>::failure(ack_range_count.error().code,
                                                      ack_range_count.error().offset);
    }

    const auto first_ack_range = read_varint(reader);
    if (!first_ack_range.has_value()) {
        return CodecResult<DecodedAckHeader>::failure(first_ack_range.error().code,
                                                      first_ack_range.error().offset);
    }

    if (largest_acknowledged.value() < first_ack_range.value()) {
        return CodecResult<DecodedAckHeader>::failure(CodecErrorCode::invalid_varint,
                                                      reader.offset());
    }

    return CodecResult<DecodedAckHeader>::success(DecodedAckHeader{
        .largest_acknowledged = largest_acknowledged.value(),
        .ack_delay = ack_delay.value(),
        .additional_range_count = ack_range_count.value(),
        .first_ack_range = first_ack_range.value(),
        .first_range_smallest = largest_acknowledged.value() - first_ack_range.value(),
    });
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
template <typename OnRange>
std::optional<CodecError>
decode_ack_additional_ranges(BufferReader &reader, std::uint64_t additional_range_count,
                             std::uint64_t ack_previous_smallest, OnRange &&on_range) {
    for (std::uint64_t i = 0; i < additional_range_count; ++i) {
        const auto additional_range_gap_result = read_varint(reader);
        if (!additional_range_gap_result.has_value()) {
            return additional_range_gap_result.error();
        }
        const auto additional_range_gap_value = additional_range_gap_result.value();

        const auto ack_range_length = read_varint(reader);
        if (!ack_range_length.has_value()) {
            return ack_range_length.error();
        }

        if (ack_previous_smallest < additional_range_gap_value + 2) {
            return CodecError{
                .code = CodecErrorCode::invalid_varint,
                .offset = reader.offset(),
            };
        }

        const auto largest = ack_previous_smallest - additional_range_gap_value - 2;
        if (largest < ack_range_length.value()) {
            return CodecError{
                .code = CodecErrorCode::invalid_varint,
                .offset = reader.offset(),
            };
        }

        on_range(additional_range_gap_value, ack_range_length.value());
        ack_previous_smallest = largest - ack_range_length.value();
    }

    return std::nullopt;
}

// NOLINTEND(bugprone-easily-swappable-parameters)

std::optional<CodecError> decode_ack_ecn_counts(BufferReader &reader, bool has_ecn_counts,
                                                std::optional<AckEcnCounts> &output) {
    if (!has_ecn_counts) {
        output.reset();
        return std::nullopt;
    }

    const auto ect0 = read_varint(reader);
    const auto ect1 = read_varint(reader);
    const auto ecn_ce = read_varint(reader);
    if (!ect0.has_value()) {
        return ect0.error();
    }
    if (!ect1.has_value()) {
        return ect1.error();
    }
    if (!ecn_ce.has_value()) {
        return ecn_ce.error();
    }

    output = AckEcnCounts{
        .ect0 = ect0.value(),
        .ect1 = ect1.value(),
        .ecn_ce = ecn_ce.value(),
    };
    return std::nullopt;
}

CodecResult<AckFrame> decode_ack_frame(BufferReader &reader, bool has_ecn_counts) {
    const auto header = decode_ack_header(reader);
    if (!header.has_value()) {
        return CodecResult<AckFrame>::failure(header.error().code, header.error().offset);
    }

    AckFrame frame{};
    frame.largest_acknowledged = header.value().largest_acknowledged;
    frame.ack_delay = header.value().ack_delay;
    frame.first_ack_range = header.value().first_ack_range;

    const auto max_decodable_additional_ranges = static_cast<std::uint64_t>(reader.remaining() / 2);
    if (header.value().additional_range_count > max_decodable_additional_ranges) {
        return CodecResult<AckFrame>::failure(CodecErrorCode::truncated_input, reader.offset());
    }

    if constexpr (sizeof(std::size_t) < sizeof(std::uint64_t)) {
        if (header.value().additional_range_count >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            return CodecResult<AckFrame>::failure(CodecErrorCode::invalid_varint, reader.offset());
        }
    }
    frame.additional_ranges.reserve(
        static_cast<std::size_t>(header.value().additional_range_count));

    if (const auto error = decode_ack_additional_ranges(
            reader, header.value().additional_range_count, header.value().first_range_smallest,
            [&frame](std::uint64_t decoded_range_gap_value, std::uint64_t ack_range_length) {
                frame.additional_ranges.push_back(AckRange{
                    .gap = decoded_range_gap_value,
                    .range_length = ack_range_length,
                });
            });
        error.has_value()) {
        return CodecResult<AckFrame>::failure(error->code, error->offset);
    }

    if (const auto error = decode_ack_ecn_counts(reader, has_ecn_counts, frame.ecn_counts)) {
        return CodecResult<AckFrame>::failure(error->code, error->offset);
    }

    return CodecResult<AckFrame>::success(std::move(frame));
}

CodecResult<ReceivedAckFrame> decode_received_ack_frame(BufferReader &reader, bool has_ecn_counts,
                                                        const SharedBytes &bytes) {
    const auto header = decode_ack_header(reader);
    if (!header.has_value()) {
        return CodecResult<ReceivedAckFrame>::failure(header.error().code, header.error().offset);
    }

    ReceivedAckFrame frame{};
    frame.largest_acknowledged = header.value().largest_acknowledged;
    frame.ack_delay = header.value().ack_delay;
    frame.first_ack_range = header.value().first_ack_range;
    frame.additional_range_count = header.value().additional_range_count;

    const auto additional_range_begin = reader.offset();
    const auto max_decodable_additional_ranges = static_cast<std::uint64_t>(reader.remaining() / 2);
    if (header.value().additional_range_count > max_decodable_additional_ranges) {
        return CodecResult<ReceivedAckFrame>::failure(CodecErrorCode::truncated_input,
                                                      additional_range_begin);
    }

    BufferReader additional_ranges_reader(bytes.span().subspan(additional_range_begin));
    if (const auto error = decode_ack_additional_ranges(
            additional_ranges_reader, header.value().additional_range_count,
            header.value().first_range_smallest, [](std::uint64_t, std::uint64_t) {});
        error.has_value()) {
        return CodecResult<ReceivedAckFrame>::failure(error->code,
                                                      additional_range_begin + error->offset);
    }
    static_cast<void>(reader.read_exact(additional_ranges_reader.offset()).value());
    frame.additional_range_bytes =
        bytes.subspan(additional_range_begin, additional_ranges_reader.offset());
    frame.additional_ranges_validated = true;

    if (const auto error = decode_ack_ecn_counts(reader, has_ecn_counts, frame.ecn_counts)) {
        return CodecResult<ReceivedAckFrame>::failure(error->code, error->offset);
    }

    return CodecResult<ReceivedAckFrame>::success(std::move(frame));
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

CodecResult<ReceivedCryptoFrame> decode_received_crypto_frame(BufferReader &reader,
                                                              const SharedBytes &bytes) {
    ReceivedCryptoFrame frame{};

    const auto offset = read_varint(reader);
    if (!offset.has_value()) {
        return CodecResult<ReceivedCryptoFrame>::failure(offset.error().code,
                                                         offset.error().offset);
    }

    auto crypto_data = read_length_prefixed_shared_bytes(reader, bytes);
    if (!crypto_data.has_value()) {
        return CodecResult<ReceivedCryptoFrame>::failure(crypto_data.error().code,
                                                         crypto_data.error().offset);
    }

    if (offset.value() > kMaxVarInt - crypto_data.value().size()) {
        return CodecResult<ReceivedCryptoFrame>::failure(CodecErrorCode::invalid_varint,
                                                         reader.offset());
    }

    frame.offset = offset.value();
    frame.crypto_data = std::move(crypto_data.value());
    return CodecResult<ReceivedCryptoFrame>::success(std::move(frame));
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

CodecResult<ReceivedStreamFrame> decode_received_stream_frame(BufferReader &reader,
                                                              std::uint64_t frame_type,
                                                              const SharedBytes &bytes) {
    ReceivedStreamFrame frame{};
    frame.fin = (frame_type & 0x01u) != 0;
    frame.has_length = (frame_type & 0x02u) != 0;
    frame.has_offset = (frame_type & 0x04u) != 0;

    const auto stream_id = read_varint(reader);
    if (!stream_id.has_value()) {
        return CodecResult<ReceivedStreamFrame>::failure(stream_id.error().code,
                                                         stream_id.error().offset);
    }
    frame.stream_id = stream_id.value();

    std::uint64_t offset_value = 0;
    if (frame.has_offset) {
        const auto offset = read_varint(reader);
        if (!offset.has_value()) {
            return CodecResult<ReceivedStreamFrame>::failure(offset.error().code,
                                                             offset.error().offset);
        }
        offset_value = offset.value();
        frame.offset = offset_value;
    }

    if (frame.has_length) {
        auto stream_data = read_length_prefixed_shared_bytes(reader, bytes);
        if (!stream_data.has_value()) {
            return CodecResult<ReceivedStreamFrame>::failure(stream_data.error().code,
                                                             stream_data.error().offset);
        }
        frame.stream_data = std::move(stream_data.value());
    } else {
        const auto data_offset = reader.offset();
        const auto remaining = reader.remaining();
        static_cast<void>(reader.read_exact(remaining).value());
        frame.stream_data = bytes.subspan(data_offset, remaining);
    }

    if (offset_value > kMaxVarInt - frame.stream_data.size()) {
        return CodecResult<ReceivedStreamFrame>::failure(CodecErrorCode::invalid_varint,
                                                         reader.offset());
    }

    return CodecResult<ReceivedStreamFrame>::success(std::move(frame));
}

CodecResult<DatagramFrame> decode_datagram_frame(BufferReader &reader, std::uint64_t frame_type) {
    DatagramFrame frame{};
    frame.has_length = (frame_type & 0x01u) != 0;

    if (frame.has_length) {
        const auto data = read_length_prefixed_bytes(reader);
        if (!data.has_value()) {
            return CodecResult<DatagramFrame>::failure(data.error().code, data.error().offset);
        }
        frame.data = data.value();
    } else {
        const auto bytes = reader.read_exact(reader.remaining()).value();
        frame.data.assign(bytes.begin(), bytes.end());
    }

    return CodecResult<DatagramFrame>::success(std::move(frame));
}

CodecResult<ReceivedDatagramFrame> decode_received_datagram_frame(BufferReader &reader,
                                                                  std::uint64_t frame_type,
                                                                  const SharedBytes &bytes) {
    ReceivedDatagramFrame frame{};
    frame.has_length = (frame_type & 0x01u) != 0;

    if (frame.has_length) {
        auto data = read_length_prefixed_shared_bytes(reader, bytes);
        if (!data.has_value()) {
            return CodecResult<ReceivedDatagramFrame>::failure(data.error().code,
                                                               data.error().offset);
        }
        frame.data = std::move(data.value());
    } else {
        const auto data_offset = reader.offset();
        const auto remaining = reader.remaining();
        static_cast<void>(reader.read_exact(remaining).value());
        frame.data = bytes.subspan(data_offset, remaining);
    }

    return CodecResult<ReceivedDatagramFrame>::success(std::move(frame));
}

ReceivedFrame to_received_frame(Frame frame) {
    return std::visit(
        [](const auto &value) -> ReceivedFrame {
            using Value = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Value, OutboundAckFrame>) {
                const auto owned = materialize_outbound_ack_frame(value).value();
                return ReceivedAckFrame{
                    .largest_acknowledged = owned.largest_acknowledged,
                    .ack_delay = owned.ack_delay,
                    .first_ack_range = owned.first_ack_range,
                    .additional_range_count = owned.additional_ranges.size(),
                    .ecn_counts = owned.ecn_counts,
                };
            } else if constexpr (std::is_same_v<Value, AckFrame>) {
                return ReceivedAckFrame{
                    .largest_acknowledged = value.largest_acknowledged,
                    .ack_delay = value.ack_delay,
                    .first_ack_range = value.first_ack_range,
                    .additional_range_count = value.additional_ranges.size(),
                    .ecn_counts = value.ecn_counts,
                };
            } else if constexpr (std::is_same_v<Value, CryptoFrame>) {
                return ReceivedCryptoFrame{
                    .offset = value.offset,
                    .crypto_data = SharedBytes(std::move(value.crypto_data)),
                };
            } else if constexpr (std::is_same_v<Value, StreamFrame>) {
                return ReceivedStreamFrame{
                    .fin = value.fin,
                    .has_offset = value.has_offset,
                    .has_length = value.has_length,
                    .stream_id = value.stream_id,
                    .offset = value.offset,
                    .stream_data = SharedBytes(std::move(value.stream_data)),
                };
            } else if constexpr (std::is_same_v<Value, DatagramFrame>) {
                return ReceivedDatagramFrame{
                    .has_length = value.has_length,
                    .data = SharedBytes(std::move(value.data)),
                };
            } else {
                return value;
            }
        },
        std::move(frame));
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
std::optional<CodecError> serialize_frame_into_writer(Writer &frame_writer, const Frame &frame) {
    // Padding and ping are the only zero-field frames.
    if (const auto *padding = std::get_if<PaddingFrame>(&frame)) {
        if (padding->length == 0) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        for (std::size_t i = 0; i < padding->length; ++i) {
            if (const auto error = append_byte(frame_writer, std::byte{0x00})) {
                return error;
            }
        }
        return std::nullopt;
    }

    if (std::holds_alternative<PingFrame>(frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x01})) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *ack = std::get_if<AckFrame>(&frame)) {
        return write_ack_frame(frame_writer, *ack);
    }

    if (const auto *ack = std::get_if<OutboundAckFrame>(&frame)) {
        return write_outbound_ack_frame(frame_writer, *ack);
    }

    // Reset, stop-sending, crypto, and token frames carry direct varint fields.
    if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x04})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, reset_stream->stream_id)) {
            return error;
        }
        if (const auto error =
                append_varint(frame_writer, reset_stream->application_protocol_error_code)) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, reset_stream->final_size)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x05})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, stop_sending->stream_id)) {
            return error;
        }
        if (const auto error =
                append_varint(frame_writer, stop_sending->application_protocol_error_code)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *crypto = std::get_if<CryptoFrame>(&frame)) {
        if (crypto->offset > kMaxVarInt - crypto->crypto_data.size()) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(frame_writer, std::byte{0x06})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, crypto->offset)) {
            return error;
        }
        if (const auto error = append_exact_length_bytes(frame_writer, crypto->crypto_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *new_token = std::get_if<NewTokenFrame>(&frame)) {
        if (new_token->token.empty()) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(frame_writer, std::byte{0x07})) {
            return error;
        }
        if (const auto error = append_exact_length_bytes(frame_writer, new_token->token)) {
            return error;
        }
        return std::nullopt;
    }

    // STREAM and DATAGRAM frame type bits encode optional length, offset, and FIN fields.
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

        if (const auto error = append_byte(frame_writer, type)) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, stream->stream_id)) {
            return error;
        }
        if (stream->has_offset) {
            if (const auto error = append_varint(frame_writer, offset)) {
                return error;
            }
        }
        if (stream->has_length) {
            if (const auto error = append_varint(frame_writer, stream->stream_data.size())) {
                return error;
            }
        }
        if (const auto error = append_bytes(frame_writer, stream->stream_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *datagram = std::get_if<DatagramFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, datagram->has_length ? std::byte{0x31}
                                                                              : std::byte{0x30})) {
            return error;
        }
        if (datagram->has_length) {
            if (const auto error = append_varint(frame_writer, datagram->data.size())) {
                return error;
            }
        }
        if (const auto error = append_bytes(frame_writer, datagram->data)) {
            return error;
        }
        return std::nullopt;
    }

    // Flow-control frames share the same compact varint limit encoding.
    if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
        return append_single_varint_frame(frame_writer, std::byte{0x10}, max_data->maximum_data);
    }

    if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x11})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, max_stream_data->stream_id)) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, max_stream_data->maximum_stream_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
        if (max_streams->maximum_streams > kMaxStreamsLimit) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        if (const auto error =
                append_byte(frame_writer, max_streams->stream_type == StreamLimitType::bidirectional
                                              ? std::byte{0x12}
                                              : std::byte{0x13})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, max_streams->maximum_streams)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
        return append_single_varint_frame(frame_writer, std::byte{0x14},
                                          data_blocked->maximum_data);
    }

    if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x15})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, stream_data_blocked->stream_id)) {
            return error;
        }
        if (const auto error =
                append_varint(frame_writer, stream_data_blocked->maximum_stream_data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *streams_blocked = std::get_if<StreamsBlockedFrame>(&frame)) {
        if (streams_blocked->maximum_streams > kMaxStreamsLimit) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }
        if (const auto error = append_byte(frame_writer, streams_blocked->stream_type ==
                                                                 StreamLimitType::bidirectional
                                                             ? std::byte{0x16}
                                                             : std::byte{0x17})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, streams_blocked->maximum_streams)) {
            return error;
        }
        return std::nullopt;
    }

    // Connection-ID and path-validation frames carry bounded identifiers or fixed challenge bytes.
    if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
        const auto invalid_new_connection_id =
            new_connection_id->connection_id.empty() |
            (new_connection_id->connection_id.size() > 20) |
            (new_connection_id->retire_prior_to > new_connection_id->sequence_number);
        if (invalid_new_connection_id) {
            return CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0};
        }

        if (const auto error = append_byte(frame_writer, std::byte{0x18})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, new_connection_id->sequence_number)) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, new_connection_id->retire_prior_to)) {
            return error;
        }
        if (const auto error = append_byte(
                frame_writer, static_cast<std::byte>(new_connection_id->connection_id.size()))) {
            return error;
        }
        if (const auto error = append_bytes(frame_writer, new_connection_id->connection_id)) {
            return error;
        }
        if (const auto error =
                append_bytes(frame_writer, new_connection_id->stateless_reset_token)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *retire_connection_id = std::get_if<RetireConnectionIdFrame>(&frame)) {
        return append_single_varint_frame(frame_writer, std::byte{0x19},
                                          retire_connection_id->sequence_number);
    }

    if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x1a})) {
            return error;
        }
        if (const auto error = append_bytes(frame_writer, path_challenge->data)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x1b})) {
            return error;
        }
        if (const auto error = append_bytes(frame_writer, path_response->data)) {
            return error;
        }
        return std::nullopt;
    }

    // Close frames carry protocol error metadata followed by a length-prefixed reason.
    if (const auto *transport_close = std::get_if<TransportConnectionCloseFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x1c})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, transport_close->error_code)) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, transport_close->frame_type)) {
            return error;
        }
        if (const auto error =
                append_exact_length_bytes(frame_writer, transport_close->reason.bytes)) {
            return error;
        }
        return std::nullopt;
    }

    if (const auto *application_close = std::get_if<ApplicationConnectionCloseFrame>(&frame)) {
        if (const auto error = append_byte(frame_writer, std::byte{0x1d})) {
            return error;
        }
        if (const auto error = append_varint(frame_writer, application_close->error_code)) {
            return error;
        }
        if (const auto error =
                append_exact_length_bytes(frame_writer, application_close->reason.bytes)) {
            return error;
        }
        return std::nullopt;
    }

    // HANDSHAKE_DONE is the only remaining frame alternative.
    static_cast<void>(std::get<HandshakeDoneFrame>(frame));
    if (const auto error = append_byte(frame_writer, std::byte{0x1e})) {
        return error;
    }
    return std::nullopt;
}

template <typename T>
COQUIC_NO_PROFILE bool matches_codec_error(const CodecResult<T> &result, CodecErrorCode code,
                                           std::size_t offset) {
    const auto *error = std::get_if<CodecError>(&result.storage);
    return error != nullptr && error->code == code && error->offset == offset;
}

} // namespace

CodecResult<std::size_t> frame_wire_size(const Frame &frame) {
    CountingBufferWriter frame_writer;
    if (const auto *outbound_ack = std::get_if<OutboundAckFrame>(&frame)) {
        if (const auto error = write_outbound_ack_frame(frame_writer, *outbound_ack)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
    } else if (const auto error = serialize_frame_into_writer(frame_writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(frame_writer.offset());
}

CodecResult<std::size_t> write_frame_wire_bytes(std::span<std::byte> output, const Frame &frame) {
    SpanBufferWriter frame_writer(output);
    if (const auto *outbound_ack = std::get_if<OutboundAckFrame>(&frame)) {
        if (const auto error = write_outbound_ack_frame(frame_writer, *outbound_ack)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
    } else if (const auto error = serialize_frame_into_writer(frame_writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(frame_writer.offset());
}

CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame) {
    const auto size = frame_wire_size(frame);
    if (!size.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(size.error().code, size.error().offset);
    }

    std::vector<std::byte> bytes(size.value());
    const auto written = write_frame_wire_bytes(bytes, frame).value();
    static_cast<void>(written);
    return CodecResult<std::vector<std::byte>>::success(std::move(bytes));
}

CodecResult<std::size_t> serialized_frame_size(const Frame &frame) {
    return frame_wire_size(frame);
}

CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame) {
    const auto size = frame_wire_size(frame);
    if (!size.has_value()) {
        return CodecResult<std::size_t>::failure(size.error().code, size.error().offset);
    }
    if (output.size() < size.value()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
    }
    return write_frame_wire_bytes(output.first(size.value()), frame);
}

CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes,
                                                 const Frame &frame) {
    const auto begin = bytes.size();
    const auto size = frame_wire_size(frame);
    if (!size.has_value()) {
        return CodecResult<std::size_t>::failure(size.error().code, size.error().offset);
    }

    bytes.resize(begin + size.value());
    const auto written =
        write_frame_wire_bytes(std::span<std::byte>(bytes).subspan(begin, size.value()), frame)
            .value();

    return CodecResult<std::size_t>::success(written);
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
    if ((frame_type <= 0x1eu || frame_type == 0x30u || frame_type == 0x31u) &&
        frame_type_result.value().bytes_consumed != 1) {
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

    if (frame_type == 0x30 || frame_type == 0x31) {
        const auto frame = decode_datagram_frame(reader, frame_type);
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

CodecResult<ReceivedFrameDecodeResult> deserialize_received_frame(const SharedBytes &bytes) {
    const auto span = bytes.span();
    if (span.empty()) {
        return received_decode_failure(CodecErrorCode::truncated_input, 0);
    }

    if (span.front() == std::byte{0x00}) {
        std::size_t length = 1;
        while (length < span.size() && span[length] == std::byte{0x00}) {
            ++length;
        }
        return CodecResult<ReceivedFrameDecodeResult>::success(ReceivedFrameDecodeResult{
            .frame =
                PaddingFrame{
                    .length = length,
                },
            .bytes_consumed = length,
        });
    }

    BufferReader reader(span);
    const auto frame_type_result = decode_varint(reader);
    if (!frame_type_result.has_value()) {
        return received_decode_failure(frame_type_result.error().code,
                                       frame_type_result.error().offset);
    }

    const auto frame_type = frame_type_result.value().value;
    if ((frame_type <= 0x1eu || frame_type == 0x30u || frame_type == 0x31u) &&
        frame_type_result.value().bytes_consumed != 1) {
        return received_decode_failure(CodecErrorCode::non_shortest_frame_type_encoding, 0);
    }

    if (frame_type >= 0x08 && frame_type <= 0x0f) {
        auto frame = decode_received_stream_frame(reader, frame_type, bytes);
        if (!frame.has_value()) {
            return received_decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<ReceivedFrameDecodeResult>::success(ReceivedFrameDecodeResult{
            .frame = std::move(frame.value()),
            .bytes_consumed = reader.offset(),
        });
    }

    if (frame_type == 0x06) {
        auto frame = decode_received_crypto_frame(reader, bytes);
        if (!frame.has_value()) {
            return received_decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<ReceivedFrameDecodeResult>::success(ReceivedFrameDecodeResult{
            .frame = std::move(frame.value()),
            .bytes_consumed = reader.offset(),
        });
    }

    if (frame_type == 0x02 || frame_type == 0x03) {
        auto frame = decode_received_ack_frame(reader, frame_type == 0x03, bytes);
        if (!frame.has_value()) {
            return received_decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<ReceivedFrameDecodeResult>::success(ReceivedFrameDecodeResult{
            .frame = std::move(frame.value()),
            .bytes_consumed = reader.offset(),
        });
    }

    if (frame_type == 0x30 || frame_type == 0x31) {
        auto frame = decode_received_datagram_frame(reader, frame_type, bytes);
        if (!frame.has_value()) {
            return received_decode_failure(frame.error().code, frame.error().offset);
        }
        return CodecResult<ReceivedFrameDecodeResult>::success(ReceivedFrameDecodeResult{
            .frame = std::move(frame.value()),
            .bytes_consumed = reader.offset(),
        });
    }

    auto decoded = deserialize_frame(span);
    if (!decoded.has_value()) {
        return received_decode_failure(decoded.error().code, decoded.error().offset);
    }

    return CodecResult<ReceivedFrameDecodeResult>::success(ReceivedFrameDecodeResult{
        .frame = to_received_frame(std::move(decoded.value().frame)),
        .bytes_consumed = decoded.value().bytes_consumed,
    });
}

CodecResult<ReceivedAckFrameDecodeResult> deserialize_received_ack_frame(const SharedBytes &bytes) {
    const auto span = bytes.span();
    if (span.empty()) {
        return received_ack_decode_failure(CodecErrorCode::truncated_input, 0);
    }

    BufferReader reader(span);
    const auto frame_type_result = decode_varint(reader);
    if (!frame_type_result.has_value()) {
        return received_ack_decode_failure(frame_type_result.error().code,
                                           frame_type_result.error().offset);
    }

    const auto frame_type = frame_type_result.value().value;
    if ((frame_type <= 0x1eu || frame_type == 0x30u || frame_type == 0x31u) &&
        frame_type_result.value().bytes_consumed != 1) {
        return received_ack_decode_failure(CodecErrorCode::non_shortest_frame_type_encoding, 0);
    }
    if (frame_type != 0x02 && frame_type != 0x03) {
        return received_ack_decode_failure(CodecErrorCode::unknown_frame_type, 0);
    }

    auto frame = decode_received_ack_frame(reader, frame_type == 0x03, bytes);
    if (!frame.has_value()) {
        return received_ack_decode_failure(frame.error().code, frame.error().offset);
    }
    return CodecResult<ReceivedAckFrameDecodeResult>::success(ReceivedAckFrameDecodeResult{
        .frame = std::move(frame.value()),
        .bytes_consumed = reader.offset(),
    });
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

CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &ack) {
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return CodecResult<AckRangeCursor>::failure(CodecErrorCode::invalid_varint, 0);
    }

    auto previous_smallest = ack.largest_acknowledged - ack.first_ack_range;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return CodecResult<AckRangeCursor>::failure(CodecErrorCode::invalid_varint, 0);
        }

        const auto range_largest = previous_smallest - range.gap - 2;
        if (range_largest < range.range_length) {
            return CodecResult<AckRangeCursor>::failure(CodecErrorCode::invalid_varint, 0);
        }

        previous_smallest = range_largest - range.range_length;
    }

    return CodecResult<AckRangeCursor>::success(AckRangeCursor{
        .largest_acknowledged = ack.largest_acknowledged,
        .first_ack_range = ack.first_ack_range,
        .additional_ranges = ack.additional_ranges,
        .previous_smallest = ack.largest_acknowledged - ack.first_ack_range,
    });
}

CodecResult<AckRangeCursor> make_ack_range_cursor(const ReceivedAckFrame &ack) {
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return CodecResult<AckRangeCursor>::failure(CodecErrorCode::invalid_varint, 0);
    }

    if (!ack.additional_ranges_validated) {
        BufferReader additional_ranges_reader(ack.additional_range_bytes.span());
        if (const auto error =
                decode_ack_additional_ranges(additional_ranges_reader, ack.additional_range_count,
                                             ack.largest_acknowledged - ack.first_ack_range,
                                             [](std::uint64_t, std::uint64_t) {})) {
            return CodecResult<AckRangeCursor>::failure(error->code, error->offset);
        }
        if (additional_ranges_reader.offset() != ack.additional_range_bytes.size()) {
            return CodecResult<AckRangeCursor>::failure(CodecErrorCode::invalid_varint,
                                                        additional_ranges_reader.offset());
        }
    }

    return CodecResult<AckRangeCursor>::success(AckRangeCursor{
        .largest_acknowledged = ack.largest_acknowledged,
        .first_ack_range = ack.first_ack_range,
        .encoded_additional_ranges = ack.additional_range_bytes.span(),
        .next_encoded_offset = 0,
        .additional_range_count = ack.additional_range_count,
        .previous_smallest = ack.largest_acknowledged - ack.first_ack_range,
        .uses_encoded_additional_ranges = true,
    });
}

std::optional<AckPacketNumberRange> next_ack_range(AckRangeCursor &cursor) {
    if (cursor.first_range_pending) {
        cursor.first_range_pending = false;
        return AckPacketNumberRange{
            .smallest = cursor.previous_smallest,
            .largest = cursor.largest_acknowledged,
        };
    }

    if (cursor.uses_encoded_additional_ranges) {
        if (cursor.next_additional_index >= cursor.additional_range_count) {
            return std::nullopt;
        }

        if (cursor.next_encoded_offset >= cursor.encoded_additional_ranges.size()) {
            cursor.next_additional_index = cursor.additional_range_count;
            cursor.next_encoded_offset = cursor.encoded_additional_ranges.size();
            return std::nullopt;
        }

        BufferReader range_reader(
            cursor.encoded_additional_ranges.subspan(cursor.next_encoded_offset));
        AckRange decoded_range;
        if (const auto error = decode_ack_additional_ranges(
                range_reader, 1, cursor.previous_smallest,
                [&decoded_range](std::uint64_t decoded_gap_value, std::uint64_t decoded_length) {
                    decoded_range = AckRange{
                        .gap = decoded_gap_value,
                        .range_length = decoded_length,
                    };
                });
            error.has_value()) {
            cursor.next_additional_index = cursor.additional_range_count;
            cursor.next_encoded_offset = cursor.encoded_additional_ranges.size();
            return std::nullopt;
        }
        cursor.next_encoded_offset += range_reader.offset();
        ++cursor.next_additional_index;

        const auto range_largest = cursor.previous_smallest - decoded_range.gap - 2;
        cursor.previous_smallest = range_largest - decoded_range.range_length;
        return AckPacketNumberRange{
            .smallest = cursor.previous_smallest,
            .largest = range_largest,
        };
    }

    if (cursor.next_additional_index >= cursor.additional_ranges.size()) {
        return std::nullopt;
    }

    const auto &range = cursor.additional_ranges[cursor.next_additional_index];
    ++cursor.next_additional_index;

    if (cursor.previous_smallest < range.gap + 2) {
        cursor.next_additional_index = cursor.additional_ranges.size();
        return std::nullopt;
    }

    const auto range_largest = cursor.previous_smallest - range.gap - 2;
    if (range_largest < range.range_length) {
        cursor.next_additional_index = cursor.additional_ranges.size();
        return std::nullopt;
    }

    cursor.previous_smallest = range_largest - range.range_length;
    return AckPacketNumberRange{
        .smallest = cursor.previous_smallest,
        .largest = range_largest,
    };
}

namespace test {

COQUIC_NO_PROFILE bool matches_optional_codec_error(const std::optional<CodecError> &error,
                                                    CodecErrorCode code, std::size_t offset) {
    return error.has_value() && error->code == code && error->offset == offset;
}

COQUIC_NO_PROFILE bool span_writer_error_matches(const Frame &frame, CodecErrorCode code,
                                                 std::size_t offset) {
    std::array<std::byte, 512> output{};
    SpanBufferWriter frame_writer(output);
    return matches_optional_codec_error(serialize_frame_into_writer(frame_writer, frame), code,
                                        offset);
}

COQUIC_NO_PROFILE bool span_writer_fault_matches(const Frame &frame, FrameFaultPoint point,
                                                 std::size_t occurrence) {
    const ScopedFrameFault fault(point, occurrence);
    return span_writer_error_matches(frame, kFrameFaultError.code, kFrameFaultError.offset);
}

COQUIC_NO_PROFILE bool span_writer_succeeds(const Frame &frame) {
    std::array<std::byte, 512> output{};
    SpanBufferWriter frame_writer(output);
    return !serialize_frame_into_writer(frame_writer, frame).has_value();
}

} // namespace test

} // namespace coquic::quic

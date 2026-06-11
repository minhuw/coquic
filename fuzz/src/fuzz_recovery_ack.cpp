#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/transport/recovery.h"

namespace {

constexpr std::size_t kMaxInputSize = 4096;
constexpr std::uint64_t kMaxPacketNumber = 512;
constexpr std::size_t kMaxAckRanges = 16;
constexpr std::size_t kMaxPackets = 192;

coquic::quic::QuicCoreTimePoint fuzz_time(std::uint64_t micros) {
    return coquic::quic::QuicCoreTimePoint{} +
           std::chrono::microseconds(static_cast<std::int64_t>(micros % 30'000'000u));
}

coquic::quic::SentPacketRecord make_packet(std::uint64_t packet_number,
                                           coquic::quic::QuicCoreTimePoint sent_time,
                                           std::uint8_t flags, std::size_t bytes) {
    const bool ack_eliciting = (flags & 0x01u) != 0;
    return coquic::quic::SentPacketRecord{
        .packet_number = packet_number,
        .sent_time = sent_time,
        .congestion_send_sequence = packet_number,
        .ack_eliciting = ack_eliciting,
        .in_flight = ack_eliciting && (flags & 0x02u) == 0,
        .bytes_in_flight = ack_eliciting ? bytes : 0,
        .is_pmtu_probe = (flags & 0x04u) != 0,
        .pmtu_probe_size = (flags & 0x04u) != 0 ? bytes : 0,
    };
}

std::vector<coquic::quic::AckPacketNumberRange>
make_ack_ranges(coquic::fuzz::InputReader &reader, std::uint64_t largest_acknowledged) {
    std::vector<coquic::quic::AckPacketNumberRange> ranges;
    const auto count = 1u + reader.read_size(kMaxAckRanges);
    for (std::size_t i = 0; i < count; ++i) {
        const auto high = reader.read_u64() % (largest_acknowledged + 1u);
        const auto width = reader.read_u64() % 16u;
        const auto low = high > width ? high - width : 0;
        ranges.push_back(coquic::quic::AckPacketNumberRange{
            .smallest = low,
            .largest = high,
        });
    }
    return ranges;
}

coquic::quic::AckFrame make_ack_frame(coquic::fuzz::InputReader &reader,
                                      std::uint64_t largest_acknowledged) {
    coquic::quic::AckFrame ack{
        .largest_acknowledged = largest_acknowledged,
        .ack_delay = reader.read_u64() % 4096u,
        .first_ack_range = reader.read_u64() % (largest_acknowledged + 1u),
    };

    auto previous_smallest = largest_acknowledged >= ack.first_ack_range
                                 ? largest_acknowledged - ack.first_ack_range
                                 : 0;
    const auto count = reader.read_size(kMaxAckRanges);
    for (std::size_t i = 0; i < count && previous_smallest > 1; ++i) {
        const auto gap = reader.read_u64() % std::min<std::uint64_t>(previous_smallest, 16u);
        if (previous_smallest <= gap + 2u) {
            break;
        }
        const auto next_largest = previous_smallest - gap - 2u;
        const auto range_length =
            reader.read_u64() % std::min<std::uint64_t>(next_largest + 1u, 16u);
        ack.additional_ranges.push_back(coquic::quic::AckRange{
            .gap = gap,
            .range_length = range_length,
        });
        previous_smallest = next_largest >= range_length ? next_largest - range_length : 0;
    }

    if (reader.read_bool()) {
        ack.ecn_counts = coquic::quic::AckEcnCounts{
            .ect0 = reader.read_u64() % 1024u,
            .ect1 = reader.read_u64() % 1024u,
            .ecn_ce = reader.read_u64() % 1024u,
        };
    }
    return ack;
}

void exercise_ack_result(const coquic::quic::AckProcessingResult &result) {
    for (const auto packet : result.acked_packets) {
        coquic::fuzz::require(packet.packet_number <= kMaxPacketNumber,
                              "acked packet number outside fuzz range");
    }
    for (const auto packet : result.late_acked_packets) {
        coquic::fuzz::require(packet.packet_number <= kMaxPacketNumber,
                              "late acked packet number outside fuzz range");
    }
    for (const auto packet : result.lost_packets) {
        coquic::fuzz::require(packet.packet_number <= kMaxPacketNumber,
                              "lost packet number outside fuzz range");
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (size > kMaxInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    coquic::fuzz::InputReader reader(coquic::fuzz::byte_span(bytes));

    coquic::quic::ReceivedPacketHistory history;
    coquic::quic::PacketSpaceRecovery recovery;

    for (std::size_t step = 0; step < kMaxPackets && !reader.empty(); ++step) {
        switch (reader.read_u8() % 12u) {
        case 0: {
            const auto packet_number = reader.read_u64() % (kMaxPacketNumber + 1u);
            const bool ack_eliciting = reader.read_bool();
            const auto ecn = static_cast<coquic::quic::QuicEcnCodepoint>(reader.read_u8() % 5u);
            history.record_received(packet_number, ack_eliciting, fuzz_time(reader.read_u64()), ecn,
                                    1u + reader.read_size(8));
            break;
        }
        case 1: {
            const auto ack = history.build_outbound_ack_header(
                reader.read_u64() % 12u, fuzz_time(reader.read_u64()), reader.read_bool());
            if (ack.has_value()) {
                coquic::fuzz::require(ack->first_ack_range <= ack->largest_acknowledged,
                                      "outbound ACK first range exceeds largest acked");
            }
            if (reader.read_bool()) {
                history.on_ack_sent();
            }
            break;
        }
        case 2: {
            const auto ack = history.build_ack_frame(
                reader.read_u64() % 12u, fuzz_time(reader.read_u64()), reader.read_bool());
            if (ack.has_value()) {
                const auto cursor = coquic::quic::make_ack_range_cursor(*ack);
                if (cursor.has_value()) {
                    auto cursor_value = cursor.value();
                    bool first_range = true;
                    std::uint64_t previous_smallest = 0;
                    while (const auto range = coquic::quic::next_ack_range(cursor_value)) {
                        coquic::fuzz::require(range->smallest <= range->largest,
                                              "ACK cursor range is inverted");
                        if (first_range) {
                            coquic::fuzz::require(range->largest == ack->largest_acknowledged,
                                                  "ACK cursor first range misses largest acked");
                            first_range = false;
                        } else {
                            coquic::fuzz::require(range->largest < previous_smallest,
                                                  "ACK cursor ranges are not descending");
                        }
                        previous_smallest = range->smallest;
                    }
                }
            }
            break;
        }
        case 3: {
            history.retire_acknowledged_ranges_up_to(reader.read_u64() % (kMaxPacketNumber + 1u));
            break;
        }
        case 4: {
            const auto packet_number = reader.read_u64() % (kMaxPacketNumber + 1u);
            recovery.on_packet_sent(make_packet(packet_number, fuzz_time(reader.read_u64()),
                                                reader.read_u8(), 1u + reader.read_size(1500)));
            break;
        }
        case 5: {
            const auto packet_number = reader.read_u64() % (kMaxPacketNumber + 1u);
            recovery.on_simple_stream_packet_sent(coquic::quic::SimpleStreamSentPacketRecord{
                .packet_number = packet_number,
                .sent_time = fuzz_time(reader.read_u64()),
                .congestion_send_sequence = packet_number,
                .bytes_in_flight = 1u + reader.read_size(1500),
            });
            break;
        }
        case 6: {
            const auto largest_acknowledged = reader.read_u64() % (kMaxPacketNumber + 1u);
            const auto ranges = make_ack_ranges(reader, largest_acknowledged);
            exercise_ack_result(recovery.on_ack_received(ranges, largest_acknowledged,
                                                         fuzz_time(reader.read_u64())));
            break;
        }
        case 7: {
            const auto largest_acknowledged = reader.read_u64() % (kMaxPacketNumber + 1u);
            const auto ack = make_ack_frame(reader, largest_acknowledged);
            exercise_ack_result(recovery.on_ack_received(ack, fuzz_time(reader.read_u64())));
            break;
        }
        case 8: {
            recovery.on_packet_declared_lost(reader.read_u64() % (kMaxPacketNumber + 1u));
            break;
        }
        case 9: {
            recovery.retire_packet(reader.read_u64() % (kMaxPacketNumber + 1u));
            break;
        }
        case 10: {
            static_cast<void>(recovery.collect_time_threshold_losses(fuzz_time(reader.read_u64())));
            static_cast<void>(recovery.collect_pmtu_probe_timeouts(fuzz_time(reader.read_u64())));
            static_cast<void>(recovery.latest_in_flight_ack_eliciting_packet());
            static_cast<void>(recovery.earliest_loss_packet());
            break;
        }
        default: {
            auto &rtt = recovery.rtt_state();
            rtt.latest_rtt =
                std::chrono::microseconds(1 + static_cast<int>(reader.read_u64() % 500000u));
            rtt.min_rtt =
                std::chrono::microseconds(1 + static_cast<int>(reader.read_u64() % 500000u));
            rtt.smoothed_rtt =
                std::chrono::microseconds(1 + static_cast<int>(reader.read_u64() % 500000u));
            static_cast<void>(coquic::quic::compute_pto_deadline(
                rtt, std::chrono::microseconds(reader.read_u64() % 50000u),
                fuzz_time(reader.read_u64()), static_cast<std::uint32_t>(reader.read_u8() % 8u)));
            break;
        }
        }

        coquic::fuzz::require(recovery.tracked_packet_count() <= kMaxPacketNumber + 1u,
                              "recovery tracked too many packet numbers");
    }

    return 0;
}

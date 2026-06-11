#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/transport/congestion.h"

namespace {

constexpr std::size_t kMaxInputSize = 4096;
constexpr std::size_t kMaxBatchSize = 8;

coquic::quic::QuicCoreTimePoint fuzz_time(std::uint64_t micros) {
    return coquic::quic::QuicCoreTimePoint{} +
           std::chrono::microseconds(static_cast<std::int64_t>(micros % 30'000'000u));
}

coquic::quic::QuicCongestionControlAlgorithm algorithm_from(std::uint8_t value) {
    switch (value % 4u) {
    case 1:
        return coquic::quic::QuicCongestionControlAlgorithm::cubic;
    case 2:
        return coquic::quic::QuicCongestionControlAlgorithm::bbr;
    case 3:
        return coquic::quic::QuicCongestionControlAlgorithm::copa;
    default:
        return coquic::quic::QuicCongestionControlAlgorithm::newreno;
    }
}

coquic::quic::RecoveryRttState rtt_from(coquic::fuzz::InputReader &reader) {
    const auto latest =
        std::chrono::microseconds(1 + static_cast<int>(reader.read_u64() % 500000u));
    const auto min = std::chrono::microseconds(1 + static_cast<int>(reader.read_u64() % 500000u));
    return coquic::quic::RecoveryRttState{
        .latest_rtt = latest,
        .latest_adjusted_rtt = latest,
        .min_rtt = min,
        .latest_rtt_sample = latest,
        .latest_adjusted_rtt_sample = latest,
        .latest_ack_delay_compensated_rtt_sample = latest,
        .min_rtt_sample = min,
        .smoothed_rtt = latest,
        .rttvar = std::chrono::microseconds(1 + static_cast<int>(reader.read_u64() % 100000u)),
    };
}

coquic::quic::SentPacketRecord make_packet(coquic::fuzz::InputReader &reader,
                                           std::uint64_t packet_number) {
    const auto bytes = 1u + reader.read_size(4096);
    return coquic::quic::SentPacketRecord{
        .packet_number = packet_number,
        .sent_time = fuzz_time(reader.read_u64()),
        .congestion_send_sequence = packet_number,
        .ack_eliciting = reader.read_bool(),
        .in_flight = reader.read_bool(),
        .bytes_in_flight = bytes,
        .delivered = reader.read_u64() % (1u << 20u),
        .delivered_time = fuzz_time(reader.read_u64()),
        .first_sent_time = fuzz_time(reader.read_u64()),
        .tx_in_flight = reader.read_size(1u << 20u),
        .lost = reader.read_u64() % (1u << 20u),
        .app_limited = reader.read_bool(),
    };
}

std::vector<coquic::quic::SentPacketRecord> make_packet_batch(coquic::fuzz::InputReader &reader,
                                                              std::uint64_t &next_packet_number) {
    std::vector<coquic::quic::SentPacketRecord> packets;
    const auto count = 1u + reader.read_size(kMaxBatchSize);
    packets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        packets.push_back(make_packet(reader, next_packet_number++));
    }
    return packets;
}

std::vector<coquic::quic::AckedStreamPacketSample>
make_stream_ack_batch(coquic::fuzz::InputReader &reader, std::uint64_t &next_packet_number) {
    std::vector<coquic::quic::AckedStreamPacketSample> packets;
    const auto count = 1u + reader.read_size(kMaxBatchSize);
    packets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        packets.push_back(coquic::quic::AckedStreamPacketSample{
            .packet_number = next_packet_number++,
            .sent_time = fuzz_time(reader.read_u64()),
            .congestion_send_sequence = next_packet_number,
            .bytes_in_flight = 1u + reader.read_size(4096),
            .delivered = reader.read_u64() % (1u << 20u),
            .delivered_time = fuzz_time(reader.read_u64()),
            .first_sent_time = fuzz_time(reader.read_u64()),
            .tx_in_flight = reader.read_size(1u << 20u),
            .lost = reader.read_u64() % (1u << 20u),
            .app_limited = reader.read_bool(),
        });
    }
    return packets;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (size > kMaxInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    coquic::fuzz::InputReader reader(coquic::fuzz::byte_span(bytes));

    const auto algorithm = algorithm_from(reader.read_u8());
    const auto max_datagram_size = 1u + reader.read_size(4096);
    coquic::quic::QuicCongestionController controller(algorithm, max_datagram_size,
                                                      reader.read_bool());
    std::uint64_t next_packet_number = 0;

    for (std::size_t step = 0; step < 128 && !reader.empty(); ++step) {
        switch (reader.read_u8() % 11u) {
        case 0: {
            auto packet = make_packet(reader, next_packet_number++);
            controller.on_packet_sent(packet);
            break;
        }
        case 1: {
            controller.on_packet_sent(1u + reader.read_size(4096), reader.read_bool());
            break;
        }
        case 2: {
            const auto packets = make_packet_batch(reader, next_packet_number);
            controller.on_packets_acked(packets, reader.read_bool(), fuzz_time(reader.read_u64()),
                                        rtt_from(reader));
            break;
        }
        case 3: {
            const auto packets = make_stream_ack_batch(reader, next_packet_number);
            controller.on_simple_stream_packets_acked(
                packets, reader.read_bool(), fuzz_time(reader.read_u64()), rtt_from(reader));
            break;
        }
        case 4: {
            const auto aggregate = coquic::quic::AckedStreamPacketAggregate{
                .packet_count = 1u + reader.read_size(kMaxBatchSize),
                .bytes_in_flight = 1u + reader.read_size(4096 * kMaxBatchSize),
                .largest_packet_number = next_packet_number++,
                .earliest_sent_time = fuzz_time(reader.read_u64()),
                .latest_sent_time = fuzz_time(reader.read_u64()),
                .smallest_congestion_send_sequence = reader.read_u64() % 4096u,
                .largest_congestion_send_sequence = reader.read_u64() % 4096u,
            };
            controller.on_simple_stream_packets_acked(
                aggregate, reader.read_bool(), fuzz_time(reader.read_u64()), rtt_from(reader));
            break;
        }
        case 5: {
            const auto packets = make_packet_batch(reader, next_packet_number);
            controller.on_packets_lost(packets);
            break;
        }
        case 6: {
            const auto packets = make_packet_batch(reader, next_packet_number);
            controller.on_packets_discarded(packets);
            break;
        }
        case 7:
            controller.on_loss_event(fuzz_time(reader.read_u64()), fuzz_time(reader.read_u64()));
            break;
        case 8:
            controller.on_persistent_congestion();
            break;
        case 9:
            controller.reset_for_new_path();
            break;
        default:
            static_cast<void>(controller.can_send_ack_eliciting(1u + reader.read_size(4096)));
            static_cast<void>(controller.next_send_time(1u + reader.read_size(4096)));
            static_cast<void>(controller.pacing_send_quantum());
            static_cast<void>(controller.send_window());
            static_cast<void>(controller.minimum_window());
            static_cast<void>(
                controller.would_underutilize_congestion_window(1u + reader.read_size(4096)));
            break;
        }

        const auto metrics = controller.debug_metrics(fuzz_time(reader.read_u64()));
        coquic::fuzz::require(controller.congestion_window() > 0, "congestion window is zero");
        coquic::fuzz::require(controller.minimum_window() > 0, "minimum congestion window is zero");
        coquic::fuzz::require(metrics.send_quantum > 0, "congestion send quantum is zero");
    }

    return 0;
}

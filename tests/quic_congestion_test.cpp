#include <array>

#include <gtest/gtest.h>

#include "src/quic/congestion.h"

namespace {

TEST(QuicCongestionTest, UsesRfcInitialWindow) {
    coquic::quic::NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, SlowStartGrowthMatchesAcknowledgedBytes) {
    coquic::quic::NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    controller.on_packets_acked(
        std::array<coquic::quic::SentPacketRecord, 1>{
            coquic::quic::SentPacketRecord{
                .packet_number = 0,
                .ack_eliciting = true,
                .in_flight = true,
                .bytes_in_flight = 1200,
            },
        },
        /*app_limited=*/false);

    EXPECT_GT(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, PersistentCongestionCollapsesToMinimumWindow) {
    coquic::quic::NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_persistent_congestion();
    EXPECT_EQ(controller.congestion_window(), 2400u);
}

} // namespace

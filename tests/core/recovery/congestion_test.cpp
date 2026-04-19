#include <array>
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

#include "src/quic/congestion.h"
#include "tests/support/quic_test_utils.h"

namespace {

using coquic::quic::NewRenoCongestionController;
using coquic::quic::SentPacketRecord;

SentPacketRecord make_sent_packet(std::uint64_t packet_number, bool ack_eliciting, bool in_flight,
                                  std::size_t bytes_in_flight,
                                  coquic::quic::QuicCoreTimePoint sent_time) {
    return SentPacketRecord{
        .packet_number = packet_number,
        .sent_time = sent_time,
        .ack_eliciting = ack_eliciting,
        .in_flight = in_flight,
        .bytes_in_flight = bytes_in_flight,
    };
}

TEST(QuicCongestionTest, UsesRfcInitialWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, SlowStartGrowthMatchesAcknowledgedBytes) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{
            make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0)),
        },
        /*app_limited=*/false);

    EXPECT_GT(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, PersistentCongestionCollapsesToMinimumWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_persistent_congestion();
    EXPECT_EQ(controller.congestion_window(), 2400u);
}

TEST(QuicCongestionTest, AppLimitedAckSaturatesBytesInFlightWithoutGrowingWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);

    controller.on_packets_acked(
        std::array<SentPacketRecord, 2>{
            make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/false,
                             /*bytes_in_flight=*/0, coquic::quic::test::test_time(0)),
            make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/2400, coquic::quic::test::test_time(1)),
        },
        /*app_limited=*/true);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, RecoveryAckTransitionsToCongestionAvoidance) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/6000, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(1), coquic::quic::test::test_time(1));
    ASSERT_EQ(controller.congestion_window(), 6000u);

    controller.on_packet_sent(/*bytes_sent=*/6000, /*ack_eliciting=*/true);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{
            make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/6000, coquic::quic::test::test_time(2)),
        },
        /*app_limited=*/false);

    EXPECT_EQ(controller.congestion_window(), 7200u);
    EXPECT_EQ(controller.bytes_in_flight(), 6000u);
}

TEST(QuicCongestionTest, AckBatchOrderDoesNotChangeRecoveryExit) {
    NewRenoCongestionController ascending(/*max_datagram_size=*/1200);
    NewRenoCongestionController descending(/*max_datagram_size=*/1200);

    for (auto *controller : {&ascending, &descending}) {
        controller->on_packet_sent(/*bytes_sent=*/18000, /*ack_eliciting=*/true);
        controller->on_loss_event(coquic::quic::test::test_time(5),
                                  coquic::quic::test::test_time(1));
        ASSERT_EQ(controller->congestion_window(), 6000u);
        controller->on_packet_sent(/*bytes_sent=*/6000, /*ack_eliciting=*/true);
    }

    const std::array<SentPacketRecord, 3> ascending_packets{
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(1)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(2)),
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(6)),
    };
    const std::array<SentPacketRecord, 3> descending_packets{
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(6)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(2)),
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(1)),
    };

    ascending.on_packets_acked(ascending_packets, /*app_limited=*/false);
    descending.on_packets_acked(descending_packets, /*app_limited=*/false);

    EXPECT_EQ(ascending.congestion_window(), descending.congestion_window());
    EXPECT_EQ(ascending.bytes_in_flight(), descending.bytes_in_flight());
    EXPECT_EQ(ascending.congestion_window(), 7200u);
    EXPECT_EQ(ascending.bytes_in_flight(), 6000u);

    const std::array<SentPacketRecord, 1> post_batch_packet{
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/7200, coquic::quic::test::test_time(5)),
    };

    ascending.on_packets_acked(post_batch_packet, /*app_limited=*/false);
    descending.on_packets_acked(post_batch_packet, /*app_limited=*/false);

    EXPECT_EQ(ascending.congestion_window(), descending.congestion_window());
    EXPECT_EQ(ascending.bytes_in_flight(), descending.bytes_in_flight());
    EXPECT_EQ(ascending.congestion_window(), 8400u);
    EXPECT_EQ(ascending.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, LossAccountingIgnoresNonInflightPacketsAndSaturatesToZero) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);

    controller.on_packets_lost(std::array<SentPacketRecord, 2>{
        make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/false, /*in_flight=*/false,
                         /*bytes_in_flight=*/0, coquic::quic::test::test_time(0)),
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/2400, coquic::quic::test::test_time(1)),
    });

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, LossEventDoesNotReduceWindowTwiceWithinRecoveryEpoch) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    const auto first_reduction = controller.congestion_window();

    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    controller.on_loss_event(coquic::quic::test::test_time(4), coquic::quic::test::test_time(1));

    EXPECT_EQ(controller.congestion_window(), first_reduction);
}

TEST(QuicCongestionTest, LaterLossEventStartsANewRecoveryEpoch) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/12000, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    const auto first_reduction = controller.congestion_window();

    controller.on_packet_sent(/*bytes_sent=*/first_reduction, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(6), coquic::quic::test::test_time(6));

    EXPECT_LT(controller.congestion_window(), first_reduction);
    EXPECT_EQ(controller.congestion_window(), 3000u);
}

} // namespace

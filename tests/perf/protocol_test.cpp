#include <gtest/gtest.h>

#include "src/perf/perf_protocol.h"

namespace {
using namespace coquic::perf;

TEST(QuicPerfProtocolTest, RoundTripsSessionStartFrame) {
    const QuicPerfSessionStart start{
        .protocol_version = kQuicPerfProtocolVersion,
        .mode = QuicPerfMode::rr,
        .direction = QuicPerfDirection::download,
        .request_bytes = 64,
        .response_bytes = 96,
        .total_bytes = std::nullopt,
        .requests = 1000,
        .warmup_ms = 250,
        .duration_ms = 5000,
        .streams = 1,
        .connections = 1,
        .requests_in_flight = 4,
    };

    const auto bytes = encode_perf_control_message(QuicPerfControlMessage{start});
    const auto decoded = decode_perf_control_message(bytes);

    ASSERT_TRUE(decoded.has_value());
    const auto decoded_value = decoded.value_or(QuicPerfControlMessage{QuicPerfSessionReady{}});
    const auto *decoded_start = std::get_if<QuicPerfSessionStart>(&decoded_value);
    ASSERT_NE(decoded_start, nullptr);
    EXPECT_EQ(decoded_start->mode, QuicPerfMode::rr);
    EXPECT_EQ(decoded_start->request_bytes, 64u);
    EXPECT_EQ(decoded_start->requests, std::optional<std::uint64_t>{1000u});
    EXPECT_EQ(decoded_start->requests_in_flight, 4u);
}

TEST(QuicPerfProtocolTest, RejectsUnknownMessageTypeAndTruncatedPayload) {
    const std::vector<std::byte> unknown_type = {
        std::byte{0x7f}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    const std::vector<std::byte> truncated = {
        std::byte{0x7f}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x08},
    };

    EXPECT_FALSE(decode_perf_control_message(unknown_type).has_value());
    EXPECT_FALSE(decode_perf_control_message(truncated).has_value());
}
} // namespace

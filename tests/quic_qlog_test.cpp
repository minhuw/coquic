#include <array>
#include <optional>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/frame.h"
#include "src/quic/qlog/json.h"
#include "src/quic/qlog/session.h"
#include "src/quic/qlog/sink.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::qlog::FilePreamble;
using coquic::quic::qlog::QlogFileSeqSink;

std::vector<std::byte> qlog_bytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

TEST(QuicQlogTest, SerializesSequentialPreambleWithDraftQuicSchema) {
    const auto preamble = coquic::quic::qlog::serialize_file_seq_preamble(FilePreamble{
        .title = "coquic qlog",
        .description = "client trace",
        .group_id = "8394c8f03e515708",
        .vantage_point_type = "client",
        .event_schemas = {"urn:ietf:params:qlog:events:quic-12"},
    });

    EXPECT_NE(preamble.find("\"file_schema\":\"urn:ietf:params:qlog:file:sequential\""),
              std::string::npos);
    EXPECT_NE(preamble.find("\"serialization_format\":\"application/qlog+json-seq\""),
              std::string::npos);
    EXPECT_NE(preamble.find("\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-12\"]"),
              std::string::npos);
    EXPECT_NE(preamble.find("\"group_id\":\"8394c8f03e515708\""), std::string::npos);
    EXPECT_NE(preamble.find("\"type\":\"client\""), std::string::npos);
}

TEST(QuicQlogTest, EscapesJsonStringsAndFramesJsonSeqRecords) {
    EXPECT_EQ(coquic::quic::qlog::escape_json_string("a\"b\\c\n"), "a\\\"b\\\\c\\n");

    const auto record = coquic::quic::qlog::make_json_seq_record("{\"time\":1}");
    ASSERT_FALSE(record.empty());
    EXPECT_EQ(record.front(), '\x1e');
    EXPECT_EQ(record.back(), '\n');
    EXPECT_NE(record.find("{\"time\":1}"), std::string::npos);
}

TEST(QuicQlogTest, SinkDisablesAfterAppendFailure) {
    QlogFileSeqSink sink(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(sink.open());
    EXPECT_FALSE(sink.write_record("\x1e{\"time\":0}\n"));
    EXPECT_FALSE(sink.healthy());
}

TEST(QuicQlogTest, SessionInjectedSinkCoversPreambleFailureAndIdempotentFlags) {
    using coquic::quic::EndpointRole;
    using coquic::quic::qlog::Session;

    auto failing_sink = std::make_unique<QlogFileSeqSink>(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(failing_sink->open());
    EXPECT_EQ(Session::try_open_with_sink_for_test(std::move(failing_sink), EndpointRole::client,
                                                   qlog_bytes({0x83, 0x94, 0xc8, 0xf0}),
                                                   coquic::quic::test::test_time(0)),
              nullptr);

    coquic::quic::test::ScopedTempDir dir;
    auto healthy_sink = std::make_unique<QlogFileSeqSink>(dir.path() / "session.sqlog");
    ASSERT_TRUE(healthy_sink->open());
    auto session = Session::try_open_with_sink_for_test(
        std::move(healthy_sink), EndpointRole::server, qlog_bytes({0x01, 0x02, 0x03, 0x04}),
        coquic::quic::test::test_time(10));
    ASSERT_NE(session, nullptr);

    EXPECT_TRUE(session->mark_local_version_information_emitted());
    EXPECT_FALSE(session->mark_local_version_information_emitted());
    EXPECT_TRUE(session->mark_local_alpn_information_emitted());
    EXPECT_FALSE(session->mark_local_alpn_information_emitted());
    EXPECT_TRUE(session->mark_local_parameters_set_emitted());
    EXPECT_FALSE(session->mark_local_parameters_set_emitted());
    EXPECT_TRUE(session->mark_remote_parameters_set_emitted());
    EXPECT_FALSE(session->mark_remote_parameters_set_emitted());
}

TEST(QuicQlogTest, SerializersCoverRemainingFramesAndOptionalFields) {
    using coquic::quic::AckFrame;
    using coquic::quic::ApplicationConnectionCloseFrame;
    using coquic::quic::ConnectionId;
    using coquic::quic::CryptoFrame;
    using coquic::quic::DataBlockedFrame;
    using coquic::quic::EndpointRole;
    using coquic::quic::Frame;
    using coquic::quic::HandshakeDoneFrame;
    using coquic::quic::MaxDataFrame;
    using coquic::quic::MaxStreamDataFrame;
    using coquic::quic::MaxStreamsFrame;
    using coquic::quic::NewConnectionIdFrame;
    using coquic::quic::NewTokenFrame;
    using coquic::quic::PathChallengeFrame;
    using coquic::quic::PathResponseFrame;
    using coquic::quic::ResetStreamFrame;
    using coquic::quic::RetireConnectionIdFrame;
    using coquic::quic::StopSendingFrame;
    using coquic::quic::StreamDataBlockedFrame;
    using coquic::quic::StreamLimitType;
    using coquic::quic::StreamsBlockedFrame;
    using coquic::quic::TransportConnectionCloseFrame;
    using coquic::quic::qlog::PacketHeader;
    using coquic::quic::qlog::PacketSnapshot;
    using coquic::quic::qlog::RecoveryMetricsSnapshot;

    const auto snapshot = PacketSnapshot{
        .header =
            PacketHeader{
                .packet_type = "1RTT",
                .packet_number_length = 2,
                .packet_number = 7,
                .version = 1,
                .length = 42,
                .spin_bit = true,
                .key_phase = 1,
                .scid = ConnectionId(qlog_bytes({0x01, 0x02})),
                .dcid = ConnectionId(qlog_bytes({0x03, 0x04})),
                .token = qlog_bytes({0xaa, 0xbb}),
            },
        .frames =
            std::vector<Frame>{
                ResetStreamFrame{
                    .stream_id = 1, .application_protocol_error_code = 2, .final_size = 3},
                StopSendingFrame{.stream_id = 4, .application_protocol_error_code = 5},
                CryptoFrame{.offset = 6, .crypto_data = qlog_bytes({0xcc, 0xdd})},
                NewTokenFrame{.token = qlog_bytes({0xee})},
                MaxDataFrame{.maximum_data = 7},
                MaxStreamDataFrame{.stream_id = 8, .maximum_stream_data = 9},
                MaxStreamsFrame{.stream_type = StreamLimitType::unidirectional,
                                .maximum_streams = 10},
                DataBlockedFrame{.maximum_data = 11},
                StreamDataBlockedFrame{.stream_id = 12, .maximum_stream_data = 13},
                StreamsBlockedFrame{.stream_type = StreamLimitType::unidirectional,
                                    .maximum_streams = 14},
                NewConnectionIdFrame{
                    .sequence_number = 15,
                    .retire_prior_to = 1,
                    .connection_id = qlog_bytes({0xab, 0xcd}),
                    .stateless_reset_token = {},
                },
                RetireConnectionIdFrame{.sequence_number = 16},
                PathChallengeFrame{.data = {std::byte{0}, std::byte{1}, std::byte{2}, std::byte{3},
                                            std::byte{4}, std::byte{5}, std::byte{6},
                                            std::byte{7}}},
                PathResponseFrame{.data = {std::byte{7}, std::byte{6}, std::byte{5}, std::byte{4},
                                           std::byte{3}, std::byte{2}, std::byte{1}, std::byte{0}}},
                TransportConnectionCloseFrame{.error_code = 17, .frame_type = 18},
                ApplicationConnectionCloseFrame{.error_code = 19},
                HandshakeDoneFrame{},
                AckFrame{.largest_acknowledged = 20, .ack_delay = 21},
            },
        .raw_length = 1200,
        .datagram_id = 77,
        .trigger = std::string("pto_probe"),
    };
    const auto snapshot_json = coquic::quic::qlog::serialize_packet_snapshot(snapshot);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"reset_stream\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"stop_sending\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"crypto\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"new_token\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"max_data\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"max_stream_data\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"max_streams\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"data_blocked\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"stream_data_blocked\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"streams_blocked\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"new_connection_id\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"retire_connection_id\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"path_challenge\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"path_response\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"connection_close_transport\""),
              std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"connection_close_application\""),
              std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"handshake_done\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"ack\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"largest_acknowledged\":20"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"ack_delay\":21"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"sequence_number\":15"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"retire_prior_to\":1"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"connection_id\":\"abcd\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"path_challenge\",\"data\":\"0001020304050607\""),
              std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"path_response\",\"data\":\"0706050403020100\""),
              std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type\":\"connection_close_transport\",\"error_code\":17"),
              std::string::npos);
    EXPECT_NE(snapshot_json.find("\"frame_type_value\":18"), std::string::npos);
    EXPECT_NE(
        snapshot_json.find("\"frame_type\":\"connection_close_application\",\"error_code\":19"),
        std::string::npos);
    EXPECT_NE(snapshot_json.find("\"spin_bit\":true"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"key_phase\":1"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"scid\":\"0102\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"dcid\":\"0304\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"token\":\"aabb\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"datagram_id\":77"), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"trigger\":\"pto_probe\""), std::string::npos);

    const auto binary_alpn = std::vector<std::byte>{std::byte{0x00}, std::byte{0xff}};
    const auto printable_alpn = qlog_bytes({0x63, 0x6f, 0x71, 0x75, 0x69, 0x63});
    const std::array local_alpns{binary_alpn};
    const std::array peer_alpns{printable_alpn};
    const auto binary_only_alpn_json = coquic::quic::qlog::serialize_alpn_information(
        std::span(local_alpns), std::nullopt, std::span(binary_alpn), EndpointRole::client);
    EXPECT_EQ(binary_only_alpn_json.find("\"string_value\""), std::string::npos);

    const auto alpn_json = coquic::quic::qlog::serialize_alpn_information(
        std::span(local_alpns), std::span(peer_alpns), std::span(binary_alpn),
        EndpointRole::client);
    EXPECT_NE(alpn_json.find("\"client_alpns\""), std::string::npos);
    EXPECT_NE(alpn_json.find("\"server_alpns\""), std::string::npos);
    EXPECT_NE(alpn_json.find("\"chosen_alpn\""), std::string::npos);

    EXPECT_EQ(coquic::quic::qlog::escape_json_string("a\r\t"), "a\\r\\t");
    const std::array<std::uint32_t, 2> versions{1, 2};
    EXPECT_EQ(coquic::quic::qlog::serialize_version_information(EndpointRole::server, versions,
                                                                std::nullopt),
              "{\"server_versions\":[1,2]}");

    EXPECT_EQ(coquic::quic::qlog::serialize_recovery_metrics(RecoveryMetricsSnapshot{}), "{}");
    const auto metrics_json =
        coquic::quic::qlog::serialize_recovery_metrics(RecoveryMetricsSnapshot{
            .min_rtt_ms = 1.5,
            .smoothed_rtt_ms = 2.5,
            .latest_rtt_ms = 3.5,
            .rtt_variance_ms = 4.5,
            .pto_count = 2,
            .congestion_window = 4096,
            .bytes_in_flight = 512,
        });
    EXPECT_NE(metrics_json.find("\"min_rtt\":1.500000"), std::string::npos);
    EXPECT_NE(metrics_json.find("\"bytes_in_flight\":512"), std::string::npos);
}

TEST(QuicQlogTest, SinkPathAndDisabledWritesRemainObservable) {
    coquic::quic::test::ScopedTempDir dir;
    QlogFileSeqSink sink(dir.path() / "trace.sqlog");
    ASSERT_TRUE(sink.open());
    EXPECT_EQ(sink.path(), dir.path() / "trace.sqlog");
    EXPECT_TRUE(sink.write_record("\x1e{\"time\":0}\n"));

    QlogFileSeqSink full_sink(std::filesystem::path("/dev/full"));
    ASSERT_TRUE(full_sink.open());
    EXPECT_FALSE(full_sink.write_record("\x1e{\"time\":1}\n"));
    EXPECT_FALSE(full_sink.write_record("\x1e{\"time\":2}\n"));
}

} // namespace

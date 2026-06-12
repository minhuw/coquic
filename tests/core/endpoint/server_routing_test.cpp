#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <ranges>
#include <string_view>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

std::vector<std::byte> make_synthetic_zero_rtt_datagram(
    coquic::quic::ConnectionId destination_connection_id,
    coquic::quic::ConnectionId source_connection_id = {std::byte{0x82}, std::byte{0x5f},
                                                       std::byte{0xf1}, std::byte{0x6a},
                                                       std::byte{0x7a}, std::byte{0x5d},
                                                       std::byte{0x8b}, std::byte{0x9f}},
    std::uint32_t version = coquic::quic::kQuicVersion1, std::size_t payload_size = 8) {
    const auto packet_type = version == coquic::quic::kQuicVersion2 ? 0x02u : 0x01u;
    std::vector<std::byte> datagram{
        static_cast<std::byte>(0xc1u | (packet_type << 4u)),
        static_cast<std::byte>((version >> 24) & 0xffu),
        static_cast<std::byte>((version >> 16) & 0xffu),
        static_cast<std::byte>((version >> 8) & 0xffu),
        static_cast<std::byte>(version & 0xffu),
        static_cast<std::byte>(destination_connection_id.size()),
    };
    datagram.insert(datagram.end(), destination_connection_id.begin(),
                    destination_connection_id.end());
    datagram.push_back(static_cast<std::byte>(source_connection_id.size()));
    datagram.insert(datagram.end(), source_connection_id.begin(), source_connection_id.end());
    datagram.push_back(std::byte{0x40});
    datagram.push_back(static_cast<std::byte>(payload_size));
    datagram.resize(datagram.size() + payload_size, std::byte{0xaa});
    return datagram;
}

coquic::quic::QuicCoreEndpointConfig make_server_endpoint_config_with_orphan_zero_rtt_buffer(
    std::size_t max_packets = 4, std::size_t max_bytes = 4096,
    coquic::quic::QuicCoreDuration max_age = std::chrono::milliseconds(250)) {
    auto config = make_server_endpoint_config();
    config.application_protocol = "coquic";
    config.zero_rtt.allow = true;
    config.zero_rtt.application_context = {std::byte{0x10}};
    config.orphan_zero_rtt_buffer = coquic::quic::QuicOrphanZeroRttBufferConfig{
        .max_packets = max_packets,
        .max_bytes = max_bytes,
        .max_age = max_age,
    };
    return config;
}

coquic::quic::QuicResumptionState make_resumption_state_for_endpoint_zero_rtt() {
    auto warmup_client_config = coquic::quic::test::make_client_core_config();
    auto warmup_server_config = coquic::quic::test::make_server_core_config();
    warmup_client_config.zero_rtt.application_context = {std::byte{0x10}};
    warmup_server_config.zero_rtt.allow = true;
    warmup_server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore warmup_client(std::move(warmup_client_config));
    coquic::quic::QuicCore warmup_server(std::move(warmup_server_config));
    const auto transcript = coquic::quic::test::drive_quic_handshake_with_results(
        warmup_client, warmup_server, coquic::quic::test::test_time());
    auto state = coquic::quic::test::last_resumption_state_from(transcript.client_results);
    if (!state.has_value()) {
        std::abort();
    }
    return *state;
}

struct ResumedZeroRttDatagrams {
    std::vector<std::byte> initial;
    std::vector<std::byte> zero_rtt;
};

ResumedZeroRttDatagrams make_resumed_initial_and_zero_rtt_datagrams(
    const coquic::quic::QuicResumptionState &resumption_state, std::string_view early_data) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.resumption_state = resumption_state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    if (initial_datagrams.empty()) {
        std::abort();
    }

    const auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string(early_data),
            .fin = true,
        },
        coquic::quic::test::test_time(101));
    const auto zero_rtt_datagrams = coquic::quic::test::send_datagrams_from(send);
    if (zero_rtt_datagrams.empty()) {
        std::abort();
    }
    return ResumedZeroRttDatagrams{
        .initial = initial_datagrams.front(),
        .zero_rtt = zero_rtt_datagrams.front(),
    };
}

std::vector<std::byte> captured_picoquic_client_initial_datagram() {
    return bytes_from_hex(
        "ce00000001085398e92f19c3659808825ff16a7a5d8b9f0041409c471d3fbfe46c43389ad82ab17702dc"
        "9686e7157b4dcceaeecc13f61aef037f58b15e94c06417a351f30d50cf1152098bb49ce2b69c3ba80bd5"
        "cb9e1086f9a7f6d2f854b5b5638b23486d23ad1651202d87997ba51cb9f7a14d20bb430b4e6b5e25b940"
        "16b0d7ad981ae8e883a49a461444a531929c5d24044b6964cfeb5b2132e0053a434ecdd0ea2ae8adb8ca"
        "274e2ee7e6d680ea6d4756e4c37268970177613d2f31b6db1cb0799bb2f506830c96de55b72228253a6c"
        "f4d0f3512e5d93b7d8cb262a471ca0ec44eba3ceadd500870849b5cf00782bbb38188c49c95b776c97ae"
        "0fecd918f499525b6b9a61d900fb43844de41cc805abbef8c99b5727003a094b22955c2e582a45057521"
        "9cac4d4b3c51be3a436bae6e032b619c5773547abebf9f63ad9ab519f19c6813411b76e9b040d48c9d94"
        "ef16dd17aaca9bf3cd862e27007aec392281967ec218de253c37c2bc45aec40570b5c1aad297b56e3fcf"
        "aaea35a0bc7c53de7e3d5fe4a7786a02a205421d5aa9a40a4dfcc7df3415d42a96256ed422dfdeda4322"
        "8c84f714b0f312521fd34edb356fd1fc12a5c49e6b77e16cf6198a29e196a0d7afe26a8fb46ecd1215f1"
        "7125619b579e9b13e0a982faaa42605f50f992140560e3011a64248df0a6a7ac87a4b500c70206618c8c"
        "1df51145aebd76773470ca88b8cb2fb2f47bfbeb92736837d9d94dfcc7df3415d42ab2fb517033e41d7e"
        "49f54b4fddd99742ea55c6f02aea1cd3e8e4327f860d7c18c6c455b78b0f5245e98165442b45d00b4272"
        "ca77bae3d14f7e3b68f2a426ef3429eca95eb24cd1ba7c55c7ff46bae3f2614ede6e8b679bde2d52f465"
        "ab4ee9d6a72efd6b9974c9a8cad66100d27e107a7bc695cfb229120dcd21c583eae090e5164faff7db96"
        "1e139012e71c657a89b5b9770e24bbcce8b5f7f9c2a9c0146cbf1512d156bbd182301c01a7eb252a0133"
        "83bcd866859e51ff2e4322839f64f0d0357213b2d610f696fe1bc3b48fa3ad8fd349e1426c6d6c6fec01"
        "acd9304cba80bcfd4bde751f4c76cabd262fee0c15bbfbfccd0c7a547857cd813a4977f6befab20399e8"
        "62e65c0eb81f95e27387f233ef0c82823c62f61da922b268caa09bc585ee26a645b56f735231bf8ca7fe"
        "3f65387fa669c229e7f4ac0115d6da7a5ab3c84c9633a67d8b00bcae2898b8203d9d7d7e04664bc2a782"
        "672ac79f3f8de8bd3cd89730557b0a94ae103b715f221a4713cf04b42b0dd948e9089cedaf267bbbcb40"
        "e06180aa90932ede76825f3e6d6badc2542cc8746986368ce3038a36782c60cf8da7279859cbd92033d6"
        "294238f2fa3a780f5141350c9994ac0ce4814653a4d8acad56eeeeb857cf6e97a5e4542f5e3e56f9f06b"
        "0b351a0cc6bb2a7ed3af43fd69e576e20bf4fb578b83bebb79c984c3f167bb065c745cb0d6e1e83cb620"
        "e9427e6352d431fe3c0fe6a8507155c6c6117cdea8048b6637546140320447dc4b4ce533bde22778023a"
        "6e94413981afd021b3d3d6e34cc91786e95414083731cf1e8efb8e6497734a67021d7e3174391d616388"
        "da325bd70449c0f3f823f1da82c67add7701068e673ef0dba9d912082ffde7aefba917324ace49e22202"
        "fe73854a4d994a2c60696815a474a2510bca2bdec845fe96333be55b5d59e068223510494d812491b7ff"
        "cbb9abb1db0b1dbec9b72a644bf39ef778a68cec4d70120c56d9b3fa7eea849e980f");
}

TEST(QuicCoreEndpointTest, SupportedInitialIsAcceptedInsideCore) {
    coquic::quic::QuicCore core(make_server_endpoint_config());

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = captured_picoquic_client_initial_datagram(),
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1));

    const auto lifecycle = lifecycle_events_from(result);
    ASSERT_FALSE(lifecycle.empty());
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::accepted);

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    EXPECT_EQ(sends.front().connection, lifecycle.front().connection);
    ASSERT_TRUE(sends.front().route_handle.has_value());
    EXPECT_EQ(sends.front().route_handle.value_or(0), 31u);
}

TEST(QuicCoreEndpointTest, RepeatedSupportedInitialReusesAcceptedHandle) {
    coquic::quic::QuicCore core(make_server_endpoint_config());

    const auto datagram = captured_picoquic_client_initial_datagram();
    const auto first = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagram,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1));
    const auto accepted = lifecycle_events_from(first);
    ASSERT_EQ(accepted.size(), 1u);

    const auto second = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagram,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(2));

    EXPECT_EQ(core.connection_count(), 1u);
    const auto lifecycle = lifecycle_events_from(second);
    EXPECT_TRUE(lifecycle.empty());
}

TEST(QuicCoreEndpointTest, OrphanZeroRttBufferDisabledByDefaultDropsBeforeInitial) {
    coquic::quic::QuicCore core(make_server_endpoint_config());
    const auto initial = captured_picoquic_client_initial_datagram();
    auto destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial);
    ASSERT_TRUE(destination_connection_id.has_value());

    const auto parsed_destination_connection_id =
        destination_connection_id.value_or(coquic::quic::ConnectionId{});
    auto zero_rtt = make_synthetic_zero_rtt_datagram(parsed_destination_connection_id);
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = zero_rtt,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1)));

    EXPECT_TRUE(core.orphan_zero_rtt_buffer_.empty());
    EXPECT_EQ(core.orphan_zero_rtt_buffer_bytes_, 0u);
}

TEST(QuicCoreEndpointTest, OrphanZeroRttLateInitialReplaysBufferedPacketsExactlyOnce) {
    const auto resumption_state = make_resumption_state_for_endpoint_zero_rtt();
    const auto early_data = std::string_view{"GET /orphan-zero-rtt\r\n"};
    const auto datagrams =
        make_resumed_initial_and_zero_rtt_datagrams(resumption_state, early_data);

    coquic::quic::QuicCore server(make_server_endpoint_config_with_orphan_zero_rtt_buffer());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
    // # If the packet is a 0-RTT packet, the server MAY buffer a limited
    // # number of these packets in anticipation of a late-arriving Initial packet.
    auto buffered = server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagrams.zero_rtt,
            .route_handle = 44,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(102));
    EXPECT_TRUE(lifecycle_events_from(buffered).empty());
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagrams.zero_rtt,
            .route_handle = 44,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(102)));
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 2u);

    auto accepted = server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagrams.initial,
            .route_handle = 44,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(103));

    const auto lifecycle = lifecycle_events_from(accepted);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::accepted);
    const auto received = received_stream_data_from(accepted);
    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received.front().stream_id, 0u);
    EXPECT_TRUE(std::ranges::equal(received.front().payload(),
                                   coquic::quic::test::bytes_from_string(early_data)));
    EXPECT_TRUE(received.front().fin);
    EXPECT_TRUE(server.orphan_zero_rtt_buffer_.empty());
    EXPECT_EQ(server.orphan_zero_rtt_buffer_bytes_, 0u);

    auto duplicate_initial = server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagrams.initial,
            .route_handle = 44,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(104));
    EXPECT_TRUE(received_stream_data_from(duplicate_initial).empty());
}

TEST(QuicCoreEndpointTest, OrphanZeroRttDoesNotReplayWrongDestinationCidOrVersion) {
    auto config = make_server_endpoint_config_with_orphan_zero_rtt_buffer();
    config.supported_versions.push_back(coquic::quic::kQuicVersion2);
    coquic::quic::QuicCore server(std::move(config));
    const auto initial = captured_picoquic_client_initial_datagram();
    const auto matching_dcid = coquic::quic::test::long_header_destination_connection_id(initial);
    ASSERT_TRUE(matching_dcid.has_value());
    const auto matching_scid = coquic::quic::test::long_header_source_connection_id(initial);
    ASSERT_TRUE(matching_scid.has_value());
    const auto matching_destination_connection_id =
        matching_dcid.value_or(coquic::quic::ConnectionId{});
    const auto matching_source_connection_id = matching_scid.value_or(coquic::quic::ConnectionId{});

    auto wrong_dcid_zero_rtt = make_synthetic_zero_rtt_datagram(coquic::quic::ConnectionId{
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0}, std::byte{0x3e},
        std::byte{0x51}, std::byte{0x57}, std::byte{0x09}});
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = wrong_dcid_zero_rtt,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1)));

    auto wrong_version_zero_rtt = make_synthetic_zero_rtt_datagram(
        matching_destination_connection_id, matching_source_connection_id,
        coquic::quic::kQuicVersion2);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = wrong_version_zero_rtt,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(2)));
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 2u);

    auto accepted = server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(3));
    EXPECT_EQ(lifecycle_events_from(accepted).size(), 1u);
    EXPECT_TRUE(received_stream_data_from(accepted).empty());
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);
    EXPECT_EQ(server.orphan_zero_rtt_buffer_.front().bytes, wrong_dcid_zero_rtt);
}

TEST(QuicCoreEndpointTest, OrphanZeroRttRetryDropsMatchingBufferedPackets) {
    auto config = make_server_endpoint_config_with_orphan_zero_rtt_buffer();
    config.retry_enabled = true;
    coquic::quic::QuicCore server(std::move(config));
    const auto initial = captured_picoquic_client_initial_datagram();
    auto destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial);
    ASSERT_TRUE(destination_connection_id.has_value());

    const auto parsed_destination_connection_id =
        destination_connection_id.value_or(coquic::quic::ConnectionId{});
    auto zero_rtt = make_synthetic_zero_rtt_datagram(parsed_destination_connection_id);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = zero_rtt,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1)));
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);

    auto retry = server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(2));
    EXPECT_FALSE(send_effects_from(retry).empty());
    EXPECT_TRUE(lifecycle_events_from(retry).empty());
    EXPECT_TRUE(server.orphan_zero_rtt_buffer_.empty());
    EXPECT_EQ(server.orphan_zero_rtt_buffer_bytes_, 0u);
}

TEST(QuicCoreEndpointTest, OrphanZeroRttBufferEnforcesPacketByteAndAgeLimits) {
    auto config = make_server_endpoint_config_with_orphan_zero_rtt_buffer(
        1, 64, std::chrono::milliseconds(10));
    coquic::quic::QuicCore server(std::move(config));
    const auto destination_connection_id = coquic::quic::ConnectionId{
        std::byte{0x53}, std::byte{0x98}, std::byte{0xe9}, std::byte{0x2f},
        std::byte{0x19}, std::byte{0xc3}, std::byte{0x65}, std::byte{0x98}};

    auto first = make_synthetic_zero_rtt_datagram(destination_connection_id, {}, 1, 8);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = first,
            .route_handle = 7,
        },
        coquic::quic::test::test_time(1)));
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);
    EXPECT_EQ(server.orphan_zero_rtt_buffer_bytes_, first.size());
    ASSERT_TRUE(server.next_wakeup().has_value());

    auto second = make_synthetic_zero_rtt_datagram(destination_connection_id, {}, 1, 8);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = second,
            .route_handle = 7,
        },
        coquic::quic::test::test_time(2)));
    EXPECT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);
    EXPECT_EQ(server.orphan_zero_rtt_buffer_bytes_, first.size());

    static_cast<void>(server.advance_endpoint(coquic::quic::QuicCoreTimerExpired{},
                                              coquic::quic::test::test_time(11)));
    EXPECT_TRUE(server.orphan_zero_rtt_buffer_.empty());
    EXPECT_EQ(server.orphan_zero_rtt_buffer_bytes_, 0u);

    auto too_large = make_synthetic_zero_rtt_datagram(destination_connection_id, {}, 1, 128);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = too_large,
            .route_handle = 7,
        },
        coquic::quic::test::test_time(12)));
    EXPECT_TRUE(server.orphan_zero_rtt_buffer_.empty());
    EXPECT_EQ(server.orphan_zero_rtt_buffer_bytes_, 0u);
}

TEST(QuicCoreEndpointTest, OrphanZeroRttDoesNotReplayWrongTupleOrMalformedPackets) {
    const auto resumption_state = make_resumption_state_for_endpoint_zero_rtt();
    const auto datagrams =
        make_resumed_initial_and_zero_rtt_datagrams(resumption_state, "GET /tuple\r\n");

    coquic::quic::QuicCore server(make_server_endpoint_config_with_orphan_zero_rtt_buffer());
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagrams.zero_rtt,
            .route_handle = 55,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(102)));
    ASSERT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);

    auto unrelated = server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = datagrams.initial,
            .route_handle = 56,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-b"),
        },
        coquic::quic::test::test_time(103));
    EXPECT_TRUE(received_stream_data_from(unrelated).empty());
    EXPECT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);

    auto malformed = datagrams.zero_rtt;
    malformed.resize(6);
    static_cast<void>(server.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = malformed,
            .route_handle = 55,
            .address_validation_identity = coquic::quic::test::bytes_from_string("addr-a"),
        },
        coquic::quic::test::test_time(104)));
    EXPECT_EQ(server.orphan_zero_rtt_buffer_.size(), 1u);

    static_cast<void>(server.advance_endpoint(coquic::quic::QuicCoreTimerExpired{},
                                              coquic::quic::test::test_time(102 + 250)));
    EXPECT_TRUE(server.orphan_zero_rtt_buffer_.empty());
}
} // namespace

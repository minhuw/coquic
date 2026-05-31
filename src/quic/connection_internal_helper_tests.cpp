#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_support.h"

namespace coquic::quic::test {

COQUIC_NO_PROFILE bool connection_instrumented_helper_coverage_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok = ok & condition; };

    const ReceivedProtectedOneRttStreamPacket stream_packet{
        .packet_number = 17,
        .stream =
            ReceivedStreamFrame{
                .stream_id = 0,
                .stream_data = SharedBytes(std::vector<std::byte>{std::byte{0x11}}),
            },
    };
    const ReceivedProtectedOneRttAckOnlyPacket ack_only_packet{
        .packet_number = 18,
        .ack = ReceivedAckFrame{.largest_acknowledged = 18},
    };
    record(should_defer_protected_one_rtt_packet(stream_packet, EndpointRole::server,
                                                 HandshakeStatus::in_progress));
    record(!should_defer_protected_one_rtt_packet(stream_packet, EndpointRole::server,
                                                  HandshakeStatus::connected));
    record(should_defer_protected_one_rtt_packet(ack_only_packet, EndpointRole::server,
                                                 HandshakeStatus::in_progress));
    record(!should_defer_protected_one_rtt_packet(ack_only_packet, EndpointRole::client,
                                                  HandshakeStatus::in_progress));
    record(!should_defer_protected_one_rtt_packet(ack_only_packet, EndpointRole::server,
                                                  HandshakeStatus::connected));
    record(protected_one_rtt_packet_number_for_trace(ReceivedProtectedPacket{stream_packet}) ==
           17u);
    record(protected_one_rtt_packet_number_for_trace(ReceivedProtectedPacket{ack_only_packet}) ==
           18u);

    record(confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_256_gcm_sha384) ==
           kAesGcmConfidentialityLimit);
    record(confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256) ==
           kAesGcmConfidentialityLimit);
    record(!confidentiality_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256)
                .has_value());
    record(integrity_limit_for_cipher_suite(CipherSuite::tls_aes_256_gcm_sha384) ==
           kAesGcmIntegrityLimit);
    record(integrity_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256) ==
           kAesGcmIntegrityLimit);
    record(integrity_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256) ==
           kChaCha20Poly1305IntegrityLimit);

    SentPacketRecord packet;
    packet.first_stream_frame_metadata =
        StreamFrameSendMetadata{.stream_id = 0, .offset = 10, .length = 3};
    packet.stream_frame_metadata = {
        StreamFrameSendMetadata{.stream_id = 0, .offset = 13, .length = 4},
        StreamFrameSendMetadata{.stream_id = 0, .offset = 17, .length = 5, .fin = true},
    };
    record(packet_stream_frame_count(packet) == 3);
    record(packet_stream_frame_bytes(packet) == 12);
    record(packet_first_stream_frame_offset(packet) == 10u);
    std::size_t visited_metadata = 0;
    std::size_t visited_bytes = 0;
    const auto note_visited_metadata = [&](const StreamFrameSendMetadata &metadata) {
        ++visited_metadata;
        visited_bytes += metadata.length;
    };
    for_each_stream_frame_metadata(SentPacketRecord{}, note_visited_metadata);
    for_each_stream_frame_metadata(packet, note_visited_metadata);
    record(visited_metadata == 3);
    record(visited_bytes == 12);

    std::map<std::uint64_t, LocalConnectionIdRecord> local_connection_ids;
    local_connection_ids[0] = LocalConnectionIdRecord{};
    local_connection_ids[1] = LocalConnectionIdRecord{.retired = true};
    local_connection_ids[2] = LocalConnectionIdRecord{.retirement_requested = true};
    record(count_unretired_connection_ids_without_pending_retirement(local_connection_ids) == 1);

    PacketSpaceState packet_space;
    note_ignored_ack_eliciting_received_packet(packet_space, /*packet_number=*/1,
                                               /*ack_eliciting=*/false, QuicCoreTimePoint{},
                                               QuicEcnCodepoint::not_ect,
                                               /*ack_eliciting_threshold=*/2);
    record(!packet_space.pending_ack_deadline.has_value());

    SentPacketRecord empty_packet;
    record(packet_stream_frame_count(empty_packet) == 0);
    record(packet_stream_frame_bytes(empty_packet) == 0);
    record(!packet_first_stream_frame_offset(empty_packet).has_value());
    const auto ignore_stream_metadata = [](const StreamFrameSendMetadata &) {};
    for_each_stream_frame_metadata(empty_packet, ignore_stream_metadata);
    for_each_stream_frame_metadata(packet, ignore_stream_metadata);
    record(!packet_has_only_stream_frame_metadata(empty_packet));

    SentPacketRecord non_stream_frame_packet;
    non_stream_frame_packet.has_ping = true;
    record(!packet_has_only_stream_frame_metadata(non_stream_frame_packet));
    record(!packet_is_simple_congestion_ack(non_stream_frame_packet));

    const auto make_metadata_only_packet = [] {
        SentPacketRecord candidate;
        candidate.ack_eliciting = true;
        candidate.in_flight = true;
        candidate.first_stream_frame_metadata =
            StreamFrameSendMetadata{.stream_id = 0, .offset = 0, .length = 1};
        return candidate;
    };

    {
        auto candidate = make_metadata_only_packet();
        candidate.reset_stream_frames.push_back(ResetStreamFrame{.stream_id = 0});
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.stream_data_blocked_frames.push_back(StreamDataBlockedFrame{.stream_id = 0});
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.data_blocked_frame = DataBlockedFrame{.maximum_data = 1};
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.has_handshake_done = true;
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.is_pmtu_probe = true;
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.force_ack = true;
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.qlog_packet_snapshot = std::make_shared<qlog::PacketSnapshot>();
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.qlog_pto_probe = true;
        record(!packet_has_only_stream_frame_metadata(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.declared_lost = true;
        record(!packet_is_simple_congestion_ack(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.in_flight = false;
        record(!packet_is_simple_congestion_ack(candidate));
    }
    {
        auto candidate = make_metadata_only_packet();
        candidate.app_limited = true;
        record(!packet_is_simple_congestion_ack(candidate));
    }

    SentPacketRecord metadata_only_packet;
    metadata_only_packet.stream_frame_metadata = {
        StreamFrameSendMetadata{.stream_id = 0, .offset = 33, .length = 2},
    };
    record(packet_first_stream_frame_offset(metadata_only_packet) == 33u);

    SentPacketRecord fragment_only_packet;
    fragment_only_packet.stream_fragments = {
        StreamFrameSendFragment{
            .stream_id = 0,
            .offset = 44,
            .bytes = SharedBytes(std::vector<std::byte>{std::byte{0x22}, std::byte{0x23}}),
        },
    };
    record(packet_stream_frame_bytes(fragment_only_packet) == 2);
    record(packet_first_stream_frame_offset(fragment_only_packet) == 44u);

    const std::map<std::uint64_t, StreamState> empty_streams;
    record(round_robin_stream_order(empty_streams, std::nullopt).empty());
    record(unfair_stream_order(empty_streams, std::nullopt).empty());

    std::map<std::uint64_t, StreamState> streams;
    streams.emplace(4, make_implicit_stream_state(4, EndpointRole::client));
    streams.emplace(8, make_implicit_stream_state(8, EndpointRole::client));
    streams.emplace(12, make_implicit_stream_state(12, EndpointRole::client));
    record(round_robin_stream_order(streams, std::nullopt) == std::vector<std::uint64_t>{4, 8, 12});
    record(unfair_stream_order(streams, std::nullopt) == std::vector<std::uint64_t>{4, 8, 12});

    auto probe_stream = make_implicit_stream_state(0, EndpointRole::client);
    const StreamFrameSendMetadata missing_fin_metadata{
        .stream_id = 0,
        .offset = 0,
        .length = 1,
        .fin = false,
    };
    record(!stream_frame_metadata_is_probe_worthy(probe_stream, missing_fin_metadata));

    const StreamFrameSendMetadata fin_metadata{
        .stream_id = 0,
        .offset = 0,
        .length = 1,
        .fin = true,
    };
    probe_stream.send_fin_state = StreamSendFinState::acknowledged;
    record(!stream_frame_metadata_is_probe_worthy(probe_stream, fin_metadata));
    probe_stream.send_fin_state = StreamSendFinState::pending;
    probe_stream.send_final_size = 1;
    record(stream_frame_metadata_is_probe_worthy(probe_stream, fin_metadata));

    return ok;
}

} // namespace coquic::quic::test

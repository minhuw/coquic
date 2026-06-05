#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_support.h"

namespace coquic::quic::test {

COQUIC_NO_PROFILE bool connection_instrumented_helper_coverage_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok = ok & condition; };
    struct ScopedConnectionDrainHooksSnapshot {
        ConnectionDrainTestHooks previous = connection_drain_test_hooks();

        ~ScopedConnectionDrainHooksSnapshot() {
            connection_drain_test_hooks() = previous;
        }
    } hooks_snapshot;

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
    {
        std::vector<Frame> frames{PingFrame{}};
        record(!largest_acknowledged_by_ack_frame(frames).has_value());
        frames.emplace_back(OutboundAckFrame{
            .history = nullptr,
            .header = OutboundAckHeader{.largest_acknowledged = 99},
        });
        record(largest_acknowledged_by_ack_frame(frames) == 99u);
        frames.insert(frames.begin(), AckFrame{.largest_acknowledged = 77});
        record(largest_acknowledged_by_ack_frame(frames) == 77u);
        record(!largest_acknowledged_for_ack_eliciting_sent_record(false, frames).has_value());
        record(largest_acknowledged_for_ack_eliciting_sent_record(true, frames) == 77u);
    }
    record(send_continuation_allowed(/*continuation_has_pending_work=*/true,
                                     /*bypass_burst_limit=*/false,
                                     /*unpaced_ack_eliciting_packets=*/1));
    record(!send_continuation_allowed(/*continuation_has_pending_work=*/false,
                                      /*bypass_burst_limit=*/false,
                                      /*unpaced_ack_eliciting_packets=*/1));
    record(!send_continuation_allowed(/*continuation_has_pending_work=*/true,
                                      /*bypass_burst_limit=*/true,
                                      /*unpaced_ack_eliciting_packets=*/1));
    record(!send_continuation_allowed(/*continuation_has_pending_work=*/true,
                                      /*bypass_burst_limit=*/false,
                                      /*unpaced_ack_eliciting_packets=*/0));

    record(confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_256_gcm_sha384) ==
           kAesGcmConfidentialityLimit);
    record(confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256) ==
           kAesGcmConfidentialityLimit);
    record(!confidentiality_limit_for_cipher_suite(CipherSuite::tls_chacha20_poly1305_sha256)
                .has_value());
    record(!proactive_key_update_packet_limit_for_cipher_suite(
                CipherSuite::tls_chacha20_poly1305_sha256)
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
    record(!stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                    .stream_id = 0,
                                                                    .offset = 0,
                                                                    .length = 1,
                                                                    .fin = false,
                                                                }));

    probe_stream.send_fin_state = StreamSendFinState::acknowledged;
    record(!stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                    .stream_id = 0,
                                                                    .offset = 0,
                                                                    .length = 1,
                                                                    .fin = true,
                                                                }));
    probe_stream.send_fin_state = StreamSendFinState::pending;
    probe_stream.send_final_size = 1;
    record(stream_frame_metadata_is_probe_worthy(probe_stream, StreamFrameSendMetadata{
                                                                   .stream_id = 0,
                                                                   .offset = 0,
                                                                   .length = 1,
                                                                   .fin = true,
                                                               }));

    record(optional_ref_or_abort(std::optional<int>{7}) == 7);

    const auto make_serialized_datagram = [](std::size_t size) {
        SerializedProtectedDatagram datagram;
        datagram.bytes.resize(size, std::byte{0x42});
        return CodecResult<SerializedProtectedDatagram>::success(std::move(datagram));
    };

    {
        auto candidate = make_serialized_datagram(1);
        maybe_grow_application_candidate_datagram_for_tests(candidate);
        record(candidate.has_value());
        record(candidate.value().bytes.size() == 1);
    }
    {
        auto candidate = make_serialized_datagram(1);
        ScopedConnectionDrainDatagramGrowthTestHook hook(
            ScopedConnectionDrainDatagramGrowthTestHook::Countdown{0},
            ScopedConnectionDrainDatagramGrowthTestHook::ExtraBytes{2});
        maybe_grow_application_candidate_datagram_for_tests(candidate);
        record(candidate.has_value());
        record(candidate.value().bytes.size() == 3);
    }
    {
        auto candidate = make_serialized_datagram(1);
        ScopedConnectionDrainDatagramGrowthTestHook hook(
            ScopedConnectionDrainDatagramGrowthTestHook::Countdown{0},
            ScopedConnectionDrainDatagramGrowthTestHook::ExtraBytes{0});
        maybe_grow_application_candidate_datagram_for_tests(candidate);
        record(candidate.has_value());
        record(candidate.value().bytes.size() == 1);
    }
    {
        auto candidate = CodecResult<SerializedProtectedDatagram>::failure(
            CodecErrorCode::packet_length_mismatch, 0);
        ScopedConnectionDrainDatagramGrowthTestHook hook(
            ScopedConnectionDrainDatagramGrowthTestHook::Countdown{0},
            ScopedConnectionDrainDatagramGrowthTestHook::ExtraBytes{2});
        maybe_grow_application_candidate_datagram_for_tests(candidate);
        record(!candidate.has_value());
    }

    {
        std::vector<Frame> frames{PaddingFrame{.length = 3}};
        std::size_t padding = 3;
        maybe_force_pmtu_probe_padding_shortfall_for_tests(padding, frames);
        record(padding == 3);
        record(std::get<PaddingFrame>(frames.back()).length == 3);
    }
    {
        std::vector<Frame> frames{PaddingFrame{.length = 3}};
        std::size_t padding = 3;
        ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_shortfall_countdown, 0);
        maybe_force_pmtu_probe_padding_shortfall_for_tests(padding, frames);
        record(padding == 2);
        record(std::get<PaddingFrame>(frames.back()).length == 2);
    }
    {
        std::vector<Frame> frames{PaddingFrame{.length = 0}};
        std::size_t padding = 0;
        ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_shortfall_countdown, 0);
        maybe_force_pmtu_probe_padding_shortfall_for_tests(padding, frames);
        record(padding == 0);
        record(std::get<PaddingFrame>(frames.back()).length == 0);
    }

    {
        auto candidate = make_serialized_datagram(1);
        maybe_force_ack_only_datagram_serialization_failure_for_tests(candidate);
        record(candidate.has_value());
    }
    {
        auto candidate = make_serialized_datagram(1);
        ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_ack_only_datagram_serialization_failure_countdown, 0);
        maybe_force_ack_only_datagram_serialization_failure_for_tests(candidate);
        record(!candidate.has_value());
        record(candidate.error().code == CodecErrorCode::packet_length_mismatch);
    }

    {
        QuicCongestionController controller(QuicCongestionControlAlgorithm::bbr,
                                            /*max_datagram_size=*/1200);
        SendProfileCounters profile;
        record_congestion_debug_for_profile(controller, QuicCoreTimePoint{}, profile);
        record(profile.cc_debug_samples == 1);
        record(profile.cc_send_quantum_last != 0);
        record(profile.cc_send_quantum_max >= profile.cc_send_quantum_last);
        record(profile.cc_inflight_longterm_finite_samples == 0);
        record(profile.cc_inflight_shortterm_finite_samples == 0);
        record(profile.cc_target_window_finite_samples == 0);
    }
    {
        QuicCongestionController controller(QuicCongestionControlAlgorithm::copa,
                                            /*max_datagram_size=*/1200);
        const std::array acked_packets{
            SentPacketRecord{
                .packet_number = 1,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .bytes_in_flight = 1200,
            },
        };
        controller.on_packets_acked(acked_packets, /*app_limited=*/false,
                                    QuicCoreTimePoint{} + std::chrono::milliseconds(200),
                                    RecoveryRttState{
                                        .latest_rtt = std::chrono::milliseconds{200},
                                        .min_rtt = std::chrono::milliseconds{100},
                                    });
        SendProfileCounters profile;
        record_congestion_debug_for_profile(controller, QuicCoreTimePoint{}, profile);
        record(profile.cc_debug_samples == 1);
        record(profile.cc_target_window_finite_samples == 1);
        record(profile.cc_target_window_last != 0);
        record(profile.cc_target_window_max == profile.cc_target_window_last);
    }
    {
        QuicCongestionDebugMetrics metrics{
            .inflight_longterm = 111,
            .inflight_shortterm = 222,
            .finite_inflight_longterm = true,
            .finite_inflight_shortterm = true,
        };
        SendProfileCounters profile;
        record_congestion_debug_metrics_for_profile_for_tests(metrics, profile);
        record(profile.cc_debug_samples == 1);
        record(profile.cc_inflight_longterm_finite_samples == 1);
        record(profile.cc_inflight_longterm_last == 111u);
        record(profile.cc_inflight_longterm_max == 111u);
        record(profile.cc_inflight_shortterm_finite_samples == 1);
        record(profile.cc_inflight_shortterm_last == 222u);
        record(profile.cc_inflight_shortterm_max == 222u);
    }

    {
        CodecResult<SerializedProtectedDatagram> candidate = make_serialized_datagram(1);
        std::vector<Frame> frames{PaddingFrame{.length = 1}};
        std::size_t padding = 1;
        std::size_t calls = 0;
        const bool retried =
            retry_padded_pmtu_probe_serialization(candidate, frames, 4, padding, [&] {
                const auto size = calls++ == 0 ? 2u : 4u;
                return make_serialized_datagram(size);
            });
        record(retried);
        record(candidate.value().bytes.size() == 4);
        record(padding == 3);
        record(std::get<PaddingFrame>(frames.back()).length == 3);
    }
    {
        CodecResult<SerializedProtectedDatagram> candidate = make_serialized_datagram(1);
        std::vector<Frame> frames{PaddingFrame{.length = 1}};
        std::size_t padding = 1;
        const bool retried = retry_padded_pmtu_probe_serialization(
            candidate, frames, 4, padding, [&] { return make_serialized_datagram(5); });
        record(!retried);
        record(candidate.value().bytes.size() == 5);
    }
    {
        CodecResult<SerializedProtectedDatagram> candidate = make_serialized_datagram(1);
        std::vector<Frame> frames{PaddingFrame{.length = 1}};
        std::size_t padding = 1;
        ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_failure_countdown, 0);
        const bool retried = retry_padded_pmtu_probe_serialization(
            candidate, frames, 4, padding, [&] { return make_serialized_datagram(4); });
        record(!retried);
    }
    {
        CodecResult<SerializedProtectedDatagram> candidate = make_serialized_datagram(1);
        std::vector<Frame> frames{PaddingFrame{.length = 1}};
        std::size_t padding = 1;
        std::size_t calls = 0;
        const bool retried =
            retry_padded_pmtu_probe_serialization(candidate, frames, 4, padding, [&] {
                ++calls;
                return make_serialized_datagram(2);
            });
        record(retried);
        record(calls == 2u);
        record(candidate.value().bytes.size() == 2u);
        record(padding == 5u);
        record(std::get<PaddingFrame>(frames.back()).length == 5u);
    }

    {
        std::array<std::byte, 4> bytes{};
        record(rand_bytes_for_connection(bytes, /*force_failure=*/false));
        record(!rand_bytes_for_connection(bytes, /*force_failure=*/true));
    }
    {
        ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_quic_core_secret_rand_failure);
        const auto secret = make_quic_core_secret();
        record(secret.size() == kQuicCoreSecretLength);
    }
    {
        std::array<std::byte, kQuicCoreSecretLength> secret{};
        secret.fill(std::byte{0x11});
        std::array<unsigned char, 2> input{0x12, 0x34};
        unsigned int produced = 0;
        const auto digest = compute_hmac_sha256_for_connection(secret, input, produced,
                                                               /*force_failure=*/false);
        record(digest.has_value());
        record(produced == SHA256_DIGEST_LENGTH);
        record(!compute_hmac_sha256_for_connection(secret, input, produced,
                                                   /*force_failure=*/true)
                    .has_value());

        constexpr std::array label{std::byte{'l'}};
        constexpr std::array context{std::byte{'c'}};
        record(prf_bytes<8>(secret, label, context).has_value());
        {
            ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
            record(!prf_bytes<8>(secret, label, context).has_value());
        }
        {
            ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_short_prf_output);
            record(!prf_bytes<8>(secret, label, context).has_value());
        }
    }

    record(random_one_in_sixteen_from_openssl(0x10));
    record(!random_one_in_sixteen_from_openssl(0x11));
    {
        const auto previous = connection_drain_test_hooks().force_random_one_in_sixteen_result;
        connection_drain_test_hooks().force_random_one_in_sixteen_result.reset();
        static_cast<void>(connection_drain_test_hooks().force_random_one_in_sixteen_result);
        connection_drain_test_hooks().force_random_one_in_sixteen_result = previous;
    }
    {
        ScopedConnectionDrainOptionalBoolTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, true);
        record(random_one_in_sixteen());
    }
    {
        ScopedConnectionDrainOptionalBoolTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, false);
        record(!random_one_in_sixteen());
    }
    {
        ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_rand_failure);
        static_cast<void>(random_one_in_sixteen());
    }
    for (int index = 0; index < 128; ++index) {
        static_cast<void>(random_one_in_sixteen());
    }
    {
        ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_grease_quic_bit_seed_rand_failure);
        static_cast<void>(make_grease_quic_bit_seed());
    }
    static_cast<void>(random_one_in_sixteen());

    record(closing_close_packet_can_send(true, true));
    record(!closing_close_packet_can_send(true, false));
    record(!closing_close_packet_can_send(false, true));

    PathState validating_path;
    PathState validated_path;
    validated_path.validated = true;
    record(path_state_is_validating(&validating_path));
    record(!path_state_is_validating(&validated_path));
    record(!path_state_is_validating(nullptr));
    record(path_state_is_validated(&validated_path));
    record(!path_state_is_validated(&validating_path));
    record(!path_state_is_validated(nullptr));

    record(application_protocol_bytes("h3") ==
           std::vector<std::byte>({std::byte{'h'}, std::byte{'3'}}));

    record(is_empty_packet_payload_error(
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload, 0)));
    record(!is_empty_packet_payload_error(
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::packet_length_mismatch, 0)));
    record(!is_empty_packet_payload_error(
        CodecResult<std::vector<std::byte>>::success(std::vector<std::byte>{std::byte{0x01}})));
    record(is_empty_packet_payload_error(CodecResult<SerializedProtectedDatagram>::failure(
        CodecErrorCode::empty_packet_payload, 0)));
    record(!is_empty_packet_payload_error(CodecResult<SerializedProtectedDatagram>::failure(
        CodecErrorCode::packet_length_mismatch, 0)));
    record(!is_empty_packet_payload_error(make_serialized_datagram(1)));

    record(stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_id) ==
           QuicTransportErrorCode::stream_limit_error);
    record(stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_direction) ==
           QuicTransportErrorCode::stream_state_error);
    record(stream_transport_error_for_state_error(StreamStateErrorCode::send_side_closed) ==
           QuicTransportErrorCode::stream_state_error);
    record(stream_transport_error_for_state_error(StreamStateErrorCode::receive_side_closed) ==
           QuicTransportErrorCode::stream_state_error);
    record(stream_transport_error_for_state_error(StreamStateErrorCode::final_size_conflict) ==
           QuicTransportErrorCode::final_size_error);
    record(stream_transport_error_for_state_error(static_cast<StreamStateErrorCode>(0xff)) ==
           QuicTransportErrorCode::protocol_violation);

    record(datagram_frame_type_for(ReceivedDatagramFrame{.has_length = false}) ==
           kFrameTypeDatagram);
    record(datagram_frame_type_for(ReceivedDatagramFrame{.has_length = true}) ==
           (kFrameTypeDatagram | 0x01u));
    record(datagram_frame_wire_size(/*payload_size=*/3, /*has_length=*/false) == 4u);
    record(datagram_frame_wire_size(/*payload_size=*/3, /*has_length=*/true) == 5u);
    record(invalid_fixed_bit_is_rejected(/*header_byte=*/0x00, /*grease_quic_bit=*/false));
    record(!invalid_fixed_bit_is_rejected(/*header_byte=*/0x40, /*grease_quic_bit=*/false));
    record(!invalid_fixed_bit_is_rejected(/*header_byte=*/0x00, /*grease_quic_bit=*/true));
    record(application_datagram_requires_connected_state(
        /*require_connected=*/true, /*application_read_secret_available=*/false,
        HandshakeStatus::in_progress));
    record(!application_datagram_requires_connected_state(
        /*require_connected=*/false, /*application_read_secret_available=*/false,
        HandshakeStatus::in_progress));
    record(!application_datagram_requires_connected_state(
        /*require_connected=*/true, /*application_read_secret_available=*/true,
        HandshakeStatus::in_progress));
    record(!application_datagram_requires_connected_state(
        /*require_connected=*/true, /*application_read_secret_available=*/false,
        HandshakeStatus::connected));
    {
        const auto source_connection_id = ConnectionId{std::byte{0xa1}};
        std::map<std::uint64_t, PeerConnectionIdRecord> peer_ids;
        record(peer_connection_id_route_changed(peer_ids, source_connection_id,
                                                /*active_peer_connection_id_sequence=*/0));
        peer_ids.emplace(0, PeerConnectionIdRecord{.connection_id = source_connection_id});
        record(!peer_connection_id_route_changed(peer_ids, source_connection_id,
                                                 /*active_peer_connection_id_sequence=*/0));
        record(peer_connection_id_route_changed(peer_ids, ConnectionId{std::byte{0xa2}},
                                                /*active_peer_connection_id_sequence=*/0));
        peer_ids.at(0).locally_retired = true;
        record(peer_connection_id_route_changed(peer_ids, source_connection_id,
                                                /*active_peer_connection_id_sequence=*/0));
        peer_ids.at(0).locally_retired = false;
        record(peer_connection_id_route_changed(peer_ids, source_connection_id,
                                                /*active_peer_connection_id_sequence=*/1));
    }

    record(transport_error_for_codec_error(CodecErrorCode::truncated_input) ==
           QuicTransportErrorCode::frame_encoding_error);
    record(transport_error_for_codec_error(CodecErrorCode::unknown_frame_type) ==
           QuicTransportErrorCode::frame_encoding_error);
    record(transport_error_for_codec_error(CodecErrorCode::non_shortest_frame_type_encoding) ==
           QuicTransportErrorCode::frame_encoding_error);
    record(transport_error_for_codec_error(CodecErrorCode::empty_packet_payload) ==
           QuicTransportErrorCode::frame_encoding_error);
    record(transport_error_for_codec_error(CodecErrorCode::frame_not_allowed_in_packet_type) ==
           QuicTransportErrorCode::frame_encoding_error);
    record(transport_error_for_codec_error(CodecErrorCode::unsupported_cipher_suite) ==
           QuicTransportErrorCode::transport_parameter_error);
    record(transport_error_for_codec_error(CodecErrorCode::invalid_reserved_bits) ==
           QuicTransportErrorCode::protocol_violation);
    record(transport_error_for_codec_error(CodecErrorCode::malformed_short_header_context) ==
           QuicTransportErrorCode::protocol_violation);
    record(transport_error_for_codec_error(CodecErrorCode::packet_number_recovery_failed) ==
           QuicTransportErrorCode::protocol_violation);
    record(transport_error_for_codec_error(CodecErrorCode::invalid_fixed_bit) ==
           QuicTransportErrorCode::internal_error);
    record(transport_error_for_codec_error(CodecErrorCode::header_protection_failed) ==
           QuicTransportErrorCode::internal_error);
    record(transport_error_for_codec_error(CodecErrorCode::http3_parse_error) ==
           QuicTransportErrorCode::application_error);
    record(transport_error_for_codec_error(static_cast<CodecErrorCode>(0xff)) ==
           QuicTransportErrorCode::protocol_violation);

    {
        ReceivedFrameList ack_frames{ReceivedAckFrame{.largest_acknowledged = 1}};
        ReceivedFrameList stream_frames{ReceivedStreamFrame{
            .stream_id = 0,
            .stream_data = SharedBytes(std::vector<std::byte>{std::byte{0x01}}),
        }};
        ReceivedFrameList ping_frames{PingFrame{}};
        ReceivedFrameList many_frames{
            ReceivedAckFrame{.largest_acknowledged = 1},
            PingFrame{},
        };
        record(single_received_ack_frame_or_null(ack_frames) != nullptr);
        record(single_received_ack_frame_or_null(stream_frames) == nullptr);
        record(single_received_ack_frame_or_null(ping_frames) == nullptr);
        record(single_received_ack_frame_or_null(many_frames) == nullptr);
        record(single_received_stream_frame_or_null(stream_frames) != nullptr);
        record(single_received_stream_frame_or_null(ack_frames) == nullptr);
        record(single_received_stream_frame_or_null(ping_frames) == nullptr);
        record(single_received_stream_frame_or_null(many_frames) == nullptr);
    }

    record(short_header_minimum_payload_bytes_for_header_sample(4) == 0);
    record(short_header_minimum_payload_bytes_for_header_sample(1) == 3);
    {
        StreamFrame no_length_stream;
        no_length_stream.has_length = false;
        StreamFrame length_stream;
        length_stream.has_length = true;
        record(one_rtt_stream_frame_must_have_length(&no_length_stream, 0, 2, false));
        record(one_rtt_stream_frame_must_have_length(&no_length_stream, 0, 1, true));
        record(!one_rtt_stream_frame_must_have_length(&no_length_stream, 0, 1, false));
        record(!one_rtt_stream_frame_must_have_length(&length_stream, 0, 2, true));
        record(!one_rtt_stream_frame_must_have_length(nullptr, 0, 2, true));
    }
    {
        const std::array frames{
            Frame{DatagramFrame{
                .has_length = false,
                .data = {std::byte{0x01}},
            }},
            Frame{PingFrame{}},
        };
        const auto size = one_rtt_packet_fragment_view_wire_size(
            ProtectedOneRttPacketFragmentView{.packet_number_length = 1, .frames = frames});
        record(!size.has_value());
        record(size.error().code == CodecErrorCode::packet_length_mismatch);
    }
    {
        const std::array frames{
            Frame{DatagramFrame{
                .has_length = true,
                .data = {std::byte{0x01}},
            }},
            Frame{PingFrame{}},
        };
        const auto size = one_rtt_packet_fragment_view_wire_size(
            ProtectedOneRttPacketFragmentView{.packet_number_length = 1, .frames = frames});
        record(size.has_value());
    }
    {
        const std::array frames{
            Frame{DatagramFrame{
                .has_length = false,
                .data = {std::byte{0x01}},
            }},
        };
        const auto size = one_rtt_packet_fragment_view_wire_size(
            ProtectedOneRttPacketFragmentView{.packet_number_length = 1, .frames = frames});
        record(size.has_value());
    }
    {
        const std::array frames{
            Frame{DatagramFrame{
                .has_length = false,
                .data = {std::byte{0x01}},
            }},
        };
        const std::array fragments{
            StreamFrameSendFragment{
                .stream_id = 0,
                .bytes = SharedBytes(std::vector<std::byte>{std::byte{0x02}}),
            },
        };
        const auto size = one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
            .packet_number_length = 1, .frames = frames, .stream_fragments = fragments});
        record(!size.has_value());
        record(size.error().code == CodecErrorCode::packet_length_mismatch);
    }
    {
        const std::variant<PingFrame> ping_variant{PingFrame{}};
        record(!holds_alternative_if_present<DatagramFrame>(ping_variant));
    }

    record(!datagram_starts_with_initial_packet(std::span<const std::byte>{},
                                                /*accept_greased_quic_bit=*/true));
    {
        const std::array bytes{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        };
        record(!datagram_starts_with_initial_packet(bytes, /*accept_greased_quic_bit=*/true));
    }

    record(
        max_data_frame_matches(MaxDataFrame{.maximum_data = 7}, MaxDataFrame{.maximum_data = 7}));
    record(!max_data_frame_matches(std::nullopt, MaxDataFrame{.maximum_data = 7}));
    record(
        !max_data_frame_matches(MaxDataFrame{.maximum_data = 8}, MaxDataFrame{.maximum_data = 7}));
    record(data_blocked_frame_matches(DataBlockedFrame{.maximum_data = 7},
                                      DataBlockedFrame{.maximum_data = 7}));
    record(!data_blocked_frame_matches(std::nullopt, DataBlockedFrame{.maximum_data = 7}));
    record(!data_blocked_frame_matches(DataBlockedFrame{.maximum_data = 8},
                                       DataBlockedFrame{.maximum_data = 7}));
    record(reset_stream_frame_matches(
        ResetStreamFrame{.stream_id = 1, .application_protocol_error_code = 2, .final_size = 3},
        ResetStreamFrame{.stream_id = 1, .application_protocol_error_code = 2, .final_size = 3}));
    record(!reset_stream_frame_matches(std::nullopt, ResetStreamFrame{.stream_id = 1}));
    record(!reset_stream_frame_matches(ResetStreamFrame{.stream_id = 2},
                                       ResetStreamFrame{.stream_id = 1}));
    record(stop_sending_frame_matches(
        StopSendingFrame{.stream_id = 1, .application_protocol_error_code = 2},
        StopSendingFrame{.stream_id = 1, .application_protocol_error_code = 2}));
    record(!stop_sending_frame_matches(std::nullopt, StopSendingFrame{.stream_id = 1}));
    record(!stop_sending_frame_matches(StopSendingFrame{.stream_id = 2},
                                       StopSendingFrame{.stream_id = 1}));
    record(max_stream_data_frame_matches(
        MaxStreamDataFrame{.stream_id = 1, .maximum_stream_data = 2},
        MaxStreamDataFrame{.stream_id = 1, .maximum_stream_data = 2}));
    record(!max_stream_data_frame_matches(std::nullopt, MaxStreamDataFrame{.stream_id = 1}));
    record(!max_stream_data_frame_matches(MaxStreamDataFrame{.stream_id = 2},
                                          MaxStreamDataFrame{.stream_id = 1}));
    record(max_streams_frame_matches(
        MaxStreamsFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 4},
        MaxStreamsFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 4}));
    record(!max_streams_frame_matches(std::nullopt, MaxStreamsFrame{.maximum_streams = 4}));
    record(!max_streams_frame_matches(
        MaxStreamsFrame{.stream_type = StreamLimitType::bidirectional, .maximum_streams = 4},
        MaxStreamsFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 4}));
    record(stream_data_blocked_frame_matches(
        StreamDataBlockedFrame{.stream_id = 1, .maximum_stream_data = 2},
        StreamDataBlockedFrame{.stream_id = 1, .maximum_stream_data = 2}));
    record(
        !stream_data_blocked_frame_matches(std::nullopt, StreamDataBlockedFrame{.stream_id = 1}));
    record(!stream_data_blocked_frame_matches(StreamDataBlockedFrame{.stream_id = 2},
                                              StreamDataBlockedFrame{.stream_id = 1}));

    record(pmtud_probe_needs_minimum_growth(1201, 1200, 1400));
    record(!pmtud_probe_needs_minimum_growth(1216, 1200, 1400));
    record(!pmtud_probe_needs_minimum_growth(1201, 1200, 1201));
    {
        TransportParameters remembered;
        remembered.max_datagram_frame_size = 3;
        TransportParameters current;
        current.max_datagram_frame_size = 2;
        record(!zero_rtt_transport_limits_not_reduced(remembered, current));
        current.max_datagram_frame_size = 3;
        record(zero_rtt_transport_limits_not_reduced(remembered, current));
    }
    {
        TransportParameters peer_parameters;
        record(!peer_validated_grease_quic_bit_support(
            /*local_grease_quic_bit_enabled=*/false,
            /*peer_transport_parameters_validated=*/true, peer_parameters));
        record(!peer_validated_grease_quic_bit_support(
            /*local_grease_quic_bit_enabled=*/true,
            /*peer_transport_parameters_validated=*/false, peer_parameters));
        record(!peer_validated_grease_quic_bit_support(
            /*local_grease_quic_bit_enabled=*/true,
            /*peer_transport_parameters_validated=*/true, std::nullopt));
        peer_parameters.grease_quic_bit = false;
        record(!peer_validated_grease_quic_bit_support(
            /*local_grease_quic_bit_enabled=*/true,
            /*peer_transport_parameters_validated=*/true, peer_parameters));
        peer_parameters.grease_quic_bit = true;
        record(peer_validated_grease_quic_bit_support(
            /*local_grease_quic_bit_enabled=*/true,
            /*peer_transport_parameters_validated=*/true, peer_parameters));
    }
    {
        PacketSpaceState ack_space;
        const auto now = QuicCoreTimePoint{} + QuicCoreDuration{10};
        record(!initial_ack_due_for_send(ack_space, now));
        record(!handshake_ack_due_for_send(ack_space, now));
        record(!application_ack_due_for_send(ack_space, now));
        ack_space.received_packets.record_received(7, /*ack_eliciting=*/true, now,
                                                   QuicEcnCodepoint::not_ect,
                                                   /*ack_eliciting_threshold=*/1);
        record(!initial_ack_due_for_send(ack_space, now));
        ack_space.pending_ack_deadline = now;
        record(initial_ack_due_for_send(ack_space, now));
        ack_space.pending_ack_deadline = now + QuicCoreDuration{1};
        ack_space.force_ack_send = false;
        record(!handshake_ack_due_for_send(ack_space, now));
        record(!application_ack_due_for_send(ack_space, now));
        ack_space.force_ack_send = true;
        record(initial_ack_due_for_send(ack_space, now));
        record(handshake_ack_due_for_send(ack_space, now));
        record(application_ack_due_for_send(ack_space, now));
    }
    {
        std::size_t noted_bytes = 0;
        maybe_note_inbound_datagram_bytes(
            /*count_inbound_bytes=*/false, std::array<std::byte, 1>{std::byte{0x40}},
            /*accept_greased_quic_bit=*/false, [&](std::size_t bytes) { noted_bytes += bytes; });
        record(noted_bytes == 0u);
        maybe_note_inbound_datagram_bytes(
            /*count_inbound_bytes=*/true, std::array<std::byte, 1>{std::byte{0x40}},
            /*accept_greased_quic_bit=*/false, [&](std::size_t bytes) { noted_bytes += bytes; });
        record(noted_bytes == 1u);

        PacketSpaceState handshake_space;
        record(!handshake_packet_space_has_sendable_data(handshake_space, QuicCoreTimePoint{}));
        handshake_space.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x45});
        handshake_space.pending_probe_packet = SentPacketRecord{};
        record(handshake_packet_space_has_sendable_data(handshake_space, QuicCoreTimePoint{}));

        PacketSpaceState application_space;
        record(!application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/false));
        record(application_space_has_sendable_data(
            /*application_ack_due=*/true, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/false));
        record(application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/true, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/false));
        application_space.pending_probe_packet = SentPacketRecord{};
        record(application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/false));
        application_space.pending_probe_packet.reset();
        record(application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/true, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/false));
        record(application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/true,
            /*has_pending_retire_connection_id_frames=*/false));
        record(application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/true));
        application_space.send_crypto.append(std::array{std::byte{0x01}});
        record(application_space_has_sendable_data(
            /*application_ack_due=*/false, /*pending_application_send=*/false, application_space,
            /*has_pending_new_token_frames=*/false, /*has_pending_new_connection_id_frames=*/false,
            /*has_pending_retire_connection_id_frames=*/false));
    }
    {
        PacketSpaceState initial_space;
        PacketSpaceState handshake_space;
        PacketSpaceState application_space;
        record(
            packet_space_has_no_in_flight_ack_eliciting_packet(/*discarded=*/true, initial_space));
        record(
            packet_space_has_no_in_flight_ack_eliciting_packet(/*discarded=*/false, initial_space));
        record(client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/false, initial_space, /*handshake_discarded=*/false,
            handshake_space, application_space));
        record(client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/true, initial_space, /*handshake_discarded=*/true,
            handshake_space, application_space));
        initial_space.recovery.on_packet_sent(
            SentPacketRecord{.packet_number = 101, .ack_eliciting = true, .in_flight = true});
        record(!client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/false, initial_space, /*handshake_discarded=*/true,
            handshake_space, application_space));
        record(client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/true, initial_space, /*handshake_discarded=*/true,
            handshake_space, application_space));
        initial_space = PacketSpaceState{};
        record(client_handshake_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
            QuicCoreTimePoint{}, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space, application_space));
        record(!client_handshake_keepalive_is_eligible(
            EndpointRole::server, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
            QuicCoreTimePoint{}, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space, application_space));
        record(!client_handshake_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/false,
            QuicCoreTimePoint{}, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space, application_space));
        record(!client_handshake_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space, application_space));
        record(!client_handshake_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
            std::nullopt, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space, application_space));
        record(client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::server, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/false,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            std::nullopt, /*has_receive_interest=*/true, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space));
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/false, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        record(client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        handshake_space.recovery.on_packet_sent(
            SentPacketRecord{.packet_number = 102, .ack_eliciting = true, .in_flight = true});
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/true,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        handshake_space = PacketSpaceState{};

        handshake_space.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x44});
        record(has_client_handshake_keepalive_space(QuicCoreTimePoint{},
                                                    /*initial_discarded=*/true,
                                                    /*handshake_discarded=*/false,
                                                    handshake_space));
        record(client_handshake_keepalive_packet_space(QuicCoreTimePoint{},
                                                       /*initial_discarded=*/false, initial_space,
                                                       /*handshake_discarded=*/false,
                                                       handshake_space) == &handshake_space);
        record(client_handshake_keepalive_packet_space(QuicCoreTimePoint{},
                                                       /*initial_discarded=*/true, initial_space,
                                                       /*handshake_discarded=*/false,
                                                       handshake_space) == &handshake_space);
        handshake_space.write_secret.reset();
        record(client_handshake_keepalive_packet_space(QuicCoreTimePoint{},
                                                       /*initial_discarded=*/false, initial_space,
                                                       /*handshake_discarded=*/false,
                                                       handshake_space) == &initial_space);
        record(client_handshake_keepalive_packet_space(std::nullopt,
                                                       /*initial_discarded=*/false, initial_space,
                                                       /*handshake_discarded=*/false,
                                                       handshake_space) == nullptr);
        record(client_handshake_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
            QuicCoreTimePoint{}, /*initial_discarded=*/false, initial_space,
            /*handshake_discarded=*/false, handshake_space, application_space));
        record(client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/false, initial_space, /*handshake_discarded=*/false,
            handshake_space, application_space));
        record(
            packet_space_has_no_in_flight_ack_eliciting_packet(/*discarded=*/true, initial_space));
    }
    {
        PacketSpaceState initial_space;
        PacketSpaceState application_space;
        initial_space.recovery.on_packet_sent(
            SentPacketRecord{.packet_number = 1, .ack_eliciting = true, .in_flight = true});
        record(client_handshake_recovery_probe_has_other_space_in_flight(
            /*initial_discarded=*/false, initial_space, application_space));
    }
    {
        record(simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::cubic));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/true, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/true, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::client,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/true, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/true,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::bbr));
        record(!simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::copa));

        record(simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::cubic));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/true, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/true, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::client,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/true, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/true,
            QuicCongestionControlAlgorithm::newreno));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::bbr));
        record(!simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false, EndpointRole::server,
            /*qlog_enabled=*/false, /*packet_trace_enabled=*/false,
            QuicCongestionControlAlgorithm::copa));

        record(simple_stream_congestion_batch_algorithm_is_supported(
            QuicCongestionControlAlgorithm::newreno));
        record(simple_stream_congestion_batch_algorithm_is_supported(
            QuicCongestionControlAlgorithm::cubic));
        record(!simple_stream_congestion_batch_algorithm_is_supported(
            QuicCongestionControlAlgorithm::bbr));
        record(!simple_stream_congestion_batch_algorithm_is_supported(
            QuicCongestionControlAlgorithm::copa));

        SentPacketRecord key_update_packet;
        key_update_packet.protection_key_update_generation = 7;
        record(
            !acked_current_key_update_generation(nullptr,
                                                 /*current_application_write_key_generation=*/7));
        record(acked_current_key_update_generation(&key_update_packet,
                                                   /*current_application_write_key_generation=*/7));
        record(!acked_current_key_update_generation(
            &key_update_packet, /*current_application_write_key_generation=*/8));

        record(should_process_simple_stream_ack_ecn(
            /*largest_acknowledged_was_newly_acked=*/true));
        record(!should_process_simple_stream_ack_ecn(
            /*largest_acknowledged_was_newly_acked=*/false));
        record(should_reset_pto_after_ack(/*suppress_pto_reset=*/false));
        record(!should_reset_pto_after_ack(/*suppress_pto_reset=*/true));
        record(has_ack_stream_metadata_for_retirement(
            StreamFrameSendMetadata{.stream_id = 0, .offset = 0, .length = 1}));
        record(!has_ack_stream_metadata_for_retirement(std::nullopt));

        auto stream = make_implicit_stream_state(0, EndpointRole::client);
        record(!stream_has_lost_send_data_for_state_change(stream));
        stream.send_buffer.append(bytes_from_ints_for_tests({0x31, 0x32}));
        static_cast<void>(stream.send_buffer.take_ranges(/*max_bytes=*/2));
        stream.send_buffer.mark_lost(/*offset=*/0, /*length=*/2);
        record(stream_has_lost_send_data_for_state_change(stream));
        stream.reset_state = StreamControlFrameState::pending;
        record(!stream_has_lost_send_data_for_state_change(stream));

        const auto now = QuicCoreTimePoint{} + QuicCoreDuration{1};
        record(should_use_single_path_simple_stream_ack_ecn(
            /*single_path_summary=*/true, QuicPathId{3}, now));
        record(!should_use_single_path_simple_stream_ack_ecn(
            /*single_path_summary=*/false, QuicPathId{3}, now));
        record(!should_use_single_path_simple_stream_ack_ecn(
            /*single_path_summary=*/true, std::nullopt, now));
        record(!should_use_single_path_simple_stream_ack_ecn(
            /*single_path_summary=*/true, QuicPathId{3}, std::nullopt));

        record(ecn_counts_decreased(AckEcnCounts{.ect0 = 1}, AckEcnCounts{.ect0 = 2}));
        record(ecn_counts_decreased(AckEcnCounts{.ect1 = 1}, AckEcnCounts{.ect1 = 2}));
        record(ecn_counts_decreased(AckEcnCounts{.ecn_ce = 1}, AckEcnCounts{.ecn_ce = 2}));
        record(!ecn_counts_decreased(AckEcnCounts{.ect0 = 2, .ect1 = 2, .ecn_ce = 2},
                                     AckEcnCounts{.ect0 = 1, .ect1 = 1, .ecn_ce = 1}));
        record(ecn_feedback_is_invalid(/*delta_ect0=*/0, /*delta_ect1=*/0, /*delta_ce=*/0,
                                       /*newly_acked_ect0=*/1, /*newly_acked_ect1=*/0,
                                       /*current_ect0=*/0, /*current_ect1=*/0,
                                       /*total_sent_ect0=*/0, /*total_sent_ect1=*/0));
        record(ecn_feedback_is_invalid(/*delta_ect0=*/0, /*delta_ect1=*/0, /*delta_ce=*/0,
                                       /*newly_acked_ect0=*/0, /*newly_acked_ect1=*/1,
                                       /*current_ect0=*/0, /*current_ect1=*/0,
                                       /*total_sent_ect0=*/0, /*total_sent_ect1=*/0));
        record(ecn_feedback_is_invalid(/*delta_ect0=*/1, /*delta_ect1=*/1, /*delta_ce=*/0,
                                       /*newly_acked_ect0=*/0, /*newly_acked_ect1=*/0,
                                       /*current_ect0=*/2, /*current_ect1=*/0,
                                       /*total_sent_ect0=*/1, /*total_sent_ect1=*/0));
        record(ecn_feedback_is_invalid(/*delta_ect0=*/1, /*delta_ect1=*/1, /*delta_ce=*/0,
                                       /*newly_acked_ect0=*/0, /*newly_acked_ect1=*/0,
                                       /*current_ect0=*/0, /*current_ect1=*/2,
                                       /*total_sent_ect0=*/0, /*total_sent_ect1=*/1));
        record(!ecn_feedback_is_invalid(/*delta_ect0=*/1, /*delta_ect1=*/1, /*delta_ce=*/1,
                                        /*newly_acked_ect0=*/1, /*newly_acked_ect1=*/1,
                                        /*current_ect0=*/1, /*current_ect1=*/1,
                                        /*total_sent_ect0=*/1, /*total_sent_ect1=*/1));
        record(should_mark_ecn_probing_path_capable(QuicPathEcnState::probing));
        record(!should_mark_ecn_probing_path_capable(QuicPathEcnState::capable));
        record(!should_mark_ecn_probing_path_capable(QuicPathEcnState::failed));

        record(!should_ensure_inbound_application_path(
            /*paths_empty=*/true, QuicPathId{0}, std::nullopt));
        record(should_ensure_inbound_application_path(
            /*paths_empty=*/false, QuicPathId{0}, std::nullopt));
        record(should_ensure_inbound_application_path(
            /*paths_empty=*/true, QuicPathId{1}, std::nullopt));
        record(should_ensure_inbound_application_path(
            /*paths_empty=*/true, QuicPathId{0}, QuicPathId{2}));
        record(zero_rtt_state_present(/*read_secret_available=*/true,
                                      /*write_secret_available=*/false));
        record(zero_rtt_state_present(/*read_secret_available=*/false,
                                      /*write_secret_available=*/true));
        record(!zero_rtt_state_present(/*read_secret_available=*/false,
                                       /*write_secret_available=*/false));
        record(should_arm_zero_rtt_discard_deadline_after_application_packet(
            EndpointRole::server, /*zero_rtt_read_secret_available=*/true));
        record(!should_arm_zero_rtt_discard_deadline_after_application_packet(
            EndpointRole::client, /*zero_rtt_read_secret_available=*/true));
        record(!should_arm_zero_rtt_discard_deadline_after_application_packet(
            EndpointRole::server, /*zero_rtt_read_secret_available=*/false));
    }
    {
        PacketSpaceState initial_space;
        PacketSpaceState handshake_space;
        PacketSpaceState application_space;
        initial_space.recovery.on_packet_sent(
            SentPacketRecord{.packet_number = 1, .ack_eliciting = true, .in_flight = true});
        handshake_space.recovery.on_packet_sent(
            SentPacketRecord{.packet_number = 2, .ack_eliciting = true, .in_flight = true});
        application_space.recovery.on_packet_sent(
            SentPacketRecord{.packet_number = 3, .ack_eliciting = true, .in_flight = true});
        record(client_handshake_recovery_probe_has_other_space_in_flight(
            /*initial_discarded=*/true, initial_space, application_space));
        PacketSpaceState application_space_empty;
        record(client_handshake_recovery_probe_has_other_space_in_flight(
            /*initial_discarded=*/false, initial_space, application_space_empty));
        record(!packet_space_has_no_in_flight_ack_eliciting_packet(/*discarded=*/false,
                                                                   initial_space));
        record(
            packet_space_has_no_in_flight_ack_eliciting_packet(/*discarded=*/true, initial_space));
        record(!client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/false, initial_space, /*handshake_discarded=*/false,
            handshake_space, application_space));
        record(!client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/true, initial_space, /*handshake_discarded=*/false,
            handshake_space, application_space));
        record(!client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/false, initial_space, /*handshake_discarded=*/true,
            handshake_space, application_space));
        record(!client_keepalive_has_no_in_flight_packets(
            /*initial_discarded=*/true, initial_space, /*handshake_discarded=*/true,
            handshake_space, application_space));
        record(!client_handshake_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
            QuicCoreTimePoint{}, /*initial_discarded=*/true, initial_space,
            /*handshake_discarded=*/true, handshake_space, application_space));
        record(!client_receive_keepalive_is_eligible(
            EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/true,
            QuicCoreTimePoint{}, /*has_receive_interest=*/true, /*initial_discarded=*/false,
            initial_space, /*handshake_discarded=*/false, handshake_space));
        record(client_handshake_keepalive_packet_space(QuicCoreTimePoint{},
                                                       /*initial_discarded=*/false, initial_space,
                                                       /*handshake_discarded=*/false,
                                                       handshake_space) == &initial_space);
    }
    {
        std::vector<SentPacketRecord> lost_packets;
        record(!has_timer_lost_packets_for_profile(/*profile_enabled=*/true, lost_packets));
        lost_packets.push_back(SentPacketRecord{});
        record(has_timer_lost_packets_for_profile(/*profile_enabled=*/true, lost_packets));
        record(!has_timer_lost_packets_for_profile(/*profile_enabled=*/false, lost_packets));
    }
    {
        ConnectionFlowControlState flow{.advertised_max_data = 9};
        std::uint64_t connection_refresh_count = 0;
        maybe_refresh_connection_credit_for_data_blocked(DataBlockedFrame{.maximum_data = 8}, flow,
                                                         [&] { ++connection_refresh_count; });
        maybe_refresh_connection_credit_for_data_blocked(DataBlockedFrame{.maximum_data = 9}, flow,
                                                         [&] { ++connection_refresh_count; });
        record(connection_refresh_count == 1u);

        auto stream = make_implicit_stream_state(0, EndpointRole::client);
        stream.flow_control.advertised_max_stream_data = 5;
        std::uint64_t stream_refresh_count = 0;
        maybe_refresh_stream_credit_for_data_blocked(
            StreamDataBlockedFrame{.stream_id = 0, .maximum_stream_data = 4}, stream,
            [&] { ++stream_refresh_count; });
        maybe_refresh_stream_credit_for_data_blocked(
            StreamDataBlockedFrame{.stream_id = 0, .maximum_stream_data = 5}, stream,
            [&] { ++stream_refresh_count; });
        record(stream_refresh_count == 1u);
    }
    record(!should_skip_available_secret(EncryptionLevel::initial,
                                         /*initial_packet_space_discarded=*/false,
                                         /*handshake_packet_space_discarded=*/false));
    record(!should_skip_available_secret(EncryptionLevel::handshake,
                                         /*initial_packet_space_discarded=*/false,
                                         /*handshake_packet_space_discarded=*/false));
    record(!should_skip_available_secret(EncryptionLevel::application,
                                         /*initial_packet_space_discarded=*/true,
                                         /*handshake_packet_space_discarded=*/true));
    record(should_skip_available_secret(EncryptionLevel::initial,
                                        /*initial_packet_space_discarded=*/true,
                                        /*handshake_packet_space_discarded=*/false));
    record(should_skip_available_secret(EncryptionLevel::handshake,
                                        /*initial_packet_space_discarded=*/false,
                                        /*handshake_packet_space_discarded=*/true));
    {
        TrafficSecret read_secret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = bytes_from_ints_for_tests({0x10}),
        };
        TrafficSecret write_secret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = bytes_from_ints_for_tests({0x11}),
        };
        std::vector<DeferredProtectedDatagram> deferred_packets;
        const std::array<std::byte, 1> short_header{std::byte{0x40}};
        TransportParameters peer_parameters;
        record(can_skip_steady_state_receive_sync(
            EndpointRole::server, HandshakeStatus::connected,
            /*peer_transport_parameters_validated=*/true, read_secret, write_secret,
            /*resumption_state_emitted=*/false, /*peer_preferred_address_emitted=*/false,
            peer_parameters, /*qlog_session=*/nullptr, short_header));
        record(!traffic_secret_cache_is_primed(std::nullopt));
        record(!traffic_secret_cache_is_primed(read_secret));
        read_secret.cached_packet_protection_keys = PacketProtectionKeys{};
        record(traffic_secret_cache_is_primed(read_secret));
        record(can_skip_steady_state_receive_sync(
            EndpointRole::client, HandshakeStatus::connected,
            /*peer_transport_parameters_validated=*/true, read_secret, write_secret,
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/false,
            peer_parameters, /*qlog_session=*/nullptr, short_header));
        record(!can_skip_steady_state_receive_sync(
            EndpointRole::client, HandshakeStatus::connected,
            /*peer_transport_parameters_validated=*/true, read_secret, write_secret,
            /*resumption_state_emitted=*/false, /*peer_preferred_address_emitted=*/false,
            peer_parameters, /*qlog_session=*/nullptr, short_header));
        peer_parameters.preferred_address =
            PreferredAddress{.connection_id = ConnectionId{std::byte{0x01}}};
        record(!can_skip_steady_state_receive_sync(
            EndpointRole::client, HandshakeStatus::connected,
            /*peer_transport_parameters_validated=*/true, read_secret, write_secret,
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/false,
            peer_parameters, /*qlog_session=*/nullptr, short_header));
        record(can_skip_steady_state_receive_sync(
            EndpointRole::client, HandshakeStatus::connected,
            /*peer_transport_parameters_validated=*/true, read_secret, write_secret,
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/true,
            peer_parameters, /*qlog_session=*/nullptr, short_header));
        record(!can_skip_steady_state_receive_sync(
            EndpointRole::client, HandshakeStatus::connected,
            /*peer_transport_parameters_validated=*/true, read_secret, write_secret,
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/true,
            peer_parameters, /*qlog_session=*/nullptr, std::array<std::byte, 1>{std::byte{0xc0}}));
        record(can_use_single_short_header_datagram_fast_path(
            /*steady_state_one_rtt_receive=*/true, /*allow_in_place_receive_decode=*/true,
            std::nullopt, short_header));
        record(!can_use_single_short_header_datagram_fast_path(
            /*steady_state_one_rtt_receive=*/false, /*allow_in_place_receive_decode=*/true,
            std::nullopt, short_header));
        record(!can_use_single_short_header_datagram_fast_path(
            /*steady_state_one_rtt_receive=*/true, /*allow_in_place_receive_decode=*/false,
            std::nullopt, short_header));
        record(!can_use_single_short_header_datagram_fast_path(
            /*steady_state_one_rtt_receive=*/true, /*allow_in_place_receive_decode=*/true,
            read_secret, short_header));
        record(!can_use_single_short_header_datagram_fast_path(
            /*steady_state_one_rtt_receive=*/true, /*allow_in_place_receive_decode=*/true,
            std::nullopt, std::span<const std::byte>{}));
        record(!can_use_single_short_header_datagram_fast_path(
            /*steady_state_one_rtt_receive=*/true, /*allow_in_place_receive_decode=*/true,
            std::nullopt, std::array<std::byte, 1>{std::byte{0x00}}));
        record(can_skip_outbound_tls_sync_now(
            HandshakeStatus::connected, /*peer_transport_parameters_validated=*/true, read_secret,
            write_secret, /*qlog_session=*/nullptr, deferred_packets));
        record(!can_skip_outbound_tls_sync_now(
            HandshakeStatus::in_progress, /*peer_transport_parameters_validated=*/true, read_secret,
            write_secret, /*qlog_session=*/nullptr, deferred_packets));
        record(!can_skip_outbound_tls_sync_now(
            HandshakeStatus::connected, /*peer_transport_parameters_validated=*/false, read_secret,
            write_secret, /*qlog_session=*/nullptr, deferred_packets));
        record(!can_skip_outbound_tls_sync_now(
            HandshakeStatus::connected, /*peer_transport_parameters_validated=*/true, std::nullopt,
            write_secret, /*qlog_session=*/nullptr, deferred_packets));
        record(!can_skip_outbound_tls_sync_now(
            HandshakeStatus::connected, /*peer_transport_parameters_validated=*/true, read_secret,
            std::nullopt, /*qlog_session=*/nullptr, deferred_packets));
        deferred_packets.emplace_back(DatagramBuffer{std::byte{0x01}}, /*id=*/1);
        record(!can_skip_outbound_tls_sync_now(
            HandshakeStatus::connected, /*peer_transport_parameters_validated=*/true, read_secret,
            write_secret, /*qlog_session=*/nullptr, deferred_packets));
    }
    {
        TransportParameters peer_parameters;
        peer_parameters.preferred_address =
            PreferredAddress{.connection_id = ConnectionId{std::byte{0x01}}};
        record(!client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/false, /*peer_preferred_address_emitted=*/false,
            std::nullopt));
        record(!client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/false, /*peer_preferred_address_emitted=*/true,
            peer_parameters));
        record(!client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/false,
            peer_parameters));
        record(client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/true,
            peer_parameters));
        record(client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/false,
            std::nullopt));
        record(client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/true,
            std::nullopt));
        peer_parameters.preferred_address.reset();
        record(client_outbound_tls_sync_can_skip_resumption(
            /*resumption_state_emitted=*/true, /*peer_preferred_address_emitted=*/false,
            peer_parameters));
    }
    {
        PathMtuState mtu;
        mtu.outstanding_probe_packet_number = 7;
        record(should_clear_outstanding_pmtu_probe(mtu, 7));
        record(!should_clear_outstanding_pmtu_probe(mtu, 8));
        mtu.outstanding_probe_size = 1300;
        mtu.probe_ceiling = 1200;
        record(should_clear_outstanding_pmtu_probe_after_ceiling(mtu));
        mtu.outstanding_probe_size = 1200;
        record(!should_clear_outstanding_pmtu_probe_after_ceiling(mtu));
        mtu.enabled = true;
        mtu.validated_datagram_size = 1200;
        mtu.probe_ceiling = 1300;
        record(pmtud_next_probe_time(mtu, QuicCoreTimePoint{}, QuicCoreDuration{1}).has_value());
        mtu.validated_datagram_size = 1300;
        record(!pmtud_next_probe_time(mtu, QuicCoreTimePoint{}, QuicCoreDuration{1}).has_value());
        mtu.enabled = false;
        mtu.validated_datagram_size = 1200;
        mtu.probe_ceiling = 1300;
        record(!pmtud_next_probe_time(mtu, QuicCoreTimePoint{}, QuicCoreDuration{1}).has_value());
        mtu.enabled = true;
        mtu.outstanding_probe_packet_number.reset();
        record(should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                /*pending_stream_bytes=*/1301));
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/false,
                                                 /*pending_stream_bytes=*/1301));
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1200));
        mtu.next_probe_time = QuicCoreTimePoint{};
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1301));
        mtu.next_probe_time.reset();
        mtu.outstanding_probe_packet_number = 8;
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1301));
        mtu.outstanding_probe_packet_number.reset();
        mtu.validated_datagram_size = mtu.probe_ceiling;
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1301));
        mtu.enabled = false;
        mtu.validated_datagram_size = 1200;
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1301));
    }
    record(should_reset_client_handshake_peer_state_for_source(
        EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
        ConnectionId{std::byte{0x01}}, ConnectionId{std::byte{0x02}}));
    record(!should_reset_client_handshake_peer_state_for_source(
        EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
        ConnectionId{std::byte{0x01}}, ConnectionId{std::byte{0x01}}));
    record(!should_reset_client_handshake_peer_state_for_source(
        EndpointRole::server, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
        ConnectionId{std::byte{0x01}}, ConnectionId{std::byte{0x02}}));
    record(!should_reset_client_handshake_peer_state_for_source(
        EndpointRole::client, HandshakeStatus::connected, /*handshake_confirmed=*/false,
        ConnectionId{std::byte{0x01}}, ConnectionId{std::byte{0x02}}));
    record(!should_reset_client_handshake_peer_state_for_source(
        EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/true,
        ConnectionId{std::byte{0x01}}, ConnectionId{std::byte{0x02}}));
    record(!should_reset_client_handshake_peer_state_for_source(
        EndpointRole::client, HandshakeStatus::in_progress, /*handshake_confirmed=*/false,
        std::nullopt, ConnectionId{std::byte{0x02}}));
    {
        SentPacketRecord pending_probe{.is_pmtu_probe = true, .pmtu_probe_size = 1300};
        record(should_use_pending_pmtu_probe_size(
            /*allow_pmtu_probe_size=*/true, /*anti_amplification_limited=*/false, pending_probe));
        record(!should_use_pending_pmtu_probe_size(
            /*allow_pmtu_probe_size=*/false, /*anti_amplification_limited=*/false, pending_probe));
        record(!should_use_pending_pmtu_probe_size(
            /*allow_pmtu_probe_size=*/true, /*anti_amplification_limited=*/true, pending_probe));
        pending_probe.pmtu_probe_size = 0;
        record(!should_use_pending_pmtu_probe_size(
            /*allow_pmtu_probe_size=*/true, /*anti_amplification_limited=*/false, pending_probe));
    }
    {
        PathMtuState mtu;
        mtu.validated_datagram_size = 1200;
        remember_pmtud_failed_probe_size(mtu, 1300);
        record(should_keep_searching_for_pmtu_probe_size(mtu, 1300));
        record(!should_keep_searching_for_pmtu_probe_size(mtu, 1199));
        record(!should_keep_searching_for_pmtu_probe_size(mtu, 1250));
        mtu.enabled = true;
        mtu.validated_datagram_size = 1200;
        mtu.probe_ceiling = 1300;
        record(should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                /*pending_stream_bytes=*/1201));
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/false,
                                                 /*pending_stream_bytes=*/1201));
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1200));
        mtu.next_probe_time = QuicCoreTimePoint{};
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1201));
        mtu.next_probe_time.reset();
        mtu.outstanding_probe_packet_number = 1;
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1201));
        mtu.outstanding_probe_packet_number.reset();
        mtu.validated_datagram_size = 1300;
        record(!should_arm_pmtu_probe_after_send(mtu, /*application_write_secret_available=*/true,
                                                 /*pending_stream_bytes=*/1301));
    }
    {
        std::optional<std::uint64_t> single_candidate;
        std::vector<std::uint64_t> additional_candidates;
        note_retirement_candidate_stream_id(single_candidate, additional_candidates, 4);
        note_retirement_candidate_stream_id(single_candidate, additional_candidates, 8);
        note_retirement_candidate_stream_id(single_candidate, additional_candidates, 8);
        record(single_candidate == 4u);
        record(additional_candidates == std::vector<std::uint64_t>{8});
    }
    {
        RecoveryRttState rtt;
        SendProfileCounters profile;
        record_latest_rtt_sample_for_profile(rtt, profile);
        record(profile.rtt_samples == 0u);
        rtt.latest_rtt = QuicCoreDuration{7};
        record_latest_rtt_sample_for_profile(rtt, profile);
        record(profile.latest_rtt_us_sum > 0u);
        record(profile.latest_rtt_us_max > 0u);
    }
    record(!fin_only_stream_frame_cannot_fit(/*fin_sendable=*/true,
                                             /*has_send_final_size=*/true));
    record(fin_only_stream_frame_cannot_fit(/*fin_sendable=*/false,
                                            /*has_send_final_size=*/true));
    record(fin_only_stream_frame_cannot_fit(/*fin_sendable=*/true,
                                            /*has_send_final_size=*/false));
    {
        TrafficSecret previous_secret;
        auto storage = std::make_shared<std::vector<std::byte>>(4, std::byte{0x01});
        auto bytes = std::span<const std::byte>(*storage);
        record(inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/true, std::nullopt, HandshakeStatus::connected,
            storage, bytes));
        record(!inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/false, std::nullopt, HandshakeStatus::connected,
            storage, bytes));
        record(!inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/true, previous_secret, HandshakeStatus::connected,
            storage, bytes));
        record(!inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/true, std::nullopt, HandshakeStatus::in_progress,
            storage, bytes));
        record(!inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/true, std::nullopt, HandshakeStatus::connected,
            nullptr, bytes));
        auto empty_storage = std::make_shared<std::vector<std::byte>>();
        record(!inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/true, std::nullopt, HandshakeStatus::connected,
            empty_storage, bytes));
        record(!inbound_packet_storage_range_is_eligible(
            /*allow_in_place_receive_decode=*/true, std::nullopt, HandshakeStatus::connected,
            storage, std::span<const std::byte>{}));
        const auto begin = reinterpret_cast<std::uintptr_t>(storage->data());
        const auto end = begin + storage->size();
        record(packet_bytes_start_inside_storage(begin, begin, end));
        record(packet_bytes_start_inside_storage(end, begin, end));
        record(!packet_bytes_start_inside_storage(begin - 1, begin, end));
        record(!packet_bytes_start_inside_storage(end + 1, begin, end));
    }
    record(no_ack_control_candidate_leaves_stream_budget(
        /*no_ack_control_candidate_size=*/18, /*congestion_limited_datagram_size=*/20,
        /*minimum_stream_wire_bytes=*/2));
    record(earliest_deadline(std::nullopt, QuicCoreTimePoint{} + QuicCoreDuration{7}) ==
           QuicCoreTimePoint{} + QuicCoreDuration{7});
    record(earliest_deadline(QuicCoreTimePoint{} + QuicCoreDuration{9},
                             QuicCoreTimePoint{} + QuicCoreDuration{7}) ==
           QuicCoreTimePoint{} + QuicCoreDuration{7});
    record(earliest_deadline(QuicCoreTimePoint{} + QuicCoreDuration{5},
                             QuicCoreTimePoint{} + QuicCoreDuration{7}) ==
           QuicCoreTimePoint{} + QuicCoreDuration{5});
    {
        PacketSpaceState zero_rtt_space;
        PacketSpaceState application_space;
        record(!can_send_zero_rtt_application_packets(
            EndpointRole::server, HandshakeStatus::in_progress, zero_rtt_space));
        record(!can_send_zero_rtt_application_packets(EndpointRole::client,
                                                      HandshakeStatus::connected, zero_rtt_space));
        record(!can_send_zero_rtt_application_packets(
            EndpointRole::client, HandshakeStatus::in_progress, zero_rtt_space));
        zero_rtt_space.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x66});
        record(can_send_zero_rtt_application_packets(EndpointRole::client,
                                                     HandshakeStatus::in_progress, zero_rtt_space));
        record(can_send_application_packets(EndpointRole::client, HandshakeStatus::in_progress,
                                            zero_rtt_space, application_space));
        application_space.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x67});
        record(can_send_application_packets(EndpointRole::server, HandshakeStatus::connected,
                                            PacketSpaceState{}, application_space));
        application_space.write_secret.reset();
        record(!can_send_application_packets(EndpointRole::server, HandshakeStatus::connected,
                                             PacketSpaceState{}, application_space));
        record(!application_send_congestion_is_forced(/*force=*/false, /*bypass=*/false,
                                                      application_space));
        record(!application_send_congestion_is_forced(/*force=*/true, /*bypass=*/true,
                                                      application_space));
        record(!application_send_congestion_is_forced(/*force=*/true, /*bypass=*/false,
                                                      application_space));
        application_space.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x68});
        record(application_send_congestion_is_forced(/*force=*/true, /*bypass=*/false,
                                                     application_space));
    }
    {
        std::vector<DeferredProtectedDatagram> deferred_packets;
        const std::array payload{std::byte{0x40}, std::byte{0x01}};
        record(!defer_short_header_packet_before_server_handshake_complete(
            /*allow_defer=*/false, /*short_header_packet=*/true, EndpointRole::server,
            HandshakeStatus::in_progress, deferred_packets, payload, QuicPathId{1},
            std::optional<std::uint32_t>{7}, QuicEcnCodepoint::ect0));
        record(deferred_packets.empty());
        record(defer_short_header_packet_before_server_handshake_complete(
            /*allow_defer=*/true, /*short_header_packet=*/true, EndpointRole::server,
            HandshakeStatus::in_progress, deferred_packets, payload, QuicPathId{1},
            std::optional<std::uint32_t>{7}, QuicEcnCodepoint::ect0));
        record(deferred_packets.size() == 1u);
        record(deferred_packets.front().datagram_id == 7u);
        record(deferred_packets.front().ecn == QuicEcnCodepoint::ect0);
        record(!should_defer_decoded_protected_packet(
            /*allow_defer=*/false, ReceivedProtectedOneRttStreamPacket{}, EndpointRole::server,
            HandshakeStatus::in_progress));
        record(should_defer_decoded_protected_packet(
            /*allow_defer=*/true, ReceivedProtectedOneRttStreamPacket{}, EndpointRole::server,
            HandshakeStatus::in_progress));
    }
    {
        maybe_trace_pmtud_timeout(ConnectionId{std::byte{0x24}});
        PathState untraced_path{.id = QuicPathId{10}};
        maybe_trace_pmtu_no_probe(ConnectionId{std::byte{0x25}}, untraced_path);
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        const ConnectionId source_connection_id{std::byte{0x42}};
        maybe_trace_pmtud_timeout(source_connection_id);
        PathState path{.id = QuicPathId{9}};
        path.mtu.validated_datagram_size = 1200;
        path.mtu.probe_ceiling = 1400;
        maybe_trace_pmtu_no_probe(source_connection_id, path);
    }
    {
        std::uint64_t last_datagram_id = 11;
        maybe_record_packet_inspection_datagram_id(last_datagram_id, PacketInspectionDatagramId{22},
                                                   PacketInspectionCount{0});
        record(last_datagram_id == 11u);
        maybe_record_packet_inspection_datagram_id(last_datagram_id, PacketInspectionDatagramId{22},
                                                   PacketInspectionCount{1});
        record(last_datagram_id == 22u);
    }
    record(pmtu_probe_padding_already_satisfied(/*target_pmtu_probe_size=*/0,
                                                /*datagram_size=*/1));
    record(pmtu_probe_padding_already_satisfied(/*target_pmtu_probe_size=*/100,
                                                /*datagram_size=*/100));
    record(!pmtu_probe_padding_already_satisfied(/*target_pmtu_probe_size=*/100,
                                                 /*datagram_size=*/99));
    record(should_fail_after_probe_credit_retry(/*retried=*/false, /*failed=*/false));
    record(should_fail_after_probe_credit_retry(/*retried=*/true, /*failed=*/true));
    record(!should_fail_after_probe_credit_retry(/*retried=*/true, /*failed=*/false));
    {
        std::map<QuicPathId, PathState> paths;
        paths.emplace(1, PathState{
                             .id = 1,
                             .challenge_pending = true,
                             .outstanding_challenge = std::array<std::byte, 8>{},
                         });
        record(has_pending_ack_only_path_validation_frame(paths, QuicPathId{1}));
        paths.begin()->second.outstanding_challenge.reset();
        record(!has_pending_ack_only_path_validation_frame(paths, QuicPathId{1}));
    }
    record(optional_frame_trace_value(std::optional<MaxDataFrame>{}) == 0u);
    record(optional_frame_trace_value(std::optional<DataBlockedFrame>{}) == 0u);
    record(optional_frame_trace_value(MaxDataFrame{.maximum_data = 44}) == 44u);
    record(optional_frame_trace_value(DataBlockedFrame{.maximum_data = 45}) == 45u);
    record(!use_fast_serialized_one_rtt_commit_for_packet(
        EndpointRole::client, /*packets_empty=*/true, /*qlog_session=*/nullptr,
        /*use_zero_rtt_packet_protection=*/false, /*has_application_close=*/false));
    record(!use_fast_serialized_one_rtt_commit_for_packet(
        EndpointRole::server, /*packets_empty=*/true, /*qlog_session=*/nullptr,
        /*use_zero_rtt_packet_protection=*/true, /*has_application_close=*/false));
    record(use_fast_serialized_one_rtt_commit_for_packet(
        EndpointRole::server, /*packets_empty=*/true, /*qlog_session=*/nullptr,
        /*use_zero_rtt_packet_protection=*/false, /*has_application_close=*/false));
    {
        SentPacketRecord non_probe;
        record(!pmtud_packet_deadline_candidate_is_live(nullptr));
        record(!pmtud_packet_deadline_candidate_is_live(&non_probe));
        SentPacketRecord probe;
        probe.is_pmtu_probe = true;
        record(pmtud_packet_deadline_candidate_is_live(&probe));
    }
    record(!make_client_receive_keepalive_reference_time(std::nullopt, std::nullopt).has_value());
    {
        std::vector<SentPacketRecord> retired_packets;
        record(!append_retired_packet_if_present(retired_packets, std::nullopt));
        record(retired_packets.empty());
    }
    {
        SentPacketRecord probe;
        probe.is_pmtu_probe = true;
        probe.pmtu_probe_size = 0;
        probe.bytes_in_flight = 123;
        probe.in_flight = true;
        const auto tracked =
            prepare_pmtu_probe_packet_for_tracking(probe, std::optional<std::size_t>{99}, 111);
        record(tracked == 99u);
        record(probe.pmtu_probe_size == 99u);
        record(!probe.in_flight);
        record(probe.bytes_in_flight == 0u);
    }
    {
        SentPacketRecord probe;
        probe.is_pmtu_probe = true;
        probe.pmtu_probe_size = 150;
        const auto tracked =
            prepare_pmtu_probe_packet_for_tracking(probe, std::optional<std::size_t>{120}, 111);
        record(tracked == 120u);
        record(probe.pmtu_probe_size == 120u);
    }
    {
        SentPacketRecord probe;
        probe.is_pmtu_probe = true;
        probe.pmtu_probe_size = 0;
        const auto tracked = prepare_pmtu_probe_packet_for_tracking(probe, std::nullopt, 111);
        record(tracked == 111u);
        record(probe.pmtu_probe_size == 0u);
    }
    {
        StreamFrameSendFragment empty_fragment{
            .stream_id = 0,
            .bytes = SharedBytes(std::vector<std::byte>{}),
            .consumes_flow_control = true,
        };
        record(!stream_fragment_consumes_connection_credit(empty_fragment));
        ConnectionFlowControlState connection_flow{.highest_sent = 5};
        std::uint64_t remaining_credit = 7;
        restore_stream_fragment_connection_credit(empty_fragment, connection_flow,
                                                  remaining_credit);
        record(connection_flow.highest_sent == 5u);
        record(remaining_credit == 7u);

        StreamFrameSendFragment uncounted_fragment{
            .stream_id = 0,
            .bytes = SharedBytes(std::vector<std::byte>{std::byte{0x01}}),
            .consumes_flow_control = false,
        };
        record(!stream_fragment_consumes_connection_credit(uncounted_fragment));
        restore_stream_fragment_connection_credit(uncounted_fragment, connection_flow,
                                                  remaining_credit);
        record(connection_flow.highest_sent == 5u);
        record(remaining_credit == 7u);
    }
    {
        std::map<std::uint64_t, StreamState> restore_streams;
        restore_streams.emplace(0, make_implicit_stream_state(0, EndpointRole::client));
        ConnectionFlowControlState connection_flow{.highest_sent = 9};
        std::uint64_t remaining_credit = 3;
        StreamFrameSendFragment fragment{
            .stream_id = 0,
            .bytes = SharedBytes(std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}}),
            .consumes_flow_control = true,
        };
        maybe_restore_stream_fragment_tail(fragment, fragment.bytes.size(), restore_streams,
                                           connection_flow, remaining_credit);
        record(fragment.bytes.size() == 2u);
        record(connection_flow.highest_sent == 9u);
        record(remaining_credit == 3u);
    }
    {
        std::vector<Frame> frames;
        std::size_t probe_padding_length = 5;
        record(!maybe_add_pmtu_probe_padding(0, frames, probe_padding_length));
        record(frames.empty());
        record(probe_padding_length == 5u);
    }
    {
        std::map<QuicPathId, PathState> paths;
        paths.emplace(1, PathState{.id = 1, .pending_response = std::array<std::byte, 8>{}});
        record(has_pending_ack_only_path_validation_frame(paths, std::nullopt));
    }
    {
        struct PathValidationFramesForTest {
            std::optional<PathChallengeFrame> challenge;
            std::optional<PathResponseFrame> response;
        };
        PathValidationFramesForTest frames;
        record(!ack_only_path_validation_is_ack_eliciting(frames));
        frames.challenge = PathChallengeFrame{};
        record(ack_only_path_validation_is_ack_eliciting(frames));
        frames.challenge.reset();
        frames.response = PathResponseFrame{};
        record(ack_only_path_validation_is_ack_eliciting(frames));
        const OutboundAckHeader ack{.largest_acknowledged = 123};
        record(!ack_largest_for_path_validation_sent_record(false, ack).has_value());
        record(ack_largest_for_path_validation_sent_record(true, ack) == 123u);
        std::size_t noted = 0;
        maybe_note_path_validation_ack_eliciting_send(false, [&] { ++noted; });
        maybe_note_path_validation_ack_eliciting_send(true, [&] { ++noted; });
        record(noted == 1u);
    }
    {
        std::optional<OutboundAckHeader> selected_ack_frame = OutboundAckHeader{};
        std::size_t application_stream_budget = 0;
        auto control_candidate_size = CodecResult<std::size_t>::success(10);
        const auto no_ack_candidate_size = CodecResult<std::size_t>::success(6);
        record(!maybe_select_empty_no_ack_candidate(
            /*base_application_stream_budget=*/2, /*minimum_stream_wire_bytes=*/3,
            selected_ack_frame, application_stream_budget, control_candidate_size,
            no_ack_candidate_size));
        record(selected_ack_frame.has_value());
        record(application_stream_budget == 0u);
        record(control_candidate_size.value() == 10u);
        record(!no_ack_control_candidate_leaves_stream_budget(
            /*no_ack_control_candidate_size=*/20, /*congestion_limited_datagram_size=*/20,
            /*minimum_stream_wire_bytes=*/1));
        record(!no_ack_control_candidate_leaves_stream_budget(
            /*no_ack_control_candidate_size=*/19, /*congestion_limited_datagram_size=*/20,
            /*minimum_stream_wire_bytes=*/2));
    }
    {
        std::optional<OutboundAckHeader> selected_ack_frame = OutboundAckHeader{};
        std::size_t application_stream_budget = 0;
        auto control_candidate_size = CodecResult<std::size_t>::success(10);
        const auto no_ack_candidate_size =
            CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0);
        record(maybe_select_empty_no_ack_candidate(
            /*base_application_stream_budget=*/4, /*minimum_stream_wire_bytes=*/3,
            selected_ack_frame, application_stream_budget, control_candidate_size,
            no_ack_candidate_size));
        record(!selected_ack_frame.has_value());
        record(application_stream_budget == 4u);
        record(!control_candidate_size.has_value());
        record(no_ack_control_candidate_leaves_stream_budget(
            /*no_ack_control_candidate_size=*/16, /*congestion_limited_datagram_size=*/20,
            /*minimum_stream_wire_bytes=*/4));
    }
    {
        auto candidate = CodecResult<std::size_t>::success(9);
        record(maybe_force_no_ack_control_candidate_size_for_tests(candidate).value() == 9u);
        {
            ScopedConnectionDrainTestHook hook(
                &ConnectionDrainTestHooks::force_no_ack_control_candidate_estimate_failure);
            record(!maybe_force_no_ack_control_candidate_size_for_tests(candidate).has_value());
        }
        {
            ScopedConnectionDrainEmptyNoAckControlEstimateTestHook hook;
            const auto forced = maybe_force_no_ack_control_candidate_size_for_tests(candidate);
            record(!forced.has_value());
            record(forced.error().code == CodecErrorCode::empty_packet_payload);
        }
        {
            ScopedConnectionDrainForcedSizeTestHook hook(6);
            record(maybe_force_no_ack_control_candidate_size_for_tests(candidate).value() == 6u);
        }

        std::optional<OutboundAckHeader> selected_ack_frame = OutboundAckHeader{};
        std::size_t application_stream_budget = 0;
        auto control_candidate_size = CodecResult<std::size_t>::success(10);
        record(!maybe_select_sized_no_ack_candidate(
            /*congestion_limited_datagram_size=*/20, /*minimum_stream_wire_bytes=*/4,
            selected_ack_frame, application_stream_budget, control_candidate_size,
            CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0)));
        record(!maybe_select_sized_no_ack_candidate(
            /*congestion_limited_datagram_size=*/20, /*minimum_stream_wire_bytes=*/4,
            selected_ack_frame, application_stream_budget, control_candidate_size,
            CodecResult<std::size_t>::success(18)));
        record(maybe_select_sized_no_ack_candidate(
            /*congestion_limited_datagram_size=*/20, /*minimum_stream_wire_bytes=*/4,
            selected_ack_frame, application_stream_budget, control_candidate_size,
            CodecResult<std::size_t>::success(16)));
        record(!selected_ack_frame.has_value());
        record(application_stream_budget == 4u);
        record(control_candidate_size.value() == 16u);
    }

    {
        SimpleApplicationAckOnlyEligibility eligibility{
            .application_ack_due_now = true,
            .has_base_ack_frame = true,
            .packets_empty = true,
            .qlog_enabled = false,
            .use_zero_rtt_packet_protection = false,
            .can_send_one_rtt_packets = true,
            .pending_application_send_after_blocked_queue = false,
            .application_probe_pending = false,
            .has_pending_new_token_frames = false,
            .has_pending_new_connection_id_frames = false,
            .has_pending_retire_connection_id_frames = false,
            .application_crypto_frames_empty = true,
            .has_current_send_path = true,
            .has_pending_ack_only_path_validation_frame = false,
        };
        record(can_try_simple_application_ack_only(eligibility));
        auto flipped = eligibility;
        flipped.application_ack_due_now = false;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.has_base_ack_frame = false;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.packets_empty = false;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.qlog_enabled = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.use_zero_rtt_packet_protection = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.can_send_one_rtt_packets = false;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.pending_application_send_after_blocked_queue = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.application_probe_pending = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.has_pending_new_token_frames = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.has_pending_new_connection_id_frames = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.has_pending_retire_connection_id_frames = true;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.application_crypto_frames_empty = false;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.has_current_send_path = false;
        record(!can_try_simple_application_ack_only(flipped));
        flipped = eligibility;
        flipped.has_pending_ack_only_path_validation_frame = true;
        record(!can_try_simple_application_ack_only(flipped));
    }

    record(one_rtt_encrypted_packet_count_for_commit(/*has_application_close=*/true,
                                                     /*use_zero_rtt_packet_protection=*/true) ==
           1u);
    record(one_rtt_encrypted_packet_count_for_commit(/*has_application_close=*/false,
                                                     /*use_zero_rtt_packet_protection=*/false) ==
           1u);
    record(one_rtt_encrypted_packet_count_for_commit(/*has_application_close=*/false,
                                                     /*use_zero_rtt_packet_protection=*/true) ==
           0u);
    record(should_consume_selected_datagram_frame_after_commit(
        /*committed_empty=*/false, /*selected_datagram_frame_has_value=*/true));
    record(!should_consume_selected_datagram_frame_after_commit(
        /*committed_empty=*/true, /*selected_datagram_frame_has_value=*/true));
    record(!should_consume_selected_datagram_frame_after_commit(
        /*committed_empty=*/false, /*selected_datagram_frame_has_value=*/false));

    record(packet_number_for_sent_record(ProtectedInitialPacket{.packet_number = 1}) == 1);
    record(packet_number_for_sent_record(ProtectedHandshakePacket{.packet_number = 2}) == 2);
    record(packet_number_for_sent_record(ProtectedZeroRttPacket{.packet_number = 3}) == 3);
    record(packet_number_for_sent_record(ProtectedOneRttPacket{.packet_number = 4}) == 4);

    {
        SerializedProtectedDatagram datagram;
        record(close_packet_metadata_length_for_tracking(datagram) == 0);
        datagram.packet_metadata.push_back(SerializedProtectedPacketMetadata{.length = 7});
        record(close_packet_metadata_length_for_tracking(datagram) == 7);
        ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_missing_close_packet_metadata);
        record(close_packet_metadata_length_for_tracking(datagram) == 0);
    }

    return ok;
}

} // namespace coquic::quic::test

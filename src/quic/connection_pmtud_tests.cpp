#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_support.h"

#include <limits>

namespace coquic::quic::test {

COQUIC_NO_PROFILE bool connection_pmtud_coverage_for_tests() {
    bool ok = true;
#define COQUIC_STRINGIFY_DETAIL(value) #value
#define COQUIC_STRINGIFY(value) COQUIC_STRINGIFY_DETAIL(value)
#define COQUIC_CONNECTION_HOOK_RECORD(expr)                                                        \
    connection_coverage_check(ok, #expr ":" COQUIC_STRINGIFY(__LINE__), static_cast<bool>(expr))

    const auto make_connected_client_connection =
        make_connected_pmtud_client_connection_for_connection_coverage;

    const auto record_packet_space_ack_ranges = [](PacketSpaceState &packet_space,
                                                   std::size_t range_count) {
        for (std::size_t index = 0; index < range_count; ++index) {
            packet_space.received_packets.record_received(static_cast<std::uint64_t>(index * 2u),
                                                          /*ack_eliciting=*/true,
                                                          QuicCoreTimePoint{});
        }
        packet_space.pending_ack_deadline = QuicCoreTimePoint{};
    };
    const auto record_application_ack_ranges = [&](QuicConnection &test_connection,
                                                   std::size_t range_count) {
        record_packet_space_ack_ranges(test_connection.application_space_, range_count);
    };
    const auto queue_application_stream_byte = [](QuicConnection &test_connection,
                                                  std::uint64_t stream_id = 0) {
        constexpr std::array payload{std::byte{0x41}};
        const auto queued = test_connection.queue_stream_send(stream_id, payload, false);
        if (!queued.has_value()) {
            return false;
        }
        test_connection.connection_flow_control_.peer_max_data =
            std::max<std::uint64_t>(test_connection.connection_flow_control_.peer_max_data, 4096);
        auto *stream = test_connection.find_stream_state(stream_id);
        stream->flow_control.peer_max_stream_data =
            std::max<std::uint64_t>(stream->flow_control.peer_max_stream_data, 4096);
        stream->send_flow_control_limit = stream->flow_control.peer_max_stream_data;
        return queued.value();
    };
    const auto queue_application_stream_bytes = [](QuicConnection &test_connection,
                                                   std::size_t size, bool fin = false,
                                                   std::uint64_t stream_id = 0) {
        const auto queued = test_connection.queue_stream_send(
            stream_id, std::vector<std::byte>(size, std::byte{0x41}), fin);
        if (!queued.has_value()) {
            return false;
        }
        test_connection.connection_flow_control_.peer_max_data =
            std::max<std::uint64_t>(test_connection.connection_flow_control_.peer_max_data, 8192);
        auto *stream = test_connection.find_stream_state(stream_id);
        stream->flow_control.peer_max_stream_data =
            std::max<std::uint64_t>(stream->flow_control.peer_max_stream_data, 8192);
        stream->send_flow_control_limit = stream->flow_control.peer_max_stream_data;
        return queued.value();
    };
    const auto reduce_remaining_congestion_window = [](QuicConnection &test_connection,
                                                       std::size_t remaining_bytes) {
        const auto cwnd = test_connection.congestion_controller_.congestion_window();
        test_connection.congestion_controller_.on_packet_sent(cwnd - remaining_bytes,
                                                              /*ack_eliciting=*/true);
    };
    const auto make_path_validation_data = [](std::uint8_t first) {
        return std::array{
            std::byte{first},
            std::byte{static_cast<std::uint8_t>(first + 1u)},
            std::byte{static_cast<std::uint8_t>(first + 2u)},
            std::byte{static_cast<std::uint8_t>(first + 3u)},
            std::byte{static_cast<std::uint8_t>(first + 4u)},
            std::byte{static_cast<std::uint8_t>(first + 5u)},
            std::byte{static_cast<std::uint8_t>(first + 6u)},
            std::byte{static_cast<std::uint8_t>(first + 7u)},
        };
    };
    const auto queue_path_validation_frames = [&](QuicConnection &test_connection,
                                                  std::uint8_t response_first,
                                                  std::uint8_t challenge_first) -> PathState & {
        auto &path_state = test_connection.ensure_path_state(0);
        path_state.pending_response = make_path_validation_data(response_first);
        path_state.challenge_pending = true;
        path_state.outstanding_challenge = make_path_validation_data(challenge_first);
        return path_state;
    };
    const auto set_outbound_datagram_limit = [](QuicConnection &test_connection,
                                                std::size_t limit) {
        test_connection.config_.max_outbound_datagram_size = limit;
        test_connection.peer_transport_parameters_->max_udp_payload_size = limit;
    };
    const auto set_path_challenge = [&](PathState &path_state, std::uint8_t first) {
        path_state.challenge_pending = true;
        path_state.outstanding_challenge = make_path_validation_data(first);
    };

    {
        PathMtuState remembered_failures;
        for (std::size_t index = 0; index <= kMaximumRememberedPmtudFailedProbeSizes; ++index) {
            remember_pmtud_failed_probe_size(remembered_failures,
                                             kMinimumInitialDatagramSize + 1 + index);
        }
        const auto retained_first = remembered_failures.failed_probe_sizes.front();
        remember_pmtud_failed_probe_size(remembered_failures, kMinimumInitialDatagramSize);
        remember_pmtud_failed_probe_size(remembered_failures, retained_first);
        const auto retained_size = remembered_failures.failed_probe_sizes.size();
        forget_pmtud_failed_probe_size(remembered_failures, retained_first);

        auto capped_config = make_client_core_config_for_connection_coverage();
        capped_config.max_outbound_datagram_size = 4096;
        capped_config.transport.pmtud_enabled = true;
        capped_config.transport.pmtud_base_datagram_size = 4096;
        capped_config.transport.pmtud_max_datagram_size = 1300;
        auto undersized_capped_config = capped_config;
        undersized_capped_config.transport.pmtud_max_datagram_size = 1000;

        COQUIC_CONNECTION_HOOK_RECORD(sanitize_pmtud_base(1) == kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(initial_congestion_datagram_size(capped_config) == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(initial_congestion_datagram_size(undersized_capped_config) ==
                                      kMaximumDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(next_probe_size_between(1000, 1010) == 1010);
        COQUIC_CONNECTION_HOOK_RECORD(next_probe_size_between(1460, 1480) == 1476);
        COQUIC_CONNECTION_HOOK_RECORD(next_probe_size_between(1480, 1500) == 1496);
        COQUIC_CONNECTION_HOOK_RECORD(retained_size == kMaximumRememberedPmtudFailedProbeSizes);
        COQUIC_CONNECTION_HOOK_RECORD(
            !pmtud_probe_size_previously_failed(remembered_failures, kMinimumInitialDatagramSize));
        COQUIC_CONNECTION_HOOK_RECORD(
            !pmtud_probe_size_previously_failed(remembered_failures, retained_first));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        remember_pmtud_failed_probe_size(path.mtu, next_probe_size_between(1200, 1600));
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_next_pmtu_probe_size_zero);
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests trace_filter("COQUIC_PACKET_TRACE_SCID", "");

        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.enabled);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.base_datagram_size == kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size ==
                                      kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() ==
                                      kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_ceiling() == 4096);
        COQUIC_CONNECTION_HOOK_RECORD(connection.congestion_controller_.congestion_window() ==
                                      10 * kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.congestion_controller_.minimum_window() ==
                                      2 * kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) ==
                                      kPmtudIPv4EthernetUdpPayloadSize);
        connection.config_.transport.pmtud_max_datagram_size = 0;
        connection.set_path_default_pmtud_search_ceiling(
            0, QuicDefaultPmtudSearchCeiling{.value = kPmtudIPv6EthernetUdpPayloadSize});
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_ceiling_for_path(0) ==
                                      kPmtudIPv6EthernetUdpPayloadSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) ==
                                      kPmtudIPv6EthernetUdpPayloadSize);
        connection.set_path_default_pmtud_search_ceiling(
            0, QuicDefaultPmtudSearchCeiling{.value = kPmtudIPv6EthernetUdpPayloadSize});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == kPmtudIPv6EthernetUdpPayloadSize);
        path.mtu.probe_ceiling = 1400;
        path.mtu.validated_datagram_size = 1390;
        path.mtu.search_low = 1390;
        path.mtu.outstanding_probe_size = 1400;
        path.mtu.outstanding_probe_packet_number = 77;
        remember_pmtud_failed_probe_size(path.mtu, 1450);
        connection.set_path_default_pmtud_search_ceiling(
            0, QuicDefaultPmtudSearchCeiling{.value = 1395});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1395);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1390);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_size.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.empty());
        connection.config_.transport.pmtud_max_datagram_size = 1300;
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_ceiling() == 1300);
        path.mtu.enabled = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(!queue_application_stream_byte(connection, 3));
        COQUIC_CONNECTION_HOOK_RECORD(!queue_application_stream_bytes(connection, 1, false, 3));
    }

    {
        auto connection = make_connected_client_connection();
        std::vector<std::byte> bytes{std::byte{0x40}};
        auto storage = std::make_shared<std::vector<std::byte>>(bytes);
        connection.process_inbound_datagram(std::shared_ptr<std::vector<std::byte>>{},
                                            /*begin=*/0, /*end=*/0, QuicCoreTimePoint{},
                                            /*path_id=*/0, QuicEcnCodepoint::unavailable,
                                            std::nullopt, /*replay_trigger=*/false,
                                            /*count_inbound_bytes=*/true,
                                            /*allow_in_place_receive_decode=*/true);
        connection.process_inbound_datagram(storage, /*begin=*/1, /*end=*/0, QuicCoreTimePoint{},
                                            /*path_id=*/0, QuicEcnCodepoint::unavailable,
                                            std::nullopt,
                                            /*replay_trigger=*/false,
                                            /*count_inbound_bytes=*/true,
                                            /*allow_in_place_receive_decode=*/true);
        connection.process_inbound_datagram(storage, /*begin=*/0, /*end=*/storage->size() + 1,
                                            QuicCoreTimePoint{}, /*path_id=*/0,
                                            QuicEcnCodepoint::unavailable, std::nullopt,
                                            /*replay_trigger=*/false,
                                            /*count_inbound_bytes=*/true,
                                            /*allow_in_place_receive_decode=*/true);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.outstanding_probe_packet_number = 31;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());

        path.mtu.outstanding_probe_packet_number.reset();
        path.mtu.viable = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());

        path.mtu.viable = true;
        path.mtu.validated_datagram_size = path.mtu.probe_ceiling;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.probe_ceiling = 1460;

        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) ==
                                      kPmtudIPv6EthernetUdpPayloadSize);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1472;
        path.mtu.search_low = 1472;
        path.mtu.probe_ceiling = 4096;

        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) > 1472);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        remember_pmtud_failed_probe_size(path.mtu, next_probe_size_between(1200, 1600));

        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) < 1600);

        while (connection.next_pmtu_probe_size(path).has_value()) {
            remember_pmtud_failed_probe_size(path.mtu,
                                             connection.next_pmtu_probe_size(path).value_or(0));
        }
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());

        path.mtu.next_probe_time = QuicCoreTimePoint{};
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);

        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        path.mtu.next_probe_time = QuicCoreTimePoint{};

        COQUIC_CONNECTION_HOOK_RECORD(connection.pmtud_deadline() == QuicCoreTimePoint{});
        connection.on_timeout(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);

        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        while (connection.next_pmtu_probe_size(path).has_value()) {
            remember_pmtud_failed_probe_size(path.mtu,
                                             connection.next_pmtu_probe_size(path).value_or(0));
        }

        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.send_crypto.append(
            std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}});
        auto stream_state = connection.get_or_open_send_stream(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream_state.has_value());
        auto &stream = *stream_state.value();
        stream.send_buffer.append(std::vector<std::byte>{std::byte{0x61}, std::byte{0x62}});
        stream.flow_control.highest_sent = 2;
        stream.flow_control.peer_max_stream_data = 8;
        connection.handshake_done_state_ = StreamControlFrameState::sent;
        connection.connection_flow_control_.pending_max_data_frame =
            MaxDataFrame{.maximum_data = 4096};
        connection.connection_flow_control_.max_data_state = StreamControlFrameState::sent;
        const auto stream_id = stream_state.value()->stream_id;
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 77,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .declared_lost = false,
                .has_handshake_done = true,
                .crypto_ranges = {ByteRange{
                    .offset = 0,
                    .bytes = SharedBytes{std::byte{0x01}, std::byte{0x02}},
                }},
                .reset_stream_frames = {ResetStreamFrame{
                    .stream_id = stream_id,
                    .application_protocol_error_code = 0,
                    .final_size = 2,
                }},
                .stop_sending_frames = {StopSendingFrame{
                    .stream_id = stream_id,
                    .application_protocol_error_code = 0,
                }},
                .max_data_frame = MaxDataFrame{.maximum_data = 4096},
                .max_stream_data_frames = {MaxStreamDataFrame{
                    .stream_id = stream_id,
                    .maximum_stream_data = 8,
                }},
                .max_streams_frames = {MaxStreamsFrame{
                    .stream_type = StreamLimitType::bidirectional,
                    .maximum_streams = 4,
                }},
                .data_blocked_frame = DataBlockedFrame{.maximum_data = 2048},
                .stream_data_blocked_frames = {StreamDataBlockedFrame{
                    .stream_id = stream_id,
                    .maximum_stream_data = 2,
                }},
                .stream_fragments = {StreamFrameSendFragment{
                    .stream_id = stream_id,
                    .offset = 0,
                    .bytes = SharedBytes{std::byte{0x61}, std::byte{0x62}},
                    .fin = false,
                    .consumes_flow_control = true,
                }},
                .bytes_in_flight = 1500,
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1500,
            });
        const auto packet_handle =
            connection.application_space_.recovery.handle_for_packet_number(77);
        COQUIC_CONNECTION_HOOK_RECORD(packet_handle.has_value());
        const auto packet =
            connection.retire_acked_packet(connection.application_space_, *packet_handle);
        COQUIC_CONNECTION_HOOK_RECORD(packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!packet->in_flight);
        COQUIC_CONNECTION_HOOK_RECORD(packet->bytes_in_flight == 0);
        COQUIC_CONNECTION_HOOK_RECORD(packet->crypto_ranges.empty());
        COQUIC_CONNECTION_HOOK_RECORD(packet->reset_stream_frames.empty());
        COQUIC_CONNECTION_HOOK_RECORD(packet->stop_sending_frames.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!packet->max_data_frame.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(packet->max_stream_data_frames.empty());
        COQUIC_CONNECTION_HOOK_RECORD(packet->max_streams_frames.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!packet->data_blocked_frame.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(packet->stream_data_blocked_frames.empty());
        COQUIC_CONNECTION_HOOK_RECORD(packet->stream_fragments.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!packet->has_handshake_done);
    }

    {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
        COQUIC_CONNECTION_HOOK_RECORD(true);
#else
        TlsAdapter client(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {std::byte{0x0f}, std::byte{0x00}},
        });
        TlsAdapter server(TlsAdapterConfig{
            .role = EndpointRole::server,
            .verify_peer = false,
            .server_name = "localhost",
            .identity =
                TlsIdentity{
                    .certificate_pem = read_text_file_for_connection_coverage(
                        "tests/fixtures/quic-server-cert.pem"),
                    .private_key_pem = read_text_file_for_connection_coverage(
                        "tests/fixtures/quic-server-key.pem"),
                },
            .local_transport_parameters = {std::byte{0x0f}, std::byte{0x00}},
        });
        COQUIC_CONNECTION_HOOK_RECORD(drive_tls_handshake_for_connection_coverage(client, server));
        static_cast<void>(client.take_available_secrets());

        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.initial_packet_space_discarded_ = true;
        connection.handshake_packet_space_discarded_ = true;
        connection.tls_.emplace(std::move(client));
        constexpr std::array<std::uint8_t, 32> secret{};
        COQUIC_CONNECTION_HOOK_RECORD(TlsAdapterTestPeer::call_on_set_secret(
                                          *connection.tls_, ssl_encryption_initial,
                                          EndpointRole::server, secret.data(), secret.size()) == 1);
        COQUIC_CONNECTION_HOOK_RECORD(TlsAdapterTestPeer::call_on_set_secret(
                                          *connection.tls_, ssl_encryption_handshake,
                                          EndpointRole::server, secret.data(), secret.size()) == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.initial_space_.read_secret.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.handshake_space_.read_secret.has_value());

        connection.install_available_secrets();

        COQUIC_CONNECTION_HOOK_RECORD(!connection.initial_space_.read_secret.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.handshake_space_.read_secret.has_value());
#endif
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 7,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 2048,
        };

        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.last_drained_is_pmtu_probe());

        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit(false) ==
                                      kMinimumInitialDatagramSize);
        connection.config_.role = EndpointRole::server;
        path.validated = false;
        path.anti_amplification_received_bytes = 400;
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() ==
                                      kMinimumInitialDatagramSize);
        connection.config_.role = EndpointRole::client;
        path.validated = true;
        path.anti_amplification_received_bytes = 0;

        const auto probe_ack_time = QuicCoreTimePoint{} + std::chrono::milliseconds(15);
        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 7,
                .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(10),
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 2048,
            },
            probe_ack_time);

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.search_low == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      probe_ack_time + std::chrono::seconds(1));
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() == 2048);

        connection.note_pmtu_probe_sent(0, 8, 0);
        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 8,
                .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(20),
                .path_id = 0,
                .is_pmtu_probe = true,
            },
            probe_ack_time + std::chrono::milliseconds(5));
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());

        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 9,
                .path_id = 0,
                .is_pmtu_probe = true,
            },
            probe_ack_time);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());

        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 10,
                .path_id = 0,
            },
            probe_ack_time);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 2048);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
                       std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28}};
        reduce_remaining_congestion_window(connection, 20);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.recovery.tracked_packet_count() == 1);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x61}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x91}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.peer_source_connection_id_ = {std::byte{0xa9}};
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = kMinimumInitialDatagramSize,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = connection.peer_source_connection_id_,
        };
        connection.config_.max_outbound_datagram_size = kMinimumInitialDatagramSize;
        connection.peer_transport_parameters_validated_ = true;
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &send_path = connection.ensure_path_state(0);
        send_path.validated = true;
        send_path.is_current_send_path = true;
        connection.original_version_ = kQuicVersion1;
        connection.current_version_ = kQuicVersion2;
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x57});
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x67});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        const ScopedConnectionDrainTestHook congestion_block_guard(
            &ConnectionDrainTestHooks::force_duplicate_initial_congestion_blocked);
        std::ignore = congestion_block_guard;

        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x61}, std::byte{0x02}},
            .initial_destination_connection_id = {std::byte{0x91}, std::byte{0x02}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.peer_source_connection_id_ = {std::byte{0xaa}};
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = connection.peer_source_connection_id_,
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &send_path = connection.ensure_path_state(0);
        send_path.validated = true;
        send_path.is_current_send_path = true;
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x68});
        connection.application_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x78});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        const ScopedConnectionDrainTestHook application_block_guard(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);
        std::ignore = application_block_guard;

        COQUIC_CONNECTION_HOOK_RECORD(
            connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.next_send_packet_number == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
                       std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44},
                       std::byte{0x45}, std::byte{0x46}, std::byte{0x47}, std::byte{0x48}};
        reduce_remaining_congestion_window(connection, 20);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.recovery.tracked_packet_count() == 1);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54},
                       std::byte{0x55}, std::byte{0x56}, std::byte{0x57}, std::byte{0x58}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64},
                       std::byte{0x65}, std::byte{0x66}, std::byte{0x67}, std::byte{0x68}};
        reduce_remaining_congestion_window(connection, 20);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto failed_application_datagram =
            connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(failed_application_datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        set_outbound_datagram_limit(connection, 8);
        record_application_ack_ranges(connection, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        const ScopedConnectionDrainCountdownTestHook serialization_hook(
            &ConnectionDrainTestHooks::force_ack_only_datagram_serialization_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        auto &path = connection.ensure_path_state(0);
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74},
                       std::byte{0x75}, std::byte{0x76}, std::byte{0x77}, std::byte{0x78}};

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.challenge_pending);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_application_candidate_estimate_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 81,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .force_ack = true,
            .path_id = 0,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_application_candidate_estimate_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1500));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_no_ack_control_candidate_estimate_failure);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainForcedSizeTestHook hook(1240);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainForcedSizeTestHook hook(1190);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainEmptyNoAckControlEstimateTestHook hook;

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = queue_path_validation_frames(connection, 0x91, 0xa1);
        const ScopedConnectionDrainTestHook congestion_hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);
        const ScopedConnectionDrainTestHook packet_number_hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto failed_application_datagram =
            connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(failed_application_datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 82,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = kPmtudIPv4EthernetUdpPayloadSize,
        };
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_drained_is_pmtu_probe());
        COQUIC_CONNECTION_HOOK_RECORD(datagram.size() == kPmtudIPv4EthernetUdpPayloadSize);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_size ==
                                      kPmtudIPv4EthernetUdpPayloadSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_space_.pending_probe_packet ==
                                      std::nullopt);
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 83,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto failed_application_datagram =
            connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(failed_application_datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 8));
        connection.remaining_pto_probe_datagrams_ = 2;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 90,
            .ack_eliciting = true,
            .in_flight = true,
            .first_stream_frame_metadata =
                StreamFrameSendMetadata{
                    .stream_id = 0,
                    .offset = 0,
                    .length = 2,
                    .consumes_flow_control = true,
                },
            .stream_frame_metadata =
                {
                    StreamFrameSendMetadata{
                        .stream_id = 0,
                        .offset = 2,
                        .length = 2,
                        .consumes_flow_control = true,
                    },
                },
            .path_id = 0,
        };

        COQUIC_CONNECTION_HOOK_RECORD(
            connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 8));
        connection.remaining_pto_probe_datagrams_ = 2;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 91,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_frame_metadata =
                {
                    StreamFrameSendMetadata{
                        .stream_id = 0,
                        .offset = 0,
                        .length = 2,
                        .consumes_flow_control = true,
                    },
                },
            .path_id = 0,
        };

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 86,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 87,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .force_ack = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_failure_countdown, 2);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 89,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_shortfall_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(datagram.size() == 1500);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        set_outbound_datagram_limit(connection, 8);
        record_application_ack_ranges(connection, 1);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 88,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments = {StreamFrameSendFragment{
                .stream_id = 0,
                .offset = 0,
                .bytes = SharedBytes(std::vector<std::byte>(100, std::byte{0x5a})),
                .fin = false,
                .consumes_flow_control = false,
            }},
            .force_ack = true,
            .path_id = 0,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_no_ack_retry_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 84,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 2);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x38});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook serialization_hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.application_space_.read_secret.reset();
        connection.application_space_.write_secret.reset();
        connection.zero_rtt_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x71});
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 85,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments = {StreamFrameSendFragment{
                .stream_id = 0,
                .offset = 0,
                .bytes = SharedBytes(std::vector<std::byte>(1400, std::byte{0x5a})),
                .fin = false,
                .consumes_flow_control = false,
            }},
            .force_ack = true,
            .path_id = 0,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1500});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook no_ack_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_candidate_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.peer_source_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x37});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook trim_hook(
            &ConnectionDrainTestHooks::force_application_trim_candidate_empty_payload_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        set_outbound_datagram_limit(connection, 8);
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 100));
        const ScopedConnectionDrainCountdownTestHook trim_hook(
            &ConnectionDrainTestHooks::force_application_trim_candidate_empty_payload_countdown, 0);
        const ScopedConnectionDrainCountdownTestHook no_ack_retry_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_retry_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x33});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1500});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x34});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        connection.connection_flow_control_.pending_max_data_frame =
            MaxDataFrame{.maximum_data = 4096};
        connection.connection_flow_control_.max_data_state = StreamControlFrameState::pending;

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1, true));
        auto *stream = connection.find_stream_state(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream != nullptr);
        stream->send_buffer.acknowledge(0, 1);
        stream->send_buffer.mark_unsent(0, 1);
        stream->flow_control.highest_sent = 1;
        connection.refresh_stream_sendable_byte_caches();
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1400});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.max_outbound_datagram_size = 8;
        connection.peer_transport_parameters_->max_udp_payload_size = 8;
        constexpr auto large_client_bidi_stream_id = kMaxQuicVarInt - 3u;
        auto stream =
            make_implicit_stream_state(large_client_bidi_stream_id, connection.config_.role);
        stream.send_final_size = kMaxQuicVarInt;
        stream.send_fin_state = StreamSendFinState::pending;
        stream.send_flow_control_committed = kMaxQuicVarInt;
        stream.flow_control.peer_max_stream_data = kMaxQuicVarInt;
        connection.connection_flow_control_.peer_max_data = kMaxQuicVarInt;
        connection.streams_.emplace(stream.stream_id, std::move(stream));
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400, true));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {10});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto reset_stream = make_implicit_stream_state(0, connection.config_.role);
        reset_stream.reset_state = StreamControlFrameState::pending;
        reset_stream.pending_reset_frame = ResetStreamFrame{
            .stream_id = reset_stream.stream_id,
            .application_protocol_error_code = 11,
            .final_size = 0,
        };
        connection.streams_.emplace(reset_stream.stream_id, std::move(reset_stream));
        auto empty_stream = make_implicit_stream_state(4, connection.config_.role);
        empty_stream.flow_control.peer_max_stream_data = 4096;
        connection.streams_.emplace(empty_stream.stream_id, std::move(empty_stream));
        auto data_stream = make_implicit_stream_state(8, connection.config_.role);
        data_stream.send_buffer.append(std::vector<std::byte>{std::byte{0x62}});
        data_stream.send_flow_control_committed = 1;
        data_stream.flow_control.peer_max_stream_data = 1;
        data_stream.send_flow_control_limit = 1;
        connection.streams_.emplace(data_stream.stream_id, std::move(data_stream));
        connection.connection_flow_control_.peer_max_data = 4096;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_application_send_stream_id_ == 8);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.remaining_pto_probe_datagrams_ = 1;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 111,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
        };
        auto reset_stream = make_implicit_stream_state(0, connection.config_.role);
        reset_stream.reset_state = StreamControlFrameState::sent;
        connection.streams_.emplace(reset_stream.stream_id, std::move(reset_stream));
        auto empty_stream = make_implicit_stream_state(4, connection.config_.role);
        empty_stream.flow_control.peer_max_stream_data = 4096;
        connection.streams_.emplace(empty_stream.stream_id, std::move(empty_stream));
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 12, false, 8));
        connection.connection_flow_control_.peer_max_data = 4096;
        connection.last_application_send_stream_id_ = 0;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.remaining_pto_probe_datagrams_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_application_send_stream_id_ == 8);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.remaining_pto_probe_datagrams_ = 1;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 113,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
        };
        set_outbound_datagram_limit(connection, 29);
        auto stream = make_implicit_stream_state(kMaxQuicVarInt - 3u, connection.config_.role);
        stream.send_buffer.append(std::vector<std::byte>{std::byte{0x64}});
        stream.send_flow_control_committed = 1;
        stream.flow_control.peer_max_stream_data = kMaxQuicVarInt;
        stream.send_flow_control_limit = kMaxQuicVarInt;
        connection.streams_.emplace(stream.stream_id, std::move(stream));
        connection.connection_flow_control_.peer_max_data = kMaxQuicVarInt;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.remaining_pto_probe_datagrams_ = 1;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 112,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
        };
        connection.config_.max_outbound_datagram_size = kDefaultInitialPacketNumberLength;
        connection.peer_transport_parameters_->max_udp_payload_size =
            kDefaultInitialPacketNumberLength;
        auto stream = make_implicit_stream_state(kMaxQuicVarInt - 3u, connection.config_.role);
        stream.send_buffer.append(std::vector<std::byte>{std::byte{0x63}});
        stream.send_flow_control_committed = 1;
        stream.flow_control.peer_max_stream_data = 1;
        stream.send_flow_control_limit = 1;
        connection.streams_.emplace(stream.stream_id, std::move(stream));
        connection.connection_flow_control_.peer_max_data = 4096;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        for (std::uint64_t stream_id = 0; stream_id < 20; stream_id += 4) {
            COQUIC_CONNECTION_HOOK_RECORD(
                queue_application_stream_bytes(connection, 256, false, stream_id));
        }
        connection.config_.max_outbound_datagram_size = 32768;
        connection.peer_transport_parameters_->max_udp_payload_size = 32768;
        connection.connection_flow_control_.peer_max_data = 32768;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_application_send_stream_id_.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.max_outbound_datagram_size = 26;
        connection.peer_transport_parameters_->max_udp_payload_size = 26;
        auto stream = make_implicit_stream_state(kMaxQuicVarInt - 3u, connection.config_.role);
        stream.send_final_size = kMaxQuicVarInt;
        stream.send_fin_state = StreamSendFinState::pending;
        stream.flow_control.peer_max_stream_data = kMaxQuicVarInt;
        stream.send_flow_control_limit = kMaxQuicVarInt;
        connection.streams_.emplace(stream.stream_id, std::move(stream));
        connection.connection_flow_control_.peer_max_data = kMaxQuicVarInt;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook serialization_hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x35});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook no_ack_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_candidate_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x39});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainTestHook estimate_hook(
            &ConnectionDrainTestHooks::force_no_ack_control_candidate_estimate_failure);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x3a});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainEmptyNoAckControlEstimateTestHook empty_hook;

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainForcedSizeTestHook size_hook(64);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainForcedSizeTestHook size_hook(1200);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x36});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook no_ack_retry_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_retry_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        connection.config_.max_outbound_datagram_size = 48;
        connection.peer_transport_parameters_->max_udp_payload_size = 48;
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook trim_hook(
            &ConnectionDrainTestHooks::force_application_trim_candidate_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_transport_parameters_.has_value());
        connection.peer_transport_parameters_->max_datagram_frame_size = 1200;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_datagram_send(bytes_from_ints_for_tests({0xd1, 0xd2})).has_value());

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_datagram_send_queue_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_transport_parameters_.has_value());
        connection.peer_transport_parameters_.reset();
        connection.pending_datagram_send_queue_.push_back(
            SharedBytes(bytes_from_ints_for_tests({0xe1, 0xe2})));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_datagram_send_queue_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_transport_parameters_.has_value());
        connection.peer_transport_parameters_->max_datagram_frame_size = 0;
        connection.pending_datagram_send_queue_.push_back(
            SharedBytes(bytes_from_ints_for_tests({0xe3, 0xe4})));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_datagram_send_queue_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_transport_parameters_.has_value());
        connection.peer_transport_parameters_->max_datagram_frame_size = 2;
        connection.pending_datagram_send_queue_.push_back(
            SharedBytes(bytes_from_ints_for_tests({0xe5, 0xe6})));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_datagram_send_queue_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_transport_parameters_.has_value());
        connection.config_.max_outbound_datagram_size = 24;
        connection.peer_transport_parameters_->max_udp_payload_size = 24;
        connection.peer_transport_parameters_->max_datagram_frame_size = 1200;
        connection.pending_datagram_send_queue_.push_back(
            SharedBytes(bytes_from_ints_for_tests({0xe7, 0xe8, 0xe9})));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_datagram_send_queue_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x61}, std::byte{0x03}},
            .initial_destination_connection_id = {std::byte{0x91}, std::byte{0x03}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.peer_source_connection_id_ = {std::byte{0xab}};
        connection.application_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
        connection.application_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = connection.peer_source_connection_id_,
            .max_datagram_frame_size = 1200,
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &path = connection.ensure_path_state(0);
        path.validated = true;
        path.is_current_send_path = true;
        connection.pending_datagram_send_queue_.push_back(
            SharedBytes(bytes_from_ints_for_tests({0xea, 0xeb})));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_datagram_send_queue_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = queue_path_validation_frames(connection, 0x79, 0x81);
        connection.current_send_path_id_.reset();
        const ScopedConnectionDrainTestHook congestion_hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);
        const ScopedConnectionDrainCountdownTestHook serialization_hook(
            &ConnectionDrainTestHooks::force_ack_only_datagram_serialization_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        connection.application_space_.pending_ack_deadline =
            QuicCoreTimePoint{} + std::chrono::milliseconds(10);
        connection.current_send_path_id_.reset();
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        connection.application_space_.pending_ack_deadline =
            QuicCoreTimePoint{} + std::chrono::milliseconds(10);
        auto &path = connection.ensure_path_state(0);
        set_path_challenge(path, 0x89);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        connection.application_space_.pending_ack_deadline =
            QuicCoreTimePoint{} + std::chrono::milliseconds(10);
        connection.current_send_path_id_ = 77;
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        connection.application_space_.pending_ack_deadline =
            QuicCoreTimePoint{} + std::chrono::milliseconds(10);
        auto &path = connection.ensure_path_state(1);
        path.pending_response = make_path_validation_data(0xa9);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.note_pmtu_probe_sent(0, 19, 1433);
        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 19,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1433,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1432);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.size() == 1);

        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 19,
                .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(10),
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1433,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(20));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1433);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.search_low == 1433);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1433);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1400;
        path.mtu.search_low = 1400;
        path.mtu.probe_ceiling = 1600;
        connection.note_pmtu_probe_sent(0, 21, 1300);
        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 21,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1300,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1400);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1600);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.empty());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1400;
        path.mtu.search_low = 1400;
        path.mtu.probe_ceiling = 1400;

        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 22,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1500,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 2048;
        path.mtu.search_low = 2048;
        path.mtu.probe_ceiling = 4096;
        connection.note_pmtu_probe_sent(0, 9, 3072);
        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 9,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 3072,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 3071);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(150));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        connection.note_outbound_datagram_bytes(1200, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        const std::array<std::byte, 1> small_payload{std::byte{0x41}};
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(0, small_payload, false).value());
        connection.note_outbound_datagram_bytes(1200, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        const std::vector<std::byte> large_payload(path.mtu.validated_datagram_size + 1u,
                                                   std::byte{0x42});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(4, large_payload, false).value());
        connection.note_outbound_datagram_bytes(1200, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(10));

        connection.note_outbound_datagram_bytes(0, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(10));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 4096;
        connection.application_space_.recovery.rtt_state().latest_rtt =
            std::chrono::milliseconds(8);
        connection.application_space_.recovery.rtt_state().smoothed_rtt =
            std::chrono::milliseconds(8);
        connection.note_pmtu_probe_sent(0, 13, 2048);
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 13,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = false,
                                         .has_ping = true,
                                         .path_id = 0,
                                         .is_pmtu_probe = true,
                                         .pmtu_probe_size = 2048,
                                     });

        COQUIC_CONNECTION_HOOK_RECORD(connection.loss_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.loss_deadline() ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(9));

        connection.on_timeout(QuicCoreTimePoint{} + std::chrono::milliseconds(9));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 2047);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(109));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 2048;
        path.mtu.search_low = 2048;
        path.mtu.probe_ceiling = 4096;
        connection.note_pmtu_probe_sent(0, 11, 3072);

        connection.apply_path_mtu_update(0, 1300);

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.search_low == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_size.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        connection.apply_path_mtu_update(0, 1199);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1199);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.viable);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.enabled);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_sendable_datagram(QuicCoreTimePoint{}));

        auto &previous_path = connection.ensure_path_state(1);
        previous_path.validated = true;
        previous_path.mtu.viable = true;
        path.is_current_send_path = true;
        connection.previous_path_id_ = 1;
        connection.current_send_path_id_ = 0;
        connection.pending_transport_close_.reset();
        connection.closing_close_packet_pending_ = false;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 1);
        COQUIC_CONNECTION_HOOK_RECORD(previous_path.is_current_send_path);

        path.mtu.probe_ceiling = 1000;
        connection.apply_path_mtu_update(0, 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1300);

        path.mtu.failed_probe_sizes = {1299, 1301};
        path.mtu.enabled = true;
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 4096;
        connection.apply_path_mtu_update(0, 1400);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1400);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.size() == 2);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_.reset();
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.viable);

        connection = make_connected_client_connection();
        auto &same_path = connection.ensure_path_state(0);
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 0;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!same_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &current_path = connection.ensure_path_state(0);
        auto &missing_previous_path = connection.ensure_path_state(2);
        static_cast<void>(missing_previous_path);
        connection.paths_.erase(2);
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 2;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!current_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &nonviable_path = connection.ensure_path_state(0);
        auto &nonviable_previous = connection.ensure_path_state(3);
        nonviable_previous.validated = true;
        nonviable_previous.mtu.viable = false;
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 3;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!nonviable_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &unvalidated_path = connection.ensure_path_state(0);
        auto &unvalidated_previous = connection.ensure_path_state(4);
        unvalidated_previous.validated = false;
        unvalidated_previous.mtu.viable = true;
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 4;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!unvalidated_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &validated_previous = connection.ensure_path_state(5);
        validated_previous.validated = true;
        validated_previous.mtu.viable = true;
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 5;
        connection.paths_.erase(0);
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 5);
        COQUIC_CONNECTION_HOOK_RECORD(validated_previous.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.at(0).mtu.viable);
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        connection.current_send_path_id_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        auto &nonviable_pending_path = connection.ensure_path_state(8);
        path.mtu.viable = false;
        nonviable_pending_path.pending_response =
            std::array{std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44},
                       std::byte{0x45}, std::byte{0x46}, std::byte{0x47}, std::byte{0x48}};
        nonviable_pending_path.mtu.viable = false;
        connection.current_send_path_id_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        path.mtu.viable = true;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        connection.drain_outbound_datagram(QuicCoreTimePoint{});
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 99;
        auto &nonviable_response_path = connection.ensure_path_state(8);
        nonviable_response_path.pending_response =
            std::array{std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84},
                       std::byte{0x85}, std::byte{0x86}, std::byte{0x87}, std::byte{0x88}};
        nonviable_response_path.mtu.viable = false;
        connection.drain_outbound_datagram(QuicCoreTimePoint{});
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        connection.config_.transport.pmtud_enabled = false;
        path.mtu.enabled = false;
        path.mtu.next_probe_time = std::nullopt;
        path.pending_response.reset();
        path.challenge_pending = false;
        path.mtu.viable = true;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 0;
        connection.anti_amplification_sent_bytes_ = 0;
        connection.current_send_path_id_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.max_outbound_datagram_size = kMaximumDatagramSize;
        connection.peer_transport_parameters_->max_udp_payload_size = kMaximumDatagramSize;
        COQUIC_CONNECTION_HOOK_RECORD(connection
                                          .queue_application_close(LocalApplicationCloseCommand{
                                              .application_error_code = 77,
                                          })
                                          .has_value());
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1500});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_application_close_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_application_close_sent_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::closing);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.application_space_.received_packets.record_received(63, /*ack_eliciting=*/true,
                                                                       QuicCoreTimePoint{});
        connection.application_space_.pending_ack_deadline = QuicCoreTimePoint{};
        set_outbound_datagram_limit(connection, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.transport.send_stream_fairness = true;
        auto reset_stream = make_implicit_stream_state(0, connection.config_.role);
        reset_stream.reset_state = StreamControlFrameState::sent;
        connection.streams_.emplace(reset_stream.stream_id, std::move(reset_stream));
        auto data_stream = make_implicit_stream_state(4, connection.config_.role);
        data_stream.send_buffer.append(std::vector<std::byte>{std::byte{0x76}});
        data_stream.send_flow_control_committed = 1;
        data_stream.flow_control.peer_max_stream_data = 1;
        data_stream.send_flow_control_limit = 1;
        connection.streams_.emplace(data_stream.stream_id, std::move(data_stream));
        connection.connection_flow_control_.peer_max_data = 4096;
        connection.remaining_pto_probe_datagrams_ = 1;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 131,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
        };
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_application_send_stream_id_ == 4);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.transport.send_stream_fairness = true;
        connection.last_application_send_stream_id_ = 0;
        auto wide_id_stream =
            make_implicit_stream_state(kMaxQuicVarInt - 3u, connection.config_.role);
        wide_id_stream.send_buffer.append(std::vector<std::byte>{std::byte{0x77}});
        wide_id_stream.send_flow_control_committed = 1;
        wide_id_stream.flow_control.peer_max_stream_data = kMaxQuicVarInt;
        wide_id_stream.send_flow_control_limit = kMaxQuicVarInt;
        connection.streams_.emplace(wide_id_stream.stream_id, std::move(wide_id_stream));
        connection.connection_flow_control_.peer_max_data = kMaxQuicVarInt;
        auto *inserted_stream = connection.find_stream_state(kMaxQuicVarInt - 3u);
        COQUIC_CONNECTION_HOOK_RECORD(inserted_stream != nullptr);
        connection.remaining_pto_probe_datagrams_ = 1;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 132,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
        };
        set_outbound_datagram_limit(connection, 8);
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto reset_stream = make_implicit_stream_state(0, connection.config_.role);
        reset_stream.reset_state = StreamControlFrameState::sent;
        connection.streams_.emplace(reset_stream.stream_id, std::move(reset_stream));
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 512, false, 4));
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 512, false, 8));
        connection.connection_flow_control_.peer_max_data = 4096;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        for (std::uint64_t stream_id = 0; stream_id < 12; stream_id += 4) {
            COQUIC_CONNECTION_HOOK_RECORD(
                queue_application_stream_bytes(connection, 16384, false, stream_id));
        }
        connection.config_.transport.send_stream_fairness = true;
        set_outbound_datagram_limit(connection, 32768);
        connection.connection_flow_control_.peer_max_data = 65536;
        connection.refresh_stream_sendable_byte_caches();

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 133,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments = {},
            .stream_frame_metadata = {StreamFrameSendMetadata{
                .stream_id = 44,
                .offset = 0,
                .length = 4,
                .fin = false,
                .consumes_flow_control = true,
            }},
            .path_id = 0,
        };
        connection.remaining_pto_probe_datagrams_ = 1;

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        path.mtu.viable = true;
        path.mtu.outstanding_probe_packet_number = 40;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_packet_number == 40);

        path.mtu.outstanding_probe_packet_number.reset();
        path.mtu.next_probe_time = QuicCoreTimePoint{} + std::chrono::milliseconds(5);
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time.has_value());

        path.mtu.next_probe_time.reset();
        path.mtu.validated_datagram_size = path.mtu.probe_ceiling;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.config_.role = EndpointRole::server;
        path.validated = false;
        path.anti_amplification_received_bytes = 400;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(100));

        connection.config_.role = EndpointRole::client;
        path.validated = true;
        path.anti_amplification_received_bytes = 0;
        connection.paths_.erase(0);
        connection.current_send_path_id_ = 0;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.application_space_.received_packets.record_received(61, /*ack_eliciting=*/true,
                                                                       QuicCoreTimePoint{});
        connection.application_space_.pending_ack_deadline = QuicCoreTimePoint{};
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54},
                       std::byte{0x55}, std::byte{0x56}, std::byte{0x57}, std::byte{0x58}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64},
                       std::byte{0x65}, std::byte{0x66}, std::byte{0x67}, std::byte{0x68}};
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.application_space_.received_packets.record_received(62, /*ack_eliciting=*/true,
                                                                       QuicCoreTimePoint{});
        connection.application_space_.pending_ack_deadline = QuicCoreTimePoint{};
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x59}, std::byte{0x5a}, std::byte{0x5b}, std::byte{0x5c},
                       std::byte{0x5d}, std::byte{0x5e}, std::byte{0x5f}, std::byte{0x60}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x69}, std::byte{0x6a}, std::byte{0x6b}, std::byte{0x6c},
                       std::byte{0x6d}, std::byte{0x6e}, std::byte{0x6f}, std::byte{0x70}};
        reduce_remaining_congestion_window(connection, 20);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_probe_packet.has_value());

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_drained_is_pmtu_probe());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_size.has_value());
    }

    {
        auto config = make_client_core_config_for_connection_coverage();
        config.max_outbound_datagram_size = 4096;
        config.transport.pmtud_enabled = false;
        QuicConnection connection(config);
        auto &path = connection.ensure_path_state(0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.enabled);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size ==
                                      connection.outbound_datagram_size_ceiling_for_path(0));
        COQUIC_CONNECTION_HOOK_RECORD(connection.congestion_controller_.minimum_window() ==
                                      2 * config.max_outbound_datagram_size);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto control_stream = make_implicit_stream_state(0, connection.config_.role);
        control_stream.reset_state = StreamControlFrameState::pending;
        control_stream.pending_reset_frame = ResetStreamFrame{
            .stream_id = control_stream.stream_id,
            .application_protocol_error_code = 1,
            .final_size = 0,
        };
        connection.streams_.emplace(control_stream.stream_id, std::move(control_stream));

        auto data_stream = make_implicit_stream_state(4, connection.config_.role);
        data_stream.send_buffer.append(std::vector<std::byte>{std::byte{0x61}});
        data_stream.send_flow_control_committed = 1;
        data_stream.flow_control.peer_max_stream_data = 1;
        connection.streams_.emplace(data_stream.stream_id, std::move(data_stream));

        auto fin_stream = make_implicit_stream_state(8, connection.config_.role);
        fin_stream.send_final_size = 0;
        fin_stream.send_fin_state = StreamSendFinState::pending;
        fin_stream.flow_control.peer_max_stream_data = 0;
        connection.streams_.emplace(fin_stream.stream_id, std::move(fin_stream));
        connection.refresh_stream_sendability_cache();

        COQUIC_CONNECTION_HOOK_RECORD(connection.stream_sendability_cache_.has_pending_control);
        COQUIC_CONNECTION_HOOK_RECORD(connection.stream_sendability_cache_.has_sendable_data);
        COQUIC_CONNECTION_HOOK_RECORD(connection.stream_sendability_cache_.has_sendable_fin);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.minimum_pending_application_stream_datagram_bytes().has_value());

        auto stream = make_implicit_stream_state(kMaxQuicVarInt - 3u, connection.config_.role);
        stream.send_final_size = kMaxQuicVarInt;
        stream.send_fin_state = StreamSendFinState::pending;
        stream.flow_control.peer_max_stream_data = kMaxQuicVarInt;
        connection.streams_.emplace(stream.stream_id, std::move(stream));
        connection.config_.max_outbound_datagram_size = 8;
        connection.peer_transport_parameters_->max_udp_payload_size = 8;
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.minimum_pending_application_stream_datagram_bytes().has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.max_outbound_datagram_size = kDefaultInitialPacketNumberLength;
        connection.peer_transport_parameters_->max_udp_payload_size =
            kDefaultInitialPacketNumberLength;
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_stream_pacing_deadline_bytes(
                                          kDefaultInitialPacketNumberLength) ==
                                      kDefaultInitialPacketNumberLength);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        auto &path = connection.ensure_path_state(0);
        path.pending_response = make_path_validation_data(0x91);
        path.mtu.viable = true;
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_control_send(false));

        path.pending_response.reset();
        path.challenge_pending = true;
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_control_send(false));

        path.challenge_pending = false;
        connection.handshake_done_state_ = StreamControlFrameState::pending;
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_control_send(false));
        connection.handshake_done_state_ = StreamControlFrameState::none;
        connection.connection_flow_control_.data_blocked_state = StreamControlFrameState::pending;
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_control_send(false));
        connection.connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
        connection.local_stream_limit_state_.max_streams_uni_state =
            StreamControlFrameState::pending;
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_control_send(false));
    }

    {
        auto config = make_client_core_config_for_connection_coverage();
        config.role = EndpointRole::server;
        auto connection = make_connected_client_connection_for_connection_coverage(config);
        connection.config_.role = EndpointRole::server;
        connection.status_ = HandshakeStatus::connected;
        connection.peer_address_validated_ = true;
        connection.current_send_path_id_ = 7;
        auto &path = connection.ensure_path_state(7);
        path.validated = false;
        path.anti_amplification_sent_bytes = 3;

        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_applies(7));
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_applies());
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_send_budget() == 0);
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() == 0);

        path.anti_amplification_received_bytes = 4;
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_send_budget() == 12);
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() == 9);

        path.validated = true;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.anti_amplification_applies(7));
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        QuicConnection::RetiredPeerStreamRange range{
            .first_index = 1,
            .last_index = 3,
            .receive_final_size = 5,
            .send_final_size = 7,
            .peer_max_stream_data = 9,
            .local_receive_window = 11,
            .advertised_max_stream_data = 13,
        };
        connection.retired_peer_bidi_stream_ranges_.emplace(1, range);
        auto retired_bidi = connection.make_retired_peer_stream_state(5, range);
        COQUIC_CONNECTION_HOOK_RECORD(retired_bidi.send_fin_state ==
                                      StreamSendFinState::acknowledged);
        range.first_index = 2;
        range.last_index = 2;
        connection.retired_peer_uni_stream_ranges_.emplace(2, range);
        auto retired_uni = connection.make_retired_peer_stream_state(11, range);
        COQUIC_CONNECTION_HOOK_RECORD(retired_uni.send_fin_state == StreamSendFinState::none);

        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.validate_retired_peer_stream_frame(5, 6, 0, false, kFrameTypeStreamBase)
                 .has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.validate_retired_peer_stream_frame(5, 4, 0, true, kFrameTypeStreamBase)
                 .has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.validate_retired_peer_stream_frame(5, 5, 0, true, kFrameTypeStreamBase)
                .has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.validate_retired_peer_reset_stream_frame(5, 4, kFrameTypeResetStream)
                 .has_value());

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(1,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 1,
                                                                .last_index = 1,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        connection.retired_peer_bidi_stream_ranges_.emplace(3,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 3,
                                                                .last_index = 3,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        auto stream = make_implicit_stream_state(9, connection.config_.role);
        stream.peer_fin_delivered = true;
        stream.peer_final_size = 5;
        stream.send_final_size = 7;
        stream.flow_control.peer_max_stream_data = 9;
        stream.flow_control.local_receive_window = 11;
        stream.flow_control.advertised_max_stream_data = 13;
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(stream));
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.retired_peer_bidi_stream_ranges_.begin()->second.first_index == 1);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.retired_peer_bidi_stream_ranges_.begin()->second.last_index == 3);
        COQUIC_CONNECTION_HOOK_RECORD(connection.retired_peer_stream_count() == 4);

        connection.retired_peer_bidi_stream_ranges_.clear();
        auto mismatch = make_implicit_stream_state(9, connection.config_.role);
        mismatch.peer_fin_delivered = true;
        mismatch.peer_final_size = 5;
        mismatch.send_final_size = 7;
        mismatch.flow_control.peer_max_stream_data = 9;
        mismatch.flow_control.local_receive_window = 11;
        mismatch.flow_control.advertised_max_stream_data = 13;
        connection.retired_peer_bidi_stream_ranges_.emplace(1,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 1,
                                                                .last_index = 1,
                                                                .receive_final_size = 6,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(1,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 1,
                                                                .last_index = 1,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 8,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(1,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 1,
                                                                .last_index = 1,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 10,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(1,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 1,
                                                                .last_index = 1,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 12,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(1,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 1,
                                                                .last_index = 1,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 14,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(3,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 3,
                                                                .last_index = 3,
                                                                .receive_final_size = 6,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(3,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 3,
                                                                .last_index = 3,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 8,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(3,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 3,
                                                                .last_index = 3,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 10,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(3,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 3,
                                                                .last_index = 3,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 12,
                                                                .advertised_max_stream_data = 13,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));

        connection.retired_peer_bidi_stream_ranges_.clear();
        connection.retired_peer_bidi_stream_ranges_.emplace(3,
                                                            QuicConnection::RetiredPeerStreamRange{
                                                                .first_index = 3,
                                                                .last_index = 3,
                                                                .receive_final_size = 5,
                                                                .send_final_size = 7,
                                                                .peer_max_stream_data = 9,
                                                                .local_receive_window = 11,
                                                                .advertised_max_stream_data = 14,
                                                            });
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_stream_to_peer_range(mismatch));
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const std::array token_a{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
            std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c},
            std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}, std::byte{0x10}};
        auto token_b = token_a;
        token_b[15] = std::byte{0x11};

        connection.current_send_path_id_.reset();
        connection.respond_to_path_challenge(9, make_path_validation_data(0xb1));
        COQUIC_CONNECTION_HOOK_RECORD(connection.paths_.at(9).pending_response.has_value());

        connection.current_send_path_id_ = 9;
        auto &challenge_path = connection.ensure_path_state(9);
        challenge_path.validated = true;
        challenge_path.peer_connection_id_sequence = 0;
        connection.peer_connection_ids_.clear();
        connection.respond_to_path_challenge(9, make_path_validation_data(0xb2));
        COQUIC_CONNECTION_HOOK_RECORD(challenge_path.peer_connection_id_sequence == 0);

        connection.peer_connection_ids_[0] = PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = {std::byte{0x41}},
            .stateless_reset_token = token_a,
        };
        connection.peer_connection_ids_[2] = PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = {std::byte{0x42}},
            .stateless_reset_token = token_b,
        };
        connection.respond_to_path_challenge(9, make_path_validation_data(0xb3));
        COQUIC_CONNECTION_HOOK_RECORD(challenge_path.peer_connection_id_sequence == 2);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_retire_connection_id_frames_.empty());

        NewConnectionIdFrame frame{
            .sequence_number = 7,
            .retire_prior_to = 0,
            .connection_id = {std::byte{0x51}},
            .stateless_reset_token = token_a,
        };
        connection.largest_peer_retire_prior_to_ = 8;
        connection.peer_connection_ids_.clear();
        connection.active_peer_connection_id_sequence_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.process_new_connection_id_frame(frame).has_value());
        connection.refresh_peer_connection_id_sequences_after_retirement();

        PreferredAddress preferred{
            .connection_id = {std::byte{0x61}},
            .stateless_reset_token = token_a,
        };
        auto preferred_connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(
            !preferred_connection.ensure_peer_preferred_address_connection_id().value());
        preferred_connection.peer_transport_parameters_->preferred_address = preferred;
        preferred_connection.peer_connection_ids_[kPreferredAddressConnectionIdSequence] =
            PeerConnectionIdRecord{
                .sequence_number = kPreferredAddressConnectionIdSequence,
                .connection_id = preferred.connection_id,
                .stateless_reset_token = token_a,
            };
        COQUIC_CONNECTION_HOOK_RECORD(
            preferred_connection.ensure_peer_preferred_address_connection_id().value());

        preferred_connection.peer_connection_ids_[kPreferredAddressConnectionIdSequence]
            .locally_retired = true;
        COQUIC_CONNECTION_HOOK_RECORD(
            preferred_connection.ensure_peer_preferred_address_connection_id().value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !preferred_connection.peer_connection_ids_[kPreferredAddressConnectionIdSequence]
                 .locally_retired);

        preferred_connection.peer_connection_ids_.clear();
        preferred_connection.peer_connection_ids_[3] = PeerConnectionIdRecord{
            .sequence_number = 3,
            .connection_id = preferred.connection_id,
            .stateless_reset_token = token_a,
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            !preferred_connection.ensure_peer_preferred_address_connection_id().has_value());

        preferred_connection.peer_connection_ids_.clear();
        preferred_connection.local_transport_parameters_.active_connection_id_limit = 0;
        COQUIC_CONNECTION_HOOK_RECORD(
            !preferred_connection.ensure_peer_preferred_address_connection_id().has_value());

        auto refresh_connection = make_connected_client_connection_for_connection_coverage();
        refresh_connection.current_send_path_id_ = 77;
        refresh_connection.refresh_peer_connection_id_sequences_after_retirement();
        refresh_connection.current_send_path_id_.reset();
        refresh_connection.ensure_path_state(6).peer_connection_id_sequence = 0;
        refresh_connection.refresh_peer_connection_id_sequences_after_retirement();
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.note_aead_encryption_attempt(0, QuicCoreTimePoint{}));
        auto without_write_secret = make_connected_client_connection_for_connection_coverage();
        without_write_secret.application_space_.write_secret.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            without_write_secret.note_aead_encryption_attempt(1, QuicCoreTimePoint{}));
        connection.local_key_update_requested_ = true;
        connection.maybe_request_proactive_key_update();
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_key_update_requested_);
    }

    {
        auto config = make_client_core_config_for_connection_coverage();
        config.role = EndpointRole::server;
        auto connection = make_connected_client_connection_for_connection_coverage(config);
        connection.config_.role = EndpointRole::server;
        connection.status_ = HandshakeStatus::connected;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 0;
        connection.note_inbound_datagram_bytes(9);
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_received_bytes_ == 9);

        connection.status_ = HandshakeStatus::failed;
        connection.anti_amplification_received_bytes_ = 0;
        connection.note_inbound_datagram_bytes(9);
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_received_bytes_ == 0);

        connection.status_ = HandshakeStatus::connected;
        connection.peer_address_validated_ = true;
        connection.last_inbound_path_id_ = 4;
        auto &received_path = connection.ensure_path_state(4);
        received_path.anti_amplification_received_bytes =
            std::numeric_limits<std::uint64_t>::max() - 1;
        connection.note_inbound_datagram_bytes(9);
        COQUIC_CONNECTION_HOOK_RECORD(received_path.anti_amplification_received_bytes ==
                                      std::numeric_limits<std::uint64_t>::max());

        connection.current_send_path_id_ = 4;
        received_path.validated = false;
        received_path.anti_amplification_received_bytes = 0;
        received_path.anti_amplification_sent_bytes = 0;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.anti_amplification_applies(4));
        received_path.anti_amplification_received_bytes = 1;
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_applies(4));

        received_path.pending_response = make_path_validation_data(0xa1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_send_budget() == 3);
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() == 3);
        received_path.anti_amplification_sent_bytes = 5;
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() == 0);

        received_path.anti_amplification_received_bytes = std::numeric_limits<std::uint64_t>::max();
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_send_budget(4) ==
                                      std::numeric_limits<std::uint64_t>::max());
    }

#undef COQUIC_CONNECTION_HOOK_RECORD
#undef COQUIC_STRINGIFY
#undef COQUIC_STRINGIFY_DETAIL
    return ok;
}

void connection_set_force_missing_packet_metadata_for_tests(bool enabled) {
    connection_drain_test_hooks().force_missing_packet_metadata = enabled;
}

void connection_set_force_quic_core_secret_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_quic_core_secret_rand_failure = enabled;
}

void connection_set_force_prf_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_prf_failure = enabled;
}

void connection_set_force_issued_connection_id_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_issued_connection_id_rand_failure = enabled;
}

void connection_set_force_stateless_reset_token_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_stateless_reset_token_rand_failure = enabled;
}

void connection_set_force_path_challenge_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_path_challenge_rand_failure = enabled;
}

void connection_set_force_random_one_in_sixteen_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_random_one_in_sixteen_rand_failure = enabled;
}

void connection_set_force_missing_fallback_packet_length_for_tests(bool enabled) {
    connection_drain_test_hooks().force_missing_fallback_packet_length = enabled;
}

void connection_set_force_appended_fragment_base_datagram_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_appended_fragment_base_datagram_failure = enabled;
}

void connection_set_force_aead_confidentiality_limit_for_tests(bool enabled) {
    connection_drain_test_hooks().force_aead_confidentiality_limit = enabled;
}

void connection_set_force_aead_integrity_limit_for_tests(bool enabled) {
    connection_drain_test_hooks().force_aead_integrity_limit = enabled;
}

void connection_set_force_application_candidate_estimate_failure_countdown_for_tests(int value) {
    connection_drain_test_hooks().force_application_candidate_estimate_failure_countdown = value;
}

void connection_set_force_candidate_datagram_serialization_failure_countdown_for_tests(int value) {
    connection_drain_test_hooks().force_candidate_datagram_serialization_failure_countdown = value;
}

void connection_set_force_application_candidate_datagram_extra_bytes_for_tests(
    ApplicationCandidateDatagramExtraBytesTestHook hook) {
    connection_drain_test_hooks().force_application_candidate_datagram_extra_bytes_countdown =
        hook.countdown;
    connection_drain_test_hooks().force_application_candidate_datagram_extra_bytes = hook.bytes;
}

} // namespace coquic::quic::test

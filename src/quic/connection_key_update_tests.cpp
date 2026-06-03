#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"
#include "src/quic/connection_test_support.h"

namespace coquic::quic::test {

bool connection_key_update_and_probe_coverage_for_tests() {
    bool ok = true;
#define COQUIC_STRINGIFY_DETAIL(value) #value
#define COQUIC_STRINGIFY(value) COQUIC_STRINGIFY_DETAIL(value)
#define COQUIC_CONNECTION_HOOK_RECORD(expr)                                                        \
    connection_coverage_check(ok, #expr ":" COQUIC_STRINGIFY(__LINE__), static_cast<bool>(expr))

    const auto make_connected_client_connection = [] {
        return make_connected_client_connection_for_connection_coverage();
    };
    const auto make_fast_path_connection = [&] {
        auto connection = make_connected_client_connection();
        connection.resumption_state_emitted_ = true;
        connection.peer_preferred_address_emitted_ = true;
        return connection;
    };
    const auto process_fast_path_datagram = [](QuicConnection &fast_path_connection,
                                               std::vector<std::byte> datagram,
                                               QuicCoreTimePoint now = QuicCoreTimePoint{}) {
        auto storage = std::make_shared<std::vector<std::byte>>(std::move(datagram));
        fast_path_connection.process_inbound_datagram(
            storage, /*begin=*/0, /*end=*/storage->size(), now, /*path_id=*/0,
            QuicEcnCodepoint::unavailable, std::nullopt, /*replay_trigger=*/false,
            /*count_inbound_bytes=*/true, /*allow_in_place_receive_decode=*/true);
    };
    const auto make_runtime_transport_parameters = [](const QuicConnection &parameter_connection) {
        return TransportParameters{
            .original_destination_connection_id =
                parameter_connection.config_.initial_destination_connection_id,
            .max_udp_payload_size = parameter_connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit =
                parameter_connection.config_.transport.active_connection_id_limit,
            .ack_delay_exponent = parameter_connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = parameter_connection.config_.transport.max_ack_delay,
            .initial_max_data = parameter_connection.config_.transport.initial_max_data,
            .initial_max_stream_data_bidi_local =
                parameter_connection.config_.transport.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote =
                parameter_connection.config_.transport.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni =
                parameter_connection.config_.transport.initial_max_stream_data_uni,
            .initial_max_streams_bidi =
                parameter_connection.config_.transport.initial_max_streams_bidi,
            .initial_max_streams_uni =
                parameter_connection.config_.transport.initial_max_streams_uni,
            .initial_source_connection_id = parameter_connection.peer_source_connection_id_,
            .version_information = version_information_for_handshake(
                parameter_connection.config_.supported_versions,
                parameter_connection.current_version_,
                parameter_connection.config_.retry_source_connection_id,
                parameter_connection.original_version_, parameter_connection.current_version_),
        };
    };
    const auto make_new_connection_id_frame = [](std::uint64_t sequence_number) {
        return NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints_for_tests(
                {static_cast<std::uint8_t>(0xc0u + (sequence_number & 0x0fu))}),
            .stateless_reset_token =
                std::array<std::byte, 16>{
                    std::byte{static_cast<std::uint8_t>(0x10u + (sequence_number & 0x0fu))},
                },
        };
    };
    const auto make_preferred_address = [](std::uint8_t seed) {
        return PreferredAddress{
            .ipv4_address = {std::byte{192}, std::byte{0}, std::byte{2}, std::byte{seed}},
            .ipv4_port = static_cast<std::uint16_t>(4400u + seed),
            .ipv6_port = static_cast<std::uint16_t>(5500u + seed),
            .connection_id = bytes_from_ints_for_tests({seed, static_cast<std::uint8_t>(seed + 1)}),
            .stateless_reset_token =
                std::array<std::byte, 16>{std::byte{static_cast<std::uint8_t>(seed + 2)}},
        };
    };

    const auto serialize_one_rtt_ack_datagram =
        [](const QuicConnection &ack_connection, const TrafficSecret &secret,
           std::uint64_t packet_number, bool key_phase = false) {
            const auto encoded = serialize_protected_datagram(
                std::array<ProtectedPacket, 1>{
                    ProtectedOneRttPacket{
                        .key_phase = key_phase,
                        .destination_connection_id = ack_connection.config_.source_connection_id,
                        .packet_number_length = 2,
                        .packet_number = packet_number,
                        .frames = {AckFrame{}},
                    },
                },
                SerializeProtectionContext{
                    .local_role = EndpointRole::server,
                    .client_initial_destination_connection_id =
                        ack_connection.client_initial_destination_connection_id(),
                    .one_rtt_secret = secret,
                    .one_rtt_key_phase = key_phase,
                });
            if (!encoded.has_value()) {
                return std::vector<std::byte>{};
            }
            return encoded.value();
        };
    const auto serialize_handshake_ping_datagram = [](const QuicConnection &handshake_connection,
                                                      const TrafficSecret &secret,
                                                      std::uint64_t packet_number) {
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = handshake_connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_ints_for_tests({0x11, 0x90}),
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = {PingFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    handshake_connection.client_initial_destination_connection_id(),
                .handshake_secret = secret,
            });
        if (!encoded.has_value()) {
            return std::vector<std::byte>{};
        }
        return encoded.value();
    };
    const auto serialize_one_rtt_frames_datagram =
        [](const QuicConnection &frames_connection, const TrafficSecret &secret,
           std::uint64_t packet_number, std::vector<Frame> frames, bool key_phase = false) {
            const auto encoded = serialize_protected_datagram(
                std::array<ProtectedPacket, 1>{
                    ProtectedOneRttPacket{
                        .key_phase = key_phase,
                        .destination_connection_id = frames_connection.config_.source_connection_id,
                        .packet_number_length = 2,
                        .packet_number = packet_number,
                        .frames = std::move(frames),
                    },
                },
                SerializeProtectionContext{
                    .local_role = EndpointRole::server,
                    .client_initial_destination_connection_id =
                        frames_connection.client_initial_destination_connection_id(),
                    .one_rtt_secret = secret,
                    .one_rtt_key_phase = key_phase,
                });
            if (!encoded.has_value()) {
                return std::vector<std::byte>{};
            }
            return encoded.value();
        };

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(123);
        auto connection = make_connected_client_connection();
        connection.handshake_space_.received_packets.record_received(
            /*packet_number=*/23, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_packet(
            ProtectedPacket{ProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x23}),
                .packet_number_length = 2,
                .packet_number = 23,
                .frames = {PingFrame{}},
            }},
            now, QuicEcnCodepoint::ce, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_ack_deadline == now);
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.force_ack_send);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.largest_authenticated_packet_number == 23u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(124);
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/24, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_packet(
            ProtectedPacket{ProtectedZeroRttPacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x24}),
                .packet_number_length = 2,
                .packet_number = 24,
                .frames = {PingFrame{}},
            }},
            now, QuicEcnCodepoint::not_ect, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_ack_deadline.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.largest_authenticated_packet_number == 24u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(125);
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/25, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_packet(
            ProtectedPacket{ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 25,
                .frames = {PingFrame{}},
            }},
            now, QuicEcnCodepoint::ce, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_space_.pending_ack_deadline == now);
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_space_.force_ack_send);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.largest_authenticated_packet_number == 25u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(126);
        auto connection = make_connected_client_connection();
        connection.handshake_space_.received_packets.record_received(
            /*packet_number=*/26, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x26}),
                .packet_number_length = 2,
                .packet_number = 26,
                .frames = {ReceivedFrame{PingFrame{}}},
            }},
            now, QuicEcnCodepoint::ce, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_ack_deadline == now);
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.force_ack_send);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.largest_authenticated_packet_number == 26u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(127);
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/27, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedZeroRttPacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x27}),
                .packet_number_length = 2,
                .packet_number = 27,
                .frames = {ReceivedFrame{PingFrame{}}},
            }},
            now, QuicEcnCodepoint::not_ect, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_ack_deadline.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.largest_authenticated_packet_number == 27u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(128);
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/28, /*ack_eliciting=*/false, now);
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedOneRttAckOnlyPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 28,
                .ack = ReceivedAckFrame{},
            }},
            now, QuicEcnCodepoint::ce, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_ack_deadline.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.largest_authenticated_packet_number == 28u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(129);
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/29, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedOneRttStreamPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 29,
                .stream =
                    ReceivedStreamFrame{
                        .stream_id = 0,
                        .stream_data = SharedBytes(bytes_from_ints_for_tests({0x29})),
                    },
            }},
            now, QuicEcnCodepoint::ce, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_space_.pending_ack_deadline == now);
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_space_.force_ack_send);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.largest_authenticated_packet_number == 29u);
    }

    {
        const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(130);
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/30, /*ack_eliciting=*/true, now);
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 30,
                .frames = {ReceivedFrame{PingFrame{}}},
            }},
            now, QuicEcnCodepoint::not_ect, /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        if (processed.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(processed.value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_ack_deadline.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.largest_authenticated_packet_number == 30u);
    }

    const auto enable_qlog_for_connection_coverage = [](QuicConnection &connection,
                                                        std::string_view label) {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
        static_cast<void>(connection);
        static_cast<void>(label);
        return false;
#else
        static std::uint64_t next_id = 0;
        const auto directory =
            std::filesystem::temp_directory_path() /
            ("coquic-connection-coverage-" + std::string(label) + "-" + std::to_string(next_id++));
        connection.config_.qlog = QuicQlogConfig{.directory = directory};
        connection.qlog_session_ = qlog::Session::try_open(
            *connection.config_.qlog, connection.config_.role,
            connection.client_initial_destination_connection_id(), QuicCoreTimePoint{});
        return connection.qlog_session_ != nullptr;
#endif
    };

    {
        auto connection = make_connected_client_connection();
        connection.queue_new_token({});
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.empty());
        connection.status_ = HandshakeStatus::failed;
        connection.queue_new_token(bytes_from_ints_for_tests({0x01}));
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.empty());
        const auto failed_datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(failed_datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.terminal_state_expired(QuicCoreTimePoint{}));
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "final-control-frames"));
        connection.queue_new_token(bytes_from_ints_for_tests({0xa1, 0xa2}));
        connection.local_stream_limit_state_.queue_max_streams(StreamLimitType::bidirectional, 5);

        auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::closing;
        connection.close_deadline_.reset();
        connection.on_timeout(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::closing);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.terminal_state_expired(QuicCoreTimePoint{}));

        connection.close_deadline_ = QuicCoreTimePoint{} + std::chrono::milliseconds(10);
        connection.on_timeout(QuicCoreTimePoint{} + std::chrono::milliseconds(1));
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::closing);
    }

    {
        auto connection = make_connected_client_connection();
        connection.last_drained_allows_send_continuation_ = true;
        connection.last_send_continuation_time_ =
            QuicCoreTimePoint{} + std::chrono::milliseconds(1);
        static_cast<void>(connection.drain_outbound_datagram(QuicCoreTimePoint{}));
        COQUIC_CONNECTION_HOOK_RECORD(!connection.last_drained_allows_send_continuation_);
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = HandshakeStatus::failed;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_wakeup().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.non_pacing_wakeup_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pacing_deadline().has_value());
        connection.on_timeout(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(connection.status_ == HandshakeStatus::failed);
        connection.idle_timeout_base_time_ = QuicCoreTimePoint{};
        COQUIC_CONNECTION_HOOK_RECORD(!connection.idle_timeout_deadline().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = HandshakeStatus::failed;
        connection.close_mode_ = QuicConnectionCloseMode::closing;
        connection.close_deadline_ = QuicCoreTimePoint{} + std::chrono::milliseconds(9);
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_wakeup() == connection.close_deadline_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.non_pacing_wakeup_deadline() ==
                                      connection.close_deadline_);
        connection.close_mode_ = QuicConnectionCloseMode::draining;
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_wakeup() == connection.close_deadline_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.non_pacing_wakeup_deadline() ==
                                      connection.close_deadline_);
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_->stateless_reset_token =
            std::array<std::byte, 16>{std::byte{0x21}};
        connection.peer_connection_ids_[1] = PeerConnectionIdRecord{
            .sequence_number = 1,
            .connection_id = bytes_from_ints_for_tests({0xa1}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x31}},
        };
        connection.peer_connection_ids_[2] = PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints_for_tests({0xa2}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x32}},
            .locally_retired = true,
        };
        const auto tokens = connection.peer_stateless_reset_tokens();
        COQUIC_CONNECTION_HOOK_RECORD(tokens.size() == 2);
        COQUIC_CONNECTION_HOOK_RECORD(
            std::ranges::none_of(tokens, [](const StatelessResetTokenRecord &record) {
                return record.connection_id == bytes_from_ints_for_tests({0xa2});
            }));
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_.reset();
        const auto result = connection.ensure_peer_preferred_address_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(result.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!result.value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_->preferred_address = make_preferred_address(0xb1);
        const auto result = connection.ensure_peer_preferred_address_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(result.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(result.value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.peer_connection_ids_.contains(kPreferredAddressConnectionIdSequence));
    }

    {
        auto connection = make_connected_client_connection();
        const auto preferred = make_preferred_address(0xb2);
        connection.peer_transport_parameters_->preferred_address = preferred;
        connection.peer_connection_ids_[kPreferredAddressConnectionIdSequence] =
            PeerConnectionIdRecord{
                .sequence_number = kPreferredAddressConnectionIdSequence,
                .connection_id = preferred.connection_id,
                .stateless_reset_token = preferred.stateless_reset_token,
                .locally_retired = true,
            };
        const auto result = connection.ensure_peer_preferred_address_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(result.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(result.value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.peer_connection_ids_.at(kPreferredAddressConnectionIdSequence)
                 .locally_retired);
    }

    {
        auto connection = make_connected_client_connection();
        const auto preferred = make_preferred_address(0xb3);
        connection.peer_transport_parameters_->preferred_address = preferred;
        connection.peer_connection_ids_[kPreferredAddressConnectionIdSequence] =
            PeerConnectionIdRecord{
                .sequence_number = kPreferredAddressConnectionIdSequence,
                .connection_id = bytes_from_ints_for_tests({0xde}),
                .stateless_reset_token = preferred.stateless_reset_token,
            };
        const auto result = connection.ensure_peer_preferred_address_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(!result.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(result.error().has_transport_error_code);
        COQUIC_CONNECTION_HOOK_RECORD(
            result.error().transport_error_code ==
            transport_error_code_value(QuicTransportErrorCode::protocol_violation));
    }

    {
        auto connection = make_connected_client_connection();
        const auto preferred = make_preferred_address(0xbb);
        connection.peer_transport_parameters_->preferred_address = preferred;
        connection.peer_connection_ids_[kPreferredAddressConnectionIdSequence] =
            PeerConnectionIdRecord{
                .sequence_number = kPreferredAddressConnectionIdSequence,
                .connection_id = bytes_from_ints_for_tests({0xbe}),
                .stateless_reset_token = preferred.stateless_reset_token,
            };
        const auto migrated = connection.request_connection_migration(
            /*path_id=*/41, QuicMigrationRequestReason::preferred_address, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!migrated.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.contains(41));
    }

    {
        auto connection = make_connected_client_connection();
        const auto preferred = make_preferred_address(0xb4);
        connection.peer_transport_parameters_->preferred_address = preferred;
        connection.peer_connection_ids_[7] = PeerConnectionIdRecord{
            .sequence_number = 7,
            .connection_id = preferred.connection_id,
        };
        const auto result = connection.ensure_peer_preferred_address_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(!result.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(result.error().has_transport_error_code);
        COQUIC_CONNECTION_HOOK_RECORD(
            result.error().transport_error_code ==
            transport_error_code_value(QuicTransportErrorCode::protocol_violation));
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_transport_parameters_.active_connection_id_limit = 1;
        connection.peer_transport_parameters_->preferred_address = make_preferred_address(0xb5);
        connection.peer_connection_ids_[0] = PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = bytes_from_ints_for_tests({0xc5}),
        };
        const auto result = connection.ensure_peer_preferred_address_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(!result.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(result.error().has_transport_error_code);
        COQUIC_CONNECTION_HOOK_RECORD(
            result.error().transport_error_code ==
            transport_error_code_value(QuicTransportErrorCode::connection_id_limit_error));
    }

    {
        auto connection = make_connected_client_connection();
        const auto retired_connection_id = bytes_from_ints_for_tests({0xa0, 0x77});
        const auto peer_source_connection_id = bytes_from_ints_for_tests({0xa1, 0x88});
        connection.active_peer_connection_id_sequence_ = 0;
        connection.peer_connection_ids_[0] = PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = retired_connection_id,
            .locally_retired = true,
        };
        connection.peer_source_connection_id_ = peer_source_connection_id;
        COQUIC_CONNECTION_HOOK_RECORD(connection.active_peer_destination_connection_id() ==
                                      peer_source_connection_id);
        connection.peer_source_connection_id_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(connection.active_peer_destination_connection_id() ==
                                      connection.config_.initial_destination_connection_id);
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        auto &packet_space = connection.application_space_;
        packet_space.optimistic_ack_skipped_packet_numbers = {4, 8, 12};
        const AckFrame ack_frame{
            .largest_acknowledged = 8,
            .first_ack_range = 0,
        };
        const auto cursor = make_ack_range_cursor(ack_frame);
        COQUIC_CONNECTION_HOOK_RECORD(cursor.has_value());
        if (cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection.ack_ranges_include_unsent_packet_number(packet_space, cursor.value()));
        }
        packet_space.recovery.on_packet_sent(SentPacketRecord{
            .packet_number = 8,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1,
        });
        AckFrame tracked_ack_frame{
            .largest_acknowledged = 8,
            .first_ack_range = 0,
        };
        auto tracked_cursor = make_ack_range_cursor(tracked_ack_frame);
        COQUIC_CONNECTION_HOOK_RECORD(tracked_cursor.has_value());
        if (tracked_cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(!connection.ack_ranges_include_unsent_packet_number(
                packet_space, tracked_cursor.value()));
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.initial_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed =
            connection.process_inbound_crypto(EncryptionLevel::initial,
                                              std::array<Frame, 1>{Frame{AckFrame{
                                                  .largest_acknowledged = 3,
                                                  .first_ack_range = 0,
                                              }}},
                                              QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.tls_.emplace(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {},
        });
        connection.peer_transport_parameters_validated_ = false;
        const auto remembered_transport_parameters = make_runtime_transport_parameters(connection);
        connection.peer_transport_parameters_.reset();
        connection.decoded_resumption_state_ = StoredClientResumptionState{
            .tls_state = {},
            .quic_version = kQuicVersion1,
            .application_protocol = connection.config_.application_protocol,
            .peer_transport_parameters = remembered_transport_parameters,
            .application_context = connection.config_.zero_rtt.application_context,
        };
        auto reduced = remembered_transport_parameters;
        reduced.initial_max_data = 1;
        const auto serialized_reduced = serialize_transport_parameters(reduced);
        COQUIC_CONNECTION_HOOK_RECORD(serialized_reduced.has_value());
        if (serialized_reduced.has_value()) {
            TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                              serialized_reduced.value());
            TlsAdapterTestPeer::set_early_data_attempted(*connection.tls_, true);
            TlsAdapterTestPeer::set_early_data_accepted(*connection.tls_, true);
            const auto validated = connection.validate_peer_transport_parameters_if_ready();
            COQUIC_CONNECTION_HOOK_RECORD(!validated.has_value());
            if (!validated.has_value()) {
                COQUIC_CONNECTION_HOOK_RECORD(validated.error().code ==
                                              CodecErrorCode::invalid_packet_protection_state);
            }
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.tls_.emplace(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {},
        });
        connection.peer_transport_parameters_validated_ = false;
        connection.peer_transport_parameters_.reset();
        const auto remembered_transport_parameters = make_runtime_transport_parameters(connection);
        connection.decoded_resumption_state_ = StoredClientResumptionState{
            .tls_state = {},
            .quic_version = kQuicVersion1,
            .application_protocol = connection.config_.application_protocol,
            .peer_transport_parameters = remembered_transport_parameters,
            .application_context = connection.config_.zero_rtt.application_context,
        };
        auto current = remembered_transport_parameters;
        current.initial_max_data = remembered_transport_parameters.initial_max_data + 1;
        const auto serialized_current = serialize_transport_parameters(current);
        COQUIC_CONNECTION_HOOK_RECORD(serialized_current.has_value());
        if (serialized_current.has_value()) {
            TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                              serialized_current.value());
            TlsAdapterTestPeer::set_early_data_attempted(*connection.tls_, true);
            TlsAdapterTestPeer::set_early_data_accepted(*connection.tls_, true);
            const auto validated = connection.validate_peer_transport_parameters_if_ready();
            COQUIC_CONNECTION_HOOK_RECORD(validated.has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.tls_.emplace(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {},
        });
        connection.peer_transport_parameters_validated_ = false;
        connection.peer_transport_parameters_.reset();
        auto current = make_runtime_transport_parameters(connection);
        const auto serialized_current = serialize_transport_parameters(current);
        COQUIC_CONNECTION_HOOK_RECORD(serialized_current.has_value());
        if (serialized_current.has_value()) {
            TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                              serialized_current.value());
            TlsAdapterTestPeer::set_early_data_attempted(*connection.tls_, true);
            TlsAdapterTestPeer::set_early_data_accepted(*connection.tls_, true);
            const auto validated = connection.validate_peer_transport_parameters_if_ready();
            COQUIC_CONNECTION_HOOK_RECORD(validated.has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.handshake_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed = connection.process_inbound_received_crypto(
            EncryptionLevel::handshake,
            std::array<ReceivedFrame, 1>{ReceivedFrame{ReceivedAckFrame{
                .largest_acknowledged = 3,
                .first_ack_range = 0,
            }}},
            QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.application_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{AckFrame{
                .largest_acknowledged = 3,
                .first_ack_range = 0,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.application_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed = connection.process_inbound_received_application(
            std::array<ReceivedFrame, 1>{ReceivedFrame{ReceivedAckFrame{
                .largest_acknowledged = 3,
                .first_ack_range = 0,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        const auto new_connection_id = make_new_connection_id_frame(4);
        connection.pending_new_connection_id_frames_.push_back(new_connection_id);
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 5,
        });
        connection.peer_connection_ids_[5] = PeerConnectionIdRecord{
            .sequence_number = 5,
            .connection_id = bytes_from_ints_for_tests({0xa5}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x35}},
            .locally_retired = true,
        };
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 41,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .new_connection_id_frames = {new_connection_id},
                                         .retire_connection_id_frames = {RetireConnectionIdFrame{
                                             .sequence_number = 5,
                                         }},
                                         .bytes_in_flight = 1,
                                     });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(41);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.contains(5));
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 50};
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 450,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(450);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.contains(50));
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 51};
        connection.peer_connection_ids_[51] = PeerConnectionIdRecord{
            .sequence_number = 51,
            .connection_id = bytes_from_ints_for_tests({0xd1}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x51}},
        };
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 451,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(451);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_connection_ids_.contains(51));
    }

    {
        auto connection = make_connected_client_connection();
        const NewTokenFrame new_token{.token = bytes_from_ints_for_tests({0x6e})};
        const auto new_connection_id = make_new_connection_id_frame(6);
        const RetireConnectionIdFrame retire_connection_id{.sequence_number = 7};
        connection.peer_connection_ids_[7] = PeerConnectionIdRecord{
            .sequence_number = 7,
            .connection_id = bytes_from_ints_for_tests({0xa7}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x37}},
            .retire_frame_in_flight = true,
        };
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 42,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .new_token_frames = {new_token},
                                         .new_connection_id_frames = {new_connection_id},
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(42);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto lost = connection.mark_lost_packet(connection.application_space_, *handle,
                                                          /*already_marked_in_recovery=*/false,
                                                          QuicCoreTimePoint{});
            COQUIC_CONNECTION_HOOK_RECORD(lost.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.peer_connection_ids_.at(7).retire_frame_in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 44};
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 440,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(440);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 45};
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 441,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(441);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto lost = connection.mark_lost_packet(connection.application_space_, *handle,
                                                          /*already_marked_in_recovery=*/false,
                                                          QuicCoreTimePoint{});
            COQUIC_CONNECTION_HOOK_RECORD(lost.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        const auto new_connection_id = make_new_connection_id_frame(8);
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 9};
        connection.pending_new_connection_id_frames_.push_back(new_connection_id);
        connection.pending_retire_connection_id_frames_.push_back(retire_connection_id);
        connection.pending_new_token_frames_.push_back(NewTokenFrame{
            .token = bytes_from_ints_for_tests({0x6e, 0x74}),
        });
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 43,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .new_token_frames = {NewTokenFrame{
                                             .token = bytes_from_ints_for_tests({0x6e, 0x74}),
                                         }},
                                         .new_connection_id_frames = {new_connection_id},
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        auto selected_pto_probe = connection.select_pto_probe(connection.application_space_);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.packet_number == 43);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.new_token_frames.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.new_connection_id_frames.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.retire_connection_id_frames.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &stream =
            connection.streams_
                .emplace(0, make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client))
                .first->second;
        stream.flow_control.peer_max_stream_data = 32;
        stream.send_buffer.append(bytes_from_ints_for_tests({0x71, 0x72, 0x73, 0x74}));
        static_cast<void>(stream.send_buffer.take_ranges(4));
        connection.connection_flow_control_.pending_max_data_frame = MaxDataFrame{
            .maximum_data = 64,
        };
        connection.connection_flow_control_.max_data_state = StreamControlFrameState::pending;
        connection.connection_flow_control_.pending_data_blocked_frame = DataBlockedFrame{
            .maximum_data = 16,
        };
        connection.connection_flow_control_.data_blocked_state = StreamControlFrameState::pending;
        connection.local_stream_limit_state_.pending_max_streams_bidi_frame = MaxStreamsFrame{
            .stream_type = StreamLimitType::bidirectional,
            .maximum_streams = 8,
        };
        connection.local_stream_limit_state_.max_streams_bidi_state =
            StreamControlFrameState::pending;
        connection.local_stream_limit_state_.pending_max_streams_uni_frame = MaxStreamsFrame{
            .stream_type = StreamLimitType::unidirectional,
            .maximum_streams = 9,
        };
        connection.local_stream_limit_state_.max_streams_uni_state =
            StreamControlFrameState::pending;
        stream.flow_control.pending_stream_data_blocked_frame = StreamDataBlockedFrame{
            .stream_id = 0,
            .maximum_stream_data = 32,
        };
        stream.flow_control.stream_data_blocked_state = StreamControlFrameState::pending;
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 44,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .max_data_frame = MaxDataFrame{.maximum_data = 64},
                .max_streams_frames =
                    {
                        MaxStreamsFrame{
                            .stream_type = StreamLimitType::bidirectional,
                            .maximum_streams = 8,
                        },
                        MaxStreamsFrame{
                            .stream_type = StreamLimitType::unidirectional,
                            .maximum_streams = 9,
                        },
                    },
                .data_blocked_frame = DataBlockedFrame{.maximum_data = 16},
                .stream_data_blocked_frames =
                    {
                        StreamDataBlockedFrame{
                            .stream_id = 0,
                            .maximum_stream_data = 32,
                        },
                    },
                .first_stream_frame_metadata =
                    StreamFrameSendMetadata{
                        .stream_id = 0,
                        .offset = 0,
                        .length = 4,
                        .consumes_flow_control = true,
                    },
                .stream_frame_metadata =
                    {
                        StreamFrameSendMetadata{
                            .stream_id = 0,
                            .offset = 0,
                            .length = 4,
                            .consumes_flow_control = true,
                        },
                    },
                .stream_fragments =
                    {
                        StreamFrameSendFragment{
                            .stream_id = 0,
                            .offset = 0,
                            .bytes = SharedBytes(bytes_from_ints_for_tests({0x71, 0x72})),
                            .consumes_flow_control = true,
                        },
                    },
                .bytes_in_flight = 1,
            });
        auto selected_pto_probe = connection.select_pto_probe(connection.application_space_);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.packet_number == 44);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.max_data_frame.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.max_streams_frames.size() == 2);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.data_blocked_frame.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.stream_data_blocked_frames.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.first_stream_frame_metadata.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.stream_frame_metadata.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.stream_fragments.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        connection.connection_flow_control_.pending_max_data_frame = MaxDataFrame{
            .maximum_data = 80,
        };
        connection.connection_flow_control_.max_data_state = StreamControlFrameState::pending;
        connection.connection_flow_control_.pending_data_blocked_frame = DataBlockedFrame{
            .maximum_data = 20,
        };
        connection.connection_flow_control_.data_blocked_state = StreamControlFrameState::pending;
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 45,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .max_data_frame = MaxDataFrame{.maximum_data = 81},
                                         .data_blocked_frame = DataBlockedFrame{.maximum_data = 21},
                                         .bytes_in_flight = 1,
                                     });
        auto selected_pto_probe = connection.select_pto_probe(connection.application_space_);
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.packet_number == 45);
        COQUIC_CONNECTION_HOOK_RECORD(!selected_pto_probe.max_data_frame.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!selected_pto_probe.data_blocked_frame.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.has_ping);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.destination_connection_id_override = bytes_from_ints_for_tests({0xd1});
        COQUIC_CONNECTION_HOOK_RECORD(connection.can_initiate_path_validation(0));
        path.destination_connection_id_override.reset();
        connection.ensure_path_state(7);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.can_initiate_path_validation(7));
        connection.peer_connection_ids_.clear();
        connection.active_peer_connection_id_sequence_ = 99;
        connection.start_path_validation(9, /*initiated_locally=*/true, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.contains(9));
        connection.current_send_path_id_ = 0;
        connection.maybe_switch_to_path(8, /*initiated_locally=*/true, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.contains(8));

        connection = make_connected_client_connection();
        connection.peer_connection_ids_[3] = PeerConnectionIdRecord{
            .sequence_number = 3,
            .connection_id = bytes_from_ints_for_tests({0xa3}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x43}},
            .locally_retired = true,
        };
        auto &retired_path = connection.ensure_path_state(3);
        retired_path.peer_connection_id_sequence = 3;
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.select_peer_connection_id_sequence_for_path(3).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.read_secret.reset();
        connection.next_application_read_secret_ = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa1});
        connection.next_application_read_secret_source_generation_ = 17;
        connection.application_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa0});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.make_current_short_header_deserialize_context().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.current_short_header_deserialize_cache_.has_value());
        connection.application_space_.read_secret.reset();
        const auto refreshed = connection.refresh_next_application_read_secret();
        COQUIC_CONNECTION_HOOK_RECORD(refreshed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_application_read_secret_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.next_application_read_secret_source_generation_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.current_short_header_deserialize_cache_.has_value());

        connection.next_application_read_secret_ = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa2});
        connection.next_application_read_secret_source_generation_ = 19;
        auto ensured = connection.ensure_next_application_read_secret();
        COQUIC_CONNECTION_HOOK_RECORD(ensured.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_application_read_secret_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.next_application_read_secret_source_generation_.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.read_secret = TrafficSecret{
            .cipher_suite = invalid_cipher_suite_for_tests(),
            .secret = {std::byte{0x8a}},
        };
        auto ensured = connection.ensure_next_application_read_secret();
        COQUIC_CONNECTION_HOOK_RECORD(!ensured.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &current_path = connection.ensure_path_state(0);
        current_path.peer_connection_id_sequence = 0;
        auto &new_path = connection.ensure_path_state(4);
        new_path.peer_connection_id_sequence = 4;
        new_path.outstanding_challenge =
            std::array{std::byte{0x40}, std::byte{0x41}, std::byte{0x42}, std::byte{0x43},
                       std::byte{0x44}, std::byte{0x45}, std::byte{0x46}, std::byte{0x47}};
        connection.peer_connection_ids_[0] = PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = bytes_from_ints_for_tests({0xa0}),
        };
        connection.peer_connection_ids_[4] = PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints_for_tests({0xa4}),
        };
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *new_path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/4);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 4);
        COQUIC_CONNECTION_HOOK_RECORD(connection.previous_path_id_ == std::optional<QuicPathId>{0});
        COQUIC_CONNECTION_HOOK_RECORD(!new_path.outstanding_challenge.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x50}, std::byte{0x51}, std::byte{0x52}, std::byte{0x53},
                       std::byte{0x54}, std::byte{0x55}, std::byte{0x56}, std::byte{0x57}};
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
                       std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28}};
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &nonviable_path = connection.ensure_path_state(4);
        nonviable_path.peer_connection_id_sequence = 4;
        nonviable_path.mtu.viable = false;
        nonviable_path.outstanding_challenge =
            std::array{std::byte{0x29}, std::byte{0x2a}, std::byte{0x2b}, std::byte{0x2c},
                       std::byte{0x2d}, std::byte{0x2e}, std::byte{0x2f}, std::byte{0x30}};
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *nonviable_path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/4);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!nonviable_path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x48}, std::byte{0x49}, std::byte{0x4a}, std::byte{0x4b},
                       std::byte{0x4c}, std::byte{0x4d}, std::byte{0x4e}, std::byte{0x4f}};
        connection.previous_path_id_.reset();
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
                       std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
        path.challenge_pending = true;
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_connection_ids_[1] = PeerConnectionIdRecord{
            .sequence_number = 1,
            .connection_id = bytes_from_ints_for_tests({0xa1}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x41}},
        };
        connection.peer_connection_ids_[2] = PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints_for_tests({0xa2}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x42}},
        };
        auto &old_path = connection.ensure_path_state(1);
        old_path.peer_connection_id_sequence = 1;
        auto &same_peer_path = connection.ensure_path_state(2);
        same_peer_path.peer_connection_id_sequence = 1;
        connection.retire_peer_connection_id_for_inactive_path(1, 1);
        connection.retire_peer_connection_id_for_inactive_path(1, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
        same_peer_path.peer_connection_id_sequence = 2;
        auto &third_path = connection.ensure_path_state(3);
        third_path.peer_connection_id_sequence = 1;
        connection.retire_peer_connection_id_for_inactive_path(1, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
        third_path.peer_connection_id_sequence = 2;
        connection.retire_peer_connection_id_for_inactive_path(1, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);

        auto missing_new_path = make_connected_client_connection();
        missing_new_path.peer_connection_ids_[5] = PeerConnectionIdRecord{
            .sequence_number = 5,
            .connection_id = bytes_from_ints_for_tests({0xa5}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x45}},
        };
        auto &old_only_path = missing_new_path.ensure_path_state(5);
        old_only_path.peer_connection_id_sequence = 5;
        missing_new_path.retire_peer_connection_id_for_inactive_path(5, 6);
        COQUIC_CONNECTION_HOOK_RECORD(
            missing_new_path.pending_retire_connection_id_frames_.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &validated_path = connection.ensure_path_state(9);
        validated_path.validated = true;
        validated_path.mtu.viable = false;
        connection.maybe_switch_to_path(9, /*initiated_locally=*/false, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        connection.reset_recovery_for_new_path(0);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
    }

    {
        auto connection = make_connected_client_connection();
        auto &original_path = connection.ensure_path_state(0);
        original_path.validated = true;
        original_path.is_current_send_path = false;
        auto &preferred_path = connection.ensure_path_state(1);
        preferred_path.validated = true;
        preferred_path.is_current_send_path = true;
        preferred_path.preferred_address_path = true;
        connection.current_send_path_id_ = 1;
        connection.previous_path_id_ = 0;
        connection.last_validated_path_id_ = 1;

        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PingFrame{}}}, QuicCoreTimePoint{},
            /*allow_preconnected_frames=*/false, /*path_id=*/0);

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 1);
        COQUIC_CONNECTION_HOOK_RECORD(preferred_path.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(!original_path.is_current_send_path);
    }

    {
        auto connection = make_connected_client_connection();
        auto empty_destination_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 1,
                .connection_id = bytes_from_ints_for_tests({0xb1}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(empty_destination_processed.has_value());
        connection.config_.initial_destination_connection_id.clear();
        connection.peer_connection_ids_.clear();
        connection.peer_source_connection_id_.reset();
        auto empty_destination_rejected =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 1,
                .connection_id = bytes_from_ints_for_tests({0xb2}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(!empty_destination_rejected.has_value());

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        connection.peer_connection_ids_[4] = PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints_for_tests({0xb4}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x44}},
        };
        auto stale_processed = connection.process_new_connection_id_frame(NewConnectionIdFrame{
            .sequence_number = 4,
            .retire_prior_to = 3,
            .connection_id = bytes_from_ints_for_tests({0xb4}),
        });
        COQUIC_CONNECTION_HOOK_RECORD(stale_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        auto already_retired_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 5,
                .retire_prior_to = 5,
                .connection_id = bytes_from_ints_for_tests({0xb5}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(already_retired_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.at(5).locally_retired);

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        connection.peer_connection_ids_[4] = PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints_for_tests({0xb6}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x46}},
        };
        auto lower_than_largest_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 4,
                .retire_prior_to = 4,
                .connection_id = bytes_from_ints_for_tests({0xb6}),
                .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x46}},
            });
        COQUIC_CONNECTION_HOOK_RECORD(lower_than_largest_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(std::ranges::any_of(
            connection.pending_retire_connection_id_frames_,
            [](const RetireConnectionIdFrame &frame) { return frame.sequence_number == 4; }));

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        auto stale_not_retired_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 5,
                .retire_prior_to = 4,
                .connection_id = bytes_from_ints_for_tests({0xb7}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(stale_not_retired_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());

        connection.queue_peer_connection_id_retirement(99);
        connection.peer_connection_ids_[10] = PeerConnectionIdRecord{
            .sequence_number = 10,
            .connection_id = bytes_from_ints_for_tests({0xba}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x4a}},
            .retire_frame_in_flight = true,
        };
        connection.queue_peer_connection_id_retirement(10);
        COQUIC_CONNECTION_HOOK_RECORD(std::ranges::none_of(
            connection.pending_retire_connection_id_frames_,
            [](const RetireConnectionIdFrame &frame) { return frame.sequence_number == 10; }));
        connection.peer_connection_ids_[11] = PeerConnectionIdRecord{
            .sequence_number = 11,
            .connection_id = bytes_from_ints_for_tests({0xbb}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x4b}},
        };
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 11,
        });
        connection.queue_peer_connection_id_retirement(11);
        COQUIC_CONNECTION_HOOK_RECORD(
            std::ranges::count_if(connection.pending_retire_connection_id_frames_,
                                  [](const RetireConnectionIdFrame &frame) {
                                      return frame.sequence_number == 11;
                                  }) == 1);
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_->active_connection_id_limit = 2;
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        connection.issue_spare_connection_ids();
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit_for_path(0) == 0);

        auto no_current_send_path = make_connected_client_connection();
        auto &no_current_path = no_current_send_path.ensure_path_state(0);
        no_current_send_path.current_send_path_id_.reset();
        no_current_send_path.previous_path_id_ = 0;
        no_current_send_path.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(!no_current_path.mtu.viable);
        COQUIC_CONNECTION_HOOK_RECORD(!no_current_send_path.pending_transport_close_.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_->active_connection_id_limit = 3;
        connection.current_send_path_id_.reset();
        connection.issue_spare_connection_ids();
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_new_connection_id_frames_.empty());

        auto missing_current_send_path = make_connected_client_connection();
        missing_current_send_path.peer_transport_parameters_->active_connection_id_limit = 3;
        missing_current_send_path.current_send_path_id_ = 27;
        missing_current_send_path.issue_spare_connection_ids();
        COQUIC_CONNECTION_HOOK_RECORD(
            !missing_current_send_path.pending_new_connection_id_frames_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::draining;
        connection.status_ = HandshakeStatus::failed;
        connection.close_started_at_ = QuicCoreTimePoint{};
        connection.close_deadline_ = QuicCoreTimePoint{} + std::chrono::milliseconds(1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.flush_outbound_datagram(QuicCoreTimePoint{}).empty());
        connection.enter_closing_state(QuicCoreTimePoint{}, QuicConnectionTerminalState::failed);
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::draining);
        connection.queue_transport_close_for_error(
            QuicCoreTimePoint{}, CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_transport_close_.has_value());
        connection.mark_silent_close();
        COQUIC_CONNECTION_HOOK_RECORD(connection.status_ == HandshakeStatus::failed);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.terminal_state_expired(QuicCoreTimePoint{}));
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.terminal_state_expired(QuicCoreTimePoint{} + std::chrono::milliseconds(1)));
    }

    {
        auto connection = make_connected_client_connection();
        connection.pending_transport_close_ = TransportConnectionCloseFrame{
            .error_code = transport_error_code_value(QuicTransportErrorCode::internal_error),
        };
        const auto transport_close = connection.connection_close_frame_for_send();
        COQUIC_CONNECTION_HOOK_RECORD(transport_close.has_value());
        if (transport_close.has_value()) {
            connection.mark_connection_close_frame_sent(*transport_close, QuicCoreTimePoint{});
        }
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_transport_close_.has_value());

        auto closing = make_connected_client_connection();
        closing.closing_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 1,
            .reason = ConnectionCloseReason{.bytes = bytes_from_ints_for_tests({0x63})},
        };
        COQUIC_CONNECTION_HOOK_RECORD(closing.connection_close_frame_for_send().has_value());
        auto pending = make_connected_client_connection();
        pending.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 2,
            .reason = ConnectionCloseReason{.bytes = bytes_from_ints_for_tests({0x64})},
        };
        COQUIC_CONNECTION_HOOK_RECORD(pending.connection_close_frame_for_send().has_value());
        pending.mark_connection_close_frame_sent(Frame{PingFrame{}}, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(pending.pending_application_close_.has_value());

        auto close_guard = make_connected_client_connection();
        close_guard.close_mode_ = QuicConnectionCloseMode::closing;
        close_guard.closing_close_packet_pending_ = false;
        COQUIC_CONNECTION_HOOK_RECORD(
            close_guard.flush_outbound_datagram(QuicCoreTimePoint{}).empty());
        close_guard.closing_close_packet_pending_ = true;
        close_guard.initial_packet_space_discarded_ = true;
        close_guard.handshake_space_.write_secret.reset();
        close_guard.application_space_.write_secret.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            close_guard.flush_outbound_datagram(QuicCoreTimePoint{}).empty());

        auto no_close_frame_send = make_connected_client_connection();
        no_close_frame_send.close_mode_ = QuicConnectionCloseMode::closing;
        no_close_frame_send.closing_close_packet_pending_ = true;
        no_close_frame_send.pending_application_close_.reset();
        no_close_frame_send.closing_application_close_.reset();
        no_close_frame_send.pending_transport_close_.reset();
        no_close_frame_send.closing_transport_close_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            no_close_frame_send.flush_outbound_datagram(QuicCoreTimePoint{}).empty());

        auto missing_close_metadata = make_connected_client_connection();
        missing_close_metadata.close_mode_ = QuicConnectionCloseMode::closing;
        missing_close_metadata.closing_close_packet_pending_ = true;
        missing_close_metadata.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 4,
        };
        {
            const ScopedConnectionDrainTestHook hook(
                &ConnectionDrainTestHooks::force_missing_close_packet_metadata);
            COQUIC_CONNECTION_HOOK_RECORD(
                !missing_close_metadata.flush_outbound_datagram(QuicCoreTimePoint{}).empty());
        }

        auto close_metadata_present = make_connected_client_connection();
        close_metadata_present.close_mode_ = QuicConnectionCloseMode::closing;
        close_metadata_present.closing_close_packet_pending_ = true;
        close_metadata_present.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 5,
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            !close_metadata_present.flush_outbound_datagram(QuicCoreTimePoint{}).empty());

        auto no_frame_close = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            !no_frame_close.connection_close_frame_for_send().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84},
                       std::byte{0x85}, std::byte{0x86}, std::byte{0x87}, std::byte{0x88}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_send());
        path.pending_response.reset();
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x91}, std::byte{0x92}, std::byte{0x93}, std::byte{0x94},
                       std::byte{0x95}, std::byte{0x96}, std::byte{0x97}, std::byte{0x98}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_send());
        path.mtu.viable = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
    }

    {
        auto connection = make_connected_client_connection();
        auto bidi_peer_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::server);
        bidi_peer_stream.peer_fin_delivered = true;
        bidi_peer_stream.send_fin_state = StreamSendFinState::acknowledged;
        connection.maybe_refresh_peer_stream_limit(bidi_peer_stream);
        COQUIC_CONNECTION_HOOK_RECORD(bidi_peer_stream.peer_stream_limit_released);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_stream_limit_state_.max_streams_bidi_state ==
                                      StreamControlFrameState::pending);

        auto uni_peer_stream = make_implicit_stream_state(/*stream_id=*/2, EndpointRole::server);
        uni_peer_stream.peer_fin_delivered = true;
        connection.maybe_refresh_peer_stream_limit(uni_peer_stream);
        COQUIC_CONNECTION_HOOK_RECORD(uni_peer_stream.peer_stream_limit_released);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_stream_limit_state_.max_streams_uni_state ==
                                      StreamControlFrameState::pending);
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::closing;
        connection.closing_close_packet_pending_ = true;
        connection.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 3,
        };
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_congestion_controlled_send());
    }

    {
        auto connection = make_connected_client_connection();
        connection.mark_failed();
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::failed});
        auto silent = make_connected_client_connection();
        silent.mark_silent_close();
        COQUIC_CONNECTION_HOOK_RECORD(silent.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::closed});
        auto already_terminal = make_connected_client_connection();
        already_terminal.pending_terminal_state_ = QuicConnectionTerminalState::closed;
        already_terminal.mark_failed();
        COQUIC_CONNECTION_HOOK_RECORD(already_terminal.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::closed});
        auto already_silent_terminal = make_connected_client_connection();
        already_silent_terminal.pending_terminal_state_ = QuicConnectionTerminalState::failed;
        already_silent_terminal.mark_silent_close();
        COQUIC_CONNECTION_HOOK_RECORD(already_silent_terminal.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::failed});
    }

    {
        auto connection = make_connected_client_connection();
        connection.latency_spin_bit_disabled_ = false;
        auto &path = connection.ensure_path_state(0);
        path.spin.disabled = true;
        connection.update_spin_bit_on_receive(0, true, 1);
        COQUIC_CONNECTION_HOOK_RECORD(!path.spin.largest_peer_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.outbound_spin_bit_for_path(std::nullopt));
        path.spin.disabled = false;
        path.spin.value = true;
        connection.current_send_path_id_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(!connection.outbound_spin_bit_for_path(std::nullopt));
        COQUIC_CONNECTION_HOOK_RECORD(!connection.outbound_spin_bit_for_path(99));
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x40});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x03}});
        connection.track_sent_packet(connection.initial_space_,
                                     SentPacketRecord{
                                         .packet_number = 6,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.pending_probe_packet.has_value() &&
            !connection.handshake_space_.pending_probe_packet->force_ack);
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        connection.track_sent_packet(connection.handshake_space_,
                                     SentPacketRecord{
                                         .packet_number = 7,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.handshake_space_.pending_probe_packet.has_value());
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x47});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x04}});
        connection.handshake_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 4,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.pending_probe_packet->packet_number == 4);
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x02}});
        connection.handshake_space_.received_packets.record_received(
            /*packet_number=*/3, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.track_sent_packet(connection.initial_space_,
                                     SentPacketRecord{
                                         .packet_number = 8,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.pending_probe_packet.has_value() &&
            connection.handshake_space_.pending_probe_packet->force_ack);
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        const auto original_initial_destination_connection_id =
            connection.config_.initial_destination_connection_id;
        const auto server_source_connection_id =
            bytes_from_ints_for_tests({0x02, 0x2c, 0x6e, 0x63, 0x26, 0xa1, 0xf4, 0x8e});
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            original_initial_destination_connection_id;
        connection.peer_source_connection_id_ = server_source_connection_id;
        connection.peer_connection_ids_[0] = PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = server_source_connection_id,
        };
        connection.active_peer_connection_id_sequence_ = 0;
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});

        auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});
        const auto decoded = deserialize_protected_datagram(
            datagram, DeserializeProtectionContext{
                          .peer_role = EndpointRole::client,
                          .client_initial_destination_connection_id =
                              original_initial_destination_connection_id,
                      });

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(decoded.has_value());
        if (decoded.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(decoded.value().size() == 1);
            const auto *initial = std::get_if<ProtectedInitialPacket>(&decoded.value().front());
            COQUIC_CONNECTION_HOOK_RECORD(initial != nullptr);
            if (initial != nullptr) {
                COQUIC_CONNECTION_HOOK_RECORD(initial->destination_connection_id ==
                                              server_source_connection_id);
                COQUIC_CONNECTION_HOOK_RECORD(initial->destination_connection_id !=
                                              original_initial_destination_connection_id);
                COQUIC_CONNECTION_HOOK_RECORD(initial->source_connection_id ==
                                              connection.config_.source_connection_id);
            }
        }
    }

    for (const auto secret_level :
         {EncryptionLevel::handshake, EncryptionLevel::zero_rtt, EncryptionLevel::application}) {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x90});
        if (secret_level == EncryptionLevel::handshake) {
            connection.handshake_space_.read_secret = TrafficSecret{
                .cipher_suite = invalid_cipher_suite_for_tests(),
                .secret = {std::byte{0x01}},
            };
        } else if (secret_level == EncryptionLevel::zero_rtt) {
            connection.zero_rtt_space_.read_secret = TrafficSecret{
                .cipher_suite = invalid_cipher_suite_for_tests(),
                .secret = {std::byte{0x02}},
            };
        } else {
            connection.application_space_.read_secret = TrafficSecret{
                .cipher_suite = invalid_cipher_suite_for_tests(),
                .secret = {std::byte{0x03}},
            };
        }

        auto datagram = serialize_handshake_ping_datagram(
            connection,
            make_connection_coverage_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256,
                                                    std::byte{0x90}),
            40 + static_cast<std::uint64_t>(secret_level));
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        if (!datagram.empty()) {
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        connection.handshake_space_.read_secret.reset();

        auto datagram = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_ints_for_tests({0x11, 0x22}),
                    .packet_number_length = 2,
                    .packet_number = 11,
                    .frames = {PingFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = make_connection_coverage_traffic_secret(
                    CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x43}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(datagram.has_value());
        if (datagram.has_value()) {
            connection.process_inbound_datagram(datagram.value(), QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.deferred_protected_packets_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        connection.handshake_space_.read_secret.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "discarded-handshake"));

        auto datagram = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_ints_for_tests({0x11, 0x23}),
                    .packet_number_length = 2,
                    .packet_number = 14,
                    .frames = {PingFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = make_connection_coverage_traffic_secret(
                    CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x45}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(datagram.has_value());
        if (datagram.has_value()) {
            connection.process_inbound_datagram(datagram.value(), QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.deferred_protected_packets_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x44});

        const auto first_packet = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xaa}},
                    .packet_number_length = 2,
                    .packet_number = 12,
                    .frames = {AckFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.read_secret,
            });
        auto second_packet = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xaa}},
                    .packet_number_length = 2,
                    .packet_number = 13,
                    .frames = {CryptoFrame{
                        .offset = 0,
                        .crypto_data = bytes_from_ints_for_tests({0x01}),
                    }},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.read_secret,
            });
        COQUIC_CONNECTION_HOOK_RECORD(first_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(second_packet.has_value());
        if (first_packet.has_value() && second_packet.has_value()) {
            auto datagram = first_packet.value();
            datagram.insert(datagram.end(), second_packet.value().begin(),
                            second_packet.value().end());
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_source_connection_id_ ==
                                      bytes_from_ints_for_tests({0xaa}));
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x46});
        COQUIC_CONNECTION_HOOK_RECORD(enable_qlog_for_connection_coverage(
            connection, "processed-before-deserialize-failure"));

        const auto first_packet = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xab}},
                    .packet_number_length = 2,
                    .packet_number = 15,
                    .frames = {AckFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.read_secret,
            });
        COQUIC_CONNECTION_HOOK_RECORD(first_packet.has_value());
        if (first_packet.has_value()) {
            auto datagram = first_packet.value();
            datagram.push_back(std::byte{0x40});
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_source_connection_id_ ==
                                      bytes_from_ints_for_tests({0xab}));
    }

    {
        auto connection = make_fast_path_connection();
        connection.application_space_.read_secret = TrafficSecret{
            .cipher_suite = invalid_cipher_suite_for_tests(),
            .secret = {std::byte{0xf1}},
        };
        process_fast_path_datagram(connection, {std::byte{0x40}});

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_fast_path_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                connection.application_space_.read_secret->cipher_suite =
                    invalid_cipher_suite_for_tests();
                connection.next_application_read_secret_ = next_read_secret.value();
                connection.next_application_read_secret_source_generation_ =
                    connection.application_read_secret_generation_;
                connection.next_application_read_key_phase_ =
                    !connection.application_read_key_phase_;
                process_fast_path_datagram(connection, {std::byte{0x40}});
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_fast_path_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/21,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
                const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
                    coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
                    /*occurrence=*/4);
                process_fast_path_datagram(connection, encoded);
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_fast_path_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/210,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                if (!encoded.empty()) {
                    process_fast_path_datagram(connection, encoded);
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_read_key_phase_);
    }

    {
        auto connection = make_fast_path_connection();
        const auto encoded = serialize_one_rtt_ack_datagram(
            connection, *connection.application_space_.read_secret,
            /*packet_number=*/211, connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
        if (!encoded.empty()) {
            auto truncated = encoded;
            truncated.pop_back();
            process_fast_path_datagram(connection, truncated);
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_fast_path_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.application_space_.optimistic_ack_skipped_packet_numbers = {0};
        const auto encoded = serialize_one_rtt_ack_datagram(
            connection, *connection.application_space_.read_secret,
            /*packet_number=*/212, connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
        if (!encoded.empty()) {
            process_fast_path_datagram(connection, encoded);
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_fast_path_connection();
        const auto encoded = serialize_one_rtt_frames_datagram(
            connection, *connection.application_space_.read_secret, /*packet_number=*/213,
            {CryptoFrame{.offset = 0, .crypto_data = bytes_from_ints_for_tests({0x33})}},
            connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
        if (!encoded.empty()) {
            process_fast_path_datagram(connection, encoded);
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_fast_path_connection();
        const auto encoded = serialize_one_rtt_frames_datagram(
            connection, *connection.application_space_.read_secret, /*packet_number=*/214,
            {CryptoFrame{.offset = 0, .crypto_data = bytes_from_ints_for_tests({0x34})}},
            connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
        if (!encoded.empty()) {
            const ScopedConnectionDrainTestHook hook(
                &ConnectionDrainTestHooks::force_sync_tls_state_failure);
            process_fast_path_datagram(connection, encoded);
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-context-failure"));
        auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                connection.application_space_.read_secret->header_protection_key =
                    next_read_secret.value().header_protection_key;
                const auto current_ready =
                    expand_traffic_secret_cached(*connection.application_space_.read_secret);
                COQUIC_CONNECTION_HOOK_RECORD(current_ready.has_value());
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/23,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                if (!encoded.empty()) {
                    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
                    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
                        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
                        /*occurrence=*/2);
                    connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/22,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.application_space_.write_secret = TrafficSecret{
                    .cipher_suite = invalid_cipher_suite_for_tests(),
                    .secret = {std::byte{0x01}},
                };
                connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-write-secret-failure"));
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/24,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.application_space_.write_secret = TrafficSecret{
                    .cipher_suite = invalid_cipher_suite_for_tests(),
                    .secret = {std::byte{0x01}},
                };
                connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-key-phase-qlog-retry-failure"));
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/25,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                if (!encoded.empty()) {
                    auto truncated = encoded;
                    truncated.pop_back();
                    connection.process_inbound_datagram(truncated, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.application_read_key_phase_);
    }

    {
        auto connection = make_connected_client_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/26,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.local_key_update_initiated_ = true;
                connection.local_key_update_requested_ = true;
                if (!encoded.empty()) {
                    connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_key_update_requested_);
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-key-phase-qlog-local-initiated"));
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/27,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.local_key_update_initiated_ = true;
                connection.local_key_update_requested_ = true;
                if (!encoded.empty()) {
                    connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_key_update_requested_);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.outstanding_challenge =
            std::array{std::byte{0xa1}, std::byte{0xa2}, std::byte{0xa3}, std::byte{0xa4},
                       std::byte{0xa5}, std::byte{0xa6}, std::byte{0xa7}, std::byte{0xa8}};
        path.challenge_pending = true;
        connection.previous_path_id_ = 5;
        auto &previous = connection.ensure_path_state(5);
        previous.peer_connection_id_sequence = 5;
        connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{.data = *path.outstanding_challenge}}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        const auto processed = connection.process_inbound_packet(
            ProtectedPacket{ProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x11, 0x91}),
                .packet_number_length = 2,
                .packet_number = 91,
                .frames = {PingFrame{}},
            }},
            QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x11, 0x92}),
                .packet_number_length = 2,
                .packet_number = 92,
                .frames = {PingFrame{}},
            }},
            QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_key_update_requested_ = true;
        connection.handshake_confirmed_ = true;
        connection.current_write_phase_first_packet_number_ = 0;
        connection.application_space_.recovery.largest_acked_packet_number_ = 0;
        connection.application_space_.read_secret = TrafficSecret{
            .cipher_suite = invalid_cipher_suite_for_tests(),
            .secret = {std::byte{0x05}},
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(0, bytes_from_ints_for_tests({0x61}), false).has_value());

        auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_key_update_requested_ = true;
        connection.handshake_confirmed_ = true;
        connection.current_write_phase_first_packet_number_ = 0;
        connection.application_space_.recovery.largest_acked_packet_number_ = 0;
        connection.application_space_.write_secret = TrafficSecret{
            .cipher_suite = invalid_cipher_suite_for_tests(),
            .secret = {std::byte{0x06}},
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(0, bytes_from_ints_for_tests({0x62}), false).has_value());

        auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = false;
        const auto processed = connection.process_inbound_received_crypto(
            EncryptionLevel::application,
            std::array<ReceivedFrame, 1>{ReceivedFrame{HandshakeDoneFrame{}}}, QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_confirmed_);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x51}, std::byte{0x02}},
            .initial_destination_connection_id = {std::byte{0x81}, std::byte{0x02}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = false;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{HandshakeDoneFrame{}}}, QuicCoreTimePoint{},
            /*allow_preconnected_frames=*/false, /*path_id=*/0);

        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(processed.error().code ==
                                      CodecErrorCode::frame_not_allowed_in_packet_type);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.handshake_confirmed_);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x51}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x81}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 0;
        connection.anti_amplification_sent_bytes_ = 0;
        connection.current_send_path_id_.reset();

        auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.initial_space_.recovery.on_packet_sent(SentPacketRecord{
            .packet_number = 0,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
        });
        const auto handles = connection.initial_space_.recovery.tracked_packets();
        COQUIC_CONNECTION_HOOK_RECORD(!handles.empty());
        if (!handles.empty()) {
            connection.initial_space_.recovery.retire_packet(handles.front());
            connection.initial_space_.recovery.slots_.front().state =
                PacketSpaceRecovery::LedgerSlotState::sent;
            connection.initial_space_.recovery.first_live_slot_ = 0;
            connection.initial_space_.recovery.last_live_slot_ = 0;
        }

        connection.discard_initial_packet_space();

        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_packet_space_discarded_);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x52}, std::byte{0x10}},
            .initial_destination_connection_id = {std::byte{0x82}, std::byte{0x10}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa7}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_packet_space_discarded_ = true;
        connection.handshake_packet_space_discarded_ = true;
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x52});
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x62});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x02}});
        connection.initial_space_.received_packets.record_received(
            /*packet_number=*/11, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.handshake_space_.received_packets.record_received(
            /*packet_number=*/12, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.initial_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 2,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        connection.handshake_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 3,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_sendable_datagram(QuicCoreTimePoint{}));
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.loss_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pto_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.ack_deadline().has_value());

        auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x52}, std::byte{0x11}},
            .initial_destination_connection_id = {std::byte{0x82}, std::byte{0x11}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa8}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_packet_space_discarded_ = true;
        connection.handshake_packet_space_discarded_ = true;
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x54});
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x64});
        connection.track_sent_packet(connection.initial_space_,
                                     SentPacketRecord{
                                         .packet_number = 30,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.handshake_space_,
                                     SentPacketRecord{
                                         .packet_number = 31,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.arm_pto_probe(QuicCoreTimePoint{} + std::chrono::seconds(30));
        connection.detect_lost_packets(QuicCoreTimePoint{} + std::chrono::seconds(30));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.initial_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.recovery.tracked_packet_count() ==
                                      1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.recovery.tracked_packet_count() ==
                                      1);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x52}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x82}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa5}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x53});
        connection.initial_space_.received_packets.record_received(
            /*packet_number=*/9, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.initial_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 1,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };

        auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.recovery.rtt_state().smoothed_rtt =
            std::chrono::milliseconds(1);
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 0,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        const AckFrame ack_frame{
            .largest_acknowledged = 1,
        };
        auto ack_cursor = make_ack_range_cursor(ack_frame);
        COQUIC_CONNECTION_HOOK_RECORD(ack_cursor.has_value());
        if (ack_cursor.has_value()) {
            static_cast<void>(connection.process_inbound_ack_cursor(
                connection.application_space_, ack_cursor.value(), /*largest_acknowledged=*/1,
                std::chrono::milliseconds{0}, std::nullopt, "[1-1]",
                QuicCoreTimePoint{} + std::chrono::seconds(5),
                connection.config_.transport.max_ack_delay,
                /*suppress_pto_reset=*/false));
        }
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_missing_packet_metadata);

        connection.detect_lost_packets(QuicCoreTimePoint{} + std::chrono::seconds(5));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 5,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .is_pmtu_probe = true,
                                     });
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_mark_lost_packet_missing_after_lookup);

        connection.detect_lost_packets(QuicCoreTimePoint{} + std::chrono::seconds(5));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.initial_space_.recovery.slots_.resize(1);
        auto &slot = connection.initial_space_.recovery.slots_.front();
        slot.state = PacketSpaceRecovery::LedgerSlotState::retired;
        slot.packet_number = 99;
        slot.packet = std::make_unique<SentPacketRecord>(SentPacketRecord{
            .packet_number = 99,
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
        });
        connection.initial_space_.recovery.live_links_.resize(1);
        connection.initial_space_.recovery.first_live_slot_ = 0;
        connection.initial_space_.recovery.last_live_slot_ = 0;

        connection.discard_initial_packet_space();

        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_packet_space_discarded_);
    }

    {
        auto connection = make_connected_client_connection();
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 12,
        });
        connection.peer_connection_ids_[12] = PeerConnectionIdRecord{
            .sequence_number = 12,
            .connection_id = bytes_from_ints_for_tests({0xbc}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x4c}},
        };
        auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.peer_connection_ids_.at(12).retire_frame_in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 13,
        });
        auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.contains(13));
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x54}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x84}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa6}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x55});
        connection.initial_space_.received_packets.record_received(
            /*packet_number=*/10, /*ack_eliciting=*/true, QuicCoreTimePoint{});

        auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.endpoint_route_generation_ = std::numeric_limits<std::uint64_t>::max();
        connection.note_endpoint_route_state_changed();
        COQUIC_CONNECTION_HOOK_RECORD(connection.endpoint_route_generation_ == 1);
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.max_outbound_datagram_size = 0;
        connection.peer_transport_parameters_->max_udp_payload_size = 0;
        connection.config_.transport.pmtud_enabled = false;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 1,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pacing_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_stream_pacing_deadline_bytes(std::size_t{1}).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        const auto cwnd = connection.congestion_controller_.congestion_window();
        if (cwnd > 1) {
            connection.congestion_controller_.on_packet_sent(cwnd - 1, /*ack_eliciting=*/true);
        }
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_stream_pacing_deadline_bytes(std::size_t{2}).has_value());

        connection = make_connected_client_connection();
        connection.config_.max_outbound_datagram_size = 24;
        connection.peer_transport_parameters_->max_udp_payload_size = 24;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_stream_pacing_deadline_bytes(std::size_t{1}) == 24u);

        connection = make_connected_client_connection();
        connection.peer_source_connection_id_ = std::vector<std::byte>(256, std::byte{0x22});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_stream_pacing_deadline_bytes(std::size_t{1}) ==
            connection.outbound_datagram_size_limit());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet.reset();
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_sendable_datagram(QuicCoreTimePoint{}));
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.note_aead_encryption_attempt(0, QuicCoreTimePoint{}));
        connection.application_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_chacha20_poly1305_sha256, std::byte{0x66});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.note_aead_encryption_attempt(1, QuicCoreTimePoint{}));
        connection.application_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_chacha20_poly1305_sha256, std::byte{0x67});
        COQUIC_CONNECTION_HOOK_RECORD(connection.note_packet_authentication_failure(
            CodecError{.code = CodecErrorCode::packet_decryption_failed, .offset = 0},
            QuicCoreTimePoint{}));
        connection.application_space_.read_secret.reset();
        COQUIC_CONNECTION_HOOK_RECORD(connection.note_packet_authentication_failure(
            CodecError{.code = CodecErrorCode::packet_decryption_failed, .offset = 0},
            QuicCoreTimePoint{}));
        COQUIC_CONNECTION_HOOK_RECORD(connection.non_paced_burst_allows_send(
            /*ack_eliciting=*/true, /*bypass_congestion_window=*/false, std::nullopt));
    }

    {
        auto connection = make_connected_client_connection();
        const std::array payload{std::byte{0x41}, std::byte{0x42}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.queue_stream_send(0, payload, true).has_value());
        auto *stream = connection.find_stream_state(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream != nullptr);
        if (stream != nullptr) {
            stream->send_buffer.mark_sent(0, 2);
            stream->send_buffer.mark_lost(0, 2);
            COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_send());
            COQUIC_CONNECTION_HOOK_RECORD(
                connection.minimum_pending_application_stream_wire_bytes().has_value());
            COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_fresh_application_stream_send());
        }
    }

    {
        auto connection = make_connected_client_connection();
        auto stream = connection.get_or_open_send_stream(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream.has_value());
        if (stream.has_value()) {
            stream.value()->send_buffer.append(std::vector<std::byte>{std::byte{0x51}});
            stream.value()->send_buffer.mark_sent(0, 1);
            SentPacketRecord packet{
                .packet_number = 71,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
            };
            packet.first_stream_frame_metadata = StreamFrameSendMetadata{
                .stream_id = 0,
                .offset = 0,
                .length = 1,
            };
            packet.bytes_in_flight = 1;
            connection.track_sent_packet(connection.application_space_, std::move(packet));
            const auto handles = connection.application_space_.recovery.tracked_packets();
            std::vector<SentPacketRecord> acked_packets;
            std::vector<AckedStreamPacketSample> simple_samples;
            COQUIC_CONNECTION_HOOK_RECORD(!handles.empty());
            if (!handles.empty()) {
                COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_simple_stream_acked_packet(
                    connection.application_space_, handles.front(), acked_packets, simple_samples,
                    /*use_lightweight_sample=*/false));
                COQUIC_CONNECTION_HOOK_RECORD(acked_packets.size() == 1);
            }
        }
    }

    {
        auto connection = make_connected_client_connection();
        AckedStreamPacketSample ect0{
            .packet_number = 1,
            .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(1),
            .bytes_in_flight = 1200,
            .path_id = 1,
            .ecn = QuicEcnCodepoint::ect0,
        };
        AckedStreamPacketSample ect1{
            .packet_number = 2,
            .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(2),
            .bytes_in_flight = 1200,
            .path_id = 2,
            .ecn = QuicEcnCodepoint::ect1,
        };
        std::array multi_path_samples{ect0, ect1};
        connection.ensure_path_state(1).ecn.total_sent_ect0 = 2;
        connection.ensure_path_state(1).ecn.total_sent_ect1 = 2;
        connection.ensure_path_state(2).ecn.total_sent_ect0 = 2;
        connection.ensure_path_state(2).ecn.total_sent_ect1 = 2;
        std::optional<QuicCoreTimePoint> latest_ce;
        COQUIC_CONNECTION_HOOK_RECORD(connection.process_simple_stream_ack_ecn(
            connection.application_space_, multi_path_samples,
            AckEcnCounts{.ect0 = 1, .ect1 = 1, .ecn_ce = 1}, latest_ce));
        COQUIC_CONNECTION_HOOK_RECORD(latest_ce.has_value());

        auto &path = connection.ensure_path_state(3);
        path.ecn.has_last_peer_counts[2] = true;
        path.ecn.last_peer_counts[2] = AckEcnCounts{.ect0 = 2, .ect1 = 2, .ecn_ce = 2};
        latest_ce.reset();
        COQUIC_CONNECTION_HOOK_RECORD(connection.process_single_path_simple_stream_ack_ecn(
            connection.application_space_, 3, /*newly_acked_ect0=*/0, /*newly_acked_ect1=*/1,
            QuicCoreTimePoint{} + std::chrono::milliseconds(3),
            AckEcnCounts{.ect0 = 2, .ect1 = 1, .ecn_ce = 2}, latest_ce));
        COQUIC_CONNECTION_HOOK_RECORD(path.ecn.state == QuicPathEcnState::failed);
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.role = EndpointRole::server;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.zero_rtt_space_.read_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x68});
        connection.current_send_path_id_ = 0;
        connection.last_inbound_path_id_ = 7;
        auto &current_path = connection.ensure_path_state(0);
        current_path.validated = false;
        auto &inbound_path = connection.ensure_path_state(7);
        inbound_path.validated = true;
        ReceivedStreamFrame stream_frame{
            .stream_id = 0,
            .stream_data = SharedBytes{std::byte{0x61}},
        };
        const auto processed_stream = connection.process_inbound_received_application_stream_packet(
            /*packet_number=*/91, /*spin_bit=*/true, stream_frame, QuicCoreTimePoint{},
            QuicEcnCodepoint::ect0);
        COQUIC_CONNECTION_HOOK_RECORD(processed_stream.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_address_validated_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.zero_rtt_discard_deadline().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.role = EndpointRole::client;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.zero_rtt_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x6a});
        connection.current_send_path_id_ = 0;
        connection.last_inbound_path_id_ = 8;
        auto &current_path = connection.ensure_path_state(0);
        current_path.validated = true;
        auto &inbound_path = connection.ensure_path_state(8);
        inbound_path.validated = true;
        ReceivedStreamFrame stream_frame{
            .stream_id = 0,
            .stream_data = SharedBytes{std::byte{0x62}},
        };
        const auto processed_stream = connection.process_inbound_received_application_stream_packet(
            /*packet_number=*/93, /*spin_bit=*/false, stream_frame, QuicCoreTimePoint{},
            QuicEcnCodepoint::ect1);
        COQUIC_CONNECTION_HOOK_RECORD(processed_stream.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 8);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.zero_rtt_space_.write_secret.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.role = EndpointRole::server;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.peer_transport_parameters_.reset();
        connection.zero_rtt_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x69});
        const auto processed_ack = connection.process_inbound_received_application_ack_only(
            /*packet_number=*/92, /*spin_bit=*/false, ReceivedAckFrame{.largest_acknowledged = 0},
            QuicCoreTimePoint{}, QuicEcnCodepoint::ect1, /*path_id=*/0,
            /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(processed_ack.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.zero_rtt_space_.write_secret == std::nullopt);
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 2;
        connection.previous_path_id_ = 1;
        auto &old_path = connection.ensure_path_state(1);
        old_path.validated = true;
        old_path.is_current_send_path = false;
        old_path.largest_inbound_application_packet_number = 94;
        auto &new_path = connection.ensure_path_state(2);
        new_path.validated = true;
        new_path.is_current_send_path = true;
        new_path.largest_inbound_application_packet_number = 100;

        const auto processed_ack = connection.process_inbound_received_application_ack_only(
            /*packet_number=*/95, /*spin_bit=*/false, ReceivedAckFrame{.largest_acknowledged = 0},
            QuicCoreTimePoint{}, QuicEcnCodepoint::ect1, /*path_id=*/1,
            /*used_previous_application_read_secret=*/false);

        COQUIC_CONNECTION_HOOK_RECORD(processed_ack.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 2);
        COQUIC_CONNECTION_HOOK_RECORD(new_path.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(!old_path.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(old_path.largest_inbound_application_packet_number == 95);
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 2;
        connection.previous_path_id_ = 1;
        auto &old_path = connection.ensure_path_state(1);
        old_path.validated = true;
        old_path.is_current_send_path = false;
        old_path.largest_inbound_application_packet_number = 94;
        auto &new_path = connection.ensure_path_state(2);
        new_path.validated = true;
        new_path.is_current_send_path = true;
        new_path.largest_inbound_application_packet_number = 100;

        const auto processed_ack = connection.process_inbound_received_application_ack_only(
            /*packet_number=*/101, /*spin_bit=*/false, ReceivedAckFrame{.largest_acknowledged = 0},
            QuicCoreTimePoint{}, QuicEcnCodepoint::ect1, /*path_id=*/1,
            /*used_previous_application_read_secret=*/false);

        COQUIC_CONNECTION_HOOK_RECORD(processed_ack.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 1);
        COQUIC_CONNECTION_HOOK_RECORD(old_path.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(!new_path.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(old_path.largest_inbound_application_packet_number == 101);
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::closing;
        connection.close_deadline_ = QuicCoreTimePoint{};
        connection.pending_connection_close_terminal_state_ = QuicConnectionTerminalState::failed;

        connection.on_timeout(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::none);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::failed});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.close_deadline_.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.last_drained_allows_send_continuation_ = true;
        connection.last_send_continuation_time_ =
            QuicCoreTimePoint{} + std::chrono::milliseconds(1);

        static_cast<void>(connection.drain_outbound_datagram(QuicCoreTimePoint{}));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.last_drained_allows_send_continuation_);
    }

    {
        auto connection = make_connected_client_connection();
        const std::array payload{std::byte{0x91}, std::byte{0x92}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.queue_stream_send(0, payload, false).has_value());
        auto *stream = connection.find_stream_state(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream != nullptr);
        if (stream != nullptr) {
            static_cast<void>(stream->send_buffer.take_ranges(2));
            stream->send_buffer.mark_lost(0, 2);
            connection.refresh_stream_sendable_byte_caches();
            COQUIC_CONNECTION_HOOK_RECORD(connection.streams_with_lost_send_data_ == 1);
            COQUIC_CONNECTION_HOOK_RECORD(
                connection.queue_stream_send(0, bytes_from_ints_for_tests({0x93}), false)
                    .has_value());
            COQUIC_CONNECTION_HOOK_RECORD(connection.streams_with_lost_send_data_ == 1);
            COQUIC_CONNECTION_HOOK_RECORD(connection
                                              .queue_stream_reset(LocalResetCommand{
                                                  .stream_id = 0,
                                                  .application_error_code = 7,
                                              })
                                              .has_value());
            COQUIC_CONNECTION_HOOK_RECORD(connection.streams_with_lost_send_data_ == 0);
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.max_outbound_datagram_size = 20;
        if (connection.peer_transport_parameters_.has_value()) {
            connection.peer_transport_parameters_->max_udp_payload_size = 20;
        }
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(0, bytes_from_ints_for_tests({0xa1}), false).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_sendable_datagram(QuicCoreTimePoint{}));
    }

    {
        auto connection = make_connected_client_connection();
        connection.initial_packet_space_discarded_ = false;
        connection.initial_space_.send_crypto = ReliableSendBuffer{};
        connection.initial_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 9,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pacing_deadline().has_value());

        connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = false;
        connection.handshake_space_.send_crypto = ReliableSendBuffer{};
        connection.handshake_space_.write_secret = make_connection_coverage_traffic_secret(
            CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa2});
        connection.handshake_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 10,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pacing_deadline().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 700,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .first_stream_frame_metadata =
                                             StreamFrameSendMetadata{
                                                 .stream_id = 9900,
                                                 .offset = 0,
                                                 .length = 1,
                                             },
                                         .stream_frame_metadata =
                                             {
                                                 StreamFrameSendMetadata{
                                                     .stream_id = 9901,
                                                     .offset = 0,
                                                     .length = 1,
                                                 },
                                             },
                                         .bytes_in_flight = 1,
                                     });

        auto selected_pto_probe = connection.select_pto_probe(connection.application_space_);

        COQUIC_CONNECTION_HOOK_RECORD(!selected_pto_probe.first_stream_frame_metadata.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(selected_pto_probe.stream_frame_metadata.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.next_application_read_secret_.reset();
        connection.next_application_read_secret_source_generation_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(connection.ensure_next_application_read_secret().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_application_read_secret_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.ensure_next_application_read_secret().has_value());

        connection.current_short_header_deserialize_cache_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.make_current_short_header_deserialize_context().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.current_short_header_deserialize_cache_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.make_current_short_header_deserialize_context().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        const AckFrame ack{.largest_acknowledged = 10};
        const auto cursor = make_ack_range_cursor(ack);
        COQUIC_CONNECTION_HOOK_RECORD(cursor.has_value());
        if (cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection
                    .detect_old_key_ack_of_current_key_phase_packet(
                        connection.initial_space_, cursor.value(), QuicCoreTimePoint{})
                    .has_value());
        }

        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 20,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .bytes_in_flight = 1,
                .protection_key_update_generation =
                    connection.current_application_write_key_generation_ + 1,
            });
        AckFrame out_of_range_ack{.largest_acknowledged = 10};
        auto out_of_range_cursor = make_ack_range_cursor(out_of_range_ack);
        COQUIC_CONNECTION_HOOK_RECORD(out_of_range_cursor.has_value());
        if (out_of_range_cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(connection
                                              .detect_old_key_ack_of_current_key_phase_packet(
                                                  connection.application_space_,
                                                  out_of_range_cursor.value(), QuicCoreTimePoint{})
                                              .has_value());
        }

        const AckFrame mismatched_ack{.largest_acknowledged = 20};
        auto mismatched_cursor = make_ack_range_cursor(mismatched_ack);
        COQUIC_CONNECTION_HOOK_RECORD(mismatched_cursor.has_value());
        if (mismatched_cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(connection
                                              .detect_old_key_ack_of_current_key_phase_packet(
                                                  connection.application_space_,
                                                  mismatched_cursor.value(), QuicCoreTimePoint{})
                                              .has_value());
        }

        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 21,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1,
                                         .protection_key_update_generation =
                                             connection.current_application_write_key_generation_,
                                     });
        auto failed_ack_receive_time = QuicCoreTimePoint{};
        auto failed_ack = connection.process_inbound_ack(
            connection.application_space_, AckFrame{.largest_acknowledged = 21},
            failed_ack_receive_time,
            /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
            /*suppress_pto_reset=*/false, /*used_previous_application_read_secret=*/true);
        COQUIC_CONNECTION_HOOK_RECORD(!failed_ack.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        std::vector<SentPacketRecord> acked_packets;
        std::vector<AckedStreamPacketSample> simple_samples;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.try_retire_simple_stream_acked_packet(
            connection.application_space_, RecoveryPacketHandle{.packet_number = 9999},
            acked_packets, simple_samples, /*use_lightweight_sample=*/false));

        const std::array not_empty_acked{SentPacketRecord{.packet_number = 1}};
        COQUIC_CONNECTION_HOOK_RECORD(!connection.try_ack_simple_congestion_batch(
            std::span<const AckedStreamPacketSample>{}, not_empty_acked, QuicCoreTimePoint{},
            connection.shared_recovery_rtt_state()));
        COQUIC_CONNECTION_HOOK_RECORD(connection.try_ack_simple_congestion_batch(
            std::span<const AckedStreamPacketSample>{}, std::span<const SentPacketRecord>{},
            QuicCoreTimePoint{}, connection.shared_recovery_rtt_state()));

        auto copa_config = make_client_core_config_for_connection_coverage();
        copa_config.role = EndpointRole::server;
        copa_config.transport.congestion_control = QuicCongestionControlAlgorithm::copa;
        auto copa_connection =
            make_connected_client_connection_for_connection_coverage(copa_config);
        copa_connection.track_sent_packet(
            copa_connection.application_space_,
            SentPacketRecord{
                .packet_number = 1,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .first_stream_frame_metadata =
                    StreamFrameSendMetadata{.stream_id = 0, .offset = 0, .length = 1},
                .bytes_in_flight = 1,
            });
        auto copa_ack_receive_time = QuicCoreTimePoint{} + std::chrono::milliseconds(1);
        auto copa_processed_ack = copa_connection.process_inbound_ack(
            copa_connection.application_space_, AckFrame{.largest_acknowledged = 1},
            copa_ack_receive_time, /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false,
            /*used_previous_application_read_secret=*/false);
        COQUIC_CONNECTION_HOOK_RECORD(copa_processed_ack.has_value());
        std::array sample{AckedStreamPacketSample{
            .packet_number = 2,
            .sent_time = QuicCoreTimePoint{},
            .bytes_in_flight = 1,
        }};
        COQUIC_CONNECTION_HOOK_RECORD(!copa_connection.try_ack_simple_congestion_batch(
            sample, std::span<const SentPacketRecord>{}, QuicCoreTimePoint{},
            copa_connection.shared_recovery_rtt_state()));
        COQUIC_CONNECTION_HOOK_RECORD(!copa_connection.try_ack_simple_congestion_batch(
            not_empty_acked, QuicCoreTimePoint{}, copa_connection.shared_recovery_rtt_state()));
        COQUIC_CONNECTION_HOOK_RECORD(!copa_connection.can_use_simple_stream_ack_fast_path(
            std::span<const SentPacketRecord>{}, /*has_late_acked_packets=*/false));

        auto cubic_config = make_client_core_config_for_connection_coverage();
        cubic_config.role = EndpointRole::server;
        cubic_config.transport.congestion_control = QuicCongestionControlAlgorithm::cubic;
        auto cubic_connection =
            make_connected_client_connection_for_connection_coverage(cubic_config);
        COQUIC_CONNECTION_HOOK_RECORD(cubic_connection.can_use_simple_stream_ack_fast_path(
            std::span<const SentPacketRecord>{}, /*has_late_acked_packets=*/false));

        auto fast_path_config = make_client_core_config_for_connection_coverage();
        fast_path_config.role = EndpointRole::server;
        auto fast_path_connection =
            make_connected_client_connection_for_connection_coverage(fast_path_config);
        std::array ce_sample{AckedStreamPacketSample{
            .packet_number = 3,
            .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(3),
            .congestion_send_sequence = 3,
            .bytes_in_flight = 1200,
            .path_id = 33,
            .ecn = QuicEcnCodepoint::ect1,
        }};
        AckApplyResult ack_result{.largest_acknowledged_was_newly_acked = true};
        COQUIC_CONNECTION_HOOK_RECORD(fast_path_connection.try_ack_simple_stream_fast_path(
            fast_path_connection.application_space_, ack_result, ce_sample,
            std::span<const SentPacketRecord>{}, QuicCoreTimePoint{} + std::chrono::milliseconds(4),
            AckEcnCounts{.ecn_ce = 1}, /*suppress_pto_reset=*/false));

        AckApplyResult lost_ack_result;
        lost_ack_result.lost_packets.push_back(RecoveryPacketHandle{.packet_number = 99});
        COQUIC_CONNECTION_HOOK_RECORD(!fast_path_connection.try_ack_simple_stream_fast_path(
            fast_path_connection.application_space_, lost_ack_result, ce_sample,
            std::span<const SentPacketRecord>{}, QuicCoreTimePoint{}, AckEcnCounts{},
            /*suppress_pto_reset=*/false));

        std::array non_empty_acked_packet{SentPacketRecord{.packet_number = 4}};
        COQUIC_CONNECTION_HOOK_RECORD(!fast_path_connection.try_ack_simple_stream_fast_path(
            fast_path_connection.application_space_, AckApplyResult{}, ce_sample,
            non_empty_acked_packet, QuicCoreTimePoint{}, AckEcnCounts{},
            /*suppress_pto_reset=*/false));
    }

    {
        auto connection = make_connected_client_connection();
        SentPacketRecord packet{
            .packet_number = 72,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = true,
            .in_flight = true,
            .first_stream_frame_metadata =
                StreamFrameSendMetadata{.stream_id = 7200, .offset = 0, .length = 1},
            .bytes_in_flight = 1,
        };
        connection.track_sent_packet(connection.application_space_, std::move(packet));
        std::vector<SentPacketRecord> acked_packets;
        std::vector<AckedStreamPacketSample> simple_samples;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.try_retire_simple_stream_acked_packet(
            connection.application_space_,
            RecoveryPacketHandle{
                .packet_number = 72,
                .slot_index = std::numeric_limits<std::size_t>::max(),
            },
            acked_packets, simple_samples, /*use_lightweight_sample=*/false));
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 73,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .first_stream_frame_metadata =
                    StreamFrameSendMetadata{.stream_id = 7300, .offset = 0, .length = 1},
                .bytes_in_flight = 1,
            });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(73);
        std::vector<SentPacketRecord> acked_packets;
        std::vector<AckedStreamPacketSample> simple_samples;
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_simple_stream_acked_packet(
                connection.application_space_, *handle, acked_packets, simple_samples,
                /*use_lightweight_sample=*/true));
        }
        COQUIC_CONNECTION_HOOK_RECORD(simple_samples.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &stream =
            connection.streams_.emplace(74, make_implicit_stream_state(74, EndpointRole::client))
                .first->second;
        stream.reset_state = StreamControlFrameState::pending;
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 74,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .first_stream_frame_metadata =
                    StreamFrameSendMetadata{.stream_id = 74, .offset = 0, .length = 1},
                .bytes_in_flight = 1,
            });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(74);
        std::vector<SentPacketRecord> acked_packets;
        std::vector<AckedStreamPacketSample> simple_samples;
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(connection.try_retire_simple_stream_acked_packet(
                connection.application_space_, *handle, acked_packets, simple_samples,
                /*use_lightweight_sample=*/true));
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 77,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .reset_stream_frames = {ResetStreamFrame{.stream_id = 7700}},
                .stream_frame_metadata =
                    {
                        StreamFrameSendMetadata{.stream_id = 7701, .offset = 0, .length = 1},
                    },
                .bytes_in_flight = 1,
            });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(77);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection.retire_acked_packet(connection.application_space_, *handle).has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 75,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .reset_stream_frames = {ResetStreamFrame{.stream_id = 7500}},
                .stop_sending_frames = {StopSendingFrame{.stream_id = 7501}},
                .max_stream_data_frames = {MaxStreamDataFrame{.stream_id = 7502}},
                .stream_data_blocked_frames = {StreamDataBlockedFrame{.stream_id = 7503}},
                .first_stream_frame_metadata =
                    StreamFrameSendMetadata{.stream_id = 7504, .offset = 0, .length = 1},
                .stream_frame_metadata =
                    {
                        StreamFrameSendMetadata{.stream_id = 7506, .offset = 1, .length = 1},
                    },
                .stream_fragments =
                    {
                        StreamFrameSendFragment{
                            .stream_id = 7505,
                            .offset = 0,
                            .bytes = SharedBytes{std::byte{0x75}},
                        },
                    },
                .bytes_in_flight = 1,
            });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(75);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection.retire_acked_packet(connection.application_space_, *handle).has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 76,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .reset_stream_frames = {ResetStreamFrame{.stream_id = 7600}},
                .stop_sending_frames = {StopSendingFrame{.stream_id = 7601}},
                .max_stream_data_frames = {MaxStreamDataFrame{.stream_id = 7602}},
                .stream_data_blocked_frames = {StreamDataBlockedFrame{.stream_id = 7603}},
                .first_stream_frame_metadata =
                    StreamFrameSendMetadata{.stream_id = 7604, .offset = 0, .length = 1},
                .stream_frame_metadata =
                    {
                        StreamFrameSendMetadata{.stream_id = 7606, .offset = 1, .length = 1},
                    },
                .stream_fragments =
                    {
                        StreamFrameSendFragment{
                            .stream_id = 7605,
                            .offset = 0,
                            .bytes = SharedBytes{std::byte{0x76}},
                        },
                    },
                .bytes_in_flight = 1,
            });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(76);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection
                    .mark_lost_packet(connection.application_space_, *handle,
                                      /*already_marked_in_recovery=*/false, QuicCoreTimePoint{})
                    .has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 78,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .reset_stream_frames = {ResetStreamFrame{.stream_id = 7800}},
                .stream_frame_metadata =
                    {
                        StreamFrameSendMetadata{.stream_id = 7801, .offset = 0, .length = 1},
                    },
                .bytes_in_flight = 1,
            });
        auto handle = connection.application_space_.recovery.handle_for_packet_number(78);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection
                    .mark_lost_packet(connection.application_space_, *handle,
                                      /*already_marked_in_recovery=*/false, QuicCoreTimePoint{})
                    .has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_transport_parameters_.disable_active_migration = true;
        const auto pending_before = connection.pending_new_connection_id_frames_.size();
        connection.issue_path_probe_replacement_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.size() ==
                                      pending_before);
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_->active_connection_id_limit = 0;
        const auto pending_before = connection.pending_new_connection_id_frames_.size();
        connection.issue_path_probe_replacement_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.size() ==
                                      pending_before);
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_->active_connection_id_limit = 1;
        connection.local_connection_ids_.clear();
        connection.local_connection_ids_[0] = LocalConnectionIdRecord{
            .sequence_number = 0,
            .retired = true,
        };
        connection.local_connection_ids_[1] = LocalConnectionIdRecord{
            .sequence_number = 1,
            .retirement_requested = true,
        };
        connection.local_connection_ids_[2] = LocalConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints_for_tests({0xc2}),
        };
        connection.next_local_connection_id_sequence_ = 3;
        connection.issue_path_probe_replacement_connection_id();
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_new_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.pending_new_connection_id_frames_.back().retire_prior_to == 3);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_connection_ids_.at(2).retirement_requested);
    }

    {
        auto connection = make_connected_client_connection();
        const auto limit =
            confidentiality_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256);
        COQUIC_CONNECTION_HOOK_RECORD(limit.has_value());
        if (limit.has_value()) {
            connection.current_application_write_key_encrypted_packets_ = *limit;
            COQUIC_CONNECTION_HOOK_RECORD(
                !connection.note_aead_encryption_attempt(1, QuicCoreTimePoint{}));
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.read_secret = TrafficSecret{
            .cipher_suite = static_cast<CipherSuite>(255),
            .secret = {std::byte{0x01}},
        };
        COQUIC_CONNECTION_HOOK_RECORD(connection.note_packet_authentication_failure(
            CodecError{.code = CodecErrorCode::packet_decryption_failed, .offset = 0},
            QuicCoreTimePoint{}));
    }

    {
        auto connection = make_connected_client_connection();
        const auto limit = integrity_limit_for_cipher_suite(CipherSuite::tls_aes_128_gcm_sha256);
        COQUIC_CONNECTION_HOOK_RECORD(limit.has_value());
        if (limit.has_value()) {
            connection.failed_authentication_packets_ = *limit;
            COQUIC_CONNECTION_HOOK_RECORD(!connection.note_packet_authentication_failure(
                CodecError{.code = CodecErrorCode::packet_decryption_failed, .offset = 0},
                QuicCoreTimePoint{}));
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.active_queued_stream_bytes_ = std::numeric_limits<std::uint64_t>::max() - 1;
        connection.note_stream_send_bytes_queued(2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.active_queued_stream_bytes_ ==
                                      std::numeric_limits<std::uint64_t>::max());

        connection.fresh_sendable_stream_bytes_ = std::numeric_limits<std::uint64_t>::max() - 1;
        connection.note_stream_fresh_sendable_bytes_delta(0, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.fresh_sendable_stream_bytes_ ==
                                      std::numeric_limits<std::uint64_t>::max());

        connection.fresh_sendable_stream_bytes_ = 1;
        connection.note_stream_fresh_sendable_bytes_delta(3, 0);
        COQUIC_CONNECTION_HOOK_RECORD(connection.fresh_sendable_stream_bytes_ == 0);

        StreamState forgotten = make_implicit_stream_state(4, EndpointRole::client);
        forgotten.send_flow_control_committed = 2;
        forgotten.reset_state = StreamControlFrameState::pending;
        connection.active_queued_stream_bytes_ = 1;
        connection.forget_active_stream_queued_bytes(forgotten);
        COQUIC_CONNECTION_HOOK_RECORD(connection.active_queued_stream_bytes_ == 0);
    }

    {
        auto connection = make_connected_client_connection();
        const std::array payload{std::byte{0xa1}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.queue_stream_send(0, payload, false).has_value());
        connection.fresh_sendable_stream_bytes_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_send());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_fresh_application_stream_send());
    }

    {
        auto connection = make_connected_client_connection();
        auto &stream =
            connection.streams_.emplace(4, make_implicit_stream_state(4, EndpointRole::client))
                .first->second;
        stream.reset_state = StreamControlFrameState::pending;
        connection.fresh_sendable_stream_bytes_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_fresh_application_stream_send());
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.should_keep_current_send_path_for_inbound_non_probing(0));

        connection.current_send_path_id_ = 1;
        connection.ensure_path_state(1).validated = true;
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.should_keep_current_send_path_for_inbound_non_probing(1));

        auto &current = connection.ensure_path_state(2);
        current.preferred_address_path = true;
        current.validated = false;
        connection.current_send_path_id_ = 2;
        connection.ensure_path_state(3).validated = false;
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.should_keep_current_send_path_for_inbound_non_probing(3));

        auto &old_path = connection.ensure_path_state(4);
        old_path.validated = true;
        old_path.is_current_send_path = false;
        auto &new_path = connection.ensure_path_state(5);
        new_path.validated = true;
        new_path.is_current_send_path = true;
        new_path.largest_inbound_application_packet_number = 44;
        connection.current_send_path_id_ = 5;
        connection.previous_path_id_ = 4;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.should_keep_current_send_path_for_inbound_non_probing(4, 43));
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.should_keep_current_send_path_for_inbound_non_probing(4, 45));
    }

    {
        auto connection = make_connected_client_connection();
        AckedStreamPacketSample first{
            .packet_number = 1,
            .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(1),
            .bytes_in_flight = 1200,
            .path_id = 4,
            .ecn = QuicEcnCodepoint::ect0,
        };
        AckedStreamPacketSample second{
            .packet_number = 2,
            .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(2),
            .bytes_in_flight = 1200,
            .path_id = 5,
            .ecn = QuicEcnCodepoint::ect1,
        };
        AckedStreamPacketSample third{
            .packet_number = 3,
            .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(3),
            .bytes_in_flight = 1200,
            .path_id = 5,
            .ecn = QuicEcnCodepoint::ect0,
        };
        std::array samples{first, second, third};
        connection.ensure_path_state(4).ecn.total_sent_ect0 = 4;
        connection.ensure_path_state(4).ecn.total_sent_ect1 = 4;
        connection.ensure_path_state(5).ecn.total_sent_ect0 = 4;
        connection.ensure_path_state(5).ecn.total_sent_ect1 = 4;
        std::optional<QuicCoreTimePoint> latest_ce;
        COQUIC_CONNECTION_HOOK_RECORD(connection.process_simple_stream_ack_ecn(
            connection.application_space_, samples, AckEcnCounts{.ect0 = 2, .ect1 = 1, .ecn_ce = 1},
            latest_ce));
        COQUIC_CONNECTION_HOOK_RECORD(latest_ce.has_value());

        latest_ce.reset();
        auto &missing_feedback_path = connection.ensure_path_state(6);
        missing_feedback_path.ecn.total_sent_ect0 = 10;
        COQUIC_CONNECTION_HOOK_RECORD(connection.process_single_path_simple_stream_ack_ecn(
            connection.application_space_, 6, /*newly_acked_ect0=*/4, /*newly_acked_ect1=*/0,
            QuicCoreTimePoint{} + std::chrono::milliseconds(4),
            AckEcnCounts{.ect0 = 1, .ect1 = 0, .ecn_ce = 0}, latest_ce));
        COQUIC_CONNECTION_HOOK_RECORD(missing_feedback_path.ecn.state == QuicPathEcnState::failed);

        latest_ce.reset();
        auto &impossible_path = connection.ensure_path_state(7);
        impossible_path.ecn.total_sent_ect0 = 0;
        COQUIC_CONNECTION_HOOK_RECORD(connection.process_single_path_simple_stream_ack_ecn(
            connection.application_space_, 7, /*newly_acked_ect0=*/0, /*newly_acked_ect1=*/0,
            QuicCoreTimePoint{} + std::chrono::milliseconds(5),
            AckEcnCounts{.ect0 = 1, .ect1 = 0, .ecn_ce = 0}, latest_ce));
        COQUIC_CONNECTION_HOOK_RECORD(impossible_path.ecn.state == QuicPathEcnState::failed);
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() ==
                                      std::numeric_limits<std::uint64_t>::max());

        connection.config_.role = EndpointRole::server;
        connection.status_ = HandshakeStatus::connected;
        connection.peer_address_validated_ = true;
        connection.current_send_path_id_ = 0;
        auto &current_path = connection.ensure_path_state(0);
        current_path.validated = false;
        current_path.anti_amplification_received_bytes = 10;
        current_path.anti_amplification_sent_bytes = 7;
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_applies());
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() == 23);

        auto &pending_response_path = connection.ensure_path_state(9);
        pending_response_path.validated = false;
        pending_response_path.pending_response =
            std::array{std::byte{0xb1}, std::byte{0xb2}, std::byte{0xb3}, std::byte{0xb4},
                       std::byte{0xb5}, std::byte{0xb6}, std::byte{0xb7}, std::byte{0xb8}};
        pending_response_path.anti_amplification_received_bytes =
            std::numeric_limits<std::uint64_t>::max();
        pending_response_path.anti_amplification_sent_bytes = 1;
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_send_budget() ==
                                      std::numeric_limits<std::uint64_t>::max());
        COQUIC_CONNECTION_HOOK_RECORD(connection.anti_amplification_remaining_send_budget() ==
                                      std::numeric_limits<std::uint64_t>::max() - 1);
    }

#undef COQUIC_CONNECTION_HOOK_RECORD
#undef COQUIC_STRINGIFY
#undef COQUIC_STRINGIFY_DETAIL
    return ok;
}

} // namespace coquic::quic::test

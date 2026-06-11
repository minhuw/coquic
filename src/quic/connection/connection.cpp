#include "src/quic/connection/connection.h"
#include "src/quic/connection/connection_internal.h"

namespace coquic::quic {

QuicConnection::QuicConnection(QuicCoreConfig config)
    : config_(std::move(config)),
      //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
      // # Even when the spin bit is not disabled by the administrator,
      // # endpoints MUST disable their use of the spin bit for a random
      // # selection of at least one in every 16 network paths, or for one in
      // # every 16 connection IDs, in order to ensure that QUIC connections
      // # that disable the spin bit are commonly observed on the network.
      //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
      // # An endpoint that does not support this feature MUST disable it, as
      // # defined below.
      latency_spin_bit_disabled_(config_.transport.enable_latency_spin_bit ? random_one_in_sixteen()
                                                                           : true),
      disabled_latency_spin_bit_value_(random_bool_for_disabled_spin_bit()),
      original_version_(config_.original_version), current_version_(config_.initial_version),
      grease_quic_bit_seed_(make_grease_quic_bit_seed()),
      congestion_controller_(config_.transport.congestion_control,
                             initial_congestion_datagram_size(config_),
                             config_.transport.enable_hystart_plus_plus) {
    if (config_.supported_versions.empty()) {
        config_.supported_versions.push_back(current_version_);
    }
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .preferred_address = config_.transport.preferred_address,
        .max_datagram_frame_size = config_.transport.max_datagram_frame_size,
        .grease_quic_bit = config_.transport.grease_quic_bit,
    };
    initialize_local_flow_control();
    local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                         .sequence_number = 0,
                                         .connection_id = config_.source_connection_id,
                                         .stateless_reset_token = make_stateless_reset_token(
                                             config_.source_connection_id, /*sequence_number=*/0,
                                             config_.stateless_reset_secret),
                                     });
    if (config_.transport.preferred_address.has_value()) {
        // RFC 9000 reserves sequence number 1 for the preferred-address CID.
        local_connection_ids_.emplace(
            1,
            LocalConnectionIdRecord{
                .sequence_number = 1,
                .connection_id = config_.transport.preferred_address->connection_id,
                .stateless_reset_token = config_.transport.preferred_address->stateless_reset_token,
            });
        next_local_connection_id_sequence_ = 2;
    }
    peer_address_validated_ = config_.role == EndpointRole::client;
}

QuicConnection::~QuicConnection() = default;

QuicConnection::QuicConnection(QuicConnection &&other) noexcept = default;

QuicConnection &QuicConnection::operator=(QuicConnection &&other) noexcept = default;

void QuicConnection::start() {
    start(QuicCoreTimePoint{});
}

void QuicConnection::start(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    start_client_if_needed(now);
}

QuicInboundDatagramResult QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                                                   QuicCoreTimePoint now,
                                                                   QuicPathId path_id,
                                                                   QuicEcnCodepoint ecn) {
    const auto inbound_datagram_id = next_qlog_inbound_datagram_id(qlog_session_.get());
    return process_inbound_datagram(bytes, now, path_id, ecn, inbound_datagram_id,
                                    /*replay_trigger=*/false, /*count_inbound_bytes=*/true);
}

QuicInboundDatagramResult
QuicConnection::process_inbound_datagram_owned(std::vector<std::byte> bytes, QuicCoreTimePoint now,
                                               QuicPathId path_id, QuicEcnCodepoint ecn) {
    const auto inbound_datagram_id = next_qlog_inbound_datagram_id(qlog_session_.get());
    auto storage = std::make_shared<std::vector<std::byte>>(std::move(bytes));
    const auto storage_size = storage->size();
    return process_inbound_datagram(std::move(storage), 0, storage_size, now, path_id, ecn,
                                    inbound_datagram_id, /*replay_trigger=*/false,
                                    /*count_inbound_bytes=*/true,
                                    /*allow_in_place_receive_decode=*/true);
}

QuicInboundDatagramResult QuicConnection::process_inbound_datagram_shared(
    std::shared_ptr<std::vector<std::byte>> storage, std::size_t begin, std::size_t end,
    QuicCoreTimePoint now, QuicPathId path_id, QuicEcnCodepoint ecn) {
    const auto inbound_datagram_id = next_qlog_inbound_datagram_id(qlog_session_.get());
    return process_inbound_datagram(std::move(storage), begin, end, now, path_id, ecn,
                                    inbound_datagram_id,
                                    /*replay_trigger=*/false,
                                    /*count_inbound_bytes=*/true,
                                    /*allow_in_place_receive_decode=*/true);
}

QuicInboundDatagramResult
QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes, QuicCoreTimePoint now,
                                         QuicPathId path_id, QuicEcnCodepoint ecn,
                                         std::optional<std::uint32_t> inbound_datagram_id,
                                         bool replay_trigger, bool count_inbound_bytes) {
    auto storage = std::make_shared<std::vector<std::byte>>(bytes.begin(), bytes.end());
    const auto storage_size = storage->size();
    return process_inbound_datagram(std::move(storage), 0, storage_size, now, path_id, ecn,
                                    inbound_datagram_id, replay_trigger, count_inbound_bytes,
                                    /*allow_in_place_receive_decode=*/false);
}

QuicInboundDatagramResult QuicConnection::process_inbound_datagram(
    std::shared_ptr<std::vector<std::byte>> storage, std::size_t begin, std::size_t end,
    QuicCoreTimePoint now, QuicPathId path_id, QuicEcnCodepoint ecn,
    std::optional<std::uint32_t> inbound_datagram_id, bool replay_trigger, bool count_inbound_bytes,
    bool allow_in_place_receive_decode) {
    QuicInboundDatagramResult result;
    if (!storage || begin > end || end > storage->size()) {
        return process_inbound_datagram(std::span<const std::byte>{}, now, path_id, ecn,
                                        inbound_datagram_id, replay_trigger, count_inbound_bytes);
    }

    const auto bytes = std::span<const std::byte>(*storage).subspan(begin, end - begin);
    register_send_profile_printer_once();
    if (send_profile_enabled()) {
        ++send_profile_counters().inbound_calls;
        send_profile_counters().inbound_bytes += bytes.size();
    }
    COQUIC_SEND_PROFILE_TIMER(inbound_timer, inbound_ns);
    COQUIC_SEND_PROFILE_TIMER(setup_timer, inbound_setup_ns);
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        if (close_mode_ == QuicConnectionCloseMode::closing) {
            last_inbound_path_id_ = path_id;
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.1
            // # To avoid being used for an amplification attack, such endpoints
            // # MUST limit the cumulative size of packets it sends to three
            // # times the cumulative size of the packets that are received and
            // # attributed to the connection.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.1
            // # An endpoint in the closing state MUST either discard packets
            // # received from an unvalidated address or limit the cumulative
            // # size of packets it sends to an unvalidated address to three
            // # times the size of packets it receives from that address.
            maybe_note_inbound_datagram_bytes(
                count_inbound_bytes, bytes, accepts_greased_quic_bit(),
                [&](std::size_t byte_count) { note_inbound_datagram_bytes(byte_count); });
        }
        if (close_mode_ == QuicConnectionCloseMode::closing) {
            ++closing_packets_since_last_close_;
            if (closing_packets_since_last_close_ >= closing_packet_response_threshold_) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-11.1
                // # An endpoint SHOULD be prepared to retransmit a packet
                // # containing a CONNECTION_CLOSE frame if it receives more
                // # packets on a terminated connection.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.1
                // # An endpoint SHOULD limit the rate at which it generates
                // # packets in the closing state.
                closing_close_packet_pending_ = true;
            }
        }
        return result;
    }
    last_inbound_path_id_ = path_id;
    if (!current_send_path_id_.has_value()) {
        current_send_path_id_ = path_id;
        auto &path = ensure_path_state(path_id);
        path.is_current_send_path = true;
        if (path.mtu.validated_datagram_size < bytes.size()) {
            path.mtu.validated_datagram_size =
                std::min(bytes.size(), outbound_datagram_size_ceiling_for_path(path_id));
            path.mtu.search_low = path.mtu.validated_datagram_size;
        }
    }

    maybe_discard_server_zero_rtt_packet_space(now);
    maybe_discard_previous_application_read_secret(now);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # For the purposes of avoiding amplification prior to address
    // # validation, servers MUST count all of the payload bytes received in
    // # datagrams that are uniquely attributed to a single connection.
    maybe_note_inbound_datagram_bytes(
        count_inbound_bytes, bytes, accepts_greased_quic_bit(),
        [&](std::size_t byte_count) { note_inbound_datagram_bytes(byte_count); });

    if (!started_) {
        if (config_.role != EndpointRole::server) {
            queue_transport_close_for_error(
                now, CodecError{.code = CodecErrorCode::unsupported_packet_type, .offset = 0});
            return result;
        }

        const auto initial_destination_connection_id =
            peek_client_initial_destination_connection_id(bytes);
        if (!initial_destination_connection_id.has_value()) {
            log_codec_failure("peek_client_initial_destination_connection_id",
                              initial_destination_connection_id.error());
            queue_transport_close_for_error(now, initial_destination_connection_id.error());
            return result;
        }

        start_server_if_needed(initial_destination_connection_id.value(), now,
                               read_u32_be(bytes.subspan(1, 4)));
    }

    auto synced = CodecResult<bool>::success(true);
    auto receive_sync_state = can_skip_receive_tls_sync(bytes);
    if (!receive_sync_state) {
        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_initial_sync_tls_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(sync_timer, inbound_initial_sync_tls_ns);
        synced = sync_tls_state();
    } else if (send_profile_enabled()) {
        ++send_profile_counters().inbound_initial_sync_tls_skipped;
    }
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        queue_transport_close_for_error(now, synced.error());
        return result;
    }
    setup_timer.stop();

    const auto defer_packet =
        [&](std::span<const std::byte> packet_bytes, QuicPathId deferred_path_id,
            std::optional<std::uint32_t> deferred_datagram_id, QuicEcnCodepoint deferred_ecn,
            QuicCoreTimePoint packet_received_time) {
            queue_deferred_protected_datagram(deferred_protected_packets_, packet_bytes,
                                              deferred_path_id, deferred_datagram_id, deferred_ecn,
                                              packet_received_time);
        };
    std::size_t offset = 0;
    bool processed_any_packet = false;
    std::optional<ConnectionId> first_datagram_destination_connection_id;
    const auto make_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> CodecResult<DeserializeProtectionContext> {
        if (send_profile_enabled()) {
            ++send_profile_counters().make_deserialize_context_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(make_context_timer, make_deserialize_context_ns);
        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.read_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(
                handshake_ready.error().code, handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.read_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(
                zero_rtt_ready.error().code, zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                      one_rtt_ready.error().offset);
        }

        return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.read_secret,
            .zero_rtt_secret = zero_rtt_space_.read_secret,
            .one_rtt_secret = application_secret,
            .one_rtt_secret_cache_primed = traffic_secret_cache_is_primed(application_secret),
            .one_rtt_key_phase = application_key_phase,
            .largest_authenticated_initial_packet_number =
                initial_space_.largest_authenticated_packet_number,
            .largest_authenticated_handshake_packet_number =
                handshake_space_.largest_authenticated_packet_number,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
            .accept_greased_quic_bit = accepts_greased_quic_bit(),
        });
    };
    const auto make_short_header_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> CodecResult<DeserializeProtectionContext> {
        if (send_profile_enabled()) {
            ++send_profile_counters().make_deserialize_context_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(make_context_timer, make_deserialize_context_ns);
        const auto one_rtt_ready = prime_traffic_secret_cache(application_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                      one_rtt_ready.error().offset);
        }

        return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .one_rtt_secret_ref = &application_secret.value(),
            .one_rtt_secret_cache_primed = traffic_secret_cache_is_primed(application_secret),
            .one_rtt_key_phase = application_key_phase,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
            .accept_greased_quic_bit = accepts_greased_quic_bit(),
        });
    };
    struct PacketProcessingLabels {
        std::string_view deserialize;
        std::string_view process;
    };
    const auto process_packet_bytes_with =
        [&](std::span<const std::byte> packet_bytes, bool allow_defer, QuicPathId packet_path_id,
            QuicEcnCodepoint packet_ecn, QuicCoreTimePoint packet_received_time,
            std::optional<std::uint32_t> datagram_id, bool packet_replay_trigger,
            auto deserialize_packets, auto process_packet, auto emit_qlog_event,
            PacketProcessingLabels labels) -> bool {
        if (send_profile_enabled()) {
            ++send_profile_counters().packet_bytes_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(packet_bytes_timer, packet_bytes_ns);
        const auto fail_with_codec_error = [&](std::string_view label, const auto &error) -> bool {
            log_codec_failure(label, error);
            queue_transport_close_for_error(now, error);
            return false;
        };
        const bool short_header_packet =
            (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
        if (short_header_packet && application_space_.read_secret.has_value()) {
            const auto next_read_ready = ensure_next_application_read_secret();
            if (!next_read_ready.has_value()) {
                return fail_with_codec_error("derive_next_traffic_secret", next_read_ready.error());
            }
        }
        if (defer_short_header_packet_before_server_handshake_complete(
                allow_defer, short_header_packet, config_.role, status_,
                deferred_protected_packets_, packet_bytes, packet_path_id, datagram_id, packet_ecn,
                packet_received_time)) {
            return true;
        }

        const auto current_context = short_header_packet
                                         ? make_current_short_header_deserialize_context()
                                         : make_deserialize_context(application_space_.read_secret,
                                                                    application_read_key_phase_);
        if (!current_context.has_value()) {
            return fail_with_codec_error("expand_traffic_secret", current_context.error());
        }

        const auto timed_deserialize = [&](const DeserializeProtectionContext &context) {
            if (send_profile_enabled()) {
                ++send_profile_counters().deserialize_attempts;
            }
            COQUIC_SEND_PROFILE_TIMER(deserialize_timer, deserialize_ns);
            return deserialize_packets(packet_bytes, context);
        };
        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_packets;
        }
        auto packets = timed_deserialize(current_context.value());
        bool used_previous_application_read_secret = false;
        if (!packets.has_value()) {
            if (short_header_packet && previous_application_read_secret_.has_value()) {
                const auto previous_context = make_short_header_deserialize_context(
                    previous_application_read_secret_, previous_application_read_key_phase_);
                if (!previous_context.has_value()) {
                    log_codec_failure("expand_traffic_secret", previous_context.error());
                    queue_transport_close_for_error(now, previous_context.error());
                    return false;
                }

                auto previous_packets = timed_deserialize(previous_context.value());
                if (previous_packets.has_value()) {
                    packets = std::move(previous_packets);
                    used_previous_application_read_secret = true;
                }
            }
        }
        if (!packets.has_value()) {
            const bool retry_with_next_key_phase =
                short_header_packet && next_application_read_secret_.has_value() &&
                application_space_.write_secret.has_value() &&
                can_retry_short_header_with_next_key_phase(packets.error().code);
            if (retry_with_next_key_phase) {
                const auto next_context = make_short_header_deserialize_context(
                    next_application_read_secret_, next_application_read_key_phase_);
                if (!next_context.has_value()) {
                    return fail_with_codec_error("expand_traffic_secret", next_context.error());
                }

                auto updated_packets = timed_deserialize(next_context.value());
                if (updated_packets.has_value()) {
                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        queue_transport_close_for_error(now, next_write_secret.error());
                        return false;
                    }

                    retain_previous_application_read_secret(now);
                    promote_next_application_read_secret();
                    const auto following_read_secret = refresh_next_application_read_secret();
                    if (!following_read_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret",
                                          following_read_secret.error());
                        queue_transport_close_for_error(now, following_read_secret.error());
                        return false;
                    }
                    application_space_.write_secret = next_write_secret.value();
                    application_write_key_phase_ = !application_write_key_phase_;
                    current_application_write_key_encrypted_packets_ = 0;
                    ++current_application_write_key_generation_;
                    current_write_phase_first_packet_number_ = std::nullopt;
                    if (!local_key_update_initiated_) {
                        local_key_update_requested_ = false;
                    }
                    packets = std::move(updated_packets);
                }
            }
        }
        if (!packets.has_value()) {
            if (!note_packet_authentication_failure(packets.error(), now)) {
                return false;
            }
            if (packets.error().code == CodecErrorCode::missing_crypto_context) {
                if (packet_targets_discarded_long_header_space(packet_bytes)) {
                    return true;
                }
                // Later packets in the same datagram can depend on keys unlocked by an earlier
                // packet, so buffer them even after partial progress.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.1
                // # The client MAY drop these packets, or it MAY buffer them in
                // # anticipation of later packets that allow it to compute the key.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
                // # For example, if decryption fails (because the keys are not available
                // # or for any other reason), the receiver MAY either discard or buffer
                // # the packet for later processing and MUST attempt to process the
                // # remaining packets.
                defer_packet(packet_bytes, packet_path_id, datagram_id, packet_ecn,
                             packet_received_time);
                return true;
            }

            bool should_discard_packet = false;
            if (short_header_packet) {
                should_discard_packet =
                    is_discardable_short_header_packet_error(packets.error().code);
            }
            if (!should_discard_packet) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
                // # For this reason, endpoints MAY discard packets rather
                // # than immediately close if errors are detected in packets
                // # that lack authentication.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-11.1
                // # As the AEAD for Initial packets does not provide strong
                // # authentication, an endpoint MAY discard an invalid Initial
                // # packet.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2
                // # Invalid packets that lack strong integrity protection, such as
                // # Initial, Retry, or Version Negotiation, MAY be discarded.
                should_discard_packet = coquic::quic::should_discard_corrupted_long_header_packet(
                    short_header_packet, packets.error().code);
            }
            if (should_discard_packet) {
                if (packet_trace_matches_connection(config_.source_connection_id)) {
                    std::cerr << "quic-packet-trace discard scid="
                              << format_connection_id_hex(config_.source_connection_id)
                              << " size=" << packet_bytes.size()
                              << " code=" << static_cast<int>(packets.error().code) << '\n';
                }
                return true;
            }
            if (processed_any_packet) {
                return true;
            }
            log_codec_failure(labels.deserialize, packets.error());
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2
            // # An endpoint MUST generate a connection error if processing the contents
            // # of these packets prior to discovering an error, or fully revert any
            // # changes made during that processing.
            queue_transport_close_for_error(now, packets.error());
            return false;
        }

        const auto process_decoded_packet = [&](const auto &packet) -> bool {
            if (send_profile_enabled()) {
                ++send_profile_counters().process_decoded_packet_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(decoded_packet_timer, process_decoded_packet_ns);
            bool defer_protected_app_packet = false;
            {
                if (send_profile_enabled()) {
                    ++send_profile_counters().defer_decision_calls;
                }
                COQUIC_SEND_PROFILE_TIMER(defer_timer, defer_decision_ns);
                defer_protected_app_packet = should_defer_decoded_protected_packet(
                    allow_defer, packet, config_.role, status_);
            }
            if (defer_protected_app_packet) {
                defer_packet(packet_bytes, packet_path_id, datagram_id, packet_ecn,
                             packet_received_time);
                return true;
            }

            {
                if (send_profile_enabled()) {
                    ++send_profile_counters().qlog_emit_calls;
                }
                COQUIC_SEND_PROFILE_TIMER(qlog_timer, qlog_emit_ns);
                emit_qlog_event(packet);
            }
            CodecResult<bool> processed =
                CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            {
                COQUIC_SEND_PROFILE_TIMER(process_timer, process_packet_ns);
                const auto previous_progress_generation = inbound_progress_generation();
                processed = process_packet(packet, packet_received_time, packet_ecn,
                                           used_previous_application_read_secret);
                if (processed.has_value() &&
                    !note_packet_productivity(previous_progress_generation, packet_received_time)) {
                    return false;
                }
            }
            if (!processed.has_value()) {
                const auto traced_packet_number = protected_one_rtt_packet_number_for_trace(packet);
                if (traced_packet_number.has_value() &&
                    packet_trace_matches_connection(config_.source_connection_id)) {
                    std::cerr << "quic-packet-trace fail scid="
                              << format_connection_id_hex(config_.source_connection_id)
                              << " pn=" << *traced_packet_number
                              << " code=" << static_cast<int>(processed.error().code) << '\n';
                }
                if (processed_any_packet) {
                    return true;
                }
                log_codec_failure(labels.process, processed.error());
                queue_transport_close_for_error(now, processed.error());
                return false;
            }
            if (packet_can_advance_tls_state(packet)) {
                if (send_profile_enabled()) {
                    ++send_profile_counters().inbound_post_process_sync_tls_calls;
                }
                COQUIC_SEND_PROFILE_TIMER(sync_timer, inbound_post_process_sync_tls_ns);
                synced = sync_tls_state();
            } else if (send_profile_enabled()) {
                ++send_profile_counters().inbound_post_process_sync_tls_skipped;
            }
            if (!synced.has_value()) {
                log_codec_failure("sync_tls_state", synced.error());
                queue_transport_close_for_error(now, synced.error());
                return false;
            }
            return true;
        };

        if constexpr (requires { packets.value().begin(); }) {
            for (const auto &packet : packets.value()) {
                if (!process_decoded_packet(packet)) {
                    return false;
                }
                if (!packet_replay_trigger) {
                    result.processed_any_packet = true;
                }
            }
        } else {
            if (!process_decoded_packet(packets.value())) {
                return false;
            }
            if (!packet_replay_trigger) {
                result.processed_any_packet = true;
            }
        }

        return true;
    };
    const auto process_packet_bytes =
        [&](std::span<const std::byte> packet_bytes, bool allow_defer, QuicPathId packet_path_id,
            QuicEcnCodepoint packet_ecn, QuicCoreTimePoint packet_received_time,
            std::optional<std::uint32_t> datagram_id, bool packet_replay_trigger) -> bool {
        if (qlog_session_ != nullptr) {
            const auto emit_qlog_event = [&](const ProtectedPacket &packet) {
                if (!datagram_id.has_value()) {
                    return;
                }

                static_cast<void>(qlog_session_->write_event(
                    now, "quic:packet_received",
                    qlog::serialize_packet_snapshot(make_qlog_packet_snapshot(
                        packet, qlog::PacketSnapshotContext{
                                    .raw_length = packet_bytes.size(),
                                    .datagram_id = *datagram_id,
                                    .trigger = packet_replay_trigger
                                                   ? std::optional<std::string>("keys_available")
                                                   : std::nullopt,
                                }))));
            };
            return process_packet_bytes_with(
                packet_bytes, allow_defer, packet_path_id, packet_ecn, packet_received_time,
                datagram_id, packet_replay_trigger,
                [](std::span<const std::byte> bytes, const DeserializeProtectionContext &context) {
                    return deserialize_protected_datagram(bytes, context);
                },
                [this](const ProtectedPacket &packet, QuicCoreTimePoint packet_now,
                       QuicEcnCodepoint packet_ecn_value,
                       bool used_previous_application_read_secret) {
                    return process_inbound_packet(packet, packet_now, packet_ecn_value,
                                                  used_previous_application_read_secret);
                },
                emit_qlog_event,
                PacketProcessingLabels{
                    .deserialize = "deserialize_protected_datagram",
                    .process = "process_inbound_packet",
                });
        }

        const auto packet_storage_range =
            [&]() -> std::optional<std::pair<std::size_t, std::size_t>> {
            if (send_profile_enabled()) {
                ++send_profile_counters().packet_storage_range_checks;
            }
            COQUIC_SEND_PROFILE_TIMER(storage_range_timer, packet_storage_range_ns);
            if (!inbound_packet_storage_range_is_eligible(allow_in_place_receive_decode,
                                                          previous_application_read_secret_,
                                                          status_, storage, packet_bytes)) {
                return std::nullopt;
            }
            const auto storage_begin = reinterpret_cast<std::uintptr_t>(storage->data());
            const auto storage_end = storage_begin + storage->size();
            const auto packet_begin_address = reinterpret_cast<std::uintptr_t>(packet_bytes.data());
            if (!packet_bytes_start_inside_storage(packet_begin_address, storage_begin,
                                                   storage_end)) {
                return std::nullopt;
            }
            const auto packet_begin =
                static_cast<std::size_t>(packet_begin_address - storage_begin);
            if (packet_bytes.size() > storage->size() - packet_begin) {
                return std::nullopt;
            }
            return std::pair<std::size_t, std::size_t>{
                packet_begin,
                packet_begin + packet_bytes.size(),
            };
        }();
        return process_packet_bytes_with(
            packet_bytes, allow_defer, packet_path_id, packet_ecn, packet_received_time,
            datagram_id, packet_replay_trigger,
            [&](std::span<const std::byte> bytes, const DeserializeProtectionContext &context) {
                if (packet_storage_range.has_value()) {
                    return deserialize_received_protected_packet_fast(
                        storage, packet_storage_range->first, packet_storage_range->second,
                        context);
                }
                return deserialize_received_protected_packet(bytes, context);
            },
            [this](const ReceivedProtectedPacket &packet, QuicCoreTimePoint packet_now,
                   QuicEcnCodepoint packet_ecn_value, bool used_previous_application_read_secret) {
                return process_inbound_received_packet(packet, packet_now, packet_ecn_value,
                                                       used_previous_application_read_secret);
            },
            [](const ReceivedProtectedPacket &) {},
            PacketProcessingLabels{
                .deserialize = "deserialize_received_protected_datagram",
                .process = "process_inbound_received_packet",
            });
    };
    const auto process_single_short_header_packet_fast_path = [&]() -> bool {
        if (send_profile_enabled()) {
            ++send_profile_counters().packet_bytes_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(packet_bytes_timer, packet_bytes_ns);
        const auto fail_with_codec_error = [&](std::string_view label, const auto &error) -> bool {
            log_codec_failure(label, error);
            queue_transport_close_for_error(now, error);
            return false;
        };

        const auto next_read_ready = ensure_next_application_read_secret();
        if (!next_read_ready.has_value()) {
            return fail_with_codec_error("derive_next_traffic_secret", next_read_ready.error());
        }

        const auto timed_deserialize = [&](const DeserializeProtectionContext &context) {
            if (send_profile_enabled()) {
                ++send_profile_counters().deserialize_attempts;
            }
            COQUIC_SEND_PROFILE_TIMER(deserialize_timer, deserialize_ns);
            return deserialize_received_protected_packet_fast_compact(storage, begin, end, context);
        };

        const auto current_context = make_current_short_header_deserialize_context();
        if (!current_context.has_value()) {
            return fail_with_codec_error("expand_traffic_secret", current_context.error());
        }

        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_packets;
        }
        auto packet = timed_deserialize(current_context.value());
        if (!packet.has_value()) {
            const bool retry_with_next_key_phase =
                next_application_read_secret_.has_value() &&
                application_space_.write_secret.has_value() &&
                can_retry_short_header_with_next_key_phase(packet.error().code);
            if (retry_with_next_key_phase) {
                const auto next_context = make_short_header_deserialize_context(
                    next_application_read_secret_, next_application_read_key_phase_);
                if (!next_context.has_value()) {
                    return fail_with_codec_error("expand_traffic_secret", next_context.error());
                }

                auto updated_packet = timed_deserialize(next_context.value());
                if (updated_packet.has_value()) {
                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        return fail_with_codec_error("derive_next_traffic_secret",
                                                     next_write_secret.error());
                    }

                    retain_previous_application_read_secret(now);
                    promote_next_application_read_secret();
                    const auto following_read_secret = refresh_next_application_read_secret();
                    if (!following_read_secret.has_value()) {
                        return fail_with_codec_error("derive_next_traffic_secret",
                                                     following_read_secret.error());
                    }
                    application_space_.write_secret = next_write_secret.value();
                    application_write_key_phase_ = !application_write_key_phase_;
                    current_application_write_key_encrypted_packets_ = 0;
                    ++current_application_write_key_generation_;
                    current_write_phase_first_packet_number_ = std::nullopt;
                    if (!local_key_update_initiated_) {
                        local_key_update_requested_ = false;
                    }
                    packet = std::move(updated_packet);
                }
            }
        }
        if (!packet.has_value()) {
            if (!note_packet_authentication_failure(packet.error(), now)) {
                return false;
            }
            if (is_discardable_short_header_packet_error(packet.error().code)) {
                return true;
            }
            return fail_with_codec_error("deserialize_received_protected_datagram", packet.error());
        }

        if (const auto *ack_only =
                std::get_if<ReceivedProtectedOneRttAckOnlyFastPacket>(&packet.value());
            ack_only != nullptr) {
            if (send_profile_enabled()) {
                ++send_profile_counters().process_decoded_packet_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(decoded_packet_timer, process_decoded_packet_ns);
            CodecResult<bool> processed =
                CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            {
                COQUIC_SEND_PROFILE_TIMER(process_timer, process_packet_ns);
                const auto previous_progress_generation = inbound_progress_generation();
                note_authenticated_packet_number(application_space_, ack_only->packet_number);
                if (should_ignore_received_packet(application_space_, ack_only->packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, ack_only->packet_number, /*ack_eliciting=*/false, now,
                        ecn, config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    processed = CodecResult<bool>::success(true);
                } else {
                    processed = process_inbound_received_application_ack_only(
                        ack_only->packet_number, ack_only->spin_bit, ack_only->ack, now, ecn,
                        last_inbound_path_id_, /*used_previous_application_read_secret=*/false);
                }
                if (processed.has_value() &&
                    !note_packet_productivity(previous_progress_generation, now)) {
                    return false;
                }
            }
            if (!processed.has_value()) {
                log_codec_failure("process_inbound_received_packet", processed.error());
                queue_transport_close_for_error(now, processed.error());
                return false;
            }
            if (!replay_trigger) {
                result.processed_any_packet = true;
            }
            return true;
        }

        const auto *received_packet = std::get_if<ReceivedProtectedPacket>(&packet.value());
        if (received_packet == nullptr) {
            return fail_with_codec_error(
                "deserialize_received_protected_datagram",
                CodecError{.code = CodecErrorCode::unsupported_packet_type, .offset = 0});
        }
        if (send_profile_enabled()) {
            ++send_profile_counters().process_decoded_packet_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(decoded_packet_timer, process_decoded_packet_ns);
        CodecResult<bool> processed = CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        {
            COQUIC_SEND_PROFILE_TIMER(process_timer, process_packet_ns);
            const auto previous_progress_generation = inbound_progress_generation();
            processed = process_inbound_received_packet(*received_packet, now, ecn);
            if (processed.has_value() &&
                !note_packet_productivity(previous_progress_generation, now)) {
                return false;
            }
        }
        if (!processed.has_value()) {
            log_codec_failure("process_inbound_received_packet", processed.error());
            queue_transport_close_for_error(now, processed.error());
            return false;
        }
        if (packet_can_advance_tls_state(*received_packet)) {
            if (send_profile_enabled()) {
                ++send_profile_counters().inbound_post_process_sync_tls_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(sync_timer, inbound_post_process_sync_tls_ns);
            synced = sync_tls_state();
        } else if (send_profile_enabled()) {
            ++send_profile_counters().inbound_post_process_sync_tls_skipped;
        }
        if (!synced.has_value()) {
            log_codec_failure("sync_tls_state", synced.error());
            queue_transport_close_for_error(now, synced.error());
            return false;
        }
        if (!replay_trigger) {
            result.processed_any_packet = true;
        }
        return true;
    };
    const auto replay_deferred_packets = [&]() -> bool {
        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_replay_deferred_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(replay_timer, inbound_replay_deferred_ns);
        if (deferred_protected_packets_.empty()) {
            return true;
        }

        auto deferred_packets = std::move(deferred_protected_packets_);
        deferred_protected_packets_.clear();
        for (const auto &deferred_packet : deferred_packets) {
            const auto deferred_received_time = deferred_packet.received_time.value_or(now);
            if (!process_packet_bytes(deferred_packet.bytes, /*allow_defer=*/true,
                                      deferred_packet.path_id, deferred_packet.ecn,
                                      deferred_received_time, deferred_packet.datagram_id,
                                      /*packet_replay_trigger=*/true)) {
                return false;
            }
        }

        return true;
    };
    if (!replay_deferred_packets()) {
        return result;
    }
    if (can_use_single_short_header_datagram_fast_path(receive_sync_state,
                                                       allow_in_place_receive_decode,
                                                       previous_application_read_secret_, bytes) &&
        !packet_trace_matches_connection(config_.source_connection_id)) {
        COQUIC_SEND_PROFILE_TIMER(packet_loop_timer, packet_loop_ns);
        static_cast<void>(process_single_short_header_packet_fast_path());
        return result;
    }
    COQUIC_SEND_PROFILE_TIMER(packet_loop_timer, packet_loop_ns);
    while (offset < bytes.size()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().packet_length_peeks;
        }
        CodecResult<std::size_t> packet_length =
            CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
        {
            COQUIC_SEND_PROFILE_TIMER(packet_length_timer, packet_length_peek_ns);
            packet_length = peek_next_packet_length(bytes.subspan(offset));
        }
        if (!packet_length.has_value()) {
            if (packet_length.error().code == CodecErrorCode::invalid_fixed_bit) {
                const auto discardable_length =
                    peek_discardable_long_header_packet_length(bytes.subspan(offset));
                if (discardable_length.has_value()) {
                    offset += discardable_length.value();
                    continue;
                }
            }
            if (is_discardable_packet_length_error(packet_length.error().code)) {
                return result;
            }
            if (processed_any_packet) {
                return result;
            }
            log_codec_failure("peek_next_packet_length", packet_length.error());
            queue_transport_close_for_error(now, packet_length.error());
            return result;
        }

        const auto packet_bytes = bytes.subspan(offset, packet_length.value());
        const auto packet_destination_connection_id =
            peek_long_header_destination_connection_id(packet_bytes);
        if (packet_destination_connection_id.has_value()) {
            if (!first_datagram_destination_connection_id.has_value()) {
                first_datagram_destination_connection_id = packet_destination_connection_id.value();
            } else if (packet_destination_connection_id.value() !=
                       first_datagram_destination_connection_id.value()) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
                // # Receivers SHOULD ignore any subsequent packets with a
                // # different Destination Connection ID than the first packet
                // # in the datagram.
                offset += packet_length.value();
                continue;
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
        // # The receiver of coalesced QUIC packets MUST individually process
        // # each QUIC packet and separately acknowledge them, as if they were
        // # received as the payload of different UDP datagrams.
        if (!process_packet_bytes(packet_bytes, /*allow_defer=*/true, path_id, ecn, now,
                                  inbound_datagram_id, replay_trigger)) {
            return result;
        }
        processed_any_packet = true;
        if (!replay_deferred_packets()) {
            return result;
        }

        offset += packet_length.value();
    }
    return result;
}

StreamStateResult<bool> QuicConnection::queue_stream_send_impl(
    std::uint64_t stream_id, std::span<const std::byte> owned_bytes,
    std::optional<SharedBytes> shared_bytes, bool fin, std::int32_t priority) {
    if (status_ == HandshakeStatus::failed ||
        (owned_bytes.empty() && (!shared_bytes.has_value() || shared_bytes->empty()) && !fin)) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            stream_id);
    }

    auto *stream = stream_state.value();
    const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(*stream);
    const auto previous_has_lost_send_data =
        stream->reset_state == StreamControlFrameState::none && stream->send_buffer.has_lost_data();
    const auto validated = stream->validate_local_send(fin);
    if (!validated.has_value()) {
        return validated;
    }

    if (shared_bytes.has_value() && !shared_bytes->empty()) {
        stream->send_buffer.append(*shared_bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(shared_bytes->size());
        note_stream_send_bytes_queued(shared_bytes->size());
    } else if (!owned_bytes.empty()) {
        stream->send_buffer.append(owned_bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(owned_bytes.size());
        note_stream_send_bytes_queued(owned_bytes.size());
    }

    if (fin) {
        stream->send_final_size = stream->send_flow_control_committed;
        stream->send_fin_state = StreamSendFinState::pending;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-2.3
    // # A QUIC implementation SHOULD provide ways in which an application can
    // # indicate the relative priority of streams.
    if (priority != 0) {
        stream_send_priorities_[stream_id] = priority;
    } else if (!stream_send_priorities_.empty()) {
        stream_send_priorities_.erase(stream_id);
    }
    note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                   *stream);

    maybe_emit_zero_rtt_attempted_event();

    return StreamStateResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::queue_datagram_send_shared(SharedBytes bytes,
                                                             std::int32_t priority) {
    if (status_ == HandshakeStatus::failed) {
        return CodecResult<bool>::success(true);
    }

    if (!peer_transport_parameters_.has_value() ||
        peer_transport_parameters_->max_datagram_frame_size == 0) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.21
        // # An extension to QUIC that wishes to use a new type of frame MUST
        // # first ensure that a peer is able to understand the frame.
        //= https://www.rfc-editor.org/rfc/rfc9221#section-3
        // # An endpoint MUST NOT send DATAGRAM frames until it has received the
        // # max_datagram_frame_size transport parameter with a non-zero value
        // # during the handshake (or during a previous handshake if 0-RTT is
        // # used).
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }

    const auto wire_size = datagram_frame_wire_size(bytes.size(), /*has_length=*/true);
    if (wire_size > peer_transport_parameters_->max_datagram_frame_size) {
        //= https://www.rfc-editor.org/rfc/rfc9221#section-3
        // # An endpoint MUST NOT send DATAGRAM frames that are larger
        // # than the max_datagram_frame_size value it has received from its peer.
        return CodecResult<bool>::failure(CodecErrorCode::packet_length_mismatch, 0);
    }

    pending_datagram_send_queue_.push_back(PendingDatagramSend{
        .bytes = std::move(bytes),
        .priority = priority,
        .sequence = next_pending_datagram_sequence_++,
    });

    maybe_emit_zero_rtt_attempted_event();

    return CodecResult<bool>::success(true);
}

void QuicConnection::maybe_emit_zero_rtt_attempted_event() {
    if ((config_.role == EndpointRole::client) && config_.zero_rtt.attempt &&
        decoded_resumption_state_.has_value() && zero_rtt_space_.write_secret.has_value() &&
        (status_ != HandshakeStatus::connected) && !zero_rtt_attempted_event_emitted_) {
        pending_zero_rtt_status_event_ =
            QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::attempted};
        zero_rtt_attempted_event_emitted_ = true;
    }
}

StreamStateResult<bool> QuicConnection::queue_stream_reset(LocalResetCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(command.stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(command.stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            command.stream_id);
    }

    auto *stream = stream_state.value();
    const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(*stream);
    const auto previous_has_lost_send_data =
        stream->reset_state == StreamControlFrameState::none && stream->send_buffer.has_lost_data();
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.2
    // # RESET_STREAM MUST only be instigated by the application protocol that
    // # uses QUIC.
    const auto validated = stream->validate_local_reset(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }
    note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                   *stream);

    return StreamStateResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::request_connection_migration(QuicPathId path_id,
                                                               QuicMigrationRequestReason reason,
                                                               QuicCoreTimePoint now) {
    if (!handshake_confirmed_) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9
        // # An endpoint MUST NOT initiate connection migration before the
        // # handshake is confirmed, as defined in Section 4.1.2 of [QUIC-TLS].
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }
    const bool peer_disables_active_migration =
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->disable_active_migration;
    if (reason == QuicMigrationRequestReason::active && peer_disables_active_migration) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
        // # An endpoint that receives this transport parameter MUST NOT use a
        // # new local address when sending to the address that the peer used
        // # during the handshake.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9
        // # If the peer sent the disable_active_migration transport parameter,
        // # an endpoint also MUST NOT send packets (including probing packets;
        // # see Section 9.1) from a different local address to the address the
        // # peer used during the handshake, unless the endpoint has acted on a
        // # preferred_address transport parameter from the peer.
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }
    if (reason == QuicMigrationRequestReason::active && !can_initiate_path_validation(path_id)) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # An endpoint that initiates migration and requires non-zero-length
        // # connection IDs SHOULD ensure that the pool of connection IDs available
        // # to its peer allows the peer to use a new connection ID on migration,
        // # as the peer will be unable to respond if the pool is exhausted.
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }

    const auto *preferred_address = reason == QuicMigrationRequestReason::preferred_address &&
                                            peer_transport_parameters_.has_value()
                                        ? &peer_transport_parameters_->preferred_address
                                        : nullptr;
    if (preferred_address != nullptr && preferred_address->has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.2
        // # A client MUST NOT use these for other connections, including
        // # connections that are resumed from the current connection.
        const auto preferred_connection_id = ensure_peer_preferred_address_connection_id();
        if (!preferred_connection_id.has_value()) {
            return CodecResult<bool>::failure(preferred_connection_id.error());
        }
        auto &path = ensure_path_state(path_id);
        set_path_peer_connection_id_sequence(path, kPreferredAddressConnectionIdSequence);
        path.destination_connection_id_override = preferred_address->value().connection_id;
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.3
        // # This connection ID is provided to ensure that the client has a
        // # connection ID available for migration, but the client MAY use this
        // # connection ID on any path.
        path.preferred_address_path = true;
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.2
        // # A client that migrates to a preferred address MUST validate the
        // # address it chooses before migrating; see Section 21.5.3.
        if (current_send_path_id_.has_value() && *current_send_path_id_ != path_id) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.3
            // # In this case, the client SHOULD perform path validation to
            // # both the original and preferred server address from the
            // # client's new address concurrently.
            start_path_validation_probe(*current_send_path_id_, /*initiated_locally=*/true, now);
        }
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
    // # Once the handshake is confirmed, the client SHOULD select one of the
    // # two addresses provided by the server and initiate path validation
    // # (see Section 8.2).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.1
    // # An endpoint MAY probe for peer reachability from a new local address
    // # using path validation (Section 8.2) prior to migrating the connection
    // # to the new local address.
    maybe_switch_to_path(path_id, /*initiated_locally=*/true, now);
    return CodecResult<bool>::success(true);
}

DatagramBuffer QuicConnection::drain_outbound_datagram(QuicCoreTimePoint now) {
    const bool continue_paced_burst = last_drained_allows_send_continuation_ &&
                                      last_send_continuation_time_.has_value() &&
                                      *last_send_continuation_time_ == now;
    return drain_outbound_datagram(now, continue_paced_burst);
}

DatagramBuffer QuicConnection::drain_outbound_datagram(QuicCoreTimePoint now,
                                                       bool continue_paced_burst) {
    if (status_ == HandshakeStatus::failed && close_mode_ != QuicConnectionCloseMode::closing) {
        return {};
    }
    last_drained_path_id_.reset();
    last_drained_ecn_codepoint_ = QuicEcnCodepoint::not_ect;
    last_drained_is_pmtu_probe_ = false;
    last_drained_allows_send_continuation_ = false;
    last_drained_packet_inspection_datagram_id_ = 0;

    if (close_mode_ == QuicConnectionCloseMode::closing) {
        if (!closing_close_packet_can_send(closing_close_packet_pending_,
                                           can_send_connection_close_frame())) {
            return {};
        }
        return flush_outbound_datagram(now, continue_paced_burst);
    }

    auto synced = CodecResult<bool>::success(true);
    if (!can_skip_outbound_tls_sync()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().outbound_sync_tls_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(sync_timer, outbound_sync_tls_ns);
        synced = sync_tls_state();
    } else if (send_profile_enabled()) {
        ++send_profile_counters().outbound_sync_tls_skipped;
    }
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        queue_transport_close_for_error(now, synced.error());
        return {};
    }

    if (!deferred_protected_packets_.empty()) {
        replay_deferred_protected_packets(now);
        if (status_ == HandshakeStatus::failed) {
            return {};
        }
    }

    auto datagram = flush_outbound_datagram(now, continue_paced_burst);
    return datagram;
}

void QuicConnection::on_timeout(QuicCoreTimePoint now) {
    if (close_state_active()) {
        if (!close_deadline_.has_value()) {
            return;
        }
        if (now >= *close_deadline_) {
            pending_terminal_state_ = pending_connection_close_terminal_state_.value_or(
                QuicConnectionTerminalState::closed);
            close_mode_ = QuicConnectionCloseMode::none;
            close_started_at_.reset();
            close_deadline_.reset();
            closing_transport_close_.reset();
            closing_application_close_.reset();
            pending_transport_close_.reset();
            pending_application_close_.reset();
            pending_connection_close_terminal_state_.reset();
            closing_close_packet_pending_ = false;
            return;
        }
    }

    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (const auto idle_deadline = idle_timeout_deadline();
        idle_deadline.has_value() && now >= *idle_deadline) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
        // # If a max_idle_timeout is specified by either endpoint in its
        // # transport parameters (Section 18.2), the connection is silently
        // # closed and its state is discarded when it remains idle for longer
        // # than the minimum of the max_idle_timeout value advertised by both
        // # endpoints.
        mark_silent_close();
        return;
    }

    maybe_discard_server_zero_rtt_packet_space(now);

    if (current_send_path_id_.has_value() &&
        path_validation_timed_out(*current_send_path_id_, now)) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.4
        // # Endpoints SHOULD abandon path validation based on a timer.
        auto &current = paths_.at(*current_send_path_id_);
        current.is_current_send_path = false;
        current.challenge_pending = false;
        current.validation_initiated_locally = false;
        current.validation_probe_only = false;
        current.path_mtu_validation_pending = false;
        current.outstanding_challenge_sent_with_expanded_datagram = true;
        current.validation_deadline.reset();
        if (!last_validated_path_id_.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9
            // # When an endpoint has no validated path on which to send
            // # packets, it MAY discard connection state.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10
            // # An endpoint MAY discard connection state if it does not have a
            // # validated path on which it can send packets; see Section 8.2.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3.2
            // # If an endpoint has no state about the last validated peer
            // # address, it MUST close the connection silently by discarding
            // # all connection state.
            mark_silent_close();
            return;
        }
        previous_path_id_ = current_send_path_id_;
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3.2
        // # To protect the connection from failing due to such a spurious
        // # migration, an endpoint MUST revert to using the last validated peer
        // # address when validation of a new peer address fails.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
        // # If path validation fails, the client MUST continue sending all
        // # future packets to the server's original IP address.
        current_send_path_id_ = last_validated_path_id_;
        ensure_path_state(*last_validated_path_id_).is_current_send_path = true;
    }

    if (const auto deadline = loss_deadline(); deadline.has_value() && now >= *deadline) {
        detect_lost_packets(now);
    }

    const auto initial_ack_deadline =
        initial_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (!initial_packet_space_discarded_ && now >= initial_ack_deadline) {
        initial_space_.force_ack_send = true;
    }
    const auto handshake_ack_deadline =
        handshake_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (!handshake_packet_space_discarded_ && now >= handshake_ack_deadline) {
        handshake_space_.force_ack_send = true;
    }
    const auto application_ack_deadline =
        application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= application_ack_deadline) {
        application_space_.force_ack_send = true;
    }

    if (const auto deadline = pmtud_deadline(); pmtud_deadline_due(deadline, now)) {
        maybe_trace_pmtud_timeout(config_.source_connection_id);
        maybe_arm_pmtu_probe(now);
    }

    if (const auto deadline = pto_deadline(); deadline.has_value() && now >= *deadline) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
        // # To
        // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
        // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
        arm_pto_probe(now);
        if (packet_trace_matches_connection(config_.source_connection_id)) {
            const auto in_flight_ack_eliciting_count = [](const PacketSpaceState &packet_space) {
                const auto handles = packet_space.recovery.tracked_packets();
                return std::count_if(
                    handles.begin(), handles.end(), [&](const RecoveryPacketHandle handle) {
                        const auto &packet = *packet_space.recovery.packet_for_handle(handle);
                        return packet.ack_eliciting && packet.in_flight;
                    });
            };
            std::cerr << "quic-packet-trace timeout scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " status=" << static_cast<int>(status_)
                      << " confirmed=" << static_cast<int>(handshake_confirmed_)
                      << " initial_if=" << in_flight_ack_eliciting_count(initial_space_)
                      << " handshake_if=" << in_flight_ack_eliciting_count(handshake_space_)
                      << " application_if=" << in_flight_ack_eliciting_count(application_space_)
                      << " initial_probe="
                      << static_cast<int>(initial_space_.pending_probe_packet.has_value())
                      << " handshake_probe="
                      << static_cast<int>(handshake_space_.pending_probe_packet.has_value())
                      << " application_probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << " pto_count=" << pto_count_ << '\n';
        }
    }

    maybe_discard_previous_application_read_secret(now);
}

bool QuicConnection::has_sendable_datagram(QuicCoreTimePoint now) const {
    return has_sendable_datagram(now, /*continue_paced_burst=*/false);
}

bool QuicConnection::has_sendable_datagram(QuicCoreTimePoint now, bool continue_paced_burst) const {
    const auto note_not_sendable = [&](auto member) {
        if (!send_profile_enabled()) {
            return;
        }
        auto &profile = send_profile_counters();
        ++profile.has_sendable_false;
        ++(profile.*member);
    };
    if (send_profile_enabled()) {
        ++send_profile_counters().has_sendable_checks;
    }
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
        // # While otherwise identical to the closing state, an
        // # endpoint in the draining state MUST NOT send any packets.
        if (send_profile_enabled()) {
            ++send_profile_counters().has_sendable_false;
        }
        return false;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        static_cast<void>(now);
        return closing_close_packet_can_send(closing_close_packet_pending_,
                                             can_send_connection_close_frame());
    }
    if (status_ == HandshakeStatus::failed || !deferred_protected_packets_.empty()) {
        if (status_ == HandshakeStatus::failed && send_profile_enabled()) {
            ++send_profile_counters().has_sendable_false;
        }
        return status_ != HandshakeStatus::failed;
    }
    if (current_send_path_id_.has_value()) {
        const auto path = paths_.find(*current_send_path_id_);
        if (path != paths_.end()) {
            if (!path->second.mtu.viable) {
                if (send_profile_enabled()) {
                    ++send_profile_counters().has_sendable_false;
                }
                return false;
            }
        }
    }
    if (!initial_packet_space_discarded_ &&
        initial_packet_space_has_sendable_data(initial_space_, now)) {
        return true;
    }
    if (!handshake_packet_space_discarded_ &&
        handshake_packet_space_has_sendable_data(handshake_space_, now)) {
        return true;
    }

    if (!can_send_application_packets(config_.role, status_, zero_rtt_space_, application_space_)) {
        note_not_sendable(&SendProfileCounters::has_sendable_no_application_packets);
        return false;
    }
    const bool application_ack_due = application_ack_due_for_send(application_space_, now);
    if (!has_application_space_sendable_data(application_ack_due)) {
        note_not_sendable(&SendProfileCounters::has_sendable_no_application_data);
        return false;
    }

    if (has_pending_application_control_send(application_ack_due)) {
        if (send_profile_enabled()) {
            ++send_profile_counters().has_sendable_control;
        }
        return true;
    }

    const auto minimum_datagram_bytes = minimum_pending_application_datagram_datagram_bytes();
    if (!minimum_datagram_bytes.has_value()) {
        note_not_sendable(&SendProfileCounters::has_sendable_no_stream_minimum);
        return false;
    }
    const auto pacing_bytes = application_stream_pacing_deadline_bytes(minimum_datagram_bytes);
    if (!pacing_bytes.has_value()) {
        note_not_sendable(&SendProfileCounters::has_sendable_congestion);
        return false;
    }
    const auto pacing_deadline = continue_paced_burst
                                     ? std::optional<QuicCoreTimePoint>{}
                                     : congestion_controller_.next_send_time(*pacing_bytes);
    if (pacing_deadline.has_value() && now < *pacing_deadline) {
        note_not_sendable(&SendProfileCounters::has_sendable_pacing);
        return false;
    }
    return true;
}

bool QuicConnection::has_application_space_sendable_data(bool application_ack_due) const {
    return application_space_has_sendable_data(
        application_ack_due, has_pending_application_send(), application_space_,
        !pending_new_token_frames_.empty(), !pending_new_connection_id_frames_.empty(),
        !pending_retire_connection_id_frames_.empty());
}

bool QuicConnection::accepts_greased_quic_bit() const {
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3
    // # An endpoint that advertises the grease_quic_bit transport parameter
    // # MUST accept packets with the QUIC Bit set to a value of 0.
    return static_cast<bool>(config_.transport.grease_quic_bit |
                             local_transport_parameters_.grease_quic_bit);
}

bool QuicConnection::can_skip_receive_tls_sync(std::span<const std::byte> bytes) const {
    return can_skip_steady_state_receive_sync(
        config_.role, status_, peer_transport_parameters_validated_, application_space_.read_secret,
        application_space_.write_secret, resumption_state_emitted_, peer_preferred_address_emitted_,
        peer_transport_parameters_, qlog_session_.get(), bytes, accepts_greased_quic_bit());
}

} // namespace coquic::quic

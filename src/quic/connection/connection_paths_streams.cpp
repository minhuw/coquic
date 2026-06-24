#include "src/quic/connection/connection.h"
#include "src/quic/connection/connection_internal.h"

#include <algorithm>
#include <limits>

namespace coquic::quic {

namespace {

constexpr std::uint16_t kTlsQuicTransportParametersExtension = 0x0039;

bool contains_version(std::span<const std::uint32_t> versions, std::uint32_t version) {
    return std::find(versions.begin(), versions.end(), version) != versions.end();
}

std::uint16_t read_u16_be(std::span<const std::byte> bytes) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[0])) << 8) |
        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[1])));
}

std::uint32_t read_u24_be(std::span<const std::byte> bytes) {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2]));
}

std::optional<std::span<const std::byte>>
read_tls_vector(std::span<const std::byte> bytes, std::size_t &offset, std::size_t length_bytes) {
    if (length_bytes == 0 || length_bytes > 3 || offset + length_bytes > bytes.size()) {
        return std::nullopt;
    }

    std::size_t length = 0;
    for (std::size_t index = 0; index < length_bytes; ++index) {
        length = (length << 8) | std::to_integer<std::uint8_t>(bytes[offset + index]);
    }
    offset += length_bytes;
    if (offset + length > bytes.size()) {
        return std::nullopt;
    }

    const auto value = bytes.subspan(offset, length);
    offset += length;
    return value;
}

CodecResult<std::optional<std::span<const std::byte>>>
extract_client_hello_quic_transport_parameters(std::span<const std::byte> bytes) {
    if (bytes.size() < 4) {
        return CodecResult<std::optional<std::span<const std::byte>>>::success(std::nullopt);
    }
    if (std::to_integer<std::uint8_t>(bytes[0]) != 0x01u) {
        return CodecResult<std::optional<std::span<const std::byte>>>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
    }

    const auto handshake_length = read_u24_be(bytes.subspan(1, 3));
    if (bytes.size() < 4 + handshake_length) {
        return CodecResult<std::optional<std::span<const std::byte>>>::success(std::nullopt);
    }

    const auto client_hello = bytes.subspan(4, handshake_length);
    std::size_t offset = 0;
    if (client_hello.size() < 34) {
        return CodecResult<std::optional<std::span<const std::byte>>>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
    }
    offset += 2;
    offset += 32;

    if (!read_tls_vector(client_hello, offset, 1).has_value() ||
        !read_tls_vector(client_hello, offset, 2).has_value() ||
        !read_tls_vector(client_hello, offset, 1).has_value()) {
        return CodecResult<std::optional<std::span<const std::byte>>>::failure(
            CodecErrorCode::invalid_packet_protection_state, offset);
    }
    if (offset == client_hello.size()) {
        return CodecResult<std::optional<std::span<const std::byte>>>::success(std::nullopt);
    }

    const auto extensions = read_tls_vector(client_hello, offset, 2);
    if (!extensions.has_value() || offset != client_hello.size()) {
        return CodecResult<std::optional<std::span<const std::byte>>>::failure(
            CodecErrorCode::invalid_packet_protection_state, offset);
    }

    std::size_t extension_offset = 0;
    while (extension_offset < extensions->size()) {
        if (extension_offset + 4 > extensions->size()) {
            return CodecResult<std::optional<std::span<const std::byte>>>::failure(
                CodecErrorCode::invalid_packet_protection_state, extension_offset);
        }
        const auto extension_type = read_u16_be(extensions->subspan(extension_offset, 2));
        const auto extension_length = read_u16_be(extensions->subspan(extension_offset + 2, 2));
        extension_offset += 4;
        if (extension_offset + extension_length > extensions->size()) {
            return CodecResult<std::optional<std::span<const std::byte>>>::failure(
                CodecErrorCode::invalid_packet_protection_state, extension_offset);
        }

        const auto extension_data = extensions->subspan(extension_offset, extension_length);
        extension_offset += extension_length;
        if (extension_type == kTlsQuicTransportParametersExtension) {
            return CodecResult<std::optional<std::span<const std::byte>>>::success(extension_data);
        }
    }

    return CodecResult<std::optional<std::span<const std::byte>>>::success(std::nullopt);
}

std::optional<std::uint32_t>
select_compatible_server_version(std::span<const std::uint32_t> supported_versions,
                                 const VersionInformation &client_version_information,
                                 std::uint32_t client_initial_version) {
    if (client_version_information.chosen_version != client_initial_version ||
        !contains_version(client_version_information.available_versions, client_initial_version)) {
        //= https://www.rfc-editor.org/rfc/rfc9368#section-4
        // # When the server then processes the client's Version
        // # Information, the server MUST validate that the client's Chosen
        // # Version matches the version in use for the connection.
        //= https://www.rfc-editor.org/rfc/rfc9368#section-4
        // # If the two
        // # differ, the server MUST close the connection with a version
        // # negotiation error.
        return std::nullopt;
    }
    for (const auto supported_version : supported_versions) {
        if (contains_version(client_version_information.available_versions, supported_version)) {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-2.3
            // # In order to perform compatible version negotiation, the server MUST
            // # select one of these versions that it (1) supports and (2) knows the
            // # client's Chosen Version is compatible with.
            //= https://www.rfc-editor.org/rfc/rfc9368#section-2
            // # If the server can parse the first flight, it can establish the
            // # connection using the client's Chosen Version, or it MAY select any
            // # other compatible version, as described in Section 2.3.
            //= https://www.rfc-editor.org/rfc/rfc9368#section-3
            // # Note that this preference is only advisory; servers
            // # MAY choose to use their own preference instead.
            return supported_version;
        }
    }
    return std::nullopt;
}

} // namespace

void QuicConnection::install_available_secrets() {
    if (!tls_.has_value()) {
        return;
    }

    bool installed_client_application_keys = false;
    bool installed_application_read_secret = false;
    for (auto &available_secret : tls_->take_available_secrets()) {
        //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
        // # Both endpoints MUST send Handshake and 1-RTT packets using the
        // # negotiated version.
        available_secret.secret.quic_version = current_version_;
        if (should_skip_available_secret(available_secret.level, initial_packet_space_discarded_,
                                         handshake_packet_space_discarded_)) {
            continue;
        }
        auto &packet_space =
            packet_space_for_level(available_secret.level, initial_space_, handshake_space_,
                                   zero_rtt_space_, application_space_);
        if (available_secret.sender == config_.role) {
            packet_space.write_secret = std::move(available_secret.secret);
        } else {
            installed_application_read_secret |=
                available_secret.level == EncryptionLevel::application;
            packet_space.read_secret = std::move(available_secret.secret);
            if (available_secret.level == EncryptionLevel::application) {
                ++application_read_secret_generation_;
                reset_current_short_header_deserialize_context_cache();
            }
        }
        installed_client_application_keys |= config_.role == EndpointRole::client &&
                                             available_secret.level == EncryptionLevel::application;
    }

    if (installed_application_read_secret) {
        static_cast<void>(refresh_next_application_read_secret());
    }

    if (installed_client_application_keys && zero_rtt_space_.write_secret.has_value()) {
        discard_packet_space_state(zero_rtt_space_);
    }
}

void QuicConnection::collect_pending_tls_bytes() {
    if (!tls_.has_value()) {
        return;
    }

    auto initial = tls_->take_pending(EncryptionLevel::initial);
    if (!initial_packet_space_discarded_) {
        initial_space_.send_crypto.append(initial);
    }
    auto handshake = tls_->take_pending(EncryptionLevel::handshake);
    if (!handshake_packet_space_discarded_) {
        handshake_space_.send_crypto.append(handshake);
    }
    zero_rtt_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::zero_rtt));
    application_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::application));
}

CodecResult<bool> QuicConnection::maybe_negotiate_server_version_from_client_hello(
    std::span<const std::byte> crypto_bytes) {
    if (config_.role != EndpointRole::server || peer_transport_parameters_validated_ ||
        original_version_ != current_version_ || !tls_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    server_initial_crypto_scan_prefix_.insert(server_initial_crypto_scan_prefix_.end(),
                                              crypto_bytes.begin(), crypto_bytes.end());
    const auto extension =
        extract_client_hello_quic_transport_parameters(server_initial_crypto_scan_prefix_);
    if (!extension.has_value()) {
        return CodecResult<bool>::failure(extension.error());
    }
    if (!extension.value().has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto parameters = deserialize_transport_parameters(extension.value().value());
    if (!parameters.has_value()) {
        return CodecResult<bool>::failure(
            transport_parameter_error(parameters.error().code, parameters.error().offset));
    }

    const auto validation_context = peer_transport_parameters_validation_context();
    if (!validation_context.has_value()) {
        return CodecResult<bool>::success(true);
    }
    const auto &peer_parameters = parameters.value();
    if (const auto validated = validate_peer_transport_parameters(
            opposite_role(config_.role), peer_parameters, validation_context.value());
        !validated.has_value()) {
        return CodecResult<bool>::failure(validated.error());
    }

    peer_transport_parameters_ = peer_parameters;
    peer_transport_parameters_validated_ = true;
    server_initial_crypto_scan_prefix_.clear();
    reset_current_short_header_deserialize_context_cache();
    note_endpoint_route_state_changed();
    initialize_peer_flow_control_from_transport_parameters();

    const auto &peer_version_information = peer_parameters.version_information;
    if (peer_version_information.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9369#section-4
        // # Endpoints that support both
        // # versions SHOULD support compatible version negotiation to avoid a
        // # round trip.
        const auto selected_version = select_compatible_server_version(
            config_.supported_versions, peer_version_information.value(), original_version_);
        if (!selected_version.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-2.3
            // # If the first flight is correctly
            // # formatted, then this conversion process cannot fail by definition of
            // # the first flight being compatible; if the server is unable to convert
            // # the first flight, it MUST abort the handshake.
            return CodecResult<bool>::failure(version_negotiation_error());
        }
        current_version_ = *selected_version;
        local_transport_parameters_.version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_);

        const auto serialized_transport_parameters =
            serialize_locally_validated_transport_parameters(
                config_.role, local_transport_parameters_,
                TransportParametersValidationContext{
                    .expected_initial_source_connection_id = config_.source_connection_id,
                    .expected_original_destination_connection_id =
                        local_transport_parameters_.original_destination_connection_id,
                    .expected_retry_source_connection_id = config_.retry_source_connection_id,
                });
        if (!serialized_transport_parameters.has_value()) {
            return CodecResult<bool>::failure(serialized_transport_parameters.error());
        }
        if (!tls_.has_value()) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }
        const auto updated =
            tls_->update_local_transport_parameters(serialized_transport_parameters.value());
        if (!updated.has_value()) {
            return updated;
        }
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::replay_deferred_protected_packets(QuicCoreTimePoint now) {
    auto deferred_packets = std::move(deferred_protected_packets_);
    deferred_protected_packets_.clear();
    for (const auto &deferred_packet : deferred_packets) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.5
        // # However, endpoints SHOULD include buffering delays caused by
        // # unavailability of decryption keys, since these delays can be large
        // # and are likely to be non-repeating.
        process_inbound_datagram(deferred_packet.bytes, deferred_packet.received_at.value_or(now),
                                 deferred_packet.path_id, deferred_packet.ecn,
                                 deferred_packet.datagram_id,
                                 /*replay_trigger=*/true,
                                 /*count_inbound_bytes=*/true);
        if (status_ == HandshakeStatus::failed) {
            return;
        }
    }
}

CodecResult<bool> QuicConnection::sync_tls_state() {
    if (tls_.has_value()) {
        const auto polled = tls_->poll();
        if (!polled.has_value()) {
            return polled;
        }
    }

    install_available_secrets();
    collect_pending_tls_bytes();

    const auto validated = validate_peer_transport_parameters_if_ready();
    if (!validated.has_value()) {
        return validated;
    }

    if (!peer_preferred_address_emitted_ && peer_transport_parameters_validated_ &&
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->preferred_address.has_value()) {
        pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
            .preferred_address = *peer_transport_parameters_->preferred_address,
        };
        peer_preferred_address_emitted_ = true;
    }

    update_handshake_status();
    maybe_emit_qlog_alpn_information(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    auto *tls_adapter = tls_.has_value() ? &*tls_ : nullptr;
    bool tls_handshake_complete =
        tls_adapter != nullptr ? tls_adapter->handshake_complete() : false;
    if (resumption_state_emitted_) {
        return CodecResult<bool>::success(true);
    }
    if (tls_adapter == nullptr) {
        return CodecResult<bool>::success(true);
    }
    if (!tls_handshake_complete) {
        return CodecResult<bool>::success(true);
    }
    if (!peer_transport_parameters_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (const auto ticket = tls_adapter->take_resumption_state(); ticket.has_value()) {
        auto encoded = encode_resumption_state(
            //= https://www.rfc-editor.org/rfc/rfc9369#section-5
            // # When a connection
            // # includes compatible version negotiation, any issued server tokens are
            // # considered to originate from the negotiated version, not the original
            // # one.
            *ticket, current_version_, config_.application_protocol, *peer_transport_parameters_,
            config_.zero_rtt.application_context);
        pending_resumption_state_effect_ = QuicCoreResumptionStateAvailable{
            .state =
                QuicResumptionState{
                    .serialized = std::move(encoded),
                },
        };
        resumption_state_emitted_ = true;
    }
    return CodecResult<bool>::success(true);
}

bool QuicConnection::can_skip_outbound_tls_sync() const {
    if (!can_skip_outbound_tls_sync_now(
            status_, peer_transport_parameters_validated_, application_space_.read_secret,
            application_space_.write_secret, qlog_session_.get(), deferred_protected_packets_)) {
        return false;
    }
    if (config_.role == EndpointRole::server) {
        return true;
    }

    return client_outbound_tls_sync_can_skip_resumption(
        resumption_state_emitted_, peer_preferred_address_emitted_, peer_transport_parameters_);
}

CodecResult<bool> QuicConnection::validate_peer_transport_parameters_if_ready() {
    if (peer_transport_parameters_validated_ || !tls_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (config_.role == EndpointRole::client && decoded_resumption_state_.has_value() &&
        peer_transport_parameters_.has_value() && !tls_->handshake_complete()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
        // # When sending frames in 0-RTT packets, a client MUST only use
        // # remembered transport parameters; importantly, it MUST NOT use
        // # updated values that it learns from the server's updated transport
        // # parameters or from frames received in 1-RTT packets.
        return CodecResult<bool>::success(true);
    }

    const auto &peer_transport_parameters_bytes = tls_->peer_transport_parameters();
    const bool received_peer_transport_parameters = peer_transport_parameters_bytes.has_value();
    if (received_peer_transport_parameters) {
        const auto parameters =
            deserialize_transport_parameters(peer_transport_parameters_bytes.value());
        if (!parameters.has_value()) {
            log_codec_failure("deserialize_transport_parameters", parameters.error());
            return CodecResult<bool>::failure(
                transport_parameter_error(parameters.error().code, parameters.error().offset));
        }

        peer_transport_parameters_ = parameters.value();
        note_endpoint_route_state_changed();
    }
    if (!received_peer_transport_parameters && !peer_transport_parameters_.has_value()) {
        if (tls_->handshake_complete()) {
            //= https://www.rfc-editor.org/rfc/rfc9001#section-8.2
            // # Endpoints MUST send the quic_transport_parameters extension;
            // # endpoints that receive ClientHello or EncryptedExtensions
            // # messages without the quic_transport_parameters extension MUST
            // # close the connection with an error of type 0x016d (equivalent
            // # to a fatal TLS missing_extension alert, see Section 4.8).
            return CodecResult<bool>::failure(CodecError{
                .code = CodecErrorCode::invalid_packet_protection_state,
                .offset = 0,
                .transport_error_code = 0x016du,
                .has_transport_error_code = true,
            });
        }
        return CodecResult<bool>::success(true);
    }

    const auto validation_context = peer_transport_parameters_validation_context();
    if (!validation_context.has_value()) {
        return CodecResult<bool>::success(true);
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
    // # A client MUST NOT use remembered values for the following parameters:
    // # ack_delay_exponent, max_ack_delay, initial_source_connection_id,
    // # original_destination_connection_id, preferred_address,
    // # retry_source_connection_id, and stateless_reset_token.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
    // # The client MUST use the server's new values in the handshake instead;
    // # if the server does not provide new values, the default values are used.
    const auto peer_transport_parameters =
        peer_transport_parameters_.value_or(TransportParameters{});
    if (auto validated = validate_peer_transport_parameters(
            opposite_role(config_.role), peer_transport_parameters, validation_context.value());
        !validated.has_value()) {
        log_codec_failure("validate_peer_transport_parameters", validated.error());
        return CodecResult<bool>::failure(validated.error());
    }
    const bool accepted_zero_rtt = tls_.has_value() && tls_->early_data_accepted().value_or(false);
    if (config_.role == EndpointRole::client && accepted_zero_rtt) {
        if (decoded_resumption_state_.has_value() &&
            peer_transport_parameters.max_datagram_frame_size <
                decoded_resumption_state_->peer_transport_parameters.max_datagram_frame_size) {
            //= https://www.rfc-editor.org/rfc/rfc9221#section-3
            // # If a client stores the value of the
            // # max_datagram_frame_size transport parameter with their 0-RTT state,
            // # they MUST validate that the new value of the max_datagram_frame_size
            // # transport parameter sent by the server in the handshake is greater
            // # than or equal to the stored value; if not, the client MUST terminate
            // # the connection with error PROTOCOL_VIOLATION.
            return CodecResult<bool>::failure(protocol_violation_error(/*frame_type=*/0));
        }
        if (decoded_resumption_state_.has_value() &&
            !zero_rtt_transport_limits_not_reduced(
                decoded_resumption_state_->peer_transport_parameters, peer_transport_parameters)) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
            // # A server MUST reject 0-RTT data if the restored values for
            // # transport parameters cannot be supported.
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }
    }

    peer_transport_parameters_validated_ = true;
    reset_current_short_header_deserialize_context_cache();
    initialize_peer_flow_control_from_transport_parameters();
    auto peer_preferred_address = peer_transport_parameters.preferred_address;
    auto emitted_preferred_address = peer_preferred_address.value_or(PreferredAddress{});
    if (!peer_preferred_address_emitted_ && peer_preferred_address.has_value()) {
        pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
            .preferred_address = emitted_preferred_address,
        };
        peer_preferred_address_emitted_ = true;
    }
    maybe_emit_remote_qlog_parameters(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    return CodecResult<bool>::success(true);
}

void QuicConnection::update_handshake_status() {
    if (status_ == HandshakeStatus::failed || !started_) {
        return;
    }
    if (!tls_.has_value()) {
        return;
    }

    const bool handshake_ready =
        tls_->handshake_complete() && peer_transport_parameters_validated_ &&
        application_space_.read_secret.has_value() && application_space_.write_secret.has_value();
    if (handshake_ready) {
        if (status_ != HandshakeStatus::connected) {
            status_ = HandshakeStatus::connected;
            if (config_.role == EndpointRole::client) {
                mark_peer_address_validated();
            }
            queue_state_change(QuicCoreStateChange::handshake_ready);
        }
        if (config_.role == EndpointRole::server) {
            confirm_handshake();
            if (handshake_done_state_ == StreamControlFrameState::none) {
                //= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.2
                // # The server MUST send a HANDSHAKE_DONE frame as soon as
                // # the handshake is complete.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.20
                // # Servers MUST NOT send a HANDSHAKE_DONE frame before
                // # completing the handshake.
                handshake_done_state_ = StreamControlFrameState::pending;
            }
        }
    } else {
        status_ = HandshakeStatus::in_progress;
    }
}

void QuicConnection::confirm_handshake() {
    if (handshake_confirmed_) {
        return;
    }

    handshake_confirmed_ = true;
    queue_state_change(QuicCoreStateChange::handshake_confirmed);
    issue_spare_connection_ids();
    //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.2
    // # An endpoint MUST discard its Handshake keys when the TLS handshake is
    // # confirmed (Section 4.1.2).
    discard_handshake_packet_space();
}

PathState &QuicConnection::ensure_path_state(QuicPathId path_id) {
    auto [it, inserted] = paths_.try_emplace(
        path_id, PathState{
                     .id = path_id,
                     .peer_connection_id_sequence = active_peer_connection_id_sequence_,
                 });
    if (inserted) {
        it->second.validated =
            last_validated_path_id_.has_value() && last_validated_path_id_ == path_id;
        it->second.spin.disabled = latency_spin_bit_disabled_;
        initialize_path_mtu_state(it->second);
    }
    return it->second;
}

void QuicConnection::initialize_path_mtu_state(PathState &path) {
    const auto base = sanitize_pmtud_base(config_.transport.pmtud_base_datagram_size);
    path.mtu.default_search_ceiling =
        config_.transport.pmtud_max_datagram_size == 0 ? kPmtudIPv6EthernetUdpPayloadSize : 0;
    const auto ceiling = outbound_datagram_size_ceiling_for_path(path.id);
    path.mtu.enabled = config_.transport.pmtud_enabled;
    path.mtu.viable = true;
    path.mtu.base_datagram_size = std::min(base, ceiling);
    path.mtu.validated_datagram_size = path.mtu.enabled ? path.mtu.base_datagram_size : ceiling;
    path.mtu.probe_ceiling = ceiling;
    path.mtu.search_low = path.mtu.validated_datagram_size;
    path.mtu.outstanding_probe_size.reset();
    path.mtu.outstanding_probe_packet_number.reset();
    path.mtu.next_probe_time = std::nullopt;
    path.mtu.failed_probe_sizes.clear();
}

void QuicConnection::set_path_default_pmtud_search_ceiling(QuicPathId path_id,
                                                           QuicDefaultPmtudSearchCeiling ceiling) {
    auto &path = ensure_path_state(path_id);
    if (path.mtu.default_search_ceiling == ceiling.value) {
        return;
    }

    const auto previous_ceiling = outbound_datagram_size_ceiling_for_path(path_id);
    path.mtu.default_search_ceiling = ceiling.value;
    const auto next_ceiling = outbound_datagram_size_ceiling_for_path(path_id);
    if (path.mtu.probe_ceiling == previous_ceiling) {
        path.mtu.probe_ceiling = next_ceiling;
    } else {
        path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, next_ceiling);
    }
    path.mtu.validated_datagram_size =
        std::min(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    path.mtu.search_low = std::min(path.mtu.search_low, path.mtu.validated_datagram_size);
    if (should_clear_outstanding_pmtu_probe_after_ceiling(path.mtu)) {
        clear_outstanding_pmtu_probe(path.mtu);
    }
    path.mtu.failed_probe_sizes.erase(
        std::remove_if(path.mtu.failed_probe_sizes.begin(), path.mtu.failed_probe_sizes.end(),
                       [&](std::size_t probe_size) { return probe_size > path.mtu.probe_ceiling; }),
        path.mtu.failed_probe_sizes.end());
}

void QuicConnection::apply_path_mtu_update(
    QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::size_t max_udp_payload_size) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
    // # QUIC implementations that implement any kind of PMTU discovery
    // # therefore SHOULD maintain a maximum datagram size for each combination
    // # of local and remote IP addresses.
    auto &path = ensure_path_state(path_id);
    if (max_udp_payload_size < kMinimumInitialDatagramSize) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
        // # An endpoint MAY
        // # terminate the connection if an alternative path cannot be found.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
        // # If a QUIC endpoint determines that the PMTU between any pair of
        // # local and remote IP addresses cannot support the smallest allowed
        // # maximum datagram size of 1200 bytes, it MUST immediately cease
        // # sending QUIC packets, except for those in PMTU probes or those
        // # containing CONNECTION_CLOSE frames, on the affected path.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14
        // # QUIC MUST NOT be used if the network path cannot support a
        // # maximum datagram size of at least 1200 bytes.
        path.mtu.viable = false;
        path.mtu.enabled = false;
        path.mtu.probe_ceiling = max_udp_payload_size;
        clear_outstanding_pmtu_probe(path.mtu);
        path.mtu.next_probe_time = std::nullopt;
        if (current_send_path_id_ == path_id && previous_path_id_.has_value() &&
            *previous_path_id_ != path_id) {
            if (const auto previous = paths_.find(*previous_path_id_);
                previous != paths_.end() && previous->second.mtu.viable &&
                previous->second.validated) {
                path.is_current_send_path = false;
                previous->second.is_current_send_path = true;
                current_send_path_id_ = previous_path_id_;
            }
        }
        if (current_send_path_id_ == path_id) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.4
            // # An endpoint that has no valid network path to its peer MAY
            // # signal this using the NO_VIABLE_PATH connection error, noting
            // # that this is only possible if the network path exists but does
            // # not support the required MTU (Section 14).
            pending_transport_close_ = TransportConnectionCloseFrame{
                .error_code = transport_error_code_value(QuicTransportErrorCode::no_viable_path),
                .frame_type = 0,
            };
            pending_connection_close_terminal_state_ = QuicConnectionTerminalState::failed;
            closing_close_packet_pending_ = application_space_.write_secret.has_value();
        }
        return;
    }

    path.mtu.viable = true;
    path.mtu.enabled = config_.transport.pmtud_enabled;
    if (path.mtu.probe_ceiling < kMinimumInitialDatagramSize) {
        path.mtu.probe_ceiling = std::max(kMinimumInitialDatagramSize, max_udp_payload_size);
    }
    path.mtu.probe_ceiling =
        std::min(path.mtu.probe_ceiling, outbound_datagram_size_ceiling_for_path(path_id));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2.1
    // # An endpoint MUST NOT increase the PMTU based on ICMP messages; see
    // # Item 6 in Section 3 of [DPLPMTUD].
    path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, max_udp_payload_size);
    path.mtu.validated_datagram_size =
        std::min(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    path.mtu.search_low = std::min(path.mtu.search_low, path.mtu.validated_datagram_size);
    if (should_clear_outstanding_pmtu_probe_after_ceiling(path.mtu)) {
        clear_outstanding_pmtu_probe(path.mtu);
    }
    path.mtu.failed_probe_sizes.erase(
        std::remove_if(path.mtu.failed_probe_sizes.begin(), path.mtu.failed_probe_sizes.end(),
                       [&](std::size_t probe_size) { return probe_size > path.mtu.probe_ceiling; }),
        path.mtu.failed_probe_sizes.end());
    path.mtu.next_probe_time =
        pmtud_next_probe_time(path.mtu, QuicCoreClock::now(), QuicCoreDuration{1000000});
}

void QuicConnection::start_path_validation(QuicPathId path_id, bool initiated_locally,
                                           QuicCoreTimePoint now) {
    if (current_send_path_id_.has_value() && current_send_path_id_ != path_id) {
        previous_path_id_ = current_send_path_id_;
        if (const auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
            current->second.is_current_send_path = false;
        }
    }

    const auto peer_connection_id_sequence = [&]() -> std::optional<std::uint64_t> {
        if (initiated_locally) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
            // # At any time, endpoints MAY change the Destination Connection ID
            // # they transmit with to a value that has not been used on another
            // # path.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
            // # An endpoint MUST NOT reuse a connection ID when sending from
            // # more than one local address -- for example, when initiating
            // # connection migration as described in Section 9.2 or when
            // # probing a new network path as described in Section 9.1.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
            // # Similarly, an endpoint MUST NOT reuse a connection ID when
            // # sending to more than one destination address.
            return select_peer_connection_id_sequence_for_path(path_id);
        }
        if (const auto existing = paths_.find(path_id);
            existing != paths_.end() &&
            peer_connection_ids_.contains(existing->second.peer_connection_id_sequence)) {
            return existing->second.peer_connection_id_sequence;
        }
        if (current_send_path_id_.has_value()) {
            if (const auto current = paths_.find(*current_send_path_id_);
                current != paths_.end() &&
                peer_connection_ids_.contains(current->second.peer_connection_id_sequence)) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
                // # Due to network changes outside the control of its peer, an
                // # endpoint might receive packets from a new source address with
                // # the same Destination Connection ID field value, in which case
                // # it MAY continue to use the current connection ID with the new
                // # remote address while still sending from the same local address.
                return current->second.peer_connection_id_sequence;
            }
        }
        return active_peer_connection_id_sequence_;
    }();
    if (!peer_connection_id_sequence.has_value()) {
        return;
    }
    auto &path = ensure_path_state(path_id);
    bool path_validation_in_progress = !path.validated && path.outstanding_challenge.has_value();
    path.validated = false;
    path.path_mtu_validation_pending = false;
    path.outstanding_challenge_sent_with_expanded_datagram = true;
    path.validation_probe_only = false;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9
    // # If the peer violates this requirement, the endpoint MUST either drop
    // # the incoming packets on that path without generating a Stateless Reset
    // # or proceed with path validation and allow the peer to migrate.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3
    // # If the recipient permits the migration, it MUST send subsequent packets
    // # to the new peer address
    path.is_current_send_path = true;
    set_path_peer_connection_id_sequence(path, *peer_connection_id_sequence);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3
    // # and MUST initiate path validation (Section 8.2) to verify the peer's
    // # ownership of the address if validation is not already underway.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9
    // # An endpoint MUST perform path validation (Section 8.2) if it detects any
    // # change to a peer's address, unless it has previously validated that
    // # address.
    path.challenge_pending = true;
    path.validation_initiated_locally = initiated_locally;
    if (!path_validation_in_progress) {
        path.outstanding_challenge = next_path_challenge_data(path_id);
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.4
    // # This timer SHOULD be set as described in Section 6.2.1 of
    // # [QUIC-RECOVERY] and MUST NOT be more aggressive.
    path.validation_deadline = now + path_validation_timeout_period();
    current_send_path_id_ = path_id;
}

void QuicConnection::start_path_validation_probe(QuicPathId path_id, bool initiated_locally,
                                                 QuicCoreTimePoint now) {
    auto existing = paths_.find(path_id);
    if (existing == paths_.end()) {
        return;
    }

    auto &path = existing->second;
    const bool probe_validation_in_progress =
        !path.validated && path.outstanding_challenge.has_value();
    path.validated = false;
    path.path_mtu_validation_pending = false;
    path.outstanding_challenge_sent_with_expanded_datagram = true;
    path.validation_probe_only = true;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3.3
    // # In response to an apparent migration, endpoints MUST validate the
    // # previously active path using a PATH_CHALLENGE frame.
    path.challenge_pending = true;
    path.validation_initiated_locally = initiated_locally;
    if (!probe_validation_in_progress) {
        path.outstanding_challenge = next_path_challenge_data(path_id);
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.4
    // # This timer SHOULD be set as described in Section 6.2.1 of
    // # [QUIC-RECOVERY] and MUST NOT be more aggressive.
    path.validation_deadline = now + path_validation_timeout_period();
}

std::array<std::byte, 8> QuicConnection::next_path_challenge_data(QuicPathId path_id) {
    return make_path_challenge_data(config_.source_connection_id, path_id,
                                    next_path_challenge_sequence_++);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void QuicConnection::mark_path_challenge_sent(QuicPathId path_id, std::size_t datagram_size) {
    auto &path = ensure_path_state(path_id);
    path.outstanding_challenge_sent_with_expanded_datagram =
        datagram_size >= kMinimumInitialDatagramSize;
}

void QuicConnection::queue_path_response(QuicPathId path_id, const std::array<std::byte, 8> &data) {
    auto &path = ensure_path_state(path_id);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
    // # On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by
    // # echoing the data contained in the PATH_CHALLENGE frame in a
    // # PATH_RESPONSE frame.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3.3
    // # An endpoint that receives a PATH_CHALLENGE on an active path SHOULD
    // # send a non-probing packet in response.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.17
    // # The recipient of this frame MUST generate a PATH_RESPONSE frame
    // # (Section 19.18) containing the same Data value.
    path.pending_response = data;
}

void QuicConnection::respond_to_path_challenge(QuicPathId path_id,
                                               const std::array<std::byte, 8> &data) {
    queue_path_response(path_id, data);
    issue_path_probe_replacement_connection_id();

    if (config_.role != EndpointRole::client) {
        return;
    }
    if (!current_send_path_id_.has_value() || *current_send_path_id_ != path_id) {
        return;
    }
    const auto path = paths_.find(path_id);
    if (path == paths_.end() || !path->second.validated) {
        return;
    }

    const auto old_sequence = path->second.peer_connection_id_sequence;
    if (!rotate_peer_connection_id_for_path(path_id)) {
        return;
    }
    if (paths_.at(path_id).peer_connection_id_sequence != old_sequence) {
        queue_peer_connection_id_retirement(old_sequence);
    }
}

bool QuicConnection::path_validation_timed_out(QuicPathId path_id, QuicCoreTimePoint now) const {
    const auto path = paths_.find(path_id);
    if (path == paths_.end()) {
        return false;
    }

    const auto &validation_deadline = path->second.validation_deadline;
    return validation_deadline.has_value() && now >= validation_deadline.value();
}

void QuicConnection::complete_path_validation(QuicPathId path_id, PathState &path,
                                              QuicCoreTimePoint now) {
    path.validated = true;
    path.validation_initiated_locally = false;
    last_validated_path_id_ = path_id;

    if (!path.outstanding_challenge_sent_with_expanded_datagram) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
        // # To ensure that the path MTU is large enough, the endpoint
        // # MUST perform a second path validation by sending a PATH_CHALLENGE
        // # frame in a datagram of at least 1200 bytes.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.3
        // # However, the endpoint MUST initiate another path validation with
        // # an expanded datagram to verify that the path supports the required MTU.
        path.path_mtu_validation_pending = true;
        path.challenge_pending = true;
        path.outstanding_challenge = next_path_challenge_data(path_id);
        path.outstanding_challenge_sent_with_expanded_datagram = true;
        path.validation_deadline = now + path_validation_timeout_period();
        return;
    }

    path.path_mtu_validation_pending = false;
    path.challenge_pending = false;
    path.validation_probe_only = false;
    path.outstanding_challenge.reset();
    path.outstanding_challenge_sent_with_expanded_datagram = true;
    path.validation_deadline.reset();
}

void QuicConnection::abandon_original_address_validation_after_preferred_success(
    QuicPathId preferred_path_id) {
    const auto preferred = paths_.find(preferred_path_id);
    if (preferred == paths_.end() || !preferred->second.preferred_address_path ||
        !preferred->second.validated) {
        return;
    }

    for (auto &[path_id, path] : paths_) {
        if (path_id == preferred_path_id || path.preferred_address_path) {
            continue;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.3
        // # If path validation of the server's preferred address succeeds, the
        // # client MUST abandon validation of the original address and migrate to
        // # using the server's preferred address.
        path.challenge_pending = false;
        path.validation_probe_only = false;
        path.path_mtu_validation_pending = false;
        path.outstanding_challenge.reset();
        path.outstanding_challenge_sent_with_expanded_datagram = true;
        path.validation_deadline.reset();
    }
}

CodecResult<bool>
QuicConnection::process_new_connection_id_frame(const NewConnectionIdFrame &frame) {
    if (!peer_connection_ids_.contains(0) && peer_source_connection_id_.has_value() &&
        largest_peer_retire_prior_to_ == 0 && !retired_peer_connection_id_sequences_.contains(0)) {
        peer_connection_ids_.emplace(0, PeerConnectionIdRecord{
                                            .sequence_number = 0,
                                            .connection_id = peer_source_connection_id_.value(),
                                        });
        note_endpoint_route_state_changed();
    }
    if (frame.retire_prior_to > frame.sequence_number) {
        return CodecResult<bool>::failure(frame_encoding_error(kFrameTypeNewConnectionId));
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # An endpoint that is sending packets with a zero-length Destination
    // # Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a
    // # connection error of type PROTOCOL_VIOLATION.
    if (outbound_destination_connection_id().empty()) {
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
    }

    const bool retire_prior_increased = frame.retire_prior_to > largest_peer_retire_prior_to_;
    auto active_retire_prior_to =
        retire_prior_increased ? frame.retire_prior_to : largest_peer_retire_prior_to_;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # A receiver MUST ignore any Retire Prior To fields that do not increase
    // # the largest received Retire Prior To value.
    if (retire_prior_increased) {
        largest_peer_retire_prior_to_ = frame.retire_prior_to;
    }

    auto duplicate_sequence = peer_connection_ids_.find(frame.sequence_number);
    if (duplicate_sequence != peer_connection_ids_.end()) {
        const bool mismatched_duplicate =
            duplicate_sequence->second.connection_id != frame.connection_id ||
            duplicate_sequence->second.stateless_reset_token != frame.stateless_reset_token;
        if (mismatched_duplicate) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
            // # Endpoints are not required to compare new values
            // # against all previous values, but a duplicate value MAY be treated as
            // # a connection error of type PROTOCOL_VIOLATION.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
            // # If an endpoint receives a NEW_CONNECTION_ID frame that repeats
            // # a previously issued connection ID with a different Stateless
            // # Reset Token field value or a different Sequence Number field
            // # value, or if a sequence number is used for different connection
            // # IDs, the endpoint MAY treat that receipt as a connection error
            // # of type PROTOCOL_VIOLATION.
            return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        // # Receipt of the same frame multiple times MUST NOT be treated as a
        // # connection error.
    }

    const auto conflicting_connection_id = std::find_if(
        peer_connection_ids_.begin(), peer_connection_ids_.end(), [&](const auto &entry) {
            return entry.first != frame.sequence_number &&
                   entry.second.connection_id == frame.connection_id;
        });
    if (conflicting_connection_id != peer_connection_ids_.end()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
        // # Endpoints are not required to compare new values
        // # against all previous values, but a duplicate value MAY be treated as
        // # a connection error of type PROTOCOL_VIOLATION.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        // # If an endpoint receives a NEW_CONNECTION_ID frame that repeats a
        // # previously issued connection ID with a different Stateless Reset
        // # Token field value or a different Sequence Number field value, or
        // # if a sequence number is used for different connection IDs, the
        // # endpoint MAY treat that receipt as a connection error of type
        // # PROTOCOL_VIOLATION.
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
    }

    for (const auto &[sequence_number, record] : peer_connection_ids_) {
        static_cast<void>(record);
        if (sequence_number >= active_retire_prior_to) {
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # Upon receipt of an increased Retire Prior To field, the peer MUST
        // # stop using the corresponding connection IDs and retire them with
        // # RETIRE_CONNECTION_ID frames before adding the newly provided
        // # connection ID to the set of active connection IDs.
        queue_peer_connection_id_retirement(sequence_number);
    }
    if (frame.sequence_number < active_retire_prior_to) {
        if (!retired_peer_connection_id_sequences_.contains(frame.sequence_number)) {
            peer_connection_ids_[frame.sequence_number] = PeerConnectionIdRecord{
                .sequence_number = frame.sequence_number,
                .connection_id = frame.connection_id,
                .stateless_reset_token = frame.stateless_reset_token,
                .locally_retired = true,
            };
            note_endpoint_route_state_changed();
            //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
            // # An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
            // # number smaller than the Retire Prior To field of a previously
            // # received NEW_CONNECTION_ID frame MUST send a corresponding
            // # RETIRE_CONNECTION_ID frame that retires the newly received
            // # connection ID, unless it has already done so for that sequence
            // # number.
            queue_peer_connection_id_retirement(frame.sequence_number);
            refresh_peer_connection_id_sequences_after_retirement();
        }
        return CodecResult<bool>::success(true);
    }
    peer_connection_ids_[frame.sequence_number] = PeerConnectionIdRecord{
        .sequence_number = frame.sequence_number,
        .connection_id = frame.connection_id,
        .stateless_reset_token = frame.stateless_reset_token,
        .locally_retired = frame.sequence_number < largest_peer_retire_prior_to_,
    };
    note_endpoint_route_state_changed();
    if (frame.sequence_number >= largest_peer_retire_prior_to_) {
        retired_peer_connection_id_sequences_.erase(frame.sequence_number);
    }

    refresh_peer_connection_id_sequences_after_retirement();
    if (!peer_connection_ids_.contains(active_peer_connection_id_sequence_) ||
        peer_connection_ids_.at(active_peer_connection_id_sequence_).locally_retired) {
        active_peer_connection_id_sequence_ = frame.sequence_number;
    }

    if (static_cast<std::size_t>(std::count_if(
            peer_connection_ids_.begin(), peer_connection_ids_.end(), [](const auto &entry) {
                return !entry.second.locally_retired;
            })) > local_transport_parameters_.active_connection_id_limit) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # If the endpoint can no longer process the indicated
        // # connection IDs, it MAY close the connection.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # After processing a NEW_CONNECTION_ID frame and adding and retiring
        // # active connection IDs, if the number of active connection IDs
        // # exceeds the value advertised in its active_connection_id_limit
        // # transport parameter, an endpoint MUST close the connection with an
        // # error of type CONNECTION_ID_LIMIT_ERROR.
        return CodecResult<bool>::failure(connection_id_limit_error(kFrameTypeNewConnectionId));
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::ensure_peer_preferred_address_connection_id() {
    if (!peer_transport_parameters_.has_value() ||
        !peer_transport_parameters_->preferred_address.has_value()) {
        return CodecResult<bool>::success(false);
    }

    const auto &preferred_address = peer_transport_parameters_->preferred_address.value();
    const auto duplicate_sequence =
        peer_connection_ids_.find(kPreferredAddressConnectionIdSequence);
    if (duplicate_sequence != peer_connection_ids_.end()) {
        const bool mismatched_duplicate =
            duplicate_sequence->second.connection_id != preferred_address.connection_id ||
            duplicate_sequence->second.stateless_reset_token !=
                preferred_address.stateless_reset_token;
        if (mismatched_duplicate) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
            // # Endpoints are not required to compare new values
            // # against all previous values, but a duplicate value MAY be treated as
            // # a connection error of type PROTOCOL_VIOLATION.
            return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
        }
        if (duplicate_sequence->second.locally_retired) {
            note_endpoint_route_state_changed();
            duplicate_sequence->second.locally_retired = false;
        }
        return CodecResult<bool>::success(true);
    }

    const auto conflicting_connection_id = std::find_if(
        peer_connection_ids_.begin(), peer_connection_ids_.end(), [&](const auto &entry) {
            return entry.first != kPreferredAddressConnectionIdSequence &&
                   entry.second.connection_id == preferred_address.connection_id;
        });
    if (conflicting_connection_id != peer_connection_ids_.end()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
        // # Endpoints are not required to compare new values
        // # against all previous values, but a duplicate value MAY be treated as
        // # a connection error of type PROTOCOL_VIOLATION.
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
    }

    peer_connection_ids_[kPreferredAddressConnectionIdSequence] = PeerConnectionIdRecord{
        .sequence_number = kPreferredAddressConnectionIdSequence,
        .connection_id = preferred_address.connection_id,
        .stateless_reset_token = preferred_address.stateless_reset_token,
    };
    note_endpoint_route_state_changed();

    if (static_cast<std::size_t>(std::count_if(
            peer_connection_ids_.begin(), peer_connection_ids_.end(), [](const auto &entry) {
                return !entry.second.locally_retired;
            })) > local_transport_parameters_.active_connection_id_limit) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # If the endpoint can no longer process the indicated
        // # connection IDs, it MAY close the connection.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # After processing a NEW_CONNECTION_ID frame and adding and retiring
        // # active connection IDs, if the number of active connection IDs
        // # exceeds the value advertised in its active_connection_id_limit
        // # transport parameter, an endpoint MUST close the connection with an
        // # error of type CONNECTION_ID_LIMIT_ERROR.
        return CodecResult<bool>::failure(connection_id_limit_error(kFrameTypeNewConnectionId));
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::queue_peer_connection_id_retirement(std::uint64_t sequence_number) {
    auto peer = peer_connection_ids_.find(sequence_number);
    if (peer == peer_connection_ids_.end()) {
        return;
    }

    if (!peer->second.locally_retired) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # An endpoint MUST NOT forget a connection ID without retiring it,
        // # though it MAY choose to treat having connection IDs in need of
        // # retirement that exceed this limit as a connection error of type
        // # CONNECTION_ID_LIMIT_ERROR.
        peer->second.locally_retired = true;
        note_endpoint_route_state_changed();
    }
    if (sequence_number == active_peer_connection_id_sequence_) {
        const auto next_active =
            std::find_if(peer_connection_ids_.begin(), peer_connection_ids_.end(),
                         [](const auto &entry) { return !entry.second.locally_retired; });
        if (next_active != peer_connection_ids_.end()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-19.16
            // # The sequence number specified in a RETIRE_CONNECTION_ID frame
            // # MUST NOT refer to the Destination Connection ID field of the
            // # packet in which the frame is contained.
            active_peer_connection_id_sequence_ = next_active->first;
        }
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # An endpoint SHOULD limit the number of connection IDs it has retired
    // # locally for which RETIRE_CONNECTION_ID frames have not yet been
    // # acknowledged.
    if (peer->second.retire_frame_in_flight) {
        return;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # An endpoint SHOULD allow for sending and tracking a number of
    // # RETIRE_CONNECTION_ID frames of at least twice the value of the
    // # active_connection_id_limit transport parameter.
    const bool already_pending = std::ranges::any_of(
        pending_retire_connection_id_frames_, [&](const RetireConnectionIdFrame &pending) {
            return pending.sequence_number == sequence_number;
        });
    if (!already_pending) {
        pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = sequence_number,
        });
    }
}

void QuicConnection::refresh_peer_connection_id_sequences_after_retirement() {
    const auto refresh_path = [&](QuicPathId path_id, PathState &path) {
        const auto peer = peer_connection_ids_.find(path.peer_connection_id_sequence);
        if (peer != peer_connection_ids_.end() && !peer->second.locally_retired) {
            return;
        }
        path.destination_connection_id_override.reset();
        if (const auto replacement = select_unused_peer_connection_id_sequence_for_path(path_id)) {
            set_path_peer_connection_id_sequence(path, *replacement);
        }
    };

    if (current_send_path_id_.has_value()) {
        if (auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
            refresh_path(current->first, current->second);
        }
    }

    for (auto &[path_id, path] : paths_) {
        if (current_send_path_id_.has_value() && path_id == *current_send_path_id_) {
            continue;
        }
        refresh_path(path_id, path);
    }
}

CodecResult<bool>
QuicConnection::process_retire_connection_id_frame(const RetireConnectionIdFrame &frame) {
    if (config_.source_connection_id.empty()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.16
        // # An endpoint that provides a zero-length connection ID MUST treat
        // # receipt of a RETIRE_CONNECTION_ID frame as a connection error of
        // # type PROTOCOL_VIOLATION.
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeRetireConnectionId));
    }
    issue_spare_connection_ids();
    const auto record = local_connection_ids_.find(frame.sequence_number);
    if (record == local_connection_ids_.end()) {
        if (!handshake_confirmed_) {
            return CodecResult<bool>::success(true);
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.16
        // # Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
        // # greater than any previously sent to the peer MUST be treated as a
        // # connection error of type PROTOCOL_VIOLATION.
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeRetireConnectionId));
    }
    if (record->second.retired) {
        return CodecResult<bool>::success(true);
    }

    record->second.retired = true;
    note_endpoint_route_state_changed();
    if (frame.sequence_number == active_local_connection_id_sequence_) {
        const auto next_active =
            std::find_if(local_connection_ids_.begin(), local_connection_ids_.end(),
                         [](const auto &entry) { return !entry.second.retired; });
        if (next_active != local_connection_ids_.end()) {
            active_local_connection_id_sequence_ = next_active->first;
        }
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint SHOULD supply a new connection ID when the peer retires a
    // # connection ID.
    issue_spare_connection_ids();
    return CodecResult<bool>::success(true);
}

bool QuicConnection::can_issue_local_connection_id() const {
    if (!handshake_confirmed_ || !peer_transport_parameters_.has_value() ||
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        // # An endpoint MUST NOT send this frame if it currently requires that
        // # its peer send packets with a zero-length Destination Connection ID.
        config_.source_connection_id.empty()) {
        return false;
    }
    if (config_.role == EndpointRole::client &&
        local_transport_parameters_.disable_active_migration) {
        return false;
    }
    if (current_send_path_id_.has_value()) {
        if (const auto path = paths_.find(*current_send_path_id_); path != paths_.end()) {
            if (!path->second.mtu.viable) {
                return false;
            }
        }
    }

    return peer_transport_parameters_->active_connection_id_limit != 0;
}

NewConnectionIdFrame QuicConnection::issue_local_connection_id(std::uint64_t retire_prior_to) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # The sequence number on each newly issued connection ID MUST increase
    // # by 1.
    const auto sequence_number = next_local_connection_id_sequence_++;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1
    // # As a trivial example, this means the same connection ID
    // # MUST NOT be issued more than once on the same connection.
    const auto connection_id =
        make_issued_connection_id(config_.source_connection_id, sequence_number);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
    // # The same stateless reset token MUST NOT be used for multiple
    // # connection IDs.
    const auto stateless_reset_token =
        make_stateless_reset_token(connection_id, sequence_number, config_.stateless_reset_secret);
    local_connection_ids_[sequence_number] = LocalConnectionIdRecord{
        .sequence_number = sequence_number,
        .connection_id = connection_id,
        .stateless_reset_token = stateless_reset_token,
    };
    for (auto &[issued_sequence_number, record] : local_connection_ids_) {
        if (issued_sequence_number >= retire_prior_to || record.retired) {
            continue;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # An endpoint might need to stop accepting previously issued
        // # connection IDs in certain circumstances. Such an endpoint can cause
        // # its peer to retire connection IDs by sending a NEW_CONNECTION_ID
        // # frame with an increased Retire Prior To field.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # The endpoint SHOULD continue to accept the previously issued
        // # connection IDs until they are retired by the peer.
        record.retirement_requested = true;
    }
    note_endpoint_route_state_changed();

    auto frame = NewConnectionIdFrame{
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .connection_id = connection_id,
        .stateless_reset_token = stateless_reset_token,
    };
    pending_new_connection_id_frames_.push_back(frame);
    return frame;
}

void QuicConnection::issue_spare_connection_ids() {
    if (!can_issue_local_connection_id() || !peer_transport_parameters_.has_value()) {
        return;
    }

    const auto &peer_transport_parameters = peer_transport_parameters_.value();
    const auto peer_limit =
        static_cast<std::size_t>(peer_transport_parameters.active_connection_id_limit);

    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint SHOULD ensure that its peer has a sufficient number of
    // # available and unused connection IDs.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
    // # To ensure that migration is possible and packets sent on different
    // # paths cannot be correlated, endpoints SHOULD provide new connection
    // # IDs before peers migrate; see Section 5.1.1.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint MUST NOT provide more connection IDs than the peer's limit.
    while (count_active_connection_ids(local_connection_ids_) < peer_limit) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # An endpoint MAY limit the total number of connection IDs issued for
        // # each connection to avoid the risk of running out of connection IDs;
        // # see Section 10.3.2.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # An endpoint MAY also limit the issuance of connection IDs to reduce
        // # the amount of per-path state it maintains, such as path validation
        // # status, as its peer might interact with it over as many paths as
        // # there are issued connection IDs.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # Endpoints SHOULD NOT issue updates of the Retire Prior To field
        // # before receiving RETIRE_CONNECTION_ID frames that retire all
        // # connection IDs indicated by the previous Retire Prior To value.
        static_cast<void>(issue_local_connection_id(/*retire_prior_to=*/0));
    }
}

bool QuicConnection::request_local_connection_id_rotation() {
    if (!can_issue_local_connection_id() || !peer_transport_parameters_.has_value()) {
        return false;
    }

    const auto &peer_transport_parameters = peer_transport_parameters_.value();
    const auto has_pending_requested_retirement =
        std::ranges::any_of(local_connection_ids_, [](const auto &entry) {
            return !entry.second.retired && entry.second.retirement_requested;
        });
    if (has_pending_requested_retirement) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # Endpoints SHOULD NOT issue updates of the Retire Prior To field
        // # before receiving RETIRE_CONNECTION_ID frames that retire all
        // # connection IDs indicated by the previous Retire Prior To value.
        return false;
    }

    const auto peer_limit =
        static_cast<std::size_t>(peer_transport_parameters.active_connection_id_limit);
    const auto active_after_retire_prior_to = [&](std::uint64_t retire_prior_to) {
        const auto retained = std::count_if(
            local_connection_ids_.begin(), local_connection_ids_.end(), [&](const auto &entry) {
                return !entry.second.retired && entry.first >= retire_prior_to;
            });
        return static_cast<std::size_t>(retained) + 1u;
    };

    if (largest_local_retire_prior_to_ >= next_local_connection_id_sequence_) {
        return false;
    }

    const auto first_candidate = largest_local_retire_prior_to_ + 1u;
    for (auto retire_prior_to = first_candidate;
         retire_prior_to <= next_local_connection_id_sequence_; ++retire_prior_to) {
        const bool retires_existing_connection_id =
            std::ranges::any_of(local_connection_ids_, [&](const auto &entry) {
                return !entry.second.retired && entry.first < retire_prior_to;
            });
        if (!retires_existing_connection_id) {
            continue;
        }
        if (active_after_retire_prior_to(retire_prior_to) > peer_limit) {
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # An endpoint MAY send connection IDs that temporarily exceed a
        // # peer's limit if the NEW_CONNECTION_ID frame also requires the
        // # retirement of any excess, by including a sufficiently large value in
        // # the Retire Prior To field.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # After processing a NEW_CONNECTION_ID frame and adding and retiring
        // # active connection IDs, if the number of active connection IDs
        // # exceeds the value advertised in its active_connection_id_limit
        // # transport parameter, an endpoint MUST close the connection with an
        // # error of type CONNECTION_ID_LIMIT_ERROR.
        static_cast<void>(issue_local_connection_id(retire_prior_to));
        largest_local_retire_prior_to_ = retire_prior_to;
        return true;
    }

    return false;
}

void QuicConnection::note_local_connection_id_used_by_peer(
    const ConnectionId &destination_connection_id) {
    auto record = std::find_if(
        local_connection_ids_.begin(), local_connection_ids_.end(), [&](const auto &entry) {
            return !entry.second.retired && entry.second.connection_id == destination_connection_id;
        });
    if (record == local_connection_ids_.end() || record->second.used_by_peer) {
        return;
    }

    record->second.used_by_peer = true;
    if (!can_issue_local_connection_id()) {
        return;
    }

    if (!peer_transport_parameters_.has_value()) {
        return;
    }

    const auto &peer_transport_parameters = peer_transport_parameters_.value();
    const auto peer_limit =
        static_cast<std::size_t>(peer_transport_parameters.active_connection_id_limit);
    if (count_active_connection_ids(local_connection_ids_) >= peer_limit) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # If an endpoint provided fewer connection IDs than the peer's
    // # active_connection_id_limit, it MAY supply a new connection ID when it
    // # receives a packet with a previously unused connection ID.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint MUST NOT provide more connection IDs than the peer's
    // # limit.
    static_cast<void>(issue_local_connection_id(/*retire_prior_to=*/0));
}

void QuicConnection::issue_path_probe_replacement_connection_id() {
    if (!handshake_confirmed_ || !peer_transport_parameters_.has_value() ||
        config_.source_connection_id.empty()) {
        return;
    }
    if (config_.role == EndpointRole::client &&
        local_transport_parameters_.disable_active_migration) {
        return;
    }

    const auto peer_limit =
        static_cast<std::uint64_t>(peer_transport_parameters_->active_connection_id_limit);
    if (peer_limit == 0) {
        return;
    }
    if (count_unretired_connection_ids_without_pending_retirement(local_connection_ids_) <
        peer_limit) {
        issue_spare_connection_ids();
    }
}

std::optional<std::uint64_t>
QuicConnection::select_peer_connection_id_sequence_for_path(QuicPathId path_id) const {
    if (const auto path = paths_.find(path_id);
        path != paths_.end() &&
        peer_connection_ids_.contains(path->second.peer_connection_id_sequence)) {
        if (peer_connection_ids_.at(path->second.peer_connection_id_sequence).locally_retired) {
            return std::nullopt;
        }
        return path->second.peer_connection_id_sequence;
    }

    return select_unused_peer_connection_id_sequence_for_path(path_id);
}

std::optional<std::uint64_t>
QuicConnection::select_unused_peer_connection_id_sequence_for_path(QuicPathId path_id) const {
    const auto sequence_assigned_to_other_path = [&](std::uint64_t sequence_number) {
        return std::ranges::any_of(paths_, [&](const auto &entry) {
            return (entry.first != path_id) &
                   (entry.second.peer_connection_id_sequence == sequence_number);
        });
    };

    for (const auto &[sequence_number, connection_id] : peer_connection_ids_) {
        static_cast<void>(connection_id);
        if (connection_id.locally_retired |
            (sequence_number == active_peer_connection_id_sequence_) |
            sequence_assigned_to_other_path(sequence_number)) {
            continue;
        }

        return sequence_number;
    }

    return std::nullopt;
}

bool QuicConnection::rotate_peer_connection_id_for_path(QuicPathId path_id) {
    if (const auto sequence_number = select_unused_peer_connection_id_sequence_for_path(path_id)) {
        auto &path = ensure_path_state(path_id);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
        // # At any time, endpoints MAY change the Destination Connection ID
        // # they transmit with to a value that has not been used on another
        // # path.
        set_path_peer_connection_id_sequence(path, *sequence_number);
        return true;
    }
    return false;
}

ConnectionId QuicConnection::active_peer_destination_connection_id() const {
    if (const auto active = peer_connection_ids_.find(active_peer_connection_id_sequence_);
        active != peer_connection_ids_.end()) {
        if (!active->second.locally_retired) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
            // # A server MUST set the Destination Connection ID it uses for
            // # sending packets based on the first received Initial packet.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
            // # A client MUST change the Destination Connection ID it uses for
            // # sending packets in response to only the first received Initial
            // # or Retry packet.
            return active->second.connection_id;
        }
    }
    if (peer_source_connection_id_.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
        // # A server MUST set the Destination Connection ID it uses for
        // # sending packets based on the first received Initial packet.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
        // # A client MUST change the Destination Connection ID it uses for
        // # sending packets in response to only the first received Initial
        // # or Retry packet.
        return peer_source_connection_id_.value();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    // # Until a packet is received from the server, the client MUST use the
    // # same Destination Connection ID value on all packets in this connection.
    return config_.initial_destination_connection_id;
}

std::optional<NewConnectionIdFrame> QuicConnection::take_pending_new_connection_id_frame() {
    if (pending_new_connection_id_frames_.empty()) {
        return std::nullopt;
    }

    auto frame = pending_new_connection_id_frames_.front();
    pending_new_connection_id_frames_.erase(pending_new_connection_id_frames_.begin());
    return frame;
}

bool QuicConnection::should_discard_client_long_header_with_changed_source(
    const ConnectionId &source_connection_id) const {
    return should_discard_client_long_header_with_changed_source_for_source(
        config_.role, status_, handshake_confirmed_, peer_source_connection_id_,
        source_connection_id);
}

bool QuicConnection::packet_targets_discarded_long_header_space(
    std::span<const std::byte> packet_bytes) const {
    if (packet_bytes.size() < 5) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(packet_bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return false;
    }

    const auto version = read_u32_be(packet_bytes.subspan(1, 4));
    const auto packet_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version, packet_type)) {
        return initial_packet_space_discarded_;
    }
    if (is_handshake_long_header_type(version, packet_type)) {
        return handshake_packet_space_discarded_;
    }

    return false;
}

void QuicConnection::discard_packet_space_state(PacketSpaceState &packet_space) {
    std::vector<SentPacketRecord> discarded_packets;
    const auto handles = packet_space.recovery.tracked_packets();
    discarded_packets.reserve(handles.size());
    for (const auto handle : handles) {
        const auto *packet = packet_space.recovery.packet_for_handle(handle);
        if (packet == nullptr || !packet->in_flight || packet->bytes_in_flight == 0) {
            continue;
        }
        discarded_packets.push_back(*packet);
    }

    if (!discarded_packets.empty()) {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.4
        // # The sender MUST discard all recovery state associated with those
        // # packets and MUST remove them from the count of bytes in flight.
        congestion_controller_.on_packets_discarded(discarded_packets);
    }

    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.4
    // # The sender MUST discard all recovery state associated with those
    // # packets and MUST remove them from the count of bytes in flight.
    reset_discarded_packet_space_state(packet_space);
}

void QuicConnection::discard_initial_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    initial_packet_space_discarded_ = true;
    server_initial_crypto_scan_prefix_.clear();
    //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.1
    // # Thus, a client MUST discard Initial keys when it first sends a
    // # Handshake packet and a server MUST discard Initial keys when it first
    // # successfully processes a Handshake packet.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.1
    // # Endpoints MUST NOT send Initial packets after this point.
    discard_packet_space_state(initial_space_);
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
    // # When Initial or Handshake keys are discarded, the PTO and loss
    // # detection timers MUST be reset, because discarding keys indicates
    // # forward progress and the loss detection timer might have been set for
    // # a now-discarded packet number space.
    pto_count_ = 0;
}

void QuicConnection::discard_handshake_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    handshake_packet_space_discarded_ = true;
    discard_packet_space_state(handshake_space_);
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
    // # When Initial or Handshake keys are discarded, the PTO and loss
    // # detection timers MUST be reset, because discarding keys indicates
    // # forward progress and the loss detection timer might have been set for
    // # a now-discarded packet number space.
    pto_count_ = 0;
}

bool QuicConnection::can_send_connection_close_frame() const {
    return application_space_.write_secret.has_value() ||
           handshake_space_.write_secret.has_value() || !initial_packet_space_discarded_;
}

std::optional<Frame> QuicConnection::connection_close_frame_for_send() const {
    if (closing_transport_close_.has_value()) {
        return Frame{*closing_transport_close_};
    }
    if (pending_transport_close_.has_value()) {
        return Frame{*pending_transport_close_};
    }
    if (closing_application_close_.has_value()) {
        return Frame{*closing_application_close_};
    }
    if (pending_application_close_.has_value()) {
        return Frame{*pending_application_close_};
    }
    return std::nullopt;
}

void QuicConnection::mark_connection_close_frame_sent(const Frame &frame, QuicCoreTimePoint now) {
    if (const auto *transport_close = std::get_if<TransportConnectionCloseFrame>(&frame)) {
        closing_transport_close_ = *transport_close;
        pending_transport_close_.reset();
    } else if (const auto *application_close =
                   std::get_if<ApplicationConnectionCloseFrame>(&frame)) {
        closing_application_close_ = *application_close;
        pending_application_close_.reset();
    } else {
        return;
    }

    enter_closing_state(now, pending_connection_close_terminal_state_.value_or(
                                 QuicConnectionTerminalState::closed));
    closing_packets_since_last_close_ = 0;
    closing_packet_response_threshold_ =
        std::min<std::uint64_t>(closing_packet_response_threshold_ * 2u, 1024u);
}

void QuicConnection::clear_connection_failure_effects() {
    streams_.clear();
    invalidate_active_stream_lookup_cache();
    active_queued_stream_bytes_ = 0;
    fresh_sendable_stream_bytes_ = 0;
    streams_with_lost_send_data_ = 0;
    deferred_protected_packets_.clear();
    pending_stream_receive_effects_.clear();
    pending_peer_reset_effects_.clear();
    pending_peer_stop_effects_.clear();
    pending_state_changes_.clear();
    pending_resumption_state_effect_.reset();
    pending_zero_rtt_status_event_.reset();
    pending_new_token_frames_.clear();
    pending_new_connection_id_frames_.clear();
    pending_retire_connection_id_frames_.clear();
}

void QuicConnection::enter_closing_state(QuicCoreTimePoint now,
                                         QuicConnectionTerminalState terminal_state) {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return;
    }
    const bool entering_closing = close_mode_ != QuicConnectionCloseMode::closing;
    if (!close_started_at_.has_value()) {
        close_started_at_ = now;
    }
    if (!close_deadline_.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
        // # The closing and draining connection states exist to ensure that
        // # connections close cleanly and that delayed or reordered packets are
        // # properly discarded.  These states SHOULD persist for at least three
        // # times the current PTO interval as defined in [QUIC-RECOVERY].
        close_deadline_ = *close_started_at_ + three_pto_period(shared_recovery_rtt_state());
    }
    close_mode_ = QuicConnectionCloseMode::closing;
    pending_connection_close_terminal_state_ = terminal_state;
    closing_close_packet_pending_ = false;
    if (entering_closing) {
        closing_packets_since_last_close_ = 0;
        closing_packet_response_threshold_ = 1;
    }
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::enter_draining_state(QuicCoreTimePoint now) {
    if (!close_started_at_.has_value()) {
        close_started_at_ = now;
    }
    if (!close_deadline_.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
        // # The closing and draining connection states exist to ensure that
        // # connections close cleanly and that delayed or reordered packets are
        // # properly discarded.  These states SHOULD persist for at least three
        // # times the current PTO interval as defined in [QUIC-RECOVERY].
        close_deadline_ = *close_started_at_ + three_pto_period(shared_recovery_rtt_state());
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
    // # If the last 16 bytes of the datagram are identical in value to a
    // # stateless reset token, the endpoint MUST enter the draining period and
    // # not send any further packets on this connection.
    close_mode_ = QuicConnectionCloseMode::draining;
    pending_connection_close_terminal_state_ = QuicConnectionTerminalState::closed;
    closing_close_packet_pending_ = false;
    pending_application_close_.reset();
    pending_transport_close_.reset();
    closing_application_close_.reset();
    closing_transport_close_.reset();
    closing_packets_since_last_close_ = 0;
    closing_packet_response_threshold_ = 1;
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::queue_transport_close_for_error(QuicCoreTimePoint now, const CodecError &error,
                                                     std::uint64_t frame_type) {
    if (close_mode_ == QuicConnectionCloseMode::closing ||
        close_mode_ == QuicConnectionCloseMode::draining) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.1
    // # Errors that result in the connection being unusable, such as an
    // # obvious violation of protocol semantics or corruption of state that
    // # affects an entire connection, MUST be signaled using a
    // # CONNECTION_CLOSE frame (Section 19.19).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11
    // # An endpoint that detects an error SHOULD signal the existence of that
    // # error to its peer.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11
    // # The most appropriate error code (Section 20) SHOULD be included in
    // # the frame that signals the error.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint that wishes to communicate a fatal connection error MUST
    // # use a CONNECTION_CLOSE frame if it is able.
    pending_transport_close_ = TransportConnectionCloseFrame{
        .error_code = error.has_transport_error_code
                          ? error.transport_error_code
                          //= https://www.rfc-editor.org/rfc/rfc9000#section-11
                          // # In particular, an endpoint MAY use any applicable error
                          // # code when it detects an error condition; a generic error
                          // # code (such as PROTOCOL_VIOLATION or INTERNAL_ERROR) can
                          // # always be used in place of specific error codes.
                          : transport_error_code_value(transport_error_for_codec_error(error.code)),
        .frame_type = error.has_frame_type ? error.frame_type : frame_type,
    };
    pending_connection_close_terminal_state_ = QuicConnectionTerminalState::failed;
    enter_closing_state(now, QuicConnectionTerminalState::failed);
    closing_close_packet_pending_ = can_send_connection_close_frame();
}

bool QuicConnection::note_aead_encryption_attempt(std::size_t packet_count, QuicCoreTimePoint now) {
    if (packet_count == 0 || !application_space_.write_secret.has_value()) {
        return true;
    }

    if (connection_drain_test_hooks().force_aead_confidentiality_limit) {
        queue_transport_close_for_error(now, aead_limit_reached_error());
        return false;
    }

    const auto limit =
        confidentiality_limit_for_cipher_suite(application_space_.write_secret->cipher_suite);
    if (!limit.has_value()) {
        return true;
    }
    if (current_application_write_key_encrypted_packets_ > *limit - packet_count) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # If the total number of encrypted packets with the same key
        // # exceeds the confidentiality limit for the selected AEAD, the
        // # endpoint MUST stop using those keys.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # If a key update is not possible or integrity limits are reached,
        // # the endpoint MUST stop using the connection and only send stateless
        // # resets in response to receiving packets.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # It is RECOMMENDED that endpoints immediately close the connection
        // # with a connection error of type AEAD_LIMIT_REACHED before reaching a
        // # state where key updates are not possible.
        queue_transport_close_for_error(now, aead_limit_reached_error());
        return false;
    }

    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
    // # Endpoints MUST count the number of encrypted packets for each set of keys.
    current_application_write_key_encrypted_packets_ += packet_count;
    maybe_request_proactive_key_update();
    return true;
}

void QuicConnection::maybe_request_proactive_key_update() {
    if (local_key_update_requested_ || local_key_update_initiated_ ||
        !application_space_.write_secret.has_value()) {
        return;
    }

    const auto threshold = proactive_key_update_packet_limit_for_cipher_suite(
        application_space_.write_secret->cipher_suite);
    if (!threshold.has_value() || current_application_write_key_encrypted_packets_ < *threshold) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.3
    // # An endpoint MUST initiate a key update (Section 6) prior to exceeding
    // # any limit set for the AEAD that is in use.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
    // # Endpoints MUST initiate a key update before sending more protected
    // # packets than the confidentiality limit for the selected AEAD permits.
    request_key_update();
}

bool QuicConnection::note_packet_authentication_failure(const CodecError &error,
                                                        QuicCoreTimePoint now) {
    if (!packet_authentication_failed(error.code)) {
        return true;
    }

    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
    // # In addition to counting packets sent, endpoints MUST count the number
    // # of received packets that fail authentication during the lifetime of a
    // # connection.
    ++failed_authentication_packets_;
    if (connection_drain_test_hooks().force_aead_integrity_limit) {
        queue_transport_close_for_error(now, aead_limit_reached_error());
        return false;
    }
    if (!application_space_.read_secret.has_value()) {
        return true;
    }

    const auto limit =
        integrity_limit_for_cipher_suite(application_space_.read_secret->cipher_suite);
    if (limit.has_value() && failed_authentication_packets_ > *limit) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # If the total number of received packets that fail authentication
        // # within the connection, across all keys, exceeds the integrity
        // # limit for the selected AEAD, the endpoint MUST immediately close
        // # the connection with a connection error of type AEAD_LIMIT_REACHED
        // # and not process any more packets.
        queue_transport_close_for_error(now, aead_limit_reached_error());
        return false;
    }
    return true;
}

void QuicConnection::note_peer_progress() {
    consecutive_nonproductive_packets_ = 0;
    if (inbound_progress_generation_ < std::numeric_limits<std::uint64_t>::max()) {
        ++inbound_progress_generation_;
    }
}

std::uint64_t QuicConnection::inbound_progress_generation() const {
    return inbound_progress_generation_;
}

bool QuicConnection::note_nonproductive_packet() {
    if (consecutive_nonproductive_packets_ < std::numeric_limits<std::uint64_t>::max()) {
        ++consecutive_nonproductive_packets_;
    }
    if (consecutive_nonproductive_packets_ <= kMaxConsecutiveNonproductivePackets) {
        return true;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.9
    // # While there are legitimate uses for all messages, implementations
    // # SHOULD track cost of processing relative to progress and treat
    // # excessive quantities of any non-productive packets as indicative of an
    // # attack.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.9
    // # Endpoints MAY respond to this condition with a connection
    // # error or by dropping packets.
    return true;
}

bool QuicConnection::note_packet_productivity(std::uint64_t previous_progress_generation,
                                              QuicCoreTimePoint now) {
    if (inbound_progress_generation_ != previous_progress_generation) {
        consecutive_nonproductive_packets_ = 0;
        return true;
    }
    (void)now;
    return note_nonproductive_packet();
}

bool QuicConnection::non_paced_burst_allows_send(bool ack_eliciting, bool bypass_congestion_window,
                                                 std::optional<bool> pacing_controlled) const {
    //= https://www.rfc-editor.org/rfc/rfc9002#section-7.5
    // # Probe packets MUST NOT be blocked by the congestion controller.
    if (!ack_eliciting || bypass_congestion_window) {
        return true;
    }
    const bool has_pacing = pacing_controlled.has_value()
                                ? *pacing_controlled
                                : congestion_controller_.next_send_time(/*bytes=*/1).has_value();
    if (has_pacing) {
        return true;
    }

    return unpaced_ack_eliciting_burst_packets_ < kMaxUnpacedBurstPackets;
}

void QuicConnection::note_burst_limited_ack_eliciting_send(std::size_t packet_count,
                                                           bool bypass_congestion_window,
                                                           std::optional<bool> pacing_controlled) {
    if (packet_count == 0 || bypass_congestion_window) {
        return;
    }
    const bool has_pacing = pacing_controlled.has_value()
                                ? *pacing_controlled
                                : congestion_controller_.next_send_time(/*bytes=*/1).has_value();
    if (has_pacing) {
        return;
    }

    unpaced_ack_eliciting_burst_packets_ += packet_count;
}

void QuicConnection::reset_unpaced_ack_eliciting_burst() {
    unpaced_ack_eliciting_burst_packets_ = 0;
}

void QuicConnection::mark_failed() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (!pending_terminal_state_.has_value()) {
        pending_terminal_state_ = QuicConnectionTerminalState::failed;
    }
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::mark_silent_close() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (!pending_terminal_state_.has_value()) {
        pending_terminal_state_ = QuicConnectionTerminalState::closed;
    }
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
}

void QuicConnection::queue_state_change(QuicCoreStateChange change) {
    if (change == QuicCoreStateChange::handshake_ready) {
        if (handshake_ready_emitted_) {
            return;
        }
        handshake_ready_emitted_ = true;
    } else if (change == QuicCoreStateChange::handshake_confirmed) {
        if (handshake_confirmed_emitted_) {
            return;
        }
        handshake_confirmed_emitted_ = true;
    } else {
        if (failed_emitted_) {
            return;
        }
        failed_emitted_ = true;
    }

    pending_state_changes_.push_back(change);
}

std::optional<TransportParametersValidationContext>
QuicConnection::peer_transport_parameters_validation_context() const {
    if (!peer_source_connection_id_.has_value()) {
        return std::nullopt;
    }

    if (config_.role == EndpointRole::client) {
        const auto expected_version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_);
        //= https://www.rfc-editor.org/rfc/rfc9368#section-4
        // # If the client received and acted on a Version Negotiation packet, the
        // # client MUST validate the server's Available Versions field.
        //= https://www.rfc-editor.org/rfc/rfc9368#section-4
        // # In particular, since the client can be made aware of the
        // # Negotiated Version by the QUIC long header version during compatible
        // # version negotiation (see Section 2.3), clients MUST validate that the
        // # server's Chosen Version is equal to the Negotiated Version; if they
        // # do not match, the client MUST close the connection with a version
        // # negotiation error.
        return TransportParametersValidationContext{
            .expected_initial_source_connection_id = peer_source_connection_id_.value(),
            .expected_original_destination_connection_id =
                config_.original_destination_connection_id.value_or(
                    config_.initial_destination_connection_id),
            .expected_retry_source_connection_id = config_.retry_source_connection_id,
            .expected_version_information = expected_version_information,
            .reacted_to_version_negotiation = config_.reacted_to_version_negotiation,
        };
    }

    const auto expected_version_information = version_information_for_handshake(
        config_.supported_versions, original_version_, config_.retry_source_connection_id,
        original_version_, current_version_);
    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = peer_source_connection_id_.value(),
        .expected_original_destination_connection_id = std::nullopt,
        .expected_retry_source_connection_id = std::nullopt,
        .expected_version_information = expected_version_information,
    };
}

void QuicConnection::initialize_local_flow_control() {
    connection_flow_control_ = ConnectionFlowControlState{
        .local_receive_window = local_transport_parameters_.initial_max_data,
        .advertised_max_data = local_transport_parameters_.initial_max_data,
    };
    local_stream_limit_state_.initialize(PeerStreamOpenLimits{
        .bidirectional = local_transport_parameters_.initial_max_streams_bidi,
        .unidirectional = local_transport_parameters_.initial_max_streams_uni,
    });
}

void QuicConnection::initialize_peer_flow_control_from_transport_parameters() {
    if (!peer_transport_parameters_.has_value()) {
        return;
    }

    connection_flow_control_.note_peer_max_data(peer_transport_parameters_->initial_max_data);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::bidirectional,
                                              peer_transport_parameters_->initial_max_streams_bidi);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::unidirectional,
                                              peer_transport_parameters_->initial_max_streams_uni);

    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
        stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
        if ((stream.receive_flow_control_limit == 0) &
            (stream.flow_control.local_receive_window == 0) &
            (stream.flow_control.advertised_max_stream_data ==
             std::numeric_limits<std::uint64_t>::max())) {
            stream.flow_control.local_receive_window =
                initial_stream_receive_window(stream.stream_id);
            stream.flow_control.advertised_max_stream_data =
                stream.flow_control.local_receive_window;
            stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
        }
    }
    refresh_stream_sendable_byte_caches();
}

std::uint64_t QuicConnection::initial_stream_send_limit(std::uint64_t stream_id) const {
    if (!peer_transport_parameters_.has_value()) {
        return 0;
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return peer_transport_parameters_->initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return peer_transport_parameters_->initial_max_stream_data_bidi_remote;
    }

    return peer_transport_parameters_->initial_max_stream_data_bidi_local;
}

std::uint64_t QuicConnection::initial_stream_receive_window(std::uint64_t stream_id) const {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return local_transport_parameters_.initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return local_transport_parameters_.initial_max_stream_data_bidi_local;
    }

    return local_transport_parameters_.initial_max_stream_data_bidi_remote;
}

void QuicConnection::initialize_stream_flow_control(StreamState &stream) const {
    stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
    stream.flow_control.local_receive_window = initial_stream_receive_window(stream.stream_id);
    stream.flow_control.advertised_max_stream_data = stream.flow_control.local_receive_window;
    stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
    stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
}

void QuicConnection::invalidate_active_stream_lookup_cache() const {
    active_stream_lookup_cache_.valid = false;
}

StreamState *QuicConnection::find_active_stream_state(std::uint64_t stream_id) {
    if (active_stream_lookup_cache_.valid && active_stream_lookup_cache_.stream_id == stream_id) {
        return &active_stream_lookup_cache_.stream->second;
    }
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
        active_stream_lookup_cache_.valid = true;
        active_stream_lookup_cache_.stream_id = stream_id;
        active_stream_lookup_cache_.stream = it;
        return &it->second;
    }
    return nullptr;
}

StreamState *QuicConnection::find_retired_stream_state(std::uint64_t stream_id) {
    if (!largest_retired_stream_id_.has_value() || stream_id <= *largest_retired_stream_id_) {
        if (auto it = retired_streams_.find(stream_id); it != retired_streams_.end()) {
            return &it->second;
        }
    }
    if (const auto *range = find_retired_compact_stream_range(stream_id); range != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        retired_peer_stream_lookup_scratch_ = make_retired_peer_stream_state(stream_id, *range);
        return &retired_peer_stream_lookup_scratch_;
    }
    return nullptr;
}

StreamState *QuicConnection::find_stream_state(std::uint64_t stream_id) {
    if (auto *stream = find_active_stream_state(stream_id); stream != nullptr) {
        return stream;
    }
    return find_retired_stream_state(stream_id);
}

const StreamState *QuicConnection::find_stream_state(std::uint64_t stream_id) const {
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
        return &it->second;
    }
    if (!largest_retired_stream_id_.has_value() || stream_id <= *largest_retired_stream_id_) {
        if (auto it = retired_streams_.find(stream_id); it != retired_streams_.end()) {
            return &it->second;
        }
    }
    if (const auto *range = find_retired_compact_stream_range(stream_id); range != nullptr) {
        retired_peer_stream_lookup_scratch_ = make_retired_peer_stream_state(stream_id, *range);
        return &retired_peer_stream_lookup_scratch_;
    }
    return nullptr;
}

std::map<std::uint64_t, QuicConnection::RetiredPeerStreamRange> &
QuicConnection::retired_peer_stream_ranges(StreamDirection direction) {
    return direction == StreamDirection::bidirectional ? retired_peer_bidi_stream_ranges_
                                                       : retired_peer_uni_stream_ranges_;
}

const std::map<std::uint64_t, QuicConnection::RetiredPeerStreamRange> &
QuicConnection::retired_peer_stream_ranges(StreamDirection direction) const {
    return direction == StreamDirection::bidirectional ? retired_peer_bidi_stream_ranges_
                                                       : retired_peer_uni_stream_ranges_;
}

std::map<std::uint64_t, QuicConnection::RetiredPeerStreamRange> &
QuicConnection::retired_local_stream_ranges(StreamDirection direction) {
    return direction == StreamDirection::bidirectional ? retired_local_bidi_stream_ranges_
                                                       : retired_local_uni_stream_ranges_;
}

const std::map<std::uint64_t, QuicConnection::RetiredPeerStreamRange> &
QuicConnection::retired_local_stream_ranges(StreamDirection direction) const {
    return direction == StreamDirection::bidirectional ? retired_local_bidi_stream_ranges_
                                                       : retired_local_uni_stream_ranges_;
}

QuicConnection::RetiredPeerStreamRange *
QuicConnection::find_retired_peer_stream_range(std::uint64_t stream_id) {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (id_info.initiator != StreamInitiator::peer) {
        return nullptr;
    }
    auto &ranges = retired_peer_stream_ranges(id_info.direction);
    const auto stream_index = stream_id >> 2u;
    auto after = ranges.upper_bound(stream_index);
    if (after == ranges.begin()) {
        return nullptr;
    }
    auto candidate = std::prev(after);
    return stream_index <= candidate->second.last_index ? &candidate->second : nullptr;
}

const QuicConnection::RetiredPeerStreamRange *
QuicConnection::find_retired_peer_stream_range(std::uint64_t stream_id) const {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (id_info.initiator != StreamInitiator::peer) {
        return nullptr;
    }
    const auto &ranges = retired_peer_stream_ranges(id_info.direction);
    const auto stream_index = stream_id >> 2u;
    auto after = ranges.upper_bound(stream_index);
    if (after == ranges.begin()) {
        return nullptr;
    }
    auto candidate = std::prev(after);
    return stream_index <= candidate->second.last_index ? &candidate->second : nullptr;
}

QuicConnection::RetiredPeerStreamRange *
QuicConnection::find_retired_local_stream_range(std::uint64_t stream_id) {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (id_info.initiator != StreamInitiator::local) {
        return nullptr;
    }
    auto &ranges = retired_local_stream_ranges(id_info.direction);
    const auto stream_index = stream_id >> 2u;
    auto after = ranges.upper_bound(stream_index);
    if (after == ranges.begin()) {
        return nullptr;
    }
    auto candidate = std::prev(after);
    return stream_index <= candidate->second.last_index ? &candidate->second : nullptr;
}

const QuicConnection::RetiredPeerStreamRange *
QuicConnection::find_retired_local_stream_range(std::uint64_t stream_id) const {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (id_info.initiator != StreamInitiator::local) {
        return nullptr;
    }
    const auto &ranges = retired_local_stream_ranges(id_info.direction);
    const auto stream_index = stream_id >> 2u;
    auto after = ranges.upper_bound(stream_index);
    if (after == ranges.begin()) {
        return nullptr;
    }
    auto candidate = std::prev(after);
    return stream_index <= candidate->second.last_index ? &candidate->second : nullptr;
}

const QuicConnection::RetiredPeerStreamRange *
QuicConnection::find_retired_compact_stream_range(std::uint64_t stream_id) const {
    if (const auto *range = find_retired_peer_stream_range(stream_id); range != nullptr) {
        return range;
    }
    return find_retired_local_stream_range(stream_id);
}

StreamState
QuicConnection::make_retired_peer_stream_state(std::uint64_t stream_id,
                                               const RetiredPeerStreamRange &range) const {
    auto stream = make_implicit_stream_state(stream_id, config_.role);
    stream.send_closed = true;
    stream.receive_closed = true;
    stream.peer_fin_reported = true;
    stream.peer_fin_delivered = true;
    stream.peer_send_closed = true;
    stream.peer_final_size = range.receive_final_size;
    stream.receive_flow_control_consumed = range.receive_final_size;
    stream.highest_received_offset = range.receive_final_size;
    stream.flow_control.delivered_bytes = range.receive_final_size;
    stream.send_final_size = range.send_final_size;
    stream.send_flow_control_committed = range.send_final_size;
    stream.flow_control.highest_sent = range.send_final_size;
    stream.send_fin_state =
        stream.id_info.local_can_send ? StreamSendFinState::acknowledged : StreamSendFinState::none;
    stream.flow_control.peer_max_stream_data = range.peer_max_stream_data;
    stream.flow_control.local_receive_window = range.local_receive_window;
    stream.flow_control.advertised_max_stream_data = range.advertised_max_stream_data;
    stream.send_flow_control_limit = range.peer_max_stream_data;
    stream.receive_flow_control_limit = range.advertised_max_stream_data;
    stream.peer_stream_limit_released = true;
    return stream;
}

CodecResult<bool> QuicConnection::validate_retired_peer_stream_frame(
    std::uint64_t stream_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::uint64_t offset, std::size_t length, bool fin, std::uint64_t frame_type) const {
    const auto *range = find_retired_compact_stream_range(stream_id);
    if (range == nullptr) {
        return CodecResult<bool>::success(false);
    }

    if (offset > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(length)) {
        return CodecResult<bool>::failure(
            stream_state_codec_error(StreamStateErrorCode::final_size_conflict, frame_type));
    }
    const auto range_end = offset + static_cast<std::uint64_t>(length);
    if (range_end > range->receive_final_size || (fin && range_end != range->receive_final_size)) {
        return CodecResult<bool>::failure(
            stream_state_codec_error(StreamStateErrorCode::final_size_conflict, frame_type));
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::validate_retired_peer_reset_stream_frame(
    std::uint64_t stream_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::uint64_t final_size, std::uint64_t frame_type) const {
    const auto *range = find_retired_compact_stream_range(stream_id);
    if (range == nullptr) {
        return CodecResult<bool>::success(false);
    }
    if (final_size != range->receive_final_size) {
        return CodecResult<bool>::failure(
            stream_state_codec_error(StreamStateErrorCode::final_size_conflict, frame_type));
    }
    return CodecResult<bool>::success(true);
}

CodecResult<bool>
QuicConnection::commit_peer_stream_final_size_to_connection_flow_control(StreamState &stream,
                                                                         std::uint64_t frame_type) {
    if (!stream.peer_final_size.has_value()) {
        return CodecResult<bool>::success(true);
    }
    if (stream.highest_received_offset >= *stream.peer_final_size) {
        return CodecResult<bool>::success(true);
    }

    const auto final_size_delta = *stream.peer_final_size - stream.highest_received_offset;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # The receiver MUST use the final size of the stream to account for all
    // # bytes sent on the stream in its connection-level flow controller.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.9
    // # The sum of the final sizes on all streams -- including streams in
    // # terminal states -- MUST NOT exceed the value advertised by a receiver.
    if (connection_flow_control_.received_committed >
            connection_flow_control_.advertised_max_data ||
        final_size_delta > connection_flow_control_.advertised_max_data -
                               connection_flow_control_.received_committed) {
        return CodecResult<bool>::failure(flow_control_error(frame_type));
    }

    connection_flow_control_.received_committed += final_size_delta;
    stream.highest_received_offset = *stream.peer_final_size;
    stream.receive_flow_control_consumed = *stream.peer_final_size;
    return CodecResult<bool>::success(true);
}

bool QuicConnection::try_retire_stream_to_peer_range(const StreamState &stream) {
    if (stream.id_info.initiator != StreamInitiator::peer) {
        return false;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
    // # Both endpoints MUST maintain flow control state for the stream in the
    // # unterminated direction until that direction enters a terminal state.
    if (!stream.peer_fin_delivered || stream.peer_reset_received || !stream.peer_final_size ||
        !stream.send_final_size || stream.reset_state != StreamControlFrameState::none ||
        stream.stop_sending_state != StreamControlFrameState::none ||
        stream.flow_control.max_stream_data_state != StreamControlFrameState::none ||
        stream.flow_control.stream_data_blocked_state != StreamControlFrameState::none) {
        return false;
    }

    const auto stream_index = stream.stream_id >> 2u;
    RetiredPeerStreamRange merged{
        .first_index = stream_index,
        .last_index = stream_index,
        .receive_final_size = *stream.peer_final_size,
        .send_final_size = *stream.send_final_size,
        .peer_max_stream_data = stream.flow_control.peer_max_stream_data,
        .local_receive_window = stream.flow_control.local_receive_window,
        .advertised_max_stream_data = stream.flow_control.advertised_max_stream_data,
    };
    auto &ranges = retired_peer_stream_ranges(stream.id_info.direction);
    auto after = ranges.upper_bound(stream_index);
    if (after != ranges.begin()) {
        auto previous = std::prev(after);
        if (previous->second.last_index + 1 == stream_index &&
            previous->second.receive_final_size == merged.receive_final_size &&
            previous->second.send_final_size == merged.send_final_size &&
            previous->second.peer_max_stream_data == merged.peer_max_stream_data &&
            previous->second.local_receive_window == merged.local_receive_window &&
            previous->second.advertised_max_stream_data == merged.advertised_max_stream_data) {
            merged.first_index = previous->second.first_index;
            ranges.erase(previous);
        }
    }
    if (after != ranges.end() && stream_index + 1 == after->second.first_index &&
        after->second.receive_final_size == merged.receive_final_size &&
        after->second.send_final_size == merged.send_final_size &&
        after->second.peer_max_stream_data == merged.peer_max_stream_data &&
        after->second.local_receive_window == merged.local_receive_window &&
        after->second.advertised_max_stream_data == merged.advertised_max_stream_data) {
        merged.last_index = after->second.last_index;
        ranges.erase(after);
    }
    ranges.emplace(merged.first_index, merged);
    return true;
}

bool QuicConnection::try_retire_stream_to_local_range(const StreamState &stream) {
    if (stream.id_info.initiator != StreamInitiator::local) {
        return false;
    }
    if (!stream.peer_fin_delivered || stream.peer_reset_received || !stream.peer_final_size ||
        !stream.send_final_size || stream.reset_state != StreamControlFrameState::none ||
        stream.stop_sending_state != StreamControlFrameState::none ||
        stream.flow_control.max_stream_data_state != StreamControlFrameState::none ||
        stream.flow_control.stream_data_blocked_state != StreamControlFrameState::none) {
        return false;
    }

    const auto stream_index = stream.stream_id >> 2u;
    RetiredPeerStreamRange merged{
        .first_index = stream_index,
        .last_index = stream_index,
        .receive_final_size = *stream.peer_final_size,
        .send_final_size = *stream.send_final_size,
        .peer_max_stream_data = stream.flow_control.peer_max_stream_data,
        .local_receive_window = stream.flow_control.local_receive_window,
        .advertised_max_stream_data = stream.flow_control.advertised_max_stream_data,
    };
    auto &ranges = retired_local_stream_ranges(stream.id_info.direction);
    auto after = ranges.upper_bound(stream_index);
    if (after != ranges.begin()) {
        auto previous = std::prev(after);
        if (previous->second.last_index + 1 == stream_index &&
            previous->second.receive_final_size == merged.receive_final_size &&
            previous->second.send_final_size == merged.send_final_size &&
            previous->second.peer_max_stream_data == merged.peer_max_stream_data &&
            previous->second.local_receive_window == merged.local_receive_window &&
            previous->second.advertised_max_stream_data == merged.advertised_max_stream_data) {
            merged.first_index = previous->second.first_index;
            ranges.erase(previous);
        }
    }
    if (after != ranges.end() && stream_index + 1 == after->second.first_index &&
        after->second.receive_final_size == merged.receive_final_size &&
        after->second.send_final_size == merged.send_final_size &&
        after->second.peer_max_stream_data == merged.peer_max_stream_data &&
        after->second.local_receive_window == merged.local_receive_window &&
        after->second.advertised_max_stream_data == merged.advertised_max_stream_data) {
        merged.last_index = after->second.last_index;
        ranges.erase(after);
    }
    ranges.emplace(merged.first_index, merged);
    return true;
}

std::size_t QuicConnection::retired_peer_stream_count() const {
    std::size_t count = 0;
    const auto count_ranges = [&](const auto &ranges) {
        for (const auto &[first_index, range] : ranges) {
            static_cast<void>(first_index);
            count += static_cast<std::size_t>(range.last_index - range.first_index + 1);
        }
    };
    count_ranges(retired_peer_bidi_stream_ranges_);
    count_ranges(retired_peer_uni_stream_ranges_);
    return count;
}

std::size_t QuicConnection::retired_local_stream_count() const {
    std::size_t count = 0;
    const auto count_ranges = [&](const auto &ranges) {
        for (const auto &[first_index, range] : ranges) {
            static_cast<void>(first_index);
            count += static_cast<std::size_t>(range.last_index - range.first_index + 1);
        }
    };
    count_ranges(retired_local_bidi_stream_ranges_);
    count_ranges(retired_local_uni_stream_ranges_);
    return count;
}

void QuicConnection::maybe_retire_stream(std::uint64_t stream_id) {
    const auto stream = streams_.find(stream_id);
    if (stream == streams_.end()) {
        return;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
    // # Both endpoints MUST maintain flow control state for the stream in the
    // # unterminated direction until that direction enters a terminal state.
    if (!stream_receive_terminal(stream->second) || !stream_send_terminal(stream->second) ||
        stream->second.has_pending_send() || stream->second.has_outstanding_send()) {
        return;
    }
    const bool has_pending_receive_effect = std::ranges::any_of(
        pending_stream_receive_effects_,
        [&](const QuicCoreReceiveStreamData &effect) { return effect.stream_id == stream_id; });
    if (has_pending_receive_effect) {
        return;
    }
    if (last_application_send_stream_id_ == stream_id) {
        last_application_send_stream_id_.reset();
    }

    forget_active_stream_queued_bytes(stream->second);
    stream_send_priorities_.erase(stream_id);
    if (!try_retire_stream_to_peer_range(stream->second) &&
        !try_retire_stream_to_local_range(stream->second)) {
        largest_retired_stream_id_ = largest_retired_stream_id_.has_value()
                                         ? std::max(*largest_retired_stream_id_, stream_id)
                                         : stream_id;
        retired_streams_.insert_or_assign(stream_id, std::move(stream->second));
    }
    streams_.erase(stream);
    invalidate_active_stream_lookup_cache();
}

StreamState *QuicConnection::open_peer_initiated_stream_with_predecessors(std::uint64_t stream_id) {
    StreamState *target = nullptr;
    for (std::uint64_t candidate = stream_id & 0x03u; candidate <= stream_id; candidate += 4u) {
        auto *stream = find_stream_state(candidate);
        if (stream == nullptr) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
            // # Before a stream is created, all streams of the same type with lower-
            // # numbered stream IDs MUST be created.
            auto it = streams_.emplace_hint(streams_.end(), candidate,
                                            make_implicit_stream_state(candidate, config_.role));
            initialize_stream_flow_control(it->second);
            stream = &it->second;
        }
        if (candidate == stream_id) {
            target = stream;
        }
    }

    invalidate_active_stream_lookup_cache();
    return target;
}

StreamStateResult<StreamState *> QuicConnection::get_or_open_local_stream(std::uint64_t stream_id) {
    if (auto *existing = find_active_stream_state(stream_id); existing != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        return StreamStateResult<StreamState *>::success(existing);
    }
    if (auto *existing = find_retired_stream_state(stream_id); existing != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        return StreamStateResult<StreamState *>::success(existing);
    }

    if (!is_local_implicit_stream_open_allowed(stream_id, config_.role)) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        const auto code = !id_info.local_can_send ? StreamStateErrorCode::invalid_stream_direction
                                                  : StreamStateErrorCode::invalid_stream_id;
        return StreamStateResult<StreamState *>::failure(code, stream_id);
    }
    if (!stream_open_limits_.can_open_local_stream(stream_id, config_.role)) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        // # An endpoint that is unable to open a new stream due to the peer's
        // # limits SHOULD send a STREAMS_BLOCKED frame (Section 19.14).
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.14
        // # A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17)
        // # when it wishes to open a stream but is unable to do so due to the
        // # maximum stream limit set by its peer; see Section 19.11.
        stream_open_limits_.queue_streams_blocked(
            id_info.direction == StreamDirection::bidirectional ? StreamLimitType::bidirectional
                                                                : StreamLimitType::unidirectional);
        return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                         stream_id);
    }

    auto it = streams_.emplace_hint(streams_.end(), stream_id,
                                    make_implicit_stream_state(stream_id, config_.role));
    initialize_stream_flow_control(it->second);
    active_stream_lookup_cache_.valid = true;
    active_stream_lookup_cache_.stream_id = stream_id;
    active_stream_lookup_cache_.stream = it;
    return StreamStateResult<StreamState *>::success(&it->second);
}

StreamStateResult<StreamState *>
QuicConnection::get_existing_receive_stream(std::uint64_t stream_id) {
    if (auto *existing = find_active_stream_state(stream_id); existing != nullptr) {
        return StreamStateResult<StreamState *>::success(existing);
    }
    if (auto *existing = find_retired_stream_state(stream_id); existing != nullptr) {
        return StreamStateResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return StreamStateResult<StreamState *>::failure(
            StreamStateErrorCode::invalid_stream_direction, stream_id);
    }

    return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                     stream_id);
}

CodecResult<StreamState *> QuicConnection::get_or_open_receive_stream(std::uint64_t stream_id) {
    if (auto *existing = find_active_stream_state(stream_id); existing != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        return CodecResult<StreamState *>::success(existing);
    }
    if (auto *existing = find_retired_stream_state(stream_id); existing != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.8
        // # An endpoint MUST terminate the connection with error
        // # STREAM_STATE_ERROR if it receives a STREAM frame for a locally
        // # initiated stream that has not yet been created, or for a send-only
        // # stream.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.4
        // # An endpoint that receives a RESET_STREAM frame for a send-only
        // # stream MUST terminate the connection with error STREAM_STATE_ERROR.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.13
        // # An endpoint that receives a STREAM_DATA_BLOCKED frame for a
        // # send-only stream MUST terminate the connection with error
        // # STREAM_STATE_ERROR.
        return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
    }
    if (stream_id == kCompatibilityStreamId && id_info.initiator == StreamInitiator::local) {
        auto it = streams_.emplace_hint(streams_.end(), stream_id,
                                        make_implicit_stream_state(stream_id, config_.role));
        initialize_stream_flow_control(it->second);
        active_stream_lookup_cache_.valid = true;
        active_stream_lookup_cache_.stream_id = stream_id;
        active_stream_lookup_cache_.stream = it;
        return CodecResult<StreamState *>::success(&it->second);
    }
    if (id_info.initiator != StreamInitiator::peer ||
        !is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        if (id_info.initiator != StreamInitiator::peer) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-19.8
            // # An endpoint MUST terminate the connection with error
            // # STREAM_STATE_ERROR if it receives a STREAM frame for a locally
            // # initiated stream that has not yet been created, or for a send-only
            // # stream.
            return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        // # An endpoint that receives a frame with a stream ID exceeding the
        // # limit it has sent MUST treat this as a connection error of type
        // # STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
        // # An endpoint MUST terminate a connection with an error of type
        // # STREAM_LIMIT_ERROR if a peer opens more streams than was permitted.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
        // # A server SHOULD treat a violation of remembered limits
        // # (Section 7.4.1) as a connection error of an appropriate type (for
        // # instance, a FLOW_CONTROL_ERROR for exceeding stream data limits).
        return CodecResult<StreamState *>::failure(stream_limit_error(/*frame_type=*/0));
    }

    auto *stream = open_peer_initiated_stream_with_predecessors(stream_id);
    return CodecResult<StreamState *>::success(stream);
}

CodecResult<StreamState *> QuicConnection::get_or_open_send_stream(std::uint64_t stream_id) {
    if (auto *existing = find_active_stream_state(stream_id); existing != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        return CodecResult<StreamState *>::success(existing);
    }
    if (auto *existing = find_retired_stream_state(stream_id); existing != nullptr) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
        // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
    }

    if (id_info.initiator == StreamInitiator::local) {
        const auto local_stream = get_or_open_local_stream(stream_id);
        if (!local_stream.has_value()) {
            return CodecResult<StreamState *>::failure(
                stream_state_codec_error(local_stream.error(), /*frame_type=*/0));
        }
        return CodecResult<StreamState *>::success(local_stream.value());
    }

    if (!is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        return CodecResult<StreamState *>::failure(stream_limit_error(/*frame_type=*/0));
    }

    auto *stream = open_peer_initiated_stream_with_predecessors(stream_id);
    return CodecResult<StreamState *>::success(stream);
}

CodecResult<StreamState *>
QuicConnection::get_existing_send_stream_for_peer_control(std::uint64_t stream_id) {
    if (auto *existing = find_active_stream_state(stream_id); existing != nullptr) {
        return CodecResult<StreamState *>::success(existing);
    }
    if (auto *existing = find_retired_stream_state(stream_id); existing != nullptr) {
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.5
        // # An endpoint that receives a STOP_SENDING frame for a receive-only
        // # stream MUST terminate the connection with error STREAM_STATE_ERROR.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        // # An endpoint that receives a MAX_STREAM_DATA frame for a
        // # receive-only stream MUST terminate the connection with error
        // # STREAM_STATE_ERROR.
        return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
    }

    if (id_info.initiator == StreamInitiator::local) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.5
        // # Receiving a STOP_SENDING frame for a locally initiated stream
        // # that has not yet been created MUST be treated as a connection
        // # error of type STREAM_STATE_ERROR.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        // # Receiving a MAX_STREAM_DATA frame for a locally initiated
        // # stream that has not yet been created MUST be treated as a
        // # connection error of type STREAM_STATE_ERROR.
        return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
    }

    return get_or_open_send_stream(stream_id);
}

PeerStreamOpenLimits QuicConnection::peer_stream_open_limits() const {
    return PeerStreamOpenLimits{
        .bidirectional = local_stream_limit_state_.advertised_max_streams_bidi == 0
                             ? (local_transport_parameters_.initial_max_streams_bidi == 0
                                    ? config_.transport.initial_max_streams_bidi
                                    : local_transport_parameters_.initial_max_streams_bidi)
                             : local_stream_limit_state_.advertised_max_streams_bidi,
        .unidirectional = local_stream_limit_state_.advertised_max_streams_uni == 0
                              ? (local_transport_parameters_.initial_max_streams_uni == 0
                                     ? config_.transport.initial_max_streams_uni
                                     : local_transport_parameters_.initial_max_streams_uni)
                              : local_stream_limit_state_.advertised_max_streams_uni,
    };
}

bool QuicConnection::has_pending_application_send() const {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return false;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        return closing_close_packet_can_send(closing_close_packet_pending_,
                                             can_send_connection_close_frame());
    }

    if (current_send_path_id_.has_value()) {
        if (const auto path = paths_.find(*current_send_path_id_); path != paths_.end()) {
            if (!path->second.mtu.viable) {
                return false;
            }
        }
    }

    for (const auto &[path_id, path] : paths_) {
        static_cast<void>(path_id);
        if (path.pending_response.has_value() || path.challenge_pending) {
            if (path.mtu.viable) {
                return true;
            }
        }
    }

    if (pending_application_close_.has_value()) {
        return true;
    }

    if (!pending_new_token_frames_.empty()) {
        return true;
    }

    if (handshake_done_state_ == StreamControlFrameState::pending) {
        return true;
    }

    if (connection_flow_control_.max_data_state == StreamControlFrameState::pending ||
        connection_flow_control_.data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }
    if (local_stream_limit_state_.max_streams_bidi_state == StreamControlFrameState::pending ||
        local_stream_limit_state_.max_streams_uni_state == StreamControlFrameState::pending) {
        return true;
    }
    if (stream_open_limits_.streams_blocked_bidi_state == StreamControlFrameState::pending ||
        stream_open_limits_.streams_blocked_uni_state == StreamControlFrameState::pending) {
        return true;
    }

    if (!pending_datagram_send_queue_.empty()) {
        return true;
    }

    const auto connection_send_credit = saturating_subtract(connection_flow_control_.peer_max_data,
                                                            connection_flow_control_.highest_sent);
    if (connection_send_credit != 0 &&
        (cached_fresh_sendable_stream_bytes() != 0 || streams_have_sendable_data())) {
        return true;
    }

    if (streams_have_pending_application_control_send()) {
        return true;
    }

    if (has_lost_application_stream_data() || streams_have_sendable_fin()) {
        return true;
    }

    return false;
}

bool QuicConnection::has_pending_congestion_controlled_send() const {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return false;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        return closing_close_packet_can_send(closing_close_packet_pending_,
                                             can_send_connection_close_frame());
    }

    if (!initial_packet_space_discarded_ && (initial_space_.send_crypto.has_pending_data() ||
                                             initial_space_.pending_probe_packet.has_value())) {
        return true;
    }

    if (!handshake_packet_space_discarded_ && handshake_space_.write_secret.has_value() &&
        (handshake_space_.send_crypto.has_pending_data() ||
         handshake_space_.pending_probe_packet.has_value())) {
        return true;
    }

    const bool can_send_application_packets =
        application_space_.write_secret.has_value() ||
        ((config_.role == EndpointRole::client) && (status_ != HandshakeStatus::connected) &&
         zero_rtt_space_.write_secret.has_value());
    if (!can_send_application_packets) {
        return false;
    }

    return has_pending_application_send() || application_space_.pending_probe_packet.has_value() ||
           !pending_new_connection_id_frames_.empty() ||
           !pending_retire_connection_id_frames_.empty() ||
           application_space_.send_crypto.has_pending_data();
}

bool QuicConnection::has_pending_fresh_application_stream_send() const {
    const auto connection_send_credit = saturating_subtract(connection_flow_control_.peer_max_data,
                                                            connection_flow_control_.highest_sent);
    if (connection_send_credit != 0 &&
        (cached_fresh_sendable_stream_bytes() != 0 || streams_have_sendable_data())) {
        return true;
    }

    return streams_have_sendable_fin();
}

bool QuicConnection::has_pending_application_control_send(bool application_ack_due) const {
    if (application_ack_due || application_space_.pending_probe_packet.has_value() ||
        application_space_.send_crypto.has_pending_data() ||
        pending_application_close_.has_value() || !pending_new_token_frames_.empty() ||
        !pending_new_connection_id_frames_.empty() ||
        !pending_retire_connection_id_frames_.empty() ||
        (handshake_done_state_ == StreamControlFrameState::pending) ||
        (connection_flow_control_.max_data_state == StreamControlFrameState::pending) ||
        (connection_flow_control_.data_blocked_state == StreamControlFrameState::pending) ||
        (local_stream_limit_state_.max_streams_bidi_state == StreamControlFrameState::pending) ||
        (local_stream_limit_state_.max_streams_uni_state == StreamControlFrameState::pending) ||
        (stream_open_limits_.streams_blocked_bidi_state == StreamControlFrameState::pending) ||
        (stream_open_limits_.streams_blocked_uni_state == StreamControlFrameState::pending)) {
        return true;
    }

    for (const auto &[path_id, path] : paths_) {
        static_cast<void>(path_id);
        if ((path.pending_response.has_value() || path.challenge_pending) && path.mtu.viable) {
            return true;
        }
    }

    return streams_have_pending_application_control_send();
}

bool QuicConnection::streams_have_pending_application_control_send() const {
    refresh_stream_sendability_cache();
    return stream_sendability_cache_.has_pending_control;
}

bool QuicConnection::streams_have_sendable_fin() const {
    refresh_stream_sendability_cache();
    return stream_sendability_cache_.has_sendable_fin;
}

bool QuicConnection::streams_have_sendable_data() const {
    refresh_stream_sendability_cache();
    return stream_sendability_cache_.has_sendable_data;
}

void QuicConnection::invalidate_stream_sendability_cache() const {
    stream_sendability_cache_.valid = false;
}

void QuicConnection::refresh_stream_sendability_cache() const {
    if (stream_sendability_cache_.valid) {
        return;
    }

    StreamSendabilityCache cache;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        if ((stream.reset_state == StreamControlFrameState::pending) |
            (stream.stop_sending_state == StreamControlFrameState::pending) |
            (stream.flow_control.max_stream_data_state == StreamControlFrameState::pending) |
            (stream.flow_control.stream_data_blocked_state == StreamControlFrameState::pending)) {
            cache.has_pending_control = true;
        }
        if (stream.reset_state == StreamControlFrameState::none && stream_fin_sendable(stream)) {
            cache.has_sendable_fin = true;
        }
        if (stream.reset_state == StreamControlFrameState::none && stream.sendable_bytes() != 0) {
            cache.has_sendable_data = true;
        }
        if (cache.has_pending_control && cache.has_sendable_data && cache.has_sendable_fin) {
            break;
        }
    }

    cache.valid = true;
    stream_sendability_cache_ = cache;
}

std::optional<std::size_t> QuicConnection::minimum_pending_application_stream_wire_bytes() const {
    const auto connection_send_credit = saturating_subtract(connection_flow_control_.peer_max_data,
                                                            connection_flow_control_.highest_sent);
    std::optional<std::size_t> minimum_wire_bytes;
    for (const auto &[stream_id, stream] : streams_) {
        if (stream.reset_state != StreamControlFrameState::none) {
            continue;
        }

        if (stream.send_buffer.has_lost_data() ||
            ((connection_send_credit != 0) && (stream.sendable_bytes() != 0))) {
            remember_minimum_wire_size(
                minimum_wire_bytes,
                stream_frame_header_wire_size(stream_id, stream.flow_control.highest_sent, 1) +
                    std::size_t{1});
        }
        const auto send_final_size = stream.send_final_size;
        if (send_final_size.has_value() && stream_fin_sendable(stream)) {
            remember_minimum_wire_size(
                minimum_wire_bytes, stream_frame_header_wire_size(stream_id, *send_final_size, 0));
        }
    }

    return minimum_wire_bytes;
}

std::optional<std::size_t>
QuicConnection::minimum_pending_application_stream_datagram_bytes() const {
    const auto minimum_wire_bytes = minimum_pending_application_stream_wire_bytes();
    if (!minimum_wire_bytes.has_value()) {
        return std::nullopt;
    }
    const auto destination_connection_id_size = outbound_destination_connection_id().size();
    const auto max_datagram_size = outbound_datagram_size_limit();
    const auto stream_budget = application_stream_frame_budget(
        max_datagram_size, destination_connection_id_size,
        packet_number_length_for_send(application_space_,
                                      application_space_.next_send_packet_number));
    if (*minimum_wire_bytes > stream_budget) {
        return std::nullopt;
    }
    return *minimum_wire_bytes + (max_datagram_size - stream_budget);
}

std::optional<std::size_t> QuicConnection::minimum_pending_application_datagram_wire_bytes() const {
    auto minimum_wire_bytes = minimum_pending_application_stream_wire_bytes();
    if (!pending_datagram_send_queue_.empty()) {
        for (const auto &pending_datagram : pending_datagram_send_queue_) {
            remember_minimum_wire_size(
                minimum_wire_bytes,
                datagram_frame_wire_size(pending_datagram.bytes.size(), /*has_length=*/true));
        }
    }
    return minimum_wire_bytes;
}

std::optional<std::size_t>
QuicConnection::minimum_pending_application_datagram_datagram_bytes() const {
    const auto minimum_wire_bytes = minimum_pending_application_datagram_wire_bytes();
    if (!minimum_wire_bytes.has_value()) {
        return std::nullopt;
    }
    const auto destination_connection_id_size = outbound_destination_connection_id().size();
    const auto max_datagram_size = outbound_datagram_size_limit();
    const auto stream_budget = application_stream_frame_budget(
        max_datagram_size, destination_connection_id_size,
        packet_number_length_for_send(application_space_,
                                      application_space_.next_send_packet_number));
    if (*minimum_wire_bytes > stream_budget) {
        return std::nullopt;
    }
    return *minimum_wire_bytes + (max_datagram_size - stream_budget);
}

std::optional<std::size_t> QuicConnection::application_stream_pacing_deadline_bytes() const {
    return application_stream_pacing_deadline_bytes(
        minimum_pending_application_datagram_datagram_bytes());
}

std::optional<std::size_t> QuicConnection::application_stream_pacing_deadline_bytes(
    std::optional<std::size_t> minimum_datagram_bytes) const {
    if (!minimum_datagram_bytes.has_value()) {
        return std::nullopt;
    }

    const auto max_datagram_size = outbound_datagram_size_limit();
    if (max_datagram_size == 0) {
        return std::nullopt;
    }

    const auto congestion_window = congestion_controller_.send_window();
    const auto bytes_in_flight = congestion_controller_.bytes_in_flight();
    if (bytes_in_flight >= congestion_window) {
        return std::nullopt;
    }
    const auto congestion_window_available = congestion_window - bytes_in_flight;
    if (congestion_window_available < *minimum_datagram_bytes) {
        return std::nullopt;
    }
    const auto congestion_limited_datagram_size =
        std::min(max_datagram_size, congestion_window_available);
    if (congestion_limited_datagram_size < max_datagram_size) {
        return congestion_limited_datagram_size;
    }

    const auto send_quantum = congestion_controller_.pacing_send_quantum();
    auto deadline_bytes =
        std::max(max_datagram_size, std::min(send_quantum, congestion_window_available));
    if (deadline_bytes == max_datagram_size) {
        return deadline_bytes;
    }

    const auto destination_connection_id_size = outbound_destination_connection_id().size();
    auto stream_budget = application_stream_frame_budget(
        max_datagram_size, destination_connection_id_size,
        packet_number_length_for_send(application_space_,
                                      application_space_.next_send_packet_number));
    if (stream_budget == 0) {
        return max_datagram_size;
    }
    const auto datagrams_for_deadline =
        (deadline_bytes + max_datagram_size - std::size_t{1}) / max_datagram_size;
    auto queued_stream_payload =
        connection_flow_control_.sendable_bytes(cached_total_queued_stream_bytes());
    if (queued_stream_payload <=
        static_cast<std::uint64_t>(datagrams_for_deadline - std::size_t{1}) * stream_budget) {
        return max_datagram_size;
    }

    return deadline_bytes;
}

std::uint64_t QuicConnection::total_queued_stream_bytes() const {
    std::uint64_t total = 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        total += stream.send_flow_control_committed;
    }

    return total;
}

std::uint64_t QuicConnection::cached_total_queued_stream_bytes() const {
    return active_queued_stream_bytes_;
}

std::uint64_t QuicConnection::fresh_sendable_stream_bytes() const {
    std::uint64_t total = 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        total = saturating_add(total, fresh_sendable_bytes_for_cache(stream));
    }
    return total;
}

std::uint64_t QuicConnection::cached_fresh_sendable_stream_bytes() const {
    return fresh_sendable_stream_bytes_;
}

std::uint64_t QuicConnection::streams_with_lost_send_data() const {
    std::uint64_t total = 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        if (stream.reset_state == StreamControlFrameState::none &&
            stream.send_buffer.has_lost_data()) {
            ++total;
        }
    }
    return total;
}

bool QuicConnection::has_lost_application_stream_data() const {
    return streams_with_lost_send_data_ != 0;
}

void QuicConnection::refresh_active_queued_stream_bytes() {
    active_queued_stream_bytes_ = total_queued_stream_bytes();
}

void QuicConnection::refresh_fresh_sendable_stream_bytes() {
    fresh_sendable_stream_bytes_ = fresh_sendable_stream_bytes();
}

void QuicConnection::refresh_stream_lost_send_data_count() {
    streams_with_lost_send_data_ = streams_with_lost_send_data();
}

void QuicConnection::refresh_stream_sendable_byte_caches() {
    refresh_active_queued_stream_bytes();
    refresh_fresh_sendable_stream_bytes();
    refresh_stream_lost_send_data_count();
    invalidate_stream_sendability_cache();
}

void QuicConnection::note_stream_send_bytes_queued(std::size_t bytes) {
    const auto increment = static_cast<std::uint64_t>(bytes);
    active_queued_stream_bytes_ =
        increment > std::numeric_limits<std::uint64_t>::max() - active_queued_stream_bytes_
            ? std::numeric_limits<std::uint64_t>::max()
            : active_queued_stream_bytes_ + increment;
}

void QuicConnection::note_stream_fresh_sendable_bytes_delta(std::uint64_t before,
                                                            std::uint64_t after) {
    if (after >= before) {
        const auto increment = after - before;
        fresh_sendable_stream_bytes_ =
            increment > std::numeric_limits<std::uint64_t>::max() - fresh_sendable_stream_bytes_
                ? std::numeric_limits<std::uint64_t>::max()
                : fresh_sendable_stream_bytes_ + increment;
        return;
    }

    const auto decrement = before - after;
    fresh_sendable_stream_bytes_ =
        decrement > fresh_sendable_stream_bytes_ ? 0 : fresh_sendable_stream_bytes_ - decrement;
}

void QuicConnection::note_stream_lost_send_data_changed(bool previous_has_lost_send_data,
                                                        const StreamState &stream) {
    const auto current_has_lost_send_data =
        stream.reset_state == StreamControlFrameState::none && stream.send_buffer.has_lost_data();
    if (previous_has_lost_send_data == current_has_lost_send_data) {
        return;
    }

    if (current_has_lost_send_data) {
        ++streams_with_lost_send_data_;
        return;
    }

    if (streams_with_lost_send_data_ != 0) {
        --streams_with_lost_send_data_;
    }
}

void QuicConnection::note_stream_send_state_changed(std::uint64_t previous_fresh_sendable_bytes,
                                                    const StreamState &stream) {
    const auto current_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream);
    note_stream_fresh_sendable_bytes_delta(previous_fresh_sendable_bytes,
                                           current_fresh_sendable_bytes);
    invalidate_stream_sendability_cache();
}

void QuicConnection::note_stream_send_state_changed(std::uint64_t previous_fresh_sendable_bytes,
                                                    bool previous_has_lost_send_data,
                                                    const StreamState &stream) {
    note_stream_send_state_changed(previous_fresh_sendable_bytes, stream);
    note_stream_lost_send_data_changed(previous_has_lost_send_data, stream);
}

void QuicConnection::forget_active_stream_queued_bytes(const StreamState &stream) {
    active_queued_stream_bytes_ =
        stream.send_flow_control_committed > active_queued_stream_bytes_
            ? 0
            : active_queued_stream_bytes_ - stream.send_flow_control_committed;
    note_stream_fresh_sendable_bytes_delta(fresh_sendable_bytes_for_cache(stream), 0);
    note_stream_lost_send_data_changed(stream.reset_state == StreamControlFrameState::none &&
                                           stream.send_buffer.has_lost_data(),
                                       StreamState{});
    invalidate_stream_sendability_cache();
}

void QuicConnection::maybe_queue_connection_blocked_frame() {
    const auto queued_bytes = cached_total_queued_stream_bytes();
    const bool should_skip_queue =
        !connection_flow_control_.should_send_data_blocked(queued_bytes) ||
        (connection_flow_control_.sendable_bytes(queued_bytes) != 0);
    if (should_skip_queue) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.12
    // # A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes
    // # to send data but is unable to do so due to connection-level flow
    // # control; see Section 4.
    connection_flow_control_.queue_data_blocked(connection_flow_control_.peer_max_data);
}

void QuicConnection::maybe_queue_stream_blocked_frame(StreamState &stream) {
    if (stream.sendable_bytes() != 0) {
        return;
    }

    stream.queue_stream_data_blocked();
    invalidate_stream_sendability_cache();
}

void QuicConnection::maybe_refresh_connection_receive_credit(bool force) {
    // Connection-level flow control counts STREAM bytes that have been received, even when a
    // stream gap prevents immediate application delivery.
    const auto connection_receive_credit_basis = std::max(
        connection_flow_control_.delivered_bytes, connection_flow_control_.received_committed);
    if (!should_refresh_receive_window(connection_receive_credit_basis,
                                       connection_flow_control_.advertised_max_data,
                                       connection_flow_control_.local_receive_window, force)) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.2
    // # To avoid blocking a sender, a receiver MAY send a MAX_STREAM_DATA or
    // # MAX_DATA frame multiple times within a round trip or send it early
    // # enough to allow time for loss of the frame and subsequent recovery.
    connection_flow_control_.queue_max_data(connection_receive_credit_basis +
                                            connection_flow_control_.local_receive_window);
}

void QuicConnection::maybe_refresh_stream_receive_credit(StreamState &stream, bool force) {
    if (!should_refresh_receive_window(stream.flow_control.delivered_bytes,
                                       stream.flow_control.advertised_max_stream_data,
                                       stream.flow_control.local_receive_window, force)) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.2
    // # To avoid blocking a sender, a receiver MAY send a MAX_STREAM_DATA or
    // # MAX_DATA frame multiple times within a round trip or send it early
    // # enough to allow time for loss of the frame and subsequent recovery.
    stream.queue_max_stream_data(stream.flow_control.delivered_bytes +
                                 stream.flow_control.local_receive_window);
    invalidate_stream_sendability_cache();
}

void QuicConnection::maybe_refresh_peer_stream_limit(StreamState &stream) {
    if (stream.peer_stream_limit_released) {
        return;
    }
    if (stream.id_info.initiator != StreamInitiator::peer) {
        return;
    }
    if (!stream_receive_terminal(stream)) {
        return;
    }

    // Stream open credit limits the peer's send side.  A peer-initiated
    // stream releases that receive capacity once the peer's side is terminal,
    // even if our response side of a bidirectional stream is still active.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # An endpoint MUST NOT wait to receive this signal before advertising
    // # additional credit, since doing so will mean that the peer will be
    // # blocked for at least an entire round trip, and potentially
    // # indefinitely if the peer chooses not to send STREAMS_BLOCKED frames.
    stream.peer_stream_limit_released = true;

    const auto direction_index =
        static_cast<std::size_t>(stream.id_info.direction == StreamDirection::unidirectional);
    constexpr std::array limit_types = {
        StreamLimitType::bidirectional,
        StreamLimitType::unidirectional,
    };
    std::array initial_stream_windows = {
        local_transport_parameters_.initial_max_streams_bidi,
        local_transport_parameters_.initial_max_streams_uni,
    };
    auto released_stream_count = (stream.stream_id >> 2u) + 1u;
    auto initial_stream_window =
        std::max<std::uint64_t>(initial_stream_windows[direction_index], 1u);
    auto stream_limit_value =
        released_stream_count > std::numeric_limits<std::uint64_t>::max() - initial_stream_window
            ? std::numeric_limits<std::uint64_t>::max()
            : released_stream_count + initial_stream_window;
    local_stream_limit_state_.queue_max_streams(limit_types[direction_index], stream_limit_value);
}

bool QuicConnection::is_probing_only(std::span<const Frame> frames) const {
    return is_probing_only_frames(frames);
}

bool QuicConnection::can_initiate_path_validation(QuicPathId path_id) const {
    if (const auto path = paths_.find(path_id); path != paths_.end()) {
        if (path->second.destination_connection_id_override.has_value()) {
            return true;
        }
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint that initiates migration and requires non-zero-length
    // # connection IDs SHOULD ensure that the pool of connection IDs available
    // # to its peer allows the peer to use a new connection ID on migration,
    // # as the peer will be unable to respond if the pool is exhausted.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
    // # An endpoint SHOULD NOT initiate migration with a peer that has
    // # requested a zero-length connection ID, because traffic over the new
    // # path might be trivially linkable to traffic over the old one.
    return select_peer_connection_id_sequence_for_path(path_id).has_value();
}

void QuicConnection::retire_peer_connection_id_for_inactive_path(QuicPathId old_path_id,
                                                                 QuicPathId new_path_id) {
    if (old_path_id == new_path_id) {
        return;
    }
    const auto old_path = paths_.find(old_path_id);
    if (old_path == paths_.end()) {
        return;
    }
    const auto sequence_number = old_path->second.peer_connection_id_sequence;
    const auto new_path = paths_.find(new_path_id);
    if (new_path != paths_.end() &&
        new_path->second.peer_connection_id_sequence == sequence_number) {
        return;
    }
    const auto used_by_other_path = std::ranges::any_of(paths_, [&](const auto &entry) {
        return entry.first != old_path_id && entry.first != new_path_id &&
               entry.second.peer_connection_id_sequence == sequence_number;
    });
    if (used_by_other_path) {
        return;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # Endpoints SHOULD retire connection IDs when they are no longer actively
    // # using either the local or destination address for which the connection ID
    // # was used.
    queue_peer_connection_id_retirement(sequence_number);
}

bool QuicConnection::should_keep_current_send_path_for_inbound_non_probing(
    QuicPathId inbound_path_id, std::optional<std::uint64_t> packet_number) const {
    if (!current_send_path_id_.has_value() || inbound_path_id == *current_send_path_id_) {
        return false;
    }

    const auto *current = find_path_state(paths_, current_send_path_id_);
    const auto *inbound = find_path_state(paths_, inbound_path_id);
    if (current != nullptr && current->preferred_address_path &&
        current->validation_initiated_locally && current->outstanding_challenge.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.2
        // # A client that migrates to a preferred address MUST validate the
        // # address it chooses before migrating; see Section 21.5.3.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
        // # As soon as path validation succeeds, the client SHOULD begin sending
        // # all future packets to the new server address using the new connection
        // # ID and discontinue use of the old server address.
        return true;
    }
    if (current != nullptr && current->validated && packet_number.has_value() &&
        current->largest_inbound_application_packet_number.has_value() &&
        (path_state_is_validated(inbound)
             ? *packet_number <= *current->largest_inbound_application_packet_number
             : *packet_number < *current->largest_inbound_application_packet_number)) {
        if (path_state_is_validated(inbound)) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3
            // # An endpoint only changes the address to which it sends packets in
            // # response to the highest-numbered non-probing packet.
        }
        return true;
    }
    if (path_state_is_validating(current) && path_state_is_validated(inbound) &&
        !current->validation_initiated_locally && current->outstanding_challenge.has_value()) {
        return true;
    }
    if (path_state_is_validating(current) && path_state_is_validated(inbound) &&
        (!packet_number.has_value() ||
         !current->largest_inbound_application_packet_number.has_value() ||
         *packet_number < *current->largest_inbound_application_packet_number)) {
        return true;
    }

    return current != nullptr && current->preferred_address_path && current->validated;
}

bool QuicConnection::should_drop_inbound_packet_on_old_path_after_preferred_success(
    QuicPathId inbound_path_id, std::optional<std::uint64_t> packet_number) const {
    if (config_.role != EndpointRole::server || !current_send_path_id_.has_value() ||
        inbound_path_id == *current_send_path_id_ || !packet_number.has_value()) {
        return false;
    }

    const auto *current = find_path_state(paths_, current_send_path_id_);
    if (current == nullptr || !current->preferred_address_path || !current->validated) {
        return false;
    }

    const auto *inbound = find_path_state(paths_, inbound_path_id);
    if (inbound == nullptr || inbound->preferred_address_path ||
        !inbound->largest_inbound_application_packet_number.has_value()) {
        return false;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.2
    // # The server SHOULD drop newer packets for this connection that are
    // # received on the old IP address.
    return *packet_number > *inbound->largest_inbound_application_packet_number;
}

bool QuicConnection::should_ignore_original_address_validation_after_preferred_success(
    QuicPathId path_id) const {
    const auto *path = find_path_state(paths_, path_id);
    if (path == nullptr || path->preferred_address_path || !current_send_path_id_.has_value()) {
        return false;
    }

    const auto *current = find_path_state(paths_, current_send_path_id_);
    return current != nullptr && current->preferred_address_path && current->validated;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void QuicConnection::note_inbound_application_packet_for_path(QuicPathId path_id,
                                                              std::uint64_t packet_number) {
    auto &path = ensure_path_state(path_id);
    path.largest_inbound_application_packet_number = std::max(
        path.largest_inbound_application_packet_number.value_or(packet_number), packet_number);
}

void QuicConnection::maybe_switch_to_path(QuicPathId path_id, bool initiated_locally,
                                          QuicCoreTimePoint now) {
    if (current_send_path_id_.has_value() && current_send_path_id_ == path_id) {
        return;
    }

    const auto existing_path = paths_.find(path_id);
    if (existing_path != paths_.end() && existing_path->second.validated) {
        if (!existing_path->second.mtu.viable) {
            return;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.4
        // # Packets sent on the old path MUST NOT contribute to congestion
        // # control or RTT estimation for the new path.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.4
        // # On confirming a peer's ownership of its new address, an endpoint
        // # MUST immediately reset the congestion controller and round-trip
        // # time estimator for the new path to initial values (see Appendices
        // # A.3 and B.3 of [QUIC-RECOVERY]) unless the only change in the
        // # peer's address is its port number.
        reset_recovery_for_new_path(path_id);
        const auto old_path_id = current_send_path_id_;
        if (current_send_path_id_.has_value()) {
            previous_path_id_ = current_send_path_id_;
            if (const auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
                current->second.is_current_send_path = false;
            }
        }
        auto &path = existing_path->second;
        path.is_current_send_path = true;
        current_send_path_id_ = path_id;
        if (old_path_id.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
            // # As soon as path validation succeeds, the client SHOULD begin sending
            // # all future packets to the new server address using the new connection
            // # ID and discontinue use of the old server address.
            retire_peer_connection_id_for_inactive_path(*old_path_id, path_id);
        }
        return;
    }

    if (initiated_locally && !can_initiate_path_validation(path_id)) {
        return;
    }
    const auto old_path_id = current_send_path_id_;
    start_path_validation(path_id, initiated_locally, now);
    if (!initiated_locally && old_path_id.has_value() && *old_path_id != path_id) {
        start_path_validation_probe(*old_path_id, /*initiated_locally=*/false, now);
    }
}

bool QuicConnection::anti_amplification_applies() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        return anti_amplification_applies(pending_response_path->first);
    }
    if (peer_address_validated_ && current_send_path_id_.has_value() &&
        anti_amplification_applies(*current_send_path_id_)) {
        return true;
    }
    return config_.role == EndpointRole::server && status_ != HandshakeStatus::idle &&
           (status_ != HandshakeStatus::failed ||
            close_mode_ == QuicConnectionCloseMode::closing) &&
           //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
           // # If the client IP address has changed, the server MUST adhere to
           // # the anti-amplification limit; see Section 8.
           !peer_address_validated_;
}

bool QuicConnection::anti_amplification_applies(QuicPathId path_id) const {
    if ((config_.role != EndpointRole::server) || !paths_.contains(path_id)) {
        return false;
    }

    const auto &path = paths_.at(path_id);
    return !path.validated && ((path.anti_amplification_received_bytes != 0) ||
                               (path.anti_amplification_sent_bytes != 0));
}

std::uint64_t QuicConnection::anti_amplification_send_budget() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        return anti_amplification_send_budget(pending_response_path->first);
    }
    if (peer_address_validated_ && current_send_path_id_.has_value() &&
        anti_amplification_applies(*current_send_path_id_)) {
        return anti_amplification_send_budget(*current_send_path_id_);
    }

    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    if (anti_amplification_received_bytes_ > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # Prior to validating the client address, servers MUST NOT send more
    // # than three times as many bytes as the number of bytes they have
    // # received.
    return anti_amplification_received_bytes_ * 3u;
}

std::uint64_t QuicConnection::anti_amplification_send_budget(QuicPathId path_id) const {
    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    const auto &path = paths_.at(path_id);
    if (path.anti_amplification_received_bytes > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8
    // # Therefore, after receiving packets from an address that is not yet
    // # validated, an endpoint MUST limit the amount of data it sends to the
    // # unvalidated address to three times the amount of data received from
    // # that address.
    return path.anti_amplification_received_bytes * 3u;
}

std::uint64_t QuicConnection::anti_amplification_remaining_send_budget() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end() &&
        anti_amplification_applies(pending_response_path->first)) {
        return saturating_subtract(anti_amplification_send_budget(pending_response_path->first),
                                   pending_response_path->second.anti_amplification_sent_bytes);
    }
    if (peer_address_validated_ && current_send_path_id_.has_value() &&
        anti_amplification_applies(*current_send_path_id_)) {
        const auto &path = paths_.at(*current_send_path_id_);
        return saturating_subtract(anti_amplification_send_budget(*current_send_path_id_),
                                   path.anti_amplification_sent_bytes);
    }
    if (!anti_amplification_applies()) {
        return std::numeric_limits<std::uint64_t>::max();
    }

    return saturating_subtract(anti_amplification_send_budget(), anti_amplification_sent_bytes_);
}

std::size_t QuicConnection::outbound_datagram_size_limit(bool allow_pmtu_probe_size) const {
    auto max_datagram_size = outbound_datagram_size_limit_for_path(current_send_path_id_);

    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        max_datagram_size = outbound_datagram_size_limit_for_path(pending_response_path->first);
    }
    if (should_use_pending_pmtu_probe_size(allow_pmtu_probe_size, anti_amplification_applies(),
                                           application_space_.pending_probe_packet)) {
        return optional_ref_or_abort(application_space_.pending_probe_packet).pmtu_probe_size;
    }

    return max_datagram_size;
}

void QuicConnection::reset_recovery_for_new_path(QuicPathId path_id) {
    if (current_send_path_id_ == path_id) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.4
    // # Packets sent on the old path MUST NOT contribute to congestion control
    // # or RTT estimation for the new path.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.4
    // # On confirming a peer's ownership of its new address, an endpoint MUST
    // # immediately reset the congestion controller and round-trip time
    // # estimator for the new path to initial values (see Appendices A.3 and
    // # B.3 of [QUIC-RECOVERY]) unless the only change in the peer's address is
    // # its port number.
    congestion_controller_.reset_for_new_path();
    recovery_rtt_state_ = RecoveryRttState{};
    pto_count_ = 0;
    remaining_pto_probe_datagrams_ = 0;
    initial_space_.pending_probe_packet.reset();
    handshake_space_.pending_probe_packet.reset();
    application_space_.pending_probe_packet.reset();
}

std::size_t QuicConnection::outbound_datagram_size_ceiling() const {
    return outbound_datagram_size_ceiling_for_path(current_send_path_id_);
}

std::size_t
QuicConnection::outbound_datagram_size_ceiling_for_path(std::optional<QuicPathId> path_id) const {
    auto max_datagram_size = config_.max_outbound_datagram_size;
    if (config_.transport.pmtud_max_datagram_size != 0) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
        // # A QUIC implementation MAY be more conservative in computing the
        // # maximum datagram size to allow for unknown tunnel overheads or IP
        // # header options/extensions.
        max_datagram_size = std::min(max_datagram_size, config_.transport.pmtud_max_datagram_size);
    } else if (path_id.has_value()) {
        if (const auto path = paths_.find(*path_id);
            path != paths_.end() && path->second.mtu.default_search_ceiling != 0) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
            // # A QUIC implementation MAY be more conservative in computing
            // # the maximum datagram size to allow for unknown tunnel
            // # overheads or IP header options/extensions.
            max_datagram_size =
                std::min(max_datagram_size, path->second.mtu.default_search_ceiling);
        }
    }
    if (peer_transport_parameters_.has_value()) {
        max_datagram_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(static_cast<std::uint64_t>(max_datagram_size),
                                    peer_transport_parameters_->max_udp_payload_size));
    }
    static_cast<void>(path_id);

    return std::min(max_datagram_size, config_.max_outbound_datagram_size);
}

std::size_t
QuicConnection::outbound_datagram_size_limit_for_path(std::optional<QuicPathId> path_id) const {
    if (path_id.has_value()) {
        if (const auto path = paths_.find(*path_id);
            path != paths_.end() && !path->second.mtu.viable) {
            return 0;
        }
    }

    auto max_datagram_size = outbound_datagram_size_ceiling_for_path(path_id);
    if (!config_.transport.pmtud_enabled) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
        // # In the absence of these mechanisms, QUIC endpoints SHOULD NOT send
        // # datagrams larger than the smallest allowed maximum datagram size.
        max_datagram_size = std::min(max_datagram_size, kMinimumInitialDatagramSize);
    } else {
        const auto base = sanitize_pmtud_base(config_.transport.pmtud_base_datagram_size);
        max_datagram_size = std::min(max_datagram_size, base);
        if (path_id.has_value()) {
            if (const auto path = paths_.find(*path_id); path != paths_.end()) {
                max_datagram_size =
                    std::min(std::min(outbound_datagram_size_ceiling_for_path(path_id),
                                      path->second.mtu.probe_ceiling),
                             std::max(path->second.mtu.base_datagram_size,
                                      path->second.mtu.validated_datagram_size));
            }
        }
    }

    if (path_id.has_value() &&
        (peer_address_validated_ || close_mode_ == QuicConnectionCloseMode::closing) &&
        anti_amplification_applies(*path_id)) {
        const auto &path = paths_.at(*path_id);
        return static_cast<std::size_t>(
            std::min<std::uint64_t>(saturating_subtract(anti_amplification_send_budget(*path_id),
                                                        path.anti_amplification_sent_bytes),
                                    static_cast<std::uint64_t>(max_datagram_size)));
    }
    if (!anti_amplification_applies()) {
        return max_datagram_size;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
    // # The server MUST also limit the number of bytes it sends before
    // # validating the address of the client; see Section 8.
    return static_cast<std::size_t>(std::min<std::uint64_t>(
        anti_amplification_remaining_send_budget(), static_cast<std::uint64_t>(max_datagram_size)));
}

std::optional<std::size_t> QuicConnection::next_pmtu_probe_size(PathState &path) const {
    if (!path.mtu.enabled || !path.mtu.viable ||
        path.mtu.outstanding_probe_packet_number.has_value()) {
        return std::nullopt;
    }

    const auto ceiling = outbound_datagram_size_ceiling_for_path(path.id);
    path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, ceiling);
    if (path.mtu.validated_datagram_size >= path.mtu.probe_ceiling) {
        return std::nullopt;
    }

    auto next_probe_size =
        next_probe_size_between(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    while (should_keep_searching_for_pmtu_probe_size(path.mtu, next_probe_size)) {
        if (next_probe_size == 0) {
            return std::nullopt;
        }
        path.mtu.probe_ceiling = next_probe_size - 1;
        if (path.mtu.validated_datagram_size >= path.mtu.probe_ceiling) {
            return std::nullopt;
        }
        next_probe_size =
            next_probe_size_between(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    }
    return next_probe_size;
}

void QuicConnection::note_pmtu_probe_sent(
    QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::uint64_t packet_number, std::size_t datagram_size) {
    auto &path = ensure_path_state(path_id);
    path.mtu.outstanding_probe_size = datagram_size;
    path.mtu.outstanding_probe_packet_number = packet_number;
    path.mtu.next_probe_time.reset();
}

COQUIC_NO_PROFILE void QuicConnection::maybe_note_pmtu_probe_sent_for_tracking(
    const std::optional<std::size_t> &pmtu_probe_size, const SentPacketRecord &packet) {
    if (pmtu_probe_size.has_value()) {
        note_pmtu_probe_sent(packet.path_id, packet.packet_number, *pmtu_probe_size);
    }
}

void QuicConnection::note_pmtu_probe_acked(const SentPacketRecord &packet, QuicCoreTimePoint now) {
    if (!packet.is_pmtu_probe) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
    // # An endpoint SHOULD use DPLPMTUD (Section 14.3) or PMTUD (Section
    // # 14.2.1) to determine whether the path to a destination will support a
    // # desired maximum datagram size without fragmentation.
    auto &path = ensure_path_state(packet.path_id);
    const auto probe_size = packet.pmtu_probe_size != 0
                                ? std::optional<std::size_t>{packet.pmtu_probe_size}
                                : path.mtu.outstanding_probe_size;
    if (!probe_size.has_value()) {
        return;
    }

    const auto ceiling = outbound_datagram_size_ceiling_for_path(packet.path_id);
    const auto validated_size =
        std::min(std::max(path.mtu.validated_datagram_size, *probe_size), ceiling);
    if (validated_size > path.mtu.validated_datagram_size) {
        path.mtu.validated_datagram_size = validated_size;
        path.mtu.search_low = validated_size;
        path.mtu.probe_ceiling = std::max(path.mtu.probe_ceiling, validated_size);
    }
    forget_pmtud_failed_probe_size(path.mtu, *probe_size);
    if (should_clear_outstanding_pmtu_probe(path.mtu, packet.packet_number)) {
        path.mtu.outstanding_probe_size.reset();
        path.mtu.outstanding_probe_packet_number.reset();
    }
    path.mtu.next_probe_time = pmtud_next_probe_time(path.mtu, now, QuicCoreDuration{1000000});
}

void QuicConnection::note_pmtu_probe_lost(const SentPacketRecord &packet, QuicCoreTimePoint now) {
    if (!packet.is_pmtu_probe) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.4
    // # Loss of a QUIC packet that is carried in a PMTU probe is therefore not a
    // # reliable indication of congestion and SHOULD NOT trigger a congestion
    // # control reaction; see Item 7 in Section 3 of [DPLPMTUD].
    auto &path = ensure_path_state(packet.path_id);
    if (should_clear_outstanding_pmtu_probe(path.mtu, packet.packet_number)) {
        if (packet.pmtu_probe_size > path.mtu.validated_datagram_size) {
            remember_pmtud_failed_probe_size(path.mtu, packet.pmtu_probe_size);
            path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, packet.pmtu_probe_size - 1);
        }
        path.mtu.outstanding_probe_size.reset();
        path.mtu.outstanding_probe_packet_number.reset();
    }
    path.mtu.next_probe_time = pmtud_next_probe_time(path.mtu, now, QuicCoreDuration{100000});
}

void QuicConnection::note_inbound_datagram_bytes(std::size_t bytes) {
    if (bytes == 0) {
        return;
    }

    if ((status_ == HandshakeStatus::connected && peer_address_validated_) ||
        (close_mode_ == QuicConnectionCloseMode::closing && peer_address_validated_ &&
         paths_.contains(last_inbound_path_id_))) {
        auto &path = ensure_path_state(last_inbound_path_id_);
        const auto received = path.anti_amplification_received_bytes;
        auto increment = static_cast<std::uint64_t>(bytes);
        path.anti_amplification_received_bytes =
            received > std::numeric_limits<std::uint64_t>::max() - increment
                ? std::numeric_limits<std::uint64_t>::max()
                : received + increment;
        return;
    }
    const bool server_before_address_validation =
        config_.role == EndpointRole::server &&
        (status_ != HandshakeStatus::failed || close_mode_ == QuicConnectionCloseMode::closing) &&
        !peer_address_validated_;
    if (!server_before_address_validation && !anti_amplification_applies()) {
        return;
    }

    const auto received = anti_amplification_received_bytes_;
    auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_received_bytes_ =
        received > std::numeric_limits<std::uint64_t>::max() - increment
            ? std::numeric_limits<std::uint64_t>::max()
            : received + increment;
}

void QuicConnection::note_outbound_datagram_bytes(std::size_t bytes,
                                                  std::optional<QuicPathId> path_id,
                                                  std::optional<QuicCoreTimePoint> now) {
    if (bytes == 0) {
        return;
    }

    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (effective_path_id.has_value()) {
        auto path_it = paths_.find(*effective_path_id);
        if (path_it == paths_.end()) {
            return;
        }
        auto &path = path_it->second;
        if (should_arm_pmtu_probe_after_send(path.mtu, application_space_.write_secret.has_value(),
                                             cached_fresh_sendable_stream_bytes())) {
            path.mtu.next_probe_time = now.value_or(QuicCoreClock::now()) + QuicCoreDuration{10000};
        }
    }
    if (peer_address_validated_ && effective_path_id.has_value() &&
        anti_amplification_applies(*effective_path_id)) {
        auto &path = ensure_path_state(*effective_path_id);
        const auto sent = path.anti_amplification_sent_bytes;
        auto increment = static_cast<std::uint64_t>(bytes);
        path.anti_amplification_sent_bytes =
            sent > std::numeric_limits<std::uint64_t>::max() - increment
                ? std::numeric_limits<std::uint64_t>::max()
                : sent + increment;
        return;
    }
    if (!anti_amplification_applies()) {
        return;
    }

    const auto sent = anti_amplification_sent_bytes_;
    auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_sent_bytes_ = sent > std::numeric_limits<std::uint64_t>::max() - increment
                                         ? std::numeric_limits<std::uint64_t>::max()
                                         : sent + increment;
}

void QuicConnection::note_idle_peer_activity(QuicCoreTimePoint now) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # An endpoint restarts its idle timer when a packet from its peer is
    // # received and processed successfully.
    last_peer_activity_time_ = now;
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = false;
}

void QuicConnection::note_idle_ack_eliciting_send(QuicCoreTimePoint now) {
    if (ack_eliciting_sent_since_idle_reset_) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # An endpoint also restarts its idle timer when sending an ack-eliciting
    // # packet if no other ack-eliciting packets have been sent since last
    // # receiving and processing a packet.
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = true;
}

void QuicConnection::mark_peer_address_validated() {
    peer_address_validated_ = true;
    if (current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        path.validated = true;
        path.challenge_pending = false;
        path.validation_initiated_locally = false;
        path.validation_probe_only = false;
        path.path_mtu_validation_pending = false;
        path.outstanding_challenge_sent_with_expanded_datagram = true;
        path.outstanding_challenge.reset();
        path.validation_deadline.reset();
        last_validated_path_id_ = current_send_path_id_;
    }
}

void QuicConnection::set_path_peer_connection_id_sequence(PathState &path,
                                                          std::uint64_t sequence_number) {
    if (path.peer_connection_id_sequence == sequence_number) {
        return;
    }

    path.peer_connection_id_sequence = sequence_number;
    path.destination_connection_id_override.reset();
    path.spin.value = false;
    path.spin.largest_peer_packet_number.reset();
}

void QuicConnection::update_spin_bit_on_receive(QuicPathId path_id, bool peer_spin_bit,
                                                std::uint64_t packet_number) {
    if (latency_spin_bit_disabled_) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
        // # When the spin bit is disabled, endpoints MAY set the spin bit to any
        // # value and MUST ignore any incoming value.
        return;
    }
    auto &path = ensure_path_state(path_id);
    if (path.spin.disabled) {
        return;
    }
    if (path.spin.largest_peer_packet_number.has_value() &&
        packet_number <= *path.spin.largest_peer_packet_number) {
        return;
    }

    path.spin.largest_peer_packet_number = packet_number;
    path.spin.value =
        config_.role == EndpointRole::server ? peer_spin_bit : static_cast<bool>(!peer_spin_bit);
}

bool QuicConnection::outbound_spin_bit_for_path(std::optional<QuicPathId> path_id) const {
    if (latency_spin_bit_disabled_) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
        // # When the spin bit is disabled, endpoints MAY set the spin bit to any
        // # value and MUST ignore any incoming value.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
        // # It is RECOMMENDED that endpoints set the spin bit to a random value
        // # either chosen independently for each packet or chosen independently for
        // # each connection ID.
        return disabled_latency_spin_bit_value_;
    }
    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (!effective_path_id.has_value()) {
        return false;
    }

    const auto path = paths_.find(*effective_path_id);
    if (path == paths_.end() || path->second.spin.disabled) {
        return false;
    }
    return path->second.spin.value;
}

void QuicConnection::disable_ecn_on_path(QuicPathId path_id) {
    auto &path = ensure_path_state(path_id);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.4.2.2
    // # If validation fails, then the endpoint MUST disable ECN.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.4.2.2
    // # Network routing and path elements can change mid-connection; an endpoint
    // # MUST disable ECN if validation later fails.
    path.ecn.state = QuicPathEcnState::failed;
    path.ecn.has_last_peer_counts.fill(false);
    path.ecn.last_peer_counts = {};
    path.ecn.probing_packets_sent = 0;
    path.ecn.probing_packets_acked = 0;
    path.ecn.probing_packets_lost = 0;
}

QuicEcnCodepoint
QuicConnection::outbound_ecn_codepoint_for_path(std::optional<QuicPathId> path_id) const {
    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (!effective_path_id.has_value()) {
        return QuicEcnCodepoint::not_ect;
    }

    const auto path = paths_.find(*effective_path_id);
    if (path == paths_.end() || path->second.ecn.state == QuicPathEcnState::failed ||
        !is_ect_codepoint(path->second.ecn.transmit_mark)) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.4.2.2
        // # It stops setting the ECT codepoint in IP packets that it sends,
        // # assuming that either the network path or the peer does not support
        // # ECN.
        return QuicEcnCodepoint::not_ect;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.4.2.2
    // # Upon successful validation, an endpoint MAY continue to set an ECT
    // # codepoint in subsequent packets it sends, with the expectation that
    // # the path is ECN capable.
    return path->second.ecn.transmit_mark;
}

ConnectionId
QuicConnection::outbound_destination_connection_id(std::optional<QuicPathId> path_id) const {
    if (path_id.has_value()) {
        if (const auto path = paths_.find(*path_id); path != paths_.end()) {
            const auto &destination_connection_id_override =
                path->second.destination_connection_id_override;
            if (destination_connection_id_override.has_value()) {
                return destination_connection_id_override.value();
            }
            if (const auto peer_connection_id =
                    peer_connection_ids_.find(path->second.peer_connection_id_sequence);
                peer_connection_id != peer_connection_ids_.end() &&
                !peer_connection_id->second.locally_retired) {
                return peer_connection_id->second.connection_id;
            }
        }
    }

    return active_peer_destination_connection_id();
}

ConnectionId QuicConnection::client_initial_destination_connection_id() const {
    if (client_initial_destination_connection_id_.has_value()) {
        return client_initial_destination_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

} // namespace coquic::quic

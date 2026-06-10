#include "src/quic/connection/connection.h"
#include "src/quic/connection/connection_internal.h"

namespace coquic::quic {

std::optional<QuicCoreTimePoint> QuicConnection::next_wakeup() const {
    if (status_ == HandshakeStatus::failed && close_mode_ != QuicConnectionCloseMode::closing &&
        close_mode_ != QuicConnectionCloseMode::draining) {
        return std::nullopt;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing ||
        close_mode_ == QuicConnectionCloseMode::draining) {
        return close_deadline_;
    }

    return earliest_of({non_pacing_wakeup_deadline(), pacing_deadline()});
}

std::optional<QuicCoreTimePoint> QuicConnection::non_pacing_wakeup_deadline() const {
    if (status_ == HandshakeStatus::failed && close_mode_ != QuicConnectionCloseMode::closing &&
        close_mode_ != QuicConnectionCloseMode::draining) {
        return std::nullopt;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing ||
        close_mode_ == QuicConnectionCloseMode::draining) {
        return close_deadline_;
    }
    return earliest_of({loss_deadline(), pto_deadline(), ack_deadline(), pmtud_deadline(),
                        zero_rtt_discard_deadline(),
                        previous_application_read_secret_discard_deadline(),
                        idle_timeout_deadline()});
}

bool QuicConnection::non_pacing_wakeup_due(QuicCoreTimePoint now) const {
    const auto deadline = non_pacing_wakeup_deadline();
    return deadline.has_value() && now >= *deadline;
}

std::optional<QuicCoreTimePoint> QuicConnection::pacing_deadline() const {
    if (status_ == HandshakeStatus::failed || close_state_active()) {
        return std::nullopt;
    }
    if (!has_pending_congestion_controlled_send()) {
        return std::nullopt;
    }
    const auto max_datagram_size = outbound_datagram_size_limit();
    if (max_datagram_size == 0) {
        return std::nullopt;
    }
    const bool has_initial_send =
        !initial_packet_space_discarded_ && (initial_space_.send_crypto.has_pending_data() ||
                                             initial_space_.pending_probe_packet.has_value());
    const bool has_handshake_send = !handshake_packet_space_discarded_ &&
                                    handshake_space_.write_secret.has_value() &&
                                    (handshake_space_.send_crypto.has_pending_data() ||
                                     handshake_space_.pending_probe_packet.has_value());
    if (!has_initial_send && !has_handshake_send &&
        can_send_application_packets(config_.role, status_, zero_rtt_space_, application_space_) &&
        !has_pending_application_control_send(/*application_ack_due=*/false)) {
        const auto stream_bytes = application_stream_pacing_deadline_bytes();
        if (stream_bytes.has_value()) {
            return congestion_controller_.next_send_time(*stream_bytes);
        }
    }
    return congestion_controller_.next_send_time(max_datagram_size);
}

std::optional<QuicCoreTimePoint> QuicConnection::loss_deadline() const {
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto packet_space_loss_deadline =
        [&](const PacketSpaceState &packet_space) -> std::optional<QuicCoreTimePoint> {
        if (packet_space_discarded(packet_space)) {
            return std::nullopt;
        }
        const auto tracked_packet = earliest_loss_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return std::nullopt;
        }

        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
        // # The PTO timer MUST NOT be set if a timer is set for time threshold
        // # loss detection; see Section 6.1.2.
        return packet_space.recovery.time_threshold_deadline(tracked_packet->sent_time);
    };

    const auto pmtu_probe_deadline = [&]() -> std::optional<QuicCoreTimePoint> {
        std::optional<QuicCoreTimePoint> deadline;
        for (const auto &[path_id, path] : paths_) {
            static_cast<void>(path_id);
            if (!path.mtu.outstanding_probe_packet_number.has_value()) {
                continue;
            }

            const auto *packet =
                application_space_.recovery.find_packet(*path.mtu.outstanding_probe_packet_number);
            if (!pmtud_packet_deadline_candidate_is_live(packet)) {
                continue;
            }

            const auto candidate =
                compute_time_threshold_deadline(shared_rtt_state, packet->sent_time);
            deadline = earliest_deadline(deadline, candidate);
        }
        return deadline;
    };

    return earliest_of({packet_space_loss_deadline(initial_space_),
                        packet_space_loss_deadline(handshake_space_),
                        packet_space_loss_deadline(application_space_), pmtu_probe_deadline()});
}

std::optional<QuicCoreTimePoint> QuicConnection::pto_deadline() const {
    if (anti_amplification_applies() && anti_amplification_remaining_send_budget() == 0) {
        return std::nullopt;
    }

    const auto application_max_ack_delay = transport_parameter_milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState &packet_space) {
        if (config_.role != EndpointRole::client || handshake_confirmed_ ||
            &packet_space != &initial_space_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    const auto packet_space_pto_deadline =
        [&](const PacketSpaceState &packet_space,
            QuicCoreDuration max_ack_delay) -> std::optional<QuicCoreTimePoint> {
        if (packet_space_discarded(packet_space)) {
            return std::nullopt;
        }
        const auto tracked_packet = latest_in_flight_ack_eliciting_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return std::nullopt;
        }

        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
        // # When the PTO is armed for Initial or Handshake packet number spaces,
        // # the max_ack_delay in the PTO period computation is set to 0
        return compute_pto_deadline(shared_rtt_state, max_ack_delay, tracked_packet->sent_time,
                                    effective_pto_count(packet_space));
    };

    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
    // # When ack-eliciting packets in multiple packet number spaces are in
    // # flight, the timer MUST be set to the earlier value of the Initial and
    // # Handshake packet number spaces.
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
    // # An endpoint MUST NOT set its PTO timer for the Application Data
    // # packet number space until the handshake is confirmed.
    auto regular_deadline =
        earliest_of({packet_space_pto_deadline(initial_space_, QuicCoreDuration{0}),
                     packet_space_pto_deadline(handshake_space_, QuicCoreDuration{0}),
                     allow_application_pto
                         ? packet_space_pto_deadline(application_space_, application_max_ack_delay)
                         : std::nullopt});

    auto client_handshake_keepalive_reference_time = [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = client_handshake_keepalive_is_eligible(
            config_.role, status_, handshake_confirmed_, last_peer_activity_time_,
            initial_packet_space_discarded_, initial_space_, handshake_packet_space_discarded_,
            handshake_space_, application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto keepalive_probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (keepalive_probe_time > *reference_time) {
            reference_time = keepalive_probe_time;
        }

        return reference_time;
    }();
    auto client_handshake_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (has_client_handshake_keepalive_space(client_handshake_keepalive_reference_time,
                                             initial_packet_space_discarded_,
                                             handshake_packet_space_discarded_, handshake_space_)) {
        client_handshake_keepalive_deadline =
            compute_pto_deadline(shared_rtt_state, QuicCoreDuration{0},
                                 optional_ref_or_abort(client_handshake_keepalive_reference_time),
                                 std::min(pto_count_, 2u));
    }

    auto client_receive_keepalive_reference_time = [this]() -> std::optional<QuicCoreTimePoint> {
        const bool has_receive_interest = std::ranges::any_of(
            streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
        const bool eligible = client_receive_keepalive_is_eligible(
            config_.role, status_, handshake_confirmed_, last_peer_activity_time_,
            has_receive_interest, initial_packet_space_discarded_, initial_space_,
            handshake_packet_space_discarded_, handshake_space_);
        if (!eligible) {
            return std::nullopt;
        }

        return make_client_receive_keepalive_reference_time(
            last_peer_activity_time_, last_client_receive_keepalive_probe_time_);
    }();
    auto client_receive_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_receive_keepalive_reference_time.has_value()) {
        client_receive_keepalive_deadline = compute_pto_deadline(
            shared_rtt_state, application_max_ack_delay, *client_receive_keepalive_reference_time,
            std::min(pto_count_, 2u));
    }

    return earliest_of(
        {regular_deadline, client_handshake_keepalive_deadline, client_receive_keepalive_deadline});
}

std::optional<QuicCoreTimePoint> QuicConnection::ack_deadline() const {
    return earliest_of(
        {initial_packet_space_discarded_ ? std::nullopt : initial_space_.pending_ack_deadline,
         handshake_packet_space_discarded_ ? std::nullopt : handshake_space_.pending_ack_deadline,
         application_space_.pending_ack_deadline});
}

QuicCoreDuration QuicConnection::path_validation_timeout_period() const {
    const auto current_pto_reference =
        std::max(compute_pto_deadline(shared_recovery_rtt_state(), QuicCoreDuration{0},
                                      QuicCoreTimePoint{}, /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    const auto new_path_pto_reference =
        std::max(compute_pto_deadline(RecoveryRttState{}, QuicCoreDuration{0}, QuicCoreTimePoint{},
                                      /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.4
    // # A value of three times the larger of the current PTO or the PTO for
    // # the new path (using kInitialRtt, as defined in [QUIC-RECOVERY]) is
    // # RECOMMENDED.
    return std::chrono::duration_cast<QuicCoreDuration>(
        std::max(current_pto_reference, new_path_pto_reference) * kPersistentCongestionThreshold);
}

std::optional<QuicCoreTimePoint> QuicConnection::idle_timeout_deadline() const {
    const auto effective_timeout_ms =
        effective_idle_timeout_ms(local_transport_parameters_, peer_transport_parameters_);
    if (status_ == HandshakeStatus::failed) {
        return std::nullopt;
    }
    if (!idle_timeout_base_time_.has_value()) {
        return std::nullopt;
    }
    if (effective_timeout_ms == 0) {
        return std::nullopt;
    }

    auto timeout = transport_parameter_milliseconds(effective_timeout_ms);
    const auto pto_reference =
        std::max(compute_pto_deadline(shared_recovery_rtt_state(), QuicCoreDuration{0},
                                      QuicCoreTimePoint{}, /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # To avoid excessively small idle timeout periods, endpoints MUST
    // # increase the idle timeout period to be at least three times the
    // # current Probe Timeout (PTO).
    timeout = std::max(timeout, std::chrono::duration_cast<QuicCoreDuration>(
                                    pto_reference * kPersistentCongestionThreshold));
    return *idle_timeout_base_time_ + timeout;
}

std::optional<QuicCoreTimePoint> QuicConnection::pmtud_deadline() const {
    if (!config_.transport.pmtud_enabled || !application_space_.write_secret.has_value()) {
        return std::nullopt;
    }

    std::optional<QuicCoreTimePoint> deadline;
    for (const auto &[path_id, path] : paths_) {
        static_cast<void>(path_id);
        if (!path.mtu.next_probe_time.has_value()) {
            continue;
        }
        deadline = earliest_deadline(deadline, *path.mtu.next_probe_time);
    }
    return deadline;
}

void QuicConnection::detect_lost_packets(QuicCoreTimePoint now) {
    if (!initial_packet_space_discarded_) {
        detect_lost_packets(initial_space_, now);
    }
    if (!handshake_packet_space_discarded_) {
        detect_lost_packets(handshake_space_, now);
    }
    detect_lost_packets(application_space_, now);
}

void QuicConnection::detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now) {
    auto handles = packet_space.recovery.collect_time_threshold_losses(now);
    auto pmtu_probe_handles = packet_space.recovery.collect_pmtu_probe_timeouts(now);
    handles.insert(handles.end(), pmtu_probe_handles.begin(), pmtu_probe_handles.end());
    if (handles.empty()) {
        return;
    }

    const auto &shared_rtt_state = shared_recovery_rtt_state();

    std::vector<SentPacketRecord> lost_packets;
    lost_packets.reserve(handles.size());
    for (const auto handle : handles) {
        const auto &packet = *packet_space.recovery.packet_for_handle(handle);
        emit_qlog_packet_lost(packet, "time_threshold", now);
        if (auto lost_packet = mark_lost_packet(packet_space, handle,
                                                /*already_marked_in_recovery=*/false, now)) {
            lost_packets.push_back(*lost_packet);
        } else {
            lost_packets.push_back(packet);
        }
    }
    if (has_timer_lost_packets_for_profile(send_profile_enabled(), lost_packets)) {
        auto &profile = send_profile_counters();
        profile.timer_lost_packets += lost_packets.size();
        for (const auto &packet : lost_packets) {
            profile.timer_lost_bytes += packet.bytes_in_flight;
        }
    }
    const auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(lost_packets);
    if (!ack_eliciting_lost_packets.empty()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().loss_events;
        }
        const auto peer_max_ack_delay_ms =
            peer_transport_parameters_.value_or(TransportParameters{}).max_ack_delay;
        const auto max_ack_delay = (&packet_space == &application_space_)
                                       ? transport_parameter_milliseconds(peer_max_ack_delay_ms)
                                       : QuicCoreDuration{0};
        congestion_controller_.on_loss_event(now,
                                             latest_packet_sent_time(ack_eliciting_lost_packets));
        //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
        // # When persistent congestion is declared, the sender's congestion
        // # window MUST be reduced to the minimum congestion window
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              max_ack_delay)) {
            if (send_profile_enabled()) {
                ++send_profile_counters().persistent_congestion_events;
            }
            congestion_controller_.on_persistent_congestion();
        }
    }
    maybe_emit_qlog_recovery_metrics(now);
}

void QuicConnection::maybe_arm_pmtu_probe(QuicCoreTimePoint now) {
    if (!config_.transport.pmtud_enabled || !application_space_.write_secret.has_value() ||
        !current_send_path_id_.has_value() || application_space_.pending_probe_packet.has_value()) {
        return;
    }

    auto path_it = paths_.find(*current_send_path_id_);
    if (path_it == paths_.end()) {
        return;
    }
    auto &path = path_it->second;
    if (!path.mtu.viable) {
        return;
    }
    if (path.mtu.outstanding_probe_packet_number.has_value()) {
        return;
    }
    if (path.mtu.next_probe_time.has_value() && *path.mtu.next_probe_time > now) {
        return;
    }
    path.mtu.probe_ceiling =
        std::min(path.mtu.probe_ceiling, outbound_datagram_size_ceiling_for_path(path.id));
    if (path.mtu.validated_datagram_size >= path.mtu.probe_ceiling) {
        path.mtu.next_probe_time.reset();
        return;
    }
    if (anti_amplification_applies(*current_send_path_id_)) {
        path.mtu.next_probe_time = now + QuicCoreDuration{100000};
        return;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
    // # An endpoint SHOULD use DPLPMTUD (Section 14.3) or PMTUD (Section
    // # 14.2.1) to determine whether the path to a destination will support a
    // # desired maximum datagram size without fragmentation.
    const auto probe_size = next_pmtu_probe_size(path);
    if (!probe_size.has_value()) {
        maybe_trace_pmtu_no_probe(config_.source_connection_id, path);
        path.mtu.next_probe_time.reset();
        return;
    }
    path.mtu.next_probe_time.reset();
    if (packet_trace_matches_connection(config_.source_connection_id)) {
        std::cerr << "quic-packet-trace pmtud-arm scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path.id
                  << " probe=" << *probe_size << " validated=" << path.mtu.validated_datagram_size
                  << " ceiling=" << path.mtu.probe_ceiling << '\n';
    }

    application_space_.pending_probe_packet = SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
        .path_id = *current_send_path_id_,
        .is_pmtu_probe = true,
        .pmtu_probe_size = *probe_size,
    };
}

void QuicConnection::arm_pto_probe(QuicCoreTimePoint now) {
    PacketSpaceState *selected_packet_space = nullptr;
    std::optional<QuicCoreTimePoint> selected_deadline;
    const auto application_max_ack_delay = transport_parameter_milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState &packet_space) {
        if (config_.role != EndpointRole::client || handshake_confirmed_ ||
            &packet_space != &initial_space_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    auto client_handshake_keepalive_reference_time = [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = (config_.role == EndpointRole::client) &&
                              (status_ == HandshakeStatus::in_progress) && !handshake_confirmed_ &&
                              last_peer_activity_time_.has_value() &&
                              (initial_packet_space_discarded_ ||
                               !has_in_flight_ack_eliciting_packet(initial_space_)) &&
                              (handshake_packet_space_discarded_ ||
                               !has_in_flight_ack_eliciting_packet(handshake_space_)) &&
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    PacketSpaceState *client_handshake_keepalive_space = client_handshake_keepalive_packet_space(
        client_handshake_keepalive_reference_time, initial_packet_space_discarded_, initial_space_,
        handshake_packet_space_discarded_, handshake_space_);
    auto client_handshake_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_handshake_keepalive_space != nullptr) {
        client_handshake_keepalive_deadline =
            compute_pto_deadline(shared_rtt_state, QuicCoreDuration{0},
                                 optional_ref_or_abort(client_handshake_keepalive_reference_time),
                                 std::min(pto_count_, 2u));
    }
    const bool client_handshake_keepalive_due = client_handshake_keepalive_deadline.has_value() &&
                                                now >= *client_handshake_keepalive_deadline;
    auto client_receive_keepalive_reference_time = [this]() -> std::optional<QuicCoreTimePoint> {
        const bool has_receive_interest = std::ranges::any_of(
            streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
        const bool eligible = client_receive_keepalive_is_eligible(
            config_.role, status_, handshake_confirmed_, last_peer_activity_time_,
            has_receive_interest, initial_packet_space_discarded_, initial_space_,
            handshake_packet_space_discarded_, handshake_space_);
        if (!eligible) {
            return std::nullopt;
        }

        return make_client_receive_keepalive_reference_time(
            last_peer_activity_time_, last_client_receive_keepalive_probe_time_);
    }();
    bool client_receive_keepalive_eligible = client_receive_keepalive_reference_time.has_value();
    PacketSpaceState *client_receive_keepalive_space =
        client_receive_keepalive_eligible ? &application_space_ : nullptr;
    auto client_receive_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_receive_keepalive_reference_time.has_value()) {
        client_receive_keepalive_deadline = compute_pto_deadline(
            shared_rtt_state, application_max_ack_delay, *client_receive_keepalive_reference_time,
            std::min(pto_count_, 2u));
    }
    const bool client_receive_keepalive_due =
        client_receive_keepalive_deadline.has_value() && now >= *client_receive_keepalive_deadline;
    auto consider_packet_space = [&](PacketSpaceState &packet_space,
                                     QuicCoreDuration max_ack_delay) {
        if (packet_space_discarded(packet_space)) {
            return;
        }
        const auto tracked_packet = latest_in_flight_ack_eliciting_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return;
        }
        const auto packet_space_deadline =
            compute_pto_deadline(shared_rtt_state, max_ack_delay, tracked_packet->sent_time,
                                 effective_pto_count(packet_space));

        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
        // # When a PTO timer expires, a sender MUST send at least one ack-
        // # eliciting packet in the packet number space as a probe.
        const bool deadline_due = now >= packet_space_deadline;
        if (!deadline_due) {
            return;
        }

        const auto current_selected_deadline = selected_deadline.value_or(packet_space_deadline);
        if (!selected_deadline.has_value() || (packet_space_deadline < current_selected_deadline)) {
            selected_deadline = packet_space_deadline;
            selected_packet_space = &packet_space;
        }
    };

    consider_packet_space(initial_space_, QuicCoreDuration{0});
    consider_packet_space(handshake_space_, QuicCoreDuration{0});
    if (allow_application_pto) {
        consider_packet_space(application_space_, application_max_ack_delay);
    }

    if (selected_packet_space == nullptr) {
        if (!client_handshake_keepalive_due && !client_receive_keepalive_due) {
            return;
        }
        if (client_handshake_keepalive_due) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
            // # To
            // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
            // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
            selected_packet_space = client_handshake_keepalive_space;
            selected_deadline = client_handshake_keepalive_deadline;
        } else {
            selected_packet_space = client_receive_keepalive_space;
            selected_deadline = client_receive_keepalive_deadline;
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
    // # When a PTO timer expires, the PTO backoff MUST be increased,
    // # resulting in the PTO period being set to twice its current value.
    ++pto_count_;
    remaining_pto_probe_datagrams_ = 0;
    bool armed_pto_probe = false;
    if (current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        if (!path.validated && path.outstanding_challenge.has_value()) {
            path.challenge_pending = true;
        }
    }
    const auto arm_packet_space_probe = [&](PacketSpaceState &packet_space) {
        if (packet_space_discarded(packet_space)) {
            return;
        }
        const bool allow_client_handshake_keepalive_probe =
            client_handshake_keepalive_due && &packet_space == client_handshake_keepalive_space;
        const bool allow_client_receive_keepalive_probe =
            client_receive_keepalive_due && &packet_space == client_receive_keepalive_space;
        if (!allow_client_handshake_keepalive_probe && !allow_client_receive_keepalive_probe &&
            !has_in_flight_ack_eliciting_packet(packet_space)) {
            return;
        }

        if (&packet_space != &application_space_ && packet_space.send_crypto.has_pending_data()) {
            return;
        }

        packet_space.pending_probe_packet = select_pto_probe(packet_space);
        if ((allow_client_handshake_keepalive_probe || allow_client_receive_keepalive_probe) &&
            packet_space.pending_probe_packet.has_value()) {
            packet_space.pending_probe_packet->force_ack = true;
        }
        armed_pto_probe |= packet_space.pending_probe_packet.has_value();
    };

    arm_packet_space_probe(*selected_packet_space);

    auto arm_coalesced_probe = [&](PacketSpaceState &packet_space) {
        if (&packet_space == selected_packet_space) {
            return;
        }

        arm_packet_space_probe(packet_space);
    };

    arm_coalesced_probe(initial_space_);
    arm_coalesced_probe(handshake_space_);
    if (allow_application_pto) {
        arm_coalesced_probe(application_space_);
    }

    if (armed_pto_probe) {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
        // # An endpoint
        // # MAY send up to two full-sized datagrams containing ack-eliciting
        // # packets to avoid an expensive consecutive PTO expiration due to a
        // # single lost datagram or to transmit data from multiple packet number
        // # spaces.
        remaining_pto_probe_datagrams_ = 2;
    }

    if (packet_trace_matches_connection(config_.source_connection_id)) {
        constexpr std::array<const char *, 4> kPacketSpaceNames = {
            "none",
            "initial",
            "handshake",
            "application",
        };
        const auto selected_packet_space_index =
            static_cast<std::size_t>(selected_packet_space == &initial_space_) +
            static_cast<std::size_t>(selected_packet_space == &handshake_space_) * 2u +
            static_cast<std::size_t>(selected_packet_space == &application_space_) * 3u;
        const char *selected_packet_space_name = kPacketSpaceNames[selected_packet_space_index];

        std::cerr << "quic-packet-trace arm-pto scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " selected=" << selected_packet_space_name
                  << " client_hs_due=" << static_cast<int>(client_handshake_keepalive_due)
                  << " client_recv_due=" << static_cast<int>(client_receive_keepalive_due)
                  << " armed=" << static_cast<int>(armed_pto_probe) << " initial_probe="
                  << static_cast<int>(initial_space_.pending_probe_packet.has_value())
                  << " handshake_probe="
                  << static_cast<int>(handshake_space_.pending_probe_packet.has_value())
                  << " application_probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_ << '\n';
    }
    maybe_emit_qlog_recovery_metrics(now);
}

bool QuicConnection::packet_space_discarded(const PacketSpaceState &packet_space) const {
    if (&packet_space == &initial_space_) {
        return initial_packet_space_discarded_;
    }
    if (&packet_space == &handshake_space_) {
        return handshake_packet_space_discarded_;
    }
    return false;
}

SentPacketRecord QuicConnection::select_pto_probe(const PacketSpaceState &packet_space) const {
    std::optional<SentPacketRecord> ping_fallback;
    std::optional<SentPacketRecord> best_probe;
    int best_probe_priority = -1;
    const auto handles = packet_space.recovery.tracked_packets();
    for (auto it = handles.rbegin(); it != handles.rend(); ++it) {
        const auto &packet = *packet_space.recovery.packet_for_handle(*it);
        if (!packet.ack_eliciting || !packet.in_flight) {
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
        // # Previously sent data MAY be sent if no new data can be
        // # sent.
        ping_fallback = ping_fallback.value_or(SentPacketRecord{
            .packet_number = packet.packet_number,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        });

        auto probe = packet;
        std::erase_if(probe.crypto_ranges, [&](const ByteRange &range) {
            return !packet_space.send_crypto.has_outstanding_range(range.offset,
                                                                   range.bytes.size());
        });
        std::erase_if(probe.reset_stream_frames, [&](const ResetStreamFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool reset_acknowledged =
                stream->second.reset_state == StreamControlFrameState::acknowledged;
            const bool reset_frame_mismatch =
                !reset_stream_frame_matches(stream->second.pending_reset_frame, frame);
            return static_cast<bool>(reset_acknowledged | reset_frame_mismatch);
        });
        std::erase_if(probe.stop_sending_frames, [&](const StopSendingFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stop_sending_acknowledged =
                stream->second.stop_sending_state == StreamControlFrameState::acknowledged;
            const bool stop_sending_frame_mismatch =
                !stop_sending_frame_matches(stream->second.pending_stop_sending_frame, frame);
            return static_cast<bool>(stop_sending_acknowledged | stop_sending_frame_mismatch);
        });
        std::erase_if(probe.max_stream_data_frames, [&](const MaxStreamDataFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool max_stream_data_acknowledged =
                stream->second.flow_control.max_stream_data_state ==
                StreamControlFrameState::acknowledged;
            const bool max_stream_data_frame_mismatch = !max_stream_data_frame_matches(
                stream->second.flow_control.pending_max_stream_data_frame, frame);
            return static_cast<bool>(max_stream_data_acknowledged | max_stream_data_frame_mismatch);
        });
        std::erase_if(probe.max_streams_frames, [&](const MaxStreamsFrame &frame) {
            const bool frame_acknowledged =
                frame.stream_type == StreamLimitType::bidirectional
                    ? local_stream_limit_state_.max_streams_bidi_state ==
                          StreamControlFrameState::acknowledged
                    : local_stream_limit_state_.max_streams_uni_state ==
                          StreamControlFrameState::acknowledged;
            const auto &pending_frame =
                frame.stream_type == StreamLimitType::bidirectional
                    ? *local_stream_limit_state_.pending_max_streams_bidi_frame
                    : *local_stream_limit_state_.pending_max_streams_uni_frame;
            const bool frame_mismatch =
                std::tie(pending_frame.stream_type, pending_frame.maximum_streams) !=
                std::tie(frame.stream_type, frame.maximum_streams);
            return static_cast<bool>(frame_acknowledged | frame_mismatch);
        });
        std::erase_if(probe.streams_blocked_frames, [&](const StreamsBlockedFrame &frame) {
            const bool frame_acknowledged = frame.stream_type == StreamLimitType::bidirectional
                                                ? stream_open_limits_.streams_blocked_bidi_state ==
                                                      StreamControlFrameState::acknowledged
                                                : stream_open_limits_.streams_blocked_uni_state ==
                                                      StreamControlFrameState::acknowledged;
            const auto *pending_frame =
                frame.stream_type == StreamLimitType::bidirectional
                    ? &stream_open_limits_.pending_streams_blocked_bidi_frame
                    : &stream_open_limits_.pending_streams_blocked_uni_frame;
            const bool frame_mismatch =
                !pending_frame->has_value() ||
                std::tie((*pending_frame)->stream_type, (*pending_frame)->maximum_streams) !=
                    std::tie(frame.stream_type, frame.maximum_streams);
            return static_cast<bool>(frame_acknowledged | frame_mismatch);
        });
        std::erase_if(probe.stream_data_blocked_frames, [&](const StreamDataBlockedFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stream_data_blocked_acknowledged =
                stream->second.flow_control.stream_data_blocked_state ==
                StreamControlFrameState::acknowledged;
            const bool stream_data_blocked_frame_mismatch = !stream_data_blocked_frame_matches(
                stream->second.flow_control.pending_stream_data_blocked_frame, frame);
            return static_cast<bool>(stream_data_blocked_acknowledged |
                                     stream_data_blocked_frame_mismatch);
        });
        if (probe.first_stream_frame_metadata.has_value()) {
            const auto stream = streams_.find(probe.first_stream_frame_metadata->stream_id);
            if (stream == streams_.end() ||
                !stream_frame_metadata_is_probe_worthy(stream->second,
                                                       *probe.first_stream_frame_metadata)) {
                probe.first_stream_frame_metadata.reset();
            }
        }
        std::erase_if(probe.stream_frame_metadata, [&](const StreamFrameSendMetadata &metadata) {
            const auto stream = streams_.find(metadata.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            return !stream_frame_metadata_is_probe_worthy(stream->second, metadata);
        });
        std::erase_if(probe.stream_fragments, [&](const StreamFrameSendFragment &fragment) {
            const auto stream = streams_.find(fragment.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            return !stream_fragment_is_probe_worthy(stream->second, fragment);
        });

        if (probe.max_data_frame.has_value()) {
            const bool max_data_acknowledged =
                connection_flow_control_.max_data_state == StreamControlFrameState::acknowledged;
            const bool max_data_frame_mismatch = !max_data_frame_matches(
                connection_flow_control_.pending_max_data_frame, *probe.max_data_frame);
            if (max_data_acknowledged | max_data_frame_mismatch) {
                probe.max_data_frame = std::nullopt;
            }
        }
        if (probe.data_blocked_frame.has_value()) {
            const bool data_blocked_acknowledged = connection_flow_control_.data_blocked_state ==
                                                   StreamControlFrameState::acknowledged;
            const bool data_blocked_frame_mismatch = !data_blocked_frame_matches(
                connection_flow_control_.pending_data_blocked_frame, *probe.data_blocked_frame);
            if (data_blocked_acknowledged | data_blocked_frame_mismatch) {
                probe.data_blocked_frame = std::nullopt;
            }
        }
        if (probe.has_handshake_done &&
            handshake_done_state_ == StreamControlFrameState::acknowledged) {
            probe.has_handshake_done = false;
        }
        std::erase_if(probe.new_token_frames, [&](const NewTokenFrame &frame) {
            return std::none_of(
                pending_new_token_frames_.begin(), pending_new_token_frames_.end(),
                [&](const NewTokenFrame &pending) { return pending.token == frame.token; });
        });
        std::erase_if(probe.new_connection_id_frames, [&](const NewConnectionIdFrame &frame) {
            return std::none_of(
                pending_new_connection_id_frames_.begin(), pending_new_connection_id_frames_.end(),
                [&](const NewConnectionIdFrame &pending) {
                    return std::tie(pending.sequence_number, pending.retire_prior_to,
                                    pending.connection_id, pending.stateless_reset_token) ==
                           std::tie(frame.sequence_number, frame.retire_prior_to,
                                    frame.connection_id, frame.stateless_reset_token);
                });
        });
        std::erase_if(probe.retire_connection_id_frames, [&](const RetireConnectionIdFrame &frame) {
            return std::none_of(pending_retire_connection_id_frames_.begin(),
                                pending_retire_connection_id_frames_.end(),
                                [&](const RetireConnectionIdFrame &pending) {
                                    return pending.sequence_number == frame.sequence_number;
                                });
        });

        auto frame_count = retransmittable_probe_frame_count(probe);
        if (frame_count == 0 && !probe.has_ping) {
            continue;
        }

        int probe_priority = 0;
        if (packet_has_stream_frames(probe)) {
            probe_priority = 3;
        } else if (!probe.crypto_ranges.empty()) {
            probe_priority = 2;
        } else if (frame_count != 0) {
            probe_priority = 1;
        }

        if (!best_probe.has_value() || probe_priority > best_probe_priority) {
            best_probe = std::move(probe);
            best_probe_priority = probe_priority;
        }
        if (best_probe_priority == 3) {
            break;
        }
    }

    if (best_probe.has_value()) {
        return *best_probe;
    }
    if (ping_fallback.has_value()) {
        return *ping_fallback;
    }

    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
    // # When there is no data to send, the sender SHOULD send
    // # a PING or other ack-eliciting frame in a single packet, rearming the
    // # PTO timer.
    return SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
}

COQUIC_NOINLINE void QuicConnection::queue_client_handshake_recovery_probe() {
    if ((config_.role != EndpointRole::client) || (status_ != HandshakeStatus::in_progress) ||
        handshake_confirmed_ || handshake_packet_space_discarded_ ||
        !handshake_space_.write_secret.has_value() ||
        !handshake_space_.send_crypto.has_pending_data()) {
        return;
    }

    if (handshake_space_.pending_probe_packet.has_value() ||
        has_in_flight_ack_eliciting_packet(handshake_space_)) {
        return;
    }

    const bool has_other_space_in_flight =
        client_handshake_recovery_probe_has_other_space_in_flight(
            initial_packet_space_discarded_, initial_space_, application_space_);
    if (!has_other_space_in_flight) {
        return;
    }

    auto probe = select_pto_probe(handshake_space_);
    if (handshake_space_.received_packets.has_ack_to_send()) {
        probe.force_ack = true;
    }
    handshake_space_.pending_probe_packet = std::move(probe);
}

void QuicConnection::queue_server_handshake_recovery_probes() {
    if ((config_.role != EndpointRole::server) || (status_ != HandshakeStatus::in_progress) ||
        handshake_confirmed_ || handshake_packet_space_discarded_) {
        return;
    }

    if (handshake_space_.pending_probe_packet.has_value() ||
        handshake_space_.send_crypto.has_pending_data()) {
        return;
    }

    handshake_space_.pending_probe_packet = select_pto_probe(handshake_space_);
}

const RecoveryRttState &QuicConnection::shared_recovery_rtt_state() const {
    if (recovery_rtt_state_.latest_rtt.has_value()) {
        return recovery_rtt_state_;
    }
    if (initial_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return initial_space_.recovery.rtt_state();
    }
    if (handshake_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return handshake_space_.recovery.rtt_state();
    }
    if (application_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return application_space_.recovery.rtt_state();
    }

    return recovery_rtt_state_;
}

std::optional<QuicCoreTimePoint> QuicConnection::zero_rtt_discard_deadline() const {
    if (config_.role != EndpointRole::server || !zero_rtt_space_.read_secret.has_value()) {
        return std::nullopt;
    }

    return server_zero_rtt_discard_deadline_;
}

void QuicConnection::arm_server_zero_rtt_discard_deadline(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::server || !zero_rtt_space_.read_secret.has_value() ||
        server_zero_rtt_discard_deadline_.has_value()) {
        return;
    }

    const auto max_ack_delay = transport_parameter_milliseconds(
        peer_transport_parameters_.value_or(TransportParameters{}).max_ack_delay);
    const auto single_pto = compute_pto_deadline(shared_recovery_rtt_state(), max_ack_delay, now,
                                                 /*pto_count=*/0) -
                            now;
    server_zero_rtt_discard_deadline_ = now + single_pto * 3;
}

void QuicConnection::maybe_discard_server_zero_rtt_packet_space(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::server || !server_zero_rtt_discard_deadline_.has_value() ||
        now < *server_zero_rtt_discard_deadline_) {
        return;
    }

    discard_packet_space_state(zero_rtt_space_);
    server_zero_rtt_discard_deadline_.reset();
}

void QuicConnection::retain_previous_application_read_secret(QuicCoreTimePoint now) {
    previous_application_read_secret_ = application_space_.read_secret;
    previous_application_read_key_phase_ = application_read_key_phase_;
    previous_application_read_secret_discard_deadline_ =
        now + three_pto_period(shared_recovery_rtt_state());
}

CodecResult<bool> QuicConnection::refresh_next_application_read_secret() {
    if (!application_space_.read_secret.has_value()) {
        next_application_read_secret_.reset();
        next_application_read_secret_source_generation_.reset();
        reset_current_short_header_deserialize_context_cache();
        return CodecResult<bool>::success(true);
    }

    const auto next_read_secret = derive_next_traffic_secret(*application_space_.read_secret);
    if (!next_read_secret.has_value()) {
        return CodecResult<bool>::failure(next_read_secret.error());
    }

    next_application_read_secret_ = next_read_secret.value();
    next_application_read_secret_source_generation_ = application_read_secret_generation_;
    next_application_read_key_phase_ = !application_read_key_phase_;
    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::ensure_next_application_read_secret() {
    if (!application_space_.read_secret.has_value()) {
        next_application_read_secret_.reset();
        next_application_read_secret_source_generation_.reset();
        return CodecResult<bool>::success(true);
    }

    if (next_application_read_secret_.has_value() &&
        next_application_read_secret_source_generation_.has_value() &&
        next_application_read_secret_source_generation_.value() ==
            application_read_secret_generation_ &&
        next_application_read_key_phase_ == !application_read_key_phase_) {
        return CodecResult<bool>::success(true);
    }

    return refresh_next_application_read_secret();
}

void QuicConnection::promote_next_application_read_secret() {
    application_space_.read_secret = std::move(next_application_read_secret_);
    application_read_key_phase_ = next_application_read_key_phase_;
    ++application_read_secret_generation_;
    next_application_read_secret_.reset();
    next_application_read_secret_source_generation_.reset();
    reset_current_short_header_deserialize_context_cache();
}

CodecResult<DeserializeProtectionContext>
QuicConnection::make_current_short_header_deserialize_context() {
    if (send_profile_enabled()) {
        ++send_profile_counters().make_deserialize_context_calls;
    }
    COQUIC_SEND_PROFILE_TIMER(make_context_timer, make_deserialize_context_ns);

    if (!application_space_.read_secret.has_value()) {
        reset_current_short_header_deserialize_context_cache();
        return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .one_rtt_secret_ref = nullptr,
            .one_rtt_secret_cache_primed = false,
            .one_rtt_key_phase = application_read_key_phase_,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
            .accept_greased_quic_bit = static_cast<bool>(
                config_.transport.grease_quic_bit | local_transport_parameters_.grease_quic_bit),
        });
    }

    const auto *secret = &application_space_.read_secret.value();
    auto destination_connection_id_length = config_.source_connection_id.size();
    bool accept_greased_quic_bit = static_cast<bool>(config_.transport.grease_quic_bit |
                                                     local_transport_parameters_.grease_quic_bit);
    bool cache_matches =
        current_short_header_deserialize_cache_.has_value() &&
        current_short_header_deserialize_cache_->secret == secret &&
        current_short_header_deserialize_cache_->secret_generation ==
            application_read_secret_generation_ &&
        current_short_header_deserialize_cache_->key_phase == application_read_key_phase_ &&
        current_short_header_deserialize_cache_->destination_connection_id_length ==
            destination_connection_id_length &&
        current_short_header_deserialize_cache_->accept_greased_quic_bit ==
            accept_greased_quic_bit &&
        current_short_header_deserialize_cache_->secret_cache_primed ==
            traffic_secret_cache_is_primed(application_space_.read_secret);
    if (!cache_matches) {
        const auto one_rtt_ready = prime_traffic_secret_cache(application_space_.read_secret);
        if (!one_rtt_ready.has_value()) {
            reset_current_short_header_deserialize_context_cache();
            return CodecResult<DeserializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                      one_rtt_ready.error().offset);
        }

        current_short_header_deserialize_cache_ = ShortHeaderDeserializeContextCache{
            .secret = secret,
            .secret_generation = application_read_secret_generation_,
            .key_phase = application_read_key_phase_,
            .destination_connection_id_length = destination_connection_id_length,
            .accept_greased_quic_bit = accept_greased_quic_bit,
            .secret_cache_primed = traffic_secret_cache_is_primed(application_space_.read_secret),
        };
    }

    return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
        .peer_role = opposite_role(config_.role),
        .one_rtt_secret_ref = secret,
        .one_rtt_secret_cache_primed = current_short_header_deserialize_cache_->secret_cache_primed,
        .one_rtt_key_phase = application_read_key_phase_,
        .largest_authenticated_application_packet_number =
            application_space_.largest_authenticated_packet_number,
        .one_rtt_destination_connection_id_length = destination_connection_id_length,
        .accept_greased_quic_bit = current_short_header_deserialize_cache_->accept_greased_quic_bit,
    });
}

void QuicConnection::reset_current_short_header_deserialize_context_cache() {
    current_short_header_deserialize_cache_.reset();
}

std::optional<QuicCoreTimePoint>
QuicConnection::previous_application_read_secret_discard_deadline() const {
    if (!previous_application_read_secret_.has_value()) {
        return std::nullopt;
    }
    return previous_application_read_secret_discard_deadline_;
}

void QuicConnection::maybe_discard_previous_application_read_secret(QuicCoreTimePoint now) {
    const auto deadline = previous_application_read_secret_discard_deadline();
    if (!deadline.has_value() || now < *deadline) {
        return;
    }

    previous_application_read_secret_.reset();
    previous_application_read_secret_discard_deadline_.reset();
    static_cast<void>(ensure_next_application_read_secret());
}

void QuicConnection::synchronize_recovery_rtt_state() {
    if (!recovery_rtt_state_.latest_rtt.has_value()) {
        recovery_rtt_state_ = shared_recovery_rtt_state();
    }

    const auto shared_rtt_state = shared_recovery_rtt_state();
    initial_space_.recovery.rtt_state() = shared_rtt_state;
    handshake_space_.recovery.rtt_state() = shared_rtt_state;
    application_space_.recovery.rtt_state() = shared_rtt_state;
}

bool QuicConnection::is_handshake_complete() const {
    return status_ == HandshakeStatus::connected;
}

bool QuicConnection::has_processed_peer_packet() const {
    return processed_peer_packet_;
}

bool QuicConnection::has_failed() const {
    return status_ == HandshakeStatus::failed;
}

bool QuicConnection::close_state_active() const {
    return close_mode_ == QuicConnectionCloseMode::closing ||
           close_mode_ == QuicConnectionCloseMode::draining;
}

bool QuicConnection::terminal_state_expired(QuicCoreTimePoint now) const {
    if (!close_state_active()) {
        return status_ == HandshakeStatus::failed;
    }
    if (!close_deadline_.has_value()) {
        return false;
    }
    return now >= *close_deadline_;
}

void QuicConnection::enter_stateless_reset_draining(QuicCoreTimePoint now) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
    // # If the last 16 bytes of the datagram are identical in value to a
    // # stateless reset token, the endpoint MUST enter the draining period and
    // # not send any further packets on this connection.
    enter_draining_state(now);
}

void QuicConnection::start_client_if_needed() {
    start_client_if_needed(QuicCoreTimePoint{});
}

void QuicConnection::start_client_if_needed(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::client || started_) {
        return;
    }

    maybe_open_qlog_session(now, config_.original_destination_connection_id.value_or(
                                     client_initial_destination_connection_id()));
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = false;
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
        .version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_),
        .max_datagram_frame_size = config_.transport.max_datagram_frame_size,
        .grease_quic_bit = config_.transport.grease_quic_bit,
    };
    initialize_local_flow_control();

    auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = std::nullopt,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_client_transport_parameters",
                          serialized_transport_parameters.error());
        queue_transport_close_for_error(now, serialized_transport_parameters.error());
        return;
    }

    std::optional<std::vector<std::byte>> tls_resumption_state;
    bool enable_zero_rtt_attempt = false;
    if (config_.resumption_state.has_value()) {
        decoded_resumption_state_ = decode_resumption_state(config_.resumption_state->serialized);
        if (decoded_resumption_state_.has_value()) {
            tls_resumption_state = decoded_resumption_state_->tls_state;
            enable_zero_rtt_attempt =
                config_.zero_rtt.attempt &
                (decoded_resumption_state_->quic_version == current_version_) &
                (decoded_resumption_state_->application_protocol == config_.application_protocol) &
                (decoded_resumption_state_->application_context ==
                 config_.zero_rtt.application_context);
            if (enable_zero_rtt_attempt) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
                // # A client that attempts to send 0-RTT data MUST remember
                // # all other transport parameters used by the server that it
                // # is able to process.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
                // # When sending frames in 0-RTT packets, a client MUST only
                // # use remembered transport parameters; importantly, it MUST
                // # NOT use updated values that it learns from the server's
                // # updated transport parameters or from frames received in
                // # 1-RTT packets.
                peer_transport_parameters_ = decoded_resumption_state_->peer_transport_parameters;
                note_endpoint_route_state_changed();
                initialize_peer_flow_control_from_transport_parameters();
            } else if (config_.zero_rtt.attempt) {
                pending_zero_rtt_status_event_ =
                    QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::unavailable};
            }
        }
        const bool report_unavailable_zero_rtt_attempt =
            !decoded_resumption_state_.has_value() && config_.zero_rtt.attempt;
        if (report_unavailable_zero_rtt_attempt) {
            pending_zero_rtt_status_event_ =
                QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::unavailable};
        }
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
        .resumption_state = std::move(tls_resumption_state),
        .attempt_zero_rtt = enable_zero_rtt_attempt,
        .accept_zero_rtt = false,
        .zero_rtt_context = config_.zero_rtt.application_context,
        .tls_keylog_path = config_.tls_keylog_path,
    });
    auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        queue_transport_close_for_error(now, tls_started.error());
        return;
    }

    static_cast<void>(sync_tls_state().value());
    emit_local_qlog_startup_events(now);
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id,
    std::uint32_t client_initial_version) {
    start_server_if_needed(client_initial_destination_connection_id, QuicCoreTimePoint{},
                           client_initial_version);
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id, QuicCoreTimePoint now,
    std::uint32_t client_initial_version) {
    if (started_) {
        return;
    }

    maybe_open_qlog_session(now, config_.original_destination_connection_id.value_or(
                                     client_initial_destination_connection_id));
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = false;
    original_version_ = client_initial_version;
    if (config_.retry_source_connection_id.has_value()) {
        current_version_ = client_initial_version;
    } else {
        current_version_ =
            select_server_version(config_.supported_versions, client_initial_version);
    }
    client_initial_destination_connection_id_ = client_initial_destination_connection_id;
    const auto original_destination_connection_id =
        config_.original_destination_connection_id.value_or(
            client_initial_destination_connection_id);
    local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = original_destination_connection_id,
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .stateless_reset_token = local_connection_ids_[0].stateless_reset_token,
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
        .retry_source_connection_id = config_.retry_source_connection_id,
        .preferred_address = config_.transport.preferred_address,
        .version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_),
        .max_datagram_frame_size = config_.transport.max_datagram_frame_size,
        .grease_quic_bit = config_.transport.grease_quic_bit,
    };
    initialize_local_flow_control();

    auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = original_destination_connection_id,
            .expected_retry_source_connection_id = config_.retry_source_connection_id,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_server_transport_parameters",
                          serialized_transport_parameters.error());
        queue_transport_close_for_error(now, serialized_transport_parameters.error());
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
        .accept_zero_rtt = config_.zero_rtt.allow,
        .zero_rtt_context = config_.zero_rtt.application_context,
        .tls_keylog_path = config_.tls_keylog_path,
    });
    auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        queue_transport_close_for_error(now, tls_started.error());
        return;
    }
    static_cast<void>(sync_tls_state().value());
    emit_local_qlog_startup_events(now);

    if (!config_.retry_source_connection_id.has_value()) {
        anti_amplification_received_bytes_ +=
            static_cast<std::uint64_t>(anti_amplification_received_bytes_ == 0) *
            kMinimumInitialDatagramSize;
    }
    if (config_.retry_source_connection_id.has_value()) {
        mark_peer_address_validated();
    }
}

} // namespace coquic::quic

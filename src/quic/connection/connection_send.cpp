#include "src/quic/connection/connection.h"
#include "src/quic/connection/connection_internal.h"

namespace coquic::quic {

struct PendingPathValidationFrames {
    QuicPathId path_id = 0;
    std::optional<PathResponseFrame> response;
    std::optional<PathChallengeFrame> challenge;
};

bool path_validation_needs_minimum_datagram(
    const PendingPathValidationFrames &path_validation_frames,
    const std::map<QuicPathId, PathState> &paths) {
    if (path_validation_frames.response.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
        // # An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame
        // # to at least the smallest allowed maximum datagram size of 1200 bytes.
        return true;
    }
    if (!path_validation_frames.challenge.has_value()) {
        return false;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
    // # An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
    // # to at least the smallest allowed maximum datagram size of 1200 bytes,
    // # unless the anti-amplification limit for the path does not permit
    // # sending a datagram of this size.
    const auto path = paths.find(path_validation_frames.path_id);
    return path != paths.end() &&
           (!path->second.validated || path->second.path_mtu_validation_pending);
}

std::optional<QuicPathId>
path_challenge_path_id(const PendingPathValidationFrames &path_validation_frames) {
    if (!path_validation_frames.challenge.has_value()) {
        return std::nullopt;
    }
    return path_validation_frames.path_id;
}

std::optional<QuicPathId>
path_validation_frame_path_id(const PendingPathValidationFrames &path_validation_frames) {
    if (!path_validation_frames.response.has_value() &&
        !path_validation_frames.challenge.has_value()) {
        return std::nullopt;
    }
    return path_validation_frames.path_id;
}

std::optional<QuicPathId>
send_path_for_path_validation_frames(const PendingPathValidationFrames &path_validation_frames,
                                     const std::optional<QuicPathId> &current_send_path_id) {
    const auto validation_path_id = path_validation_frame_path_id(path_validation_frames);
    return validation_path_id.has_value() ? validation_path_id : current_send_path_id;
}

bool stream_terminal_data_fin_can_be_split(const StreamFrameSendFragment &fragment,
                                           std::size_t datagram_size_limit,
                                           std::size_t datagram_size) {
    if (!fragment.fin || fragment.bytes.empty()) {
        return false;
    }
    if (datagram_size_limit < kMinimumInitialDatagramSize ||
        datagram_size >= kMinimumInitialDatagramSize) {
        return false;
    }
    return saturating_add(fragment.offset, fragment.bytes.size()) >= kMinimumInitialDatagramSize;
}

void mark_stream_terminal_fin_pending(std::map<std::uint64_t, StreamState> &streams,
                                      std::uint64_t stream_id) {
    const auto stream = streams.find(stream_id);
    if (stream == streams.end()) {
        return;
    }
    if (stream->second.send_fin_state == StreamSendFinState::sent) {
        stream->second.send_fin_state = StreamSendFinState::pending;
    }
}

std::span<const Frame> selectable_application_crypto_frames(bool send_application_close_only,
                                                            const std::vector<Frame> &frames) {
    if (send_application_close_only) {
        return {};
    }
    return std::span<const Frame>(frames);
}

void append_application_ack_frame(std::vector<Frame> &frame_list,
                                  const ReceivedPacketHistory &received_packets,
                                  const std::optional<OutboundAckHeader> &ack_header) {
    if (!ack_header.has_value()) {
        return;
    }
    frame_list.emplace_back(OutboundAckFrame{
        .history = &received_packets,
        .header = *ack_header,
    });
}

std::span<const Frame> build_application_candidate_frames(
    std::vector<Frame> &candidate_frames, const ReceivedPacketHistory &received_packets,
    std::span<const Frame> crypto_frames, bool include_handshake_done,
    const std::optional<OutboundAckHeader> &candidate_ack_header,
    const std::optional<MaxDataFrame> &candidate_max_data_frame,
    std::span<const NewTokenFrame> new_token_frames,
    std::span<const NewConnectionIdFrame> new_connection_id_frames,
    std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
    const PendingPathValidationFrames &candidate_path_validation_frames,
    std::span<const MaxStreamDataFrame> max_stream_data_frames,
    std::span<const MaxStreamsFrame> max_streams_frames,
    std::span<const StreamsBlockedFrame> streams_blocked_frames,
    std::span<const ResetStreamFrame> reset_stream_frames,
    std::span<const StopSendingFrame> stop_sending_frames,
    const std::optional<DataBlockedFrame> &data_blocked_frame,
    std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
    const std::optional<DatagramFrame> &datagram_frame,
    const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
    bool include_ping) {
    candidate_frames.clear();
    candidate_frames.reserve(
        crypto_frames.size() + (candidate_ack_header.has_value() ? 1u : 0u) +
        (include_handshake_done ? 1u : 0u) + (candidate_max_data_frame.has_value() ? 1u : 0u) +
        new_token_frames.size() + new_connection_id_frames.size() +
        retire_connection_id_frames.size() +
        static_cast<std::size_t>(candidate_path_validation_frames.response.has_value()) +
        static_cast<std::size_t>(candidate_path_validation_frames.challenge.has_value()) +
        max_stream_data_frames.size() + max_streams_frames.size() + reset_stream_frames.size() +
        streams_blocked_frames.size() + stop_sending_frames.size() +
        (data_blocked_frame.has_value() ? 1u : 0u) + stream_data_blocked_frames.size() +
        (datagram_frame.has_value() ? 1u : 0u) + (application_close_frame.has_value() ? 1u : 0u) +
        (include_ping ? 1u : 0u));
    candidate_frames.insert(candidate_frames.end(), crypto_frames.begin(), crypto_frames.end());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
    // # An endpoint SHOULD send an ACK frame with other frames when there are
    // # new ack-eliciting packets to acknowledge.
    append_application_ack_frame(candidate_frames, received_packets, candidate_ack_header);
    if (include_handshake_done) {
        candidate_frames.emplace_back(HandshakeDoneFrame{});
    }
    if (candidate_max_data_frame.has_value()) {
        candidate_frames.emplace_back(*candidate_max_data_frame);
    }
    for (const auto &frame : new_token_frames) {
        candidate_frames.emplace_back(frame);
    }
    for (const auto &frame : new_connection_id_frames) {
        candidate_frames.emplace_back(frame);
    }
    for (const auto &frame : retire_connection_id_frames) {
        candidate_frames.emplace_back(frame);
    }
    if (candidate_path_validation_frames.response.has_value()) {
        candidate_frames.emplace_back(*candidate_path_validation_frames.response);
    }
    if (candidate_path_validation_frames.challenge.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
        // # However, an endpoint SHOULD NOT send multiple PATH_CHALLENGE frames in
        // # a single packet.
        candidate_frames.emplace_back(*candidate_path_validation_frames.challenge);
    }
    for (const auto &frame : max_stream_data_frames) {
        candidate_frames.emplace_back(frame);
    }
    for (const auto &frame : max_streams_frames) {
        candidate_frames.emplace_back(frame);
    }
    for (const auto &frame : streams_blocked_frames) {
        candidate_frames.emplace_back(frame);
    }
    for (const auto &frame : reset_stream_frames) {
        candidate_frames.emplace_back(frame);
    }
    for (const auto &frame : stop_sending_frames) {
        candidate_frames.emplace_back(frame);
    }
    if (data_blocked_frame.has_value()) {
        candidate_frames.emplace_back(*data_blocked_frame);
    }
    for (const auto &frame : stream_data_blocked_frames) {
        candidate_frames.emplace_back(frame);
    }
    if (datagram_frame.has_value()) {
        candidate_frames.emplace_back(*datagram_frame);
    }
    if (application_close_frame.has_value()) {
        candidate_frames.emplace_back(*application_close_frame);
    }
    if (include_ping) {
        candidate_frames.emplace_back(PingFrame{});
    }
    return std::span<const Frame>(candidate_frames);
}

class ApplicationCandidateFrameCache {
  public:
    void invalidate() {
        candidate_frames_valid_ = false;
        candidate_frames_ = {};
    }

    std::span<const Frame>
    current(std::vector<Frame> &scratch, const ReceivedPacketHistory &received_packets,
            std::span<const Frame> crypto_frames, bool include_handshake_done,
            const std::optional<OutboundAckHeader> &candidate_ack_header,
            const std::optional<MaxDataFrame> &candidate_max_data_frame,
            std::span<const NewTokenFrame> new_token_frames,
            std::span<const NewConnectionIdFrame> new_connection_id_frames,
            std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
            const PendingPathValidationFrames &candidate_path_validation_frames,
            std::span<const MaxStreamDataFrame> max_stream_data_frames,
            std::span<const MaxStreamsFrame> max_streams_frames,
            std::span<const StreamsBlockedFrame> streams_blocked_frames,
            std::span<const ResetStreamFrame> reset_stream_frames,
            std::span<const StopSendingFrame> stop_sending_frames,
            const std::optional<DataBlockedFrame> &data_blocked_frame,
            std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
            const std::optional<DatagramFrame> &datagram_frame,
            const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
            bool include_ping) {
        if (!candidate_frames_valid_) {
            candidate_frames_ = build_application_candidate_frames(
                scratch, received_packets, crypto_frames, include_handshake_done,
                candidate_ack_header, candidate_max_data_frame, new_token_frames,
                new_connection_id_frames, retire_connection_id_frames,
                candidate_path_validation_frames, max_stream_data_frames, max_streams_frames,
                streams_blocked_frames, reset_stream_frames, stop_sending_frames,
                data_blocked_frame, stream_data_blocked_frames, datagram_frame,
                application_close_frame, include_ping);
            candidate_frames_valid_ = true;
        }
        return candidate_frames_;
    }

  private:
    std::span<const Frame> candidate_frames_;
    bool candidate_frames_valid_ = false;
};

class ApplicationCandidateFrameBuilder {
  public:
    struct Args {
        std::vector<Frame> &scratch;
        std::vector<Frame> &alternate_scratch;
        const ReceivedPacketHistory &received_packets;
        std::span<const Frame> crypto_frames;
        bool include_handshake_done = false;
        std::optional<OutboundAckHeader> &ack_header;
        std::optional<MaxDataFrame> &max_data_frame;
        std::vector<NewTokenFrame> &new_token_frames;
        std::vector<NewConnectionIdFrame> &new_connection_id_frames;
        std::vector<RetireConnectionIdFrame> &retire_connection_id_frames;
        PendingPathValidationFrames &path_validation_frames;
        std::vector<MaxStreamDataFrame> &max_stream_data_frames;
        std::vector<MaxStreamsFrame> &max_streams_frames;
        std::vector<StreamsBlockedFrame> &streams_blocked_frames;
        std::vector<ResetStreamFrame> &reset_stream_frames;
        std::vector<StopSendingFrame> &stop_sending_frames;
        std::optional<DataBlockedFrame> &data_blocked_frame;
        std::vector<StreamDataBlockedFrame> &stream_data_blocked_frames;
        std::optional<DatagramFrame> &datagram_frame;
        std::optional<ApplicationConnectionCloseFrame> &application_close_frame;
    };

    explicit ApplicationCandidateFrameBuilder(const Args &args)
        : scratch_(args.scratch), alternate_scratch_(args.alternate_scratch),
          received_packets_(args.received_packets), crypto_frames_(args.crypto_frames),
          include_handshake_done_(args.include_handshake_done), ack_header_(args.ack_header),
          max_data_frame_(args.max_data_frame), new_token_frames_(args.new_token_frames),
          new_connection_id_frames_(args.new_connection_id_frames),
          retire_connection_id_frames_(args.retire_connection_id_frames),
          path_validation_frames_(args.path_validation_frames),
          max_stream_data_frames_(args.max_stream_data_frames),
          max_streams_frames_(args.max_streams_frames),
          streams_blocked_frames_(args.streams_blocked_frames),
          reset_stream_frames_(args.reset_stream_frames),
          stop_sending_frames_(args.stop_sending_frames),
          data_blocked_frame_(args.data_blocked_frame),
          stream_data_blocked_frames_(args.stream_data_blocked_frames),
          datagram_frame_(args.datagram_frame),
          application_close_frame_(args.application_close_frame) {
    }

    void invalidate() {
        cache_.invalidate();
    }

    std::span<const Frame> current() {
        return cache_.current(scratch_, received_packets_, crypto_frames_, include_handshake_done_,
                              ack_header_, max_data_frame_, new_token_frames_,
                              new_connection_id_frames_, retire_connection_id_frames_,
                              path_validation_frames_, max_stream_data_frames_, max_streams_frames_,
                              streams_blocked_frames_, reset_stream_frames_, stop_sending_frames_,
                              data_blocked_frame_, stream_data_blocked_frames_, datagram_frame_,
                              application_close_frame_,
                              /*include_ping=*/false);
    }

    std::span<const Frame> alternate(const std::optional<OutboundAckHeader> &ack_header) {
        return build_application_candidate_frames(
            alternate_scratch_, received_packets_, crypto_frames_, include_handshake_done_,
            ack_header, max_data_frame_, new_token_frames_, new_connection_id_frames_,
            retire_connection_id_frames_, path_validation_frames_, max_stream_data_frames_,
            max_streams_frames_, streams_blocked_frames_, reset_stream_frames_,
            stop_sending_frames_, data_blocked_frame_, stream_data_blocked_frames_, datagram_frame_,
            application_close_frame_,
            /*include_ping=*/false);
    }

  private:
    std::vector<Frame> &scratch_;
    std::vector<Frame> &alternate_scratch_;
    const ReceivedPacketHistory &received_packets_;
    std::span<const Frame> crypto_frames_;
    bool include_handshake_done_ = false;
    std::optional<OutboundAckHeader> &ack_header_;
    std::optional<MaxDataFrame> &max_data_frame_;
    std::vector<NewTokenFrame> &new_token_frames_;
    std::vector<NewConnectionIdFrame> &new_connection_id_frames_;
    std::vector<RetireConnectionIdFrame> &retire_connection_id_frames_;
    PendingPathValidationFrames &path_validation_frames_;
    std::vector<MaxStreamDataFrame> &max_stream_data_frames_;
    std::vector<MaxStreamsFrame> &max_streams_frames_;
    std::vector<StreamsBlockedFrame> &streams_blocked_frames_;
    std::vector<ResetStreamFrame> &reset_stream_frames_;
    std::vector<StopSendingFrame> &stop_sending_frames_;
    std::optional<DataBlockedFrame> &data_blocked_frame_;
    std::vector<StreamDataBlockedFrame> &stream_data_blocked_frames_;
    std::optional<DatagramFrame> &datagram_frame_;
    std::optional<ApplicationConnectionCloseFrame> &application_close_frame_;
    ApplicationCandidateFrameCache cache_;
};

std::size_t
QuicConnection::drain_fast_bulk_stream_datagrams(QuicCoreTimePoint now, bool continue_paced_burst,
                                                 std::size_t max_datagrams,
                                                 QuicConnectionDrainedDatagramSink &sink) {
    register_send_profile_printer_once();
    if (max_datagrams == 0) {
        return 0;
    }
    if (status_ != HandshakeStatus::connected || close_mode_ != QuicConnectionCloseMode::none ||
        !started_ || !handshake_confirmed_ || !application_space_.write_secret.has_value() ||
        zero_rtt_space_.write_secret.has_value() || !can_skip_outbound_tls_sync() ||
        !deferred_protected_packets_.empty() || qlog_session_ != nullptr ||
        config_.enable_packet_inspection ||
        packet_trace_matches_connection(config_.source_connection_id) ||
        local_key_update_requested_ || local_key_update_initiated_ ||
        !current_send_path_id_.has_value()) {
        return 0;
    }
    maybe_arm_pmtu_probe(now);
    if (!initial_packet_space_discarded_ || !handshake_packet_space_discarded_ ||
        initial_space_.pending_probe_packet.has_value() ||
        handshake_space_.pending_probe_packet.has_value() ||
        application_space_.pending_probe_packet.has_value() ||
        remaining_pto_probe_datagrams_ != 0 || application_space_.send_crypto.has_pending_data() ||
        application_space_.received_packets.has_ack_to_send() ||
        application_space_.pending_ack_deadline.has_value() || application_space_.force_ack_send ||
        pending_application_close_.has_value() || !pending_new_token_frames_.empty() ||
        !pending_new_connection_id_frames_.empty() ||
        !pending_retire_connection_id_frames_.empty() || !pending_datagram_send_queue_.empty() ||
        handshake_done_state_ == StreamControlFrameState::pending ||
        connection_flow_control_.max_data_state == StreamControlFrameState::pending ||
        connection_flow_control_.data_blocked_state == StreamControlFrameState::pending ||
        local_stream_limit_state_.max_streams_bidi_state == StreamControlFrameState::pending ||
        local_stream_limit_state_.max_streams_uni_state == StreamControlFrameState::pending ||
        stream_open_limits_.streams_blocked_bidi_state == StreamControlFrameState::pending ||
        stream_open_limits_.streams_blocked_uni_state == StreamControlFrameState::pending ||
        streams_have_pending_application_control_send() || streams_have_sendable_fin() ||
        has_lost_application_stream_data() ||
        !simple_stream_congestion_batch_algorithm_is_supported(
            congestion_controller_.algorithm())) {
        return 0;
    }

    auto path_it = paths_.find(*current_send_path_id_);
    if (path_it == paths_.end() || !path_it->second.mtu.viable ||
        path_it->second.pending_response.has_value() || path_it->second.challenge_pending ||
        !path_it->second.validated) {
        return 0;
    }

    const auto max_outbound_datagram_size =
        outbound_datagram_size_limit(/*allow_pmtu_probe_size=*/false);
    if (max_outbound_datagram_size == 0) {
        return 0;
    }
    const auto destination_connection_id =
        outbound_destination_connection_id(current_send_path_id_);
    const auto stream_wire_budget = application_stream_frame_budget(
        max_outbound_datagram_size, destination_connection_id.size(),
        packet_number_length_for_send(application_space_,
                                      application_space_.next_send_packet_number));
    if (stream_wire_budget == 0) {
        return 0;
    }
    const auto minimum_datagram_bytes = minimum_pending_application_datagram_datagram_bytes();
    if (!minimum_datagram_bytes.has_value()) {
        return 0;
    }
    if (!continue_paced_burst) {
        const auto pacing_bytes = application_stream_pacing_deadline_bytes(minimum_datagram_bytes);
        if (!pacing_bytes.has_value()) {
            return 0;
        }
        const auto pacing_deadline = congestion_controller_.next_send_time(*pacing_bytes);
        if (pacing_deadline.has_value() && now < *pacing_deadline) {
            if (send_profile_enabled()) {
                ++send_profile_counters().pacing_blocks;
            }
            return 0;
        }
    }
    if (!non_paced_burst_allows_send(/*ack_eliciting=*/true,
                                     /*bypass_congestion_window=*/false,
                                     /*pacing_controlled=*/std::nullopt)) {
        return 0;
    }

    const auto make_serialize_context = [&]() -> CodecResult<SerializeProtectionContext> {
        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.write_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(handshake_ready.error().code,
                                                                    handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.write_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(zero_rtt_ready.error().code,
                                                                    zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_space_.write_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                    one_rtt_ready.error().offset);
        }

        return CodecResult<SerializeProtectionContext>::success(SerializeProtectionContext{
            .local_role = config_.role,
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .one_rtt_key_phase = application_write_key_phase_,
            .handshake_secret_ref = handshake_space_.write_secret.has_value()
                                        ? &handshake_space_.write_secret.value()
                                        : nullptr,
            .zero_rtt_secret_ref = zero_rtt_space_.write_secret.has_value()
                                       ? &zero_rtt_space_.write_secret.value()
                                       : nullptr,
            .one_rtt_secret_ref = application_space_.write_secret.has_value()
                                      ? &application_space_.write_secret.value()
                                      : nullptr,
            .handshake_secret_cache_primed =
                traffic_secret_cache_is_primed(handshake_space_.write_secret),
            .zero_rtt_secret_cache_primed =
                traffic_secret_cache_is_primed(zero_rtt_space_.write_secret),
            .one_rtt_secret_cache_primed =
                traffic_secret_cache_is_primed(application_space_.write_secret),
            .grease_quic_bit = peer_validated_grease_quic_bit_support(
                config_.transport.grease_quic_bit, peer_transport_parameters_validated_,
                peer_transport_parameters_),
            .grease_quic_bit_seed = grease_quic_bit_seed_,
        });
    };
    auto serialize_context = make_serialize_context();
    if (!serialize_context.has_value()) {
        log_codec_failure("make_fast_bulk_serialize_context", serialize_context.error());
        queue_transport_close_for_error(now, serialize_context.error());
        return 0;
    }

    auto &fragments = application_stream_fragment_scratch_;
    fragments.clear();
    struct FragmentScratchGuard {
        std::vector<StreamFrameSendFragment> &fragments;
        ~FragmentScratchGuard() {
            fragments.clear();
        }
    } fragment_scratch_guard{fragments};
    auto &pending_simple_stream_packets = pending_simple_stream_packet_scratch_;
    pending_simple_stream_packets.clear();
    if (pending_simple_stream_packets.capacity() < max_datagrams) {
        pending_simple_stream_packets.reserve(max_datagrams);
    }
    struct PendingSimpleStreamPacketScratchGuard {
        std::vector<PendingSimpleStreamPacketScratch> &packets;
        ~PendingSimpleStreamPacketScratchGuard() {
            packets.clear();
        }
    } pending_simple_stream_packet_guard{pending_simple_stream_packets};
    const auto flush_pending_simple_stream_packets = [&]() {
        if (pending_simple_stream_packets.empty()) {
            return;
        }
        COQUIC_SEND_PROFILE_TIMER(track_pending_timer, commit_track_pending_ns);
        track_precongested_simple_stream_packets(application_space_, pending_simple_stream_packets);
        pending_simple_stream_packets.clear();
    };
    std::size_t emitted = 0;
    bool stopped_for_sink = false;
    while (emitted < max_datagrams) {
        const auto available_window =
            congestion_controller_.send_window() > congestion_controller_.bytes_in_flight()
                ? congestion_controller_.send_window() - congestion_controller_.bytes_in_flight()
                : std::size_t{0};
        if (available_window < *minimum_datagram_bytes) {
            if (send_profile_enabled()) {
                ++send_profile_counters().congestion_blocks;
            }
            break;
        }
        const auto datagram_limit = std::min(max_outbound_datagram_size, available_window);
        const auto packet_stream_wire_budget = application_stream_frame_budget(
            datagram_limit, destination_connection_id.size(),
            packet_number_length_for_send(application_space_,
                                          application_space_.next_send_packet_number));
        if (packet_stream_wire_budget == 0) {
            break;
        }
        const auto remaining_connection_credit = saturating_subtract(
            connection_flow_control_.peer_max_data, connection_flow_control_.highest_sent);
        if (remaining_connection_credit == 0 || cached_fresh_sendable_stream_bytes() == 0) {
            break;
        }

        auto selected = streams_.end();
        const auto visit_range = [&](auto begin, auto end) {
            for (auto it = begin; it != end; ++it) {
                auto &stream = it->second;
                if (stream.reset_state == StreamControlFrameState::none &&
                    stream.sendable_bytes() != 0 && !stream.send_buffer.has_lost_data() &&
                    !stream_fin_sendable(stream)) {
                    selected = it;
                    return false;
                }
            }
            return true;
        };
        if (last_application_send_stream_id_.has_value()) {
            const auto start = config_.transport.send_stream_fairness
                                   ? streams_.upper_bound(*last_application_send_stream_id_)
                                   : streams_.lower_bound(*last_application_send_stream_id_);
            if (visit_range(start, streams_.end())) {
                static_cast<void>(visit_range(streams_.begin(), start));
            }
        } else {
            static_cast<void>(visit_range(streams_.begin(), streams_.end()));
        }
        if (selected == streams_.end()) {
            break;
        }

        fragments.clear();
        auto &stream = selected->second;
        const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream);
        const auto previous_has_lost_send_data = false;
        const auto highest_sent_before = stream.flow_control.highest_sent;
        const auto packet_payload_budget = std::min<std::uint64_t>(
            remaining_connection_credit,
            max_stream_frame_payload_for_wire_budget(
                selected->first, stream.flow_control.highest_sent, packet_stream_wire_budget));
        if (packet_payload_budget == 0) {
            break;
        }
        stream.append_send_fragments(
            StreamSendBudget{
                .packet_bytes = static_cast<std::size_t>(packet_payload_budget),
                .new_bytes = packet_payload_budget,
                .prefer_fresh_data = true,
            },
            fragments);
        const auto new_bytes_sent = stream.flow_control.highest_sent - highest_sent_before;
        connection_flow_control_.highest_sent += new_bytes_sent;
        note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                       stream);
        if (fragments.empty() || new_bytes_sent == 0) {
            break;
        }

        const auto packet_number = reserve_packet_number(application_space_);
        if (!packet_number.has_value()) {
            for (const auto &fragment : fragments) {
                stream.restore_send_fragment(fragment);
            }
            connection_flow_control_.highest_sent -= new_bytes_sent;
            break;
        }
        if (!current_write_phase_first_packet_number_.has_value()) {
            current_write_phase_first_packet_number_ = packet_number;
        }
        const auto packet_number_length =
            packet_number_length_for_send(application_space_, *packet_number);
        DatagramBuffer datagram;
        auto serialized_packet_length = CodecResult<std::size_t>::success(0);
        {
            if (send_profile_enabled()) {
                ++send_profile_counters().serialize_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(serialize_timer, serialize_ns);
            serialized_packet_length = append_protected_one_rtt_stream_fragment_packet_to_datagram(
                datagram, outbound_spin_bit_for_path(current_send_path_id_),
                application_write_key_phase_, destination_connection_id, packet_number_length,
                *packet_number, fragments.front(), serialize_context.value());
        }
        if (!serialized_packet_length.has_value()) {
            log_codec_failure("append_protected_one_rtt_packet_to_datagram",
                              serialized_packet_length.error());
            mark_failed();
            break;
        }
        if (fragments.size() == 1 &&
            stream_terminal_data_fin_can_be_split(fragments.front(), max_outbound_datagram_size,
                                                  datagram.size())) {
            fragments.front().fin = false;
            fragments.front().prime_stream_frame_header_cache();
            mark_stream_terminal_fin_pending(streams_, fragments.front().stream_id);

            datagram.clear();
            if (send_profile_enabled()) {
                ++send_profile_counters().serialize_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(split_serialize_timer, serialize_ns);
            serialized_packet_length = append_protected_one_rtt_stream_fragment_packet_to_datagram(
                datagram, outbound_spin_bit_for_path(current_send_path_id_),
                application_write_key_phase_, destination_connection_id, packet_number_length,
                *packet_number, fragments.front(), serialize_context.value());
            if (!serialized_packet_length.has_value()) {
                log_codec_failure("append_split_fin_one_rtt_packet_to_datagram",
                                  serialized_packet_length.error());
                mark_failed();
                break;
            }
        }
        if (datagram.empty() || datagram.size() > max_outbound_datagram_size) {
            mark_failed();
            break;
        }
        if (!note_aead_encryption_attempt(1, now)) {
            break;
        }

        const auto ecn = outbound_ecn_codepoint_for_path(current_send_path_id_);
        PendingSimpleStreamPacketScratch pending_packet{
            .packet_space = &application_space_,
            .packet_number = *packet_number,
            .sent_time = now,
            .first_stream_frame_metadata = stream_frame_send_metadata(fragments.front()),
            .packet_index = 0,
            .fallback_packet_length = serialized_packet_length.value(),
            .path_id = current_send_path_id_.value_or(0),
            .ecn = ecn,
            .protection_key_update_generation = current_application_write_key_generation_,
            .bytes_in_flight = serialized_packet_length.value(),
        };
        pending_packet.stream_frame_metadata.reserve(fragments.size() - 1);
        for (const auto &fragment :
             std::span<const StreamFrameSendFragment>(fragments).subspan(1)) {
            pending_packet.stream_frame_metadata.push_back(stream_frame_send_metadata(fragment));
        }
        const bool fast_bulk_has_pending_stream_work =
            cached_fresh_sendable_stream_bytes() != 0 &&
            saturating_subtract(connection_flow_control_.peer_max_data,
                                connection_flow_control_.highest_sent) != 0;
        const auto app_limited = congestion_controller_.would_underutilize_congestion_window(
                                     pending_packet.bytes_in_flight) &&
                                 !fast_bulk_has_pending_stream_work;
        {
            COQUIC_SEND_PROFILE_TIMER(congestion_timer, track_sent_congestion_ns);
            pending_packet.congestion_result = congestion_controller_.on_simple_stream_packet_sent(
                pending_packet.bytes_in_flight, pending_packet.sent_time, app_limited);
        }
        pending_simple_stream_packets.push_back(std::move(pending_packet));

        note_idle_ack_eliciting_send(now);
        note_burst_limited_ack_eliciting_send(1, /*bypass_congestion_window=*/false,
                                              /*pacing_controlled=*/std::nullopt);
        note_outbound_datagram_bytes(datagram.size(), current_send_path_id_, now);
        last_drained_path_id_ = current_send_path_id_;
        last_drained_ecn_codepoint_ = ecn;
        last_drained_is_pmtu_probe_ = false;
        last_drained_packet_inspection_datagram_id_ = 0;
        last_application_send_stream_id_ = selected->first;
        last_drained_allows_send_continuation_ =
            send_continuation_allowed(fast_bulk_has_pending_stream_work,
                                      /*bypass_burst_limit=*/false, 1);
        if (last_drained_allows_send_continuation_) {
            last_send_continuation_time_ = now;
        } else {
            last_send_continuation_time_.reset();
        }
        if (send_profile_enabled()) {
            auto &profile = send_profile_counters();
            ++profile.datagrams;
            profile.bytes += datagram.size();
            profile.stream_bytes += new_bytes_sent;
            profile.max_datagram = std::max<std::uint64_t>(profile.max_datagram, datagram.size());
            profile.datagrams_le_1200 += static_cast<std::uint64_t>(datagram.size() <= 1200);
            profile.datagrams_le_1434 += static_cast<std::uint64_t>(datagram.size() <= 1434);
            profile.datagrams_le_1472 += static_cast<std::uint64_t>(datagram.size() <= 1472);
            profile.datagrams_gt_1472 += static_cast<std::uint64_t>(datagram.size() > 1472);
            if (last_drained_allows_send_continuation_) {
                ++profile.continuation_allowed;
            }
        }

        if (!sink.on_connection_datagram(QuicConnectionDrainedDatagram{
                .bytes = std::move(datagram),
                .path_id = current_send_path_id_,
                .ecn = ecn,
                .is_pmtu_probe = false,
                .packet_inspection_datagram_id = 0,
            })) {
            stopped_for_sink = true;
            ++emitted;
            break;
        }
        ++emitted;
        if (has_failed() || !last_drained_allows_send_continuation_) {
            break;
        }
    }

    flush_pending_simple_stream_packets();
    if (emitted == 0) {
        last_drained_allows_send_continuation_ = false;
        last_send_continuation_time_.reset();
    }
    if (stopped_for_sink) {
        last_drained_allows_send_continuation_ = false;
        last_send_continuation_time_.reset();
    }
    return emitted;
}

DatagramBuffer QuicConnection::flush_outbound_datagram(QuicCoreTimePoint now,
                                                       bool continue_paced_burst) {
    register_send_profile_printer_once();
    if (send_profile_enabled()) {
        ++send_profile_counters().drain_calls;
    }
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.2
        // # An endpoint MUST NOT send further packets.
        return {};
    }
    maybe_arm_pmtu_probe(now);
    const auto pmtu_probe_pending = application_space_.pending_probe_packet.has_value() &&
                                    application_space_.pending_probe_packet->is_pmtu_probe;
    const bool pending_application_send_on_entry = has_pending_application_send();
    const auto max_outbound_datagram_size =
        outbound_datagram_size_limit(!pending_application_send_on_entry);
    const auto pmtu_probe_datagram_size_limit =
        pmtu_probe_pending ? outbound_datagram_size_limit(/*allow_pmtu_probe_size=*/true)
                           : max_outbound_datagram_size;
    const bool traces_this_connection =
        packet_trace_matches_connection(config_.source_connection_id);
    if (max_outbound_datagram_size == 0) {
        if (traces_this_connection) {
            const auto *current_path = find_path_state(paths_, current_send_path_id_);
            const std::string_view blocked_reason =
                current_path != nullptr && !current_path->mtu.viable ? "pmtu-below-minimum"
                                                                     : "amp-budget-zero";
            std::cerr << "quic-packet-trace send-blocked scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " reason=" << blocked_reason
                      << " current=" << format_optional_path_id(current_send_path_id_)
                      << " previous=" << format_optional_path_id(previous_path_id_)
                      << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                      << " current_path={" << format_path_state_summary(current_path)
                      << "} inbound_path={"
                      << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                      << "} pending_send=" << static_cast<int>(pending_application_send_on_entry)
                      << " probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << '\n';
        }
        return {};
    }

    if (config_.role == EndpointRole::client && application_space_.write_secret.has_value() &&
        zero_rtt_space_.write_secret.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.3
        // # Therefore, a client SHOULD discard 0-RTT keys as soon as it
        // # installs 1-RTT keys as they have no use after that moment.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
        // # Once a client has installed 1-RTT keys, it MUST NOT send any more
        // # 0-RTT packets.
        discard_packet_space_state(zero_rtt_space_);
    }
    queue_client_handshake_recovery_probe();

    auto packets = std::vector<ProtectedPacket>{};
    auto selected_send_path_id = current_send_path_id_;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
    // # Senders MUST NOT coalesce QUIC packets with different connection IDs
    // # into a single UDP datagram.
    auto send_destination_connection_id = outbound_destination_connection_id();
    const auto application_destination_connection_id = [&]() {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
        // # Senders MUST NOT coalesce QUIC packets with different connection IDs
        // # into a single UDP datagram.
        return outbound_destination_connection_id(selected_send_path_id);
    };
    bool duplicate_first_compatible_server_initial_crypto =
        !initial_packet_space_discarded_ & (config_.role == EndpointRole::server) &
        (original_version_ != current_version_) & (initial_space_.next_send_packet_number == 0) &
        (handshake_space_.next_send_packet_number == 0);
    bool initial_probe_pending =
        !initial_packet_space_discarded_ && initial_space_.pending_probe_packet.has_value();
    bool handshake_probe_pending =
        !handshake_packet_space_discarded_ && handshake_space_.pending_probe_packet.has_value();
    bool application_probe_pending = application_space_.pending_probe_packet.has_value();
    auto pto_probe_burst_active =
        (remaining_pto_probe_datagrams_ > 0) &
        (initial_probe_pending | handshake_probe_pending | application_probe_pending);
    auto preserve_pto_probe_packets = pto_probe_burst_active && remaining_pto_probe_datagrams_ > 1;
    bool track_client_handshake_keepalive_probes = (config_.role == EndpointRole::client) &
                                                   (status_ == HandshakeStatus::in_progress) &
                                                   !handshake_confirmed_;
    bool track_client_receive_keepalive_probes =
        (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::connected);
    const auto clear_probe_packet_after_send =
        [&](std::optional<SentPacketRecord> &pending_probe_packet) {
            if (pending_probe_packet.has_value() && !preserve_pto_probe_packets) {
                pending_probe_packet = std::nullopt;
            }
        };
    const auto note_client_handshake_keepalive_probe = [&](const SentPacketRecord &packet_record) {
        if (!packet_record.has_ping || retransmittable_probe_frame_count(packet_record) != 0) {
            return;
        }

        last_client_handshake_keepalive_probe_time_ = now;
    };
    auto &pending_tracked_packets = pending_tracked_packet_scratch_;
    auto &pending_simple_stream_packets = pending_simple_stream_packet_scratch_;
    pending_tracked_packets.clear();
    pending_simple_stream_packets.clear();
    if (pending_tracked_packets.capacity() < 4) {
        pending_tracked_packets.reserve(4);
    }
    if (pending_simple_stream_packets.capacity() < 4) {
        pending_simple_stream_packets.reserve(4);
    }
    struct PendingTrackedPacketScratchGuard {
        std::vector<PendingTrackedPacketScratch> &packets;
        std::vector<PendingSimpleStreamPacketScratch> &simple_stream_packets;
        ~PendingTrackedPacketScratchGuard() {
            packets.clear();
            simple_stream_packets.clear();
        }
    } pending_tracked_packets_guard{pending_tracked_packets, pending_simple_stream_packets};
    const auto queue_tracked_packet_at_index =
        [&](PacketSpaceState &packet_space, SentPacketRecord packet, std::size_t packet_index,
            std::size_t fallback_packet_length) {
            pending_tracked_packets.push_back(PendingTrackedPacketScratch{
                .packet_space = &packet_space,
                .packet = std::move(packet),
                .packet_index = packet_index,
                .fallback_packet_length = fallback_packet_length,
            });
        };
    const auto queue_simple_stream_packet_at_index =
        [&](PacketSpaceState &packet_space, std::uint64_t packet_number,
            std::span<const StreamFrameSendFragment> fragments, std::size_t packet_index,
            std::size_t fallback_packet_length, QuicPathId path_id, QuicEcnCodepoint ecn,
            std::uint64_t protection_key_update_generation) {
            PendingSimpleStreamPacketScratch packet{
                .packet_space = &packet_space,
                .packet_number = packet_number,
                .sent_time = now,
                .packet_index = packet_index,
                .fallback_packet_length = fallback_packet_length,
                .path_id = path_id,
                .ecn = ecn,
                .protection_key_update_generation = protection_key_update_generation,
            };
            if (!fragments.empty()) {
                packet.first_stream_frame_metadata = stream_frame_send_metadata(fragments.front());
                packet.stream_frame_metadata.reserve(fragments.size() - 1);
                for (const auto &fragment : fragments.subspan(1)) {
                    packet.stream_frame_metadata.push_back(stream_frame_send_metadata(fragment));
                }
            }
            pending_simple_stream_packets.push_back(std::move(packet));
        };
    auto queue_tracked_packet = [&](PacketSpaceState &packet_space, SentPacketRecord packet,
                                    std::size_t fallback_packet_length) {
        queue_tracked_packet_at_index(packet_space, std::move(packet), packets.size() - 1,
                                      fallback_packet_length);
    };
    const auto track_pending_packets = [&](auto &&packet_length_for_pending,
                                           std::optional<std::size_t> datagram_size =
                                               std::nullopt) -> bool {
        for (auto &pending : pending_simple_stream_packets) {
            const auto packet_length = packet_length_for_pending(pending);
            if (!packet_length.has_value()) {
                return false;
            }
            pending.bytes_in_flight = *packet_length;
        }
        for (auto &pending : pending_tracked_packets) {
            const auto packet_length = packet_length_for_pending(pending);
            if (!packet_length.has_value()) {
                return false;
            }

            auto packet_record = std::move(pending.packet);
            packet_record.bytes_in_flight =
                *packet_length *
                static_cast<std::size_t>(packet_record.ack_eliciting & packet_record.in_flight);
            const auto pmtu_probe_size = prepare_pmtu_probe_packet_for_tracking(
                packet_record, datagram_size, *packet_length);
            maybe_note_pmtu_probe_sent_for_tracking(pmtu_probe_size, packet_record);
            track_sent_packet(*pending.packet_space, std::move(packet_record));
        }
        for (auto &pending : pending_simple_stream_packets) {
            track_sent_simple_stream_packet(*pending.packet_space, std::move(pending));
        }
        pending_tracked_packets.clear();
        pending_simple_stream_packets.clear();
        return true;
    };
    const auto track_pending_packets_from_datagram =
        [&](const SerializedProtectedDatagram &datagram) -> bool {
        return track_pending_packets(
            [&](const auto &pending) {
                if (connection_drain_test_hooks().force_missing_packet_metadata |
                    (pending.packet_index >= datagram.packet_metadata.size())) {
                    return std::optional<std::size_t>{};
                }
                return std::optional<std::size_t>{
                    datagram.packet_metadata[pending.packet_index].length,
                };
            },
            datagram.bytes.size());
    };
    const auto preserve_pending_tracked_packets = [&]() -> bool {
        return track_pending_packets([&](const auto &pending) {
            if (connection_drain_test_hooks().force_missing_fallback_packet_length |
                (pending.fallback_packet_length == 0)) {
                return std::optional<std::size_t>{};
            }
            return std::optional<std::size_t>{pending.fallback_packet_length};
        });
    };
    const auto has_pending_tracked_packet = [&]() {
        return !pending_tracked_packets.empty() || !pending_simple_stream_packets.empty();
    };
    const auto congestion_blocks_datagram = [&](std::size_t bytes, bool skips_congestion_window) {
        if (skips_congestion_window) {
            return false;
        }
        if (!congestion_controller_.can_send_ack_eliciting(bytes)) {
            return true;
        }
        const auto next_pacing_deadline = congestion_controller_.next_send_time(bytes);
        return static_cast<bool>(next_pacing_deadline.has_value() &
                                 (now < next_pacing_deadline.value_or(now)));
    };
    bool defer_server_compatible_negotiation_crypto = (config_.role == EndpointRole::server) &&
                                                      (original_version_ != current_version_) &&
                                                      !peer_transport_parameters_validated_;
    //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
    // # Before the server is able to process transport parameters from the
    // # client, it might need to respond to Initial packets from the client.
    // # For these packets, the server uses the original version.
    //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
    // # Once the client has learned the negotiated version, it SHOULD send
    // # subsequent Initial packets using that version.
    auto initial_packet_version =
        defer_server_compatible_negotiation_crypto ? original_version_ : current_version_;
    static const std::vector<std::byte> kEmptyInitialToken;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.2
    // # Initial packets sent by the server MUST set the Token Length field
    // # to 0; clients that receive an Initial packet with a non-zero Token
    // # Length field MUST either discard the packet or generate a connection
    // # error of type PROTOCOL_VIOLATION.
    const std::vector<std::byte> &initial_token =
        config_.role == EndpointRole::client ? config_.retry_token : kEmptyInitialToken;
    std::optional<SerializeProtectionContext> cached_serialize_context;
    const auto reset_serialize_context_cache = [&]() { cached_serialize_context.reset(); };
    const auto make_serialize_context = [&]() -> CodecResult<SerializeProtectionContext> {
        if (cached_serialize_context.has_value()) {
            return CodecResult<SerializeProtectionContext>::success(*cached_serialize_context);
        }

        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.write_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(handshake_ready.error().code,
                                                                    handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.write_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(zero_rtt_ready.error().code,
                                                                    zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_space_.write_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                    one_rtt_ready.error().offset);
        }

        cached_serialize_context = SerializeProtectionContext{
            .local_role = config_.role,
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .one_rtt_key_phase = application_write_key_phase_,
            .handshake_secret_ref = handshake_space_.write_secret.has_value()
                                        ? &handshake_space_.write_secret.value()
                                        : nullptr,
            .zero_rtt_secret_ref = zero_rtt_space_.write_secret.has_value()
                                       ? &zero_rtt_space_.write_secret.value()
                                       : nullptr,
            .one_rtt_secret_ref = application_space_.write_secret.has_value()
                                      ? &application_space_.write_secret.value()
                                      : nullptr,
            .handshake_secret_cache_primed =
                traffic_secret_cache_is_primed(handshake_space_.write_secret),
            .zero_rtt_secret_cache_primed =
                traffic_secret_cache_is_primed(zero_rtt_space_.write_secret),
            .one_rtt_secret_cache_primed =
                traffic_secret_cache_is_primed(application_space_.write_secret),
            .grease_quic_bit = peer_validated_grease_quic_bit_support(
                config_.transport.grease_quic_bit, peer_transport_parameters_validated_,
                peer_transport_parameters_),
            .grease_quic_bit_seed = grease_quic_bit_seed_,
        };
        return CodecResult<SerializeProtectionContext>::success(*cached_serialize_context);
    };

    const auto serialize_candidate_datagram_with_metadata =
        [&](const std::vector<ProtectedPacket> &candidate_packets,
            const ProtectedPacket *appended_packet = nullptr,
            const ProtectedOneRttPacketFragmentView *appended_one_rtt_fragment_packet =
                nullptr) -> CodecResult<SerializedProtectedDatagram> {
        if (send_profile_enabled()) {
            ++send_profile_counters().serialize_calls;
        }
        COQUIC_SEND_PROFILE_TIMER(serialize_timer, serialize_ns);
        const auto context = make_serialize_context();
        if (!context.has_value()) {
            return CodecResult<SerializedProtectedDatagram>::failure(context.error().code,
                                                                     context.error().offset);
        }
        const auto *datagram_packets = &candidate_packets;
        std::optional<std::vector<ProtectedPacket>> mutable_datagram_packets;

        const auto serialize_datagram = [&](const SerializeProtectionContext &serialize_context)
            -> CodecResult<SerializedProtectedDatagram> {
            if (appended_one_rtt_fragment_packet != nullptr) {
                auto encoded = serialize_protected_datagram_with_metadata(*datagram_packets,
                                                                          serialize_context);
                if (connection_drain_test_hooks().force_appended_fragment_base_datagram_failure) {
                    encoded = CodecResult<SerializedProtectedDatagram>::failure(
                        CodecErrorCode::packet_length_mismatch, 0);
                }
                if (!encoded.has_value()) {
                    return encoded;
                }
                const auto offset = encoded.value().bytes.size();
                const auto appended = append_protected_one_rtt_packet_to_datagram(
                    encoded.value().bytes, *appended_one_rtt_fragment_packet, serialize_context);
                if (!appended.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        appended.error().code, appended.error().offset);
                }
                encoded.value().packet_metadata.push_back(SerializedProtectedPacketMetadata{
                    .offset = offset,
                    .length = appended.value(),
                });
                return encoded;
            }
            if (appended_packet == nullptr) {
                return serialize_protected_datagram_with_metadata(*datagram_packets,
                                                                  serialize_context);
            }
            return serialize_protected_datagram_with_metadata(*datagram_packets, *appended_packet,
                                                              serialize_context);
        };

        const auto &serialize_context = context.value();
        if (consume_connection_drain_countdown(
                &ConnectionDrainTestHooks::
                    force_candidate_datagram_serialization_failure_countdown)) {
            return CodecResult<SerializedProtectedDatagram>::failure(
                CodecErrorCode::packet_length_mismatch, 0);
        }
        auto datagram = serialize_datagram(serialize_context);
        if (!datagram.has_value()) {
            return datagram;
        }

        if (datagram.value().bytes.size() >= kMinimumInitialDatagramSize) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            // # Datagrams containing Initial packets MAY exceed 1200 bytes if
            // # the sender believes that the network path and peer both
            // # support the size that it chooses.
            return datagram;
        }

        for (std::size_t packet_index = 0; packet_index < datagram_packets->size();
             ++packet_index) {
            auto *initial = std::get_if<ProtectedInitialPacket>(&(*datagram_packets)[packet_index]);
            if (initial == nullptr) {
                continue;
            }
            mutable_datagram_packets = candidate_packets;
            datagram_packets = &*mutable_datagram_packets;
            auto *mutable_initial =
                std::get_if<ProtectedInitialPacket>(&mutable_datagram_packets->at(packet_index));

            const auto frames_without_padding = mutable_initial->frames;
            const auto padding_deficit =
                kMinimumInitialDatagramSize - datagram.value().bytes.size();
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
            // # Clients MUST ensure that UDP datagrams containing Initial
            // # packets have UDP payloads of at least 1200 bytes, adding
            // # PADDING frames as necessary.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            // # A client MUST expand the payload of all UDP datagrams carrying
            // # Initial packets to at least the smallest allowed maximum
            // # datagram size of 1200 bytes by adding PADDING frames to the
            // # Initial packet or by coalescing the Initial packet; see Section
            // # 12.2.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            // # Similarly, a server MUST expand the payload of all UDP
            // # datagrams carrying ack-eliciting Initial packets to at least
            // # the smallest allowed maximum datagram size of 1200 bytes.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-6
            // # Clients that support multiple QUIC versions SHOULD ensure that
            // # the first UDP datagram they send is sized to the largest of the
            // # minimum datagram sizes from all versions they support, using
            // # PADDING frames (Section 19.1) as necessary.
            const auto serialize_padded_initial =
                [&](std::size_t padding_length) -> CodecResult<SerializedProtectedDatagram> {
                mutable_initial->frames = frames_without_padding;
                mutable_initial->frames.insert(mutable_initial->frames.end(),
                                               static_cast<std::size_t>(padding_length != 0),
                                               Frame{PaddingFrame{
                                                   .length = padding_length,
                                               }});

                return serialize_datagram(serialize_context);
            };

            auto best_oversized_datagram = std::optional<SerializedProtectedDatagram>{};
            const auto remember_candidate = [&](SerializedProtectedDatagram candidate) {
                const auto candidate_size = candidate.bytes.size();
                if (candidate_size < kMinimumInitialDatagramSize) {
                    return false;
                }
                if (candidate_size <= max_outbound_datagram_size) {
                    best_oversized_datagram.reset();
                    best_oversized_datagram = std::move(candidate);
                    return true;
                }
                if (!best_oversized_datagram.has_value() ||
                    candidate_size < best_oversized_datagram->bytes.size()) {
                    best_oversized_datagram = std::move(candidate);
                }
                return false;
            };
            const auto try_padding_length = [&](std::size_t padding_length) -> CodecResult<bool> {
                auto padded_datagram = serialize_padded_initial(padding_length);
                if (!padded_datagram.has_value()) {
                    return CodecResult<bool>::failure(padded_datagram.error().code,
                                                      padded_datagram.error().offset);
                }
                return CodecResult<bool>::success(
                    remember_candidate(std::move(padded_datagram.value())));
            };

            if (auto exact_or_fit = try_padding_length(padding_deficit);
                !exact_or_fit.has_value() || exact_or_fit.value()) {
                if (!exact_or_fit.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        exact_or_fit.error().code, exact_or_fit.error().offset);
                }
                return CodecResult<SerializedProtectedDatagram>::success(
                    std::move(best_oversized_datagram.value()));
            }

            constexpr std::size_t kInitialPaddingSearchWindow = 32;
            for (std::size_t delta = 1; delta <= kInitialPaddingSearchWindow; ++delta) {
                if (padding_deficit >= delta) {
                    auto exact_or_fit = try_padding_length(padding_deficit - delta);
                    if (!exact_or_fit.has_value()) {
                        return CodecResult<SerializedProtectedDatagram>::failure(
                            exact_or_fit.error().code, exact_or_fit.error().offset);
                    }
                    if (exact_or_fit.value()) {
                        return CodecResult<SerializedProtectedDatagram>::success(
                            std::move(best_oversized_datagram.value()));
                    }
                }

                const auto larger_padding = padding_deficit + delta;
                if (larger_padding < padding_deficit) {
                    break;
                }
                auto exact_or_fit = try_padding_length(larger_padding);
                if (!exact_or_fit.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        exact_or_fit.error().code, exact_or_fit.error().offset);
                }
                if (exact_or_fit.value()) {
                    return CodecResult<SerializedProtectedDatagram>::success(
                        std::move(best_oversized_datagram.value()));
                }
            }

            if (best_oversized_datagram.has_value()) {
                return CodecResult<SerializedProtectedDatagram>::success(
                    std::move(best_oversized_datagram.value()));
            }

            return CodecResult<SerializedProtectedDatagram>::failure(
                CodecErrorCode::packet_length_mismatch, 0);
        }

        return datagram;
    };
    struct CommitSerializedDatagramOptions {
        std::size_t one_rtt_encrypted_packets = 0;
        std::size_t unpaced_ack_eliciting_packets = 0;
        std::optional<std::size_t> single_simple_stream_packet_length;
        bool bypass_burst_limit = false;
        std::optional<bool> pacing_controlled = std::nullopt;
        bool allow_send_continuation = false;
        bool skip_pmtu_probe_scan = false;
        bool skip_qlog_commit = false;
        bool skip_packet_inspection = false;
        std::optional<QuicPathId> path_challenge_path_id;
    };
    const auto commit_serialized_datagram =
        [&](const std::vector<ProtectedPacket> &datagram_packets,
            SerializedProtectedDatagram datagram,
            CommitSerializedDatagramOptions options = {}) -> DatagramBuffer {
        COQUIC_SEND_PROFILE_TIMER(commit_timer, commit_ns);
        bool pmtu_probe_datagram = false;
        if (!options.skip_pmtu_probe_scan) {
            COQUIC_SEND_PROFILE_TIMER(pmtu_probe_scan_timer, commit_pmtu_probe_scan_ns);
            pmtu_probe_datagram = std::ranges::any_of(
                pending_tracked_packets, [](const PendingTrackedPacketScratch &pending) {
                    return pending.packet.is_pmtu_probe;
                });
        }
        {
            COQUIC_SEND_PROFILE_TIMER(packet_count_timer, commit_packet_count_ns);
            if (options.one_rtt_encrypted_packets == 0) {
                options.one_rtt_encrypted_packets = one_rtt_packet_count(datagram_packets);
            }
            if (options.unpaced_ack_eliciting_packets == 0) {
                options.unpaced_ack_eliciting_packets =
                    one_rtt_ack_eliciting_packet_count(datagram_packets);
            }
        }
        {
            COQUIC_SEND_PROFILE_TIMER(key_limit_timer, commit_key_limit_ns);
            if (!note_aead_encryption_attempt(options.one_rtt_encrypted_packets, now)) {
                return {};
            }
        }
        {
            COQUIC_SEND_PROFILE_TIMER(track_pending_timer, commit_track_pending_ns);
            bool tracked_pending_packets = false;
            if (options.single_simple_stream_packet_length.has_value() &&
                !connection_drain_test_hooks().force_missing_packet_metadata &&
                pending_tracked_packets.empty() && pending_simple_stream_packets.size() == 1) {
                auto packet = std::move(pending_simple_stream_packets.front());
                packet.bytes_in_flight = *options.single_simple_stream_packet_length;
                pending_simple_stream_packets.clear();
                track_sent_simple_stream_packet(*packet.packet_space, std::move(packet));
                tracked_pending_packets = true;
            }
            if (!tracked_pending_packets && !track_pending_packets_from_datagram(datagram)) {
                mark_failed();
                return {};
            }
        }
        {
            COQUIC_SEND_PROFILE_TIMER(burst_note_timer, commit_burst_note_ns);
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7.5
            // # A sender MUST however count these packets as being
            // # additionally in flight, since these packets add network load
            // # without establishing packet loss.
            note_burst_limited_ack_eliciting_send(options.unpaced_ack_eliciting_packets,
                                                  options.bypass_burst_limit,
                                                  options.pacing_controlled);
        }

        {
            COQUIC_SEND_PROFILE_TIMER(pto_probe_timer, commit_pto_probe_ns);
            if (pto_probe_burst_active) {
                --remaining_pto_probe_datagrams_;
                if (remaining_pto_probe_datagrams_ == 0) {
                    initial_space_.pending_probe_packet = std::nullopt;
                    handshake_space_.pending_probe_packet = std::nullopt;
                    application_space_.pending_probe_packet = std::nullopt;
                }
            }
        }

        {
            COQUIC_SEND_PROFILE_TIMER(handshake_discard_timer, commit_handshake_discard_ns);
            if (config_.role == EndpointRole::client) {
                for (const auto &packet : datagram_packets) {
                    if (std::holds_alternative<ProtectedHandshakePacket>(packet)) {
                        //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.1
                        // # Thus, a client MUST discard Initial keys when it
                        // # first sends a Handshake packet and a server MUST
                        // # discard Initial keys when it first successfully
                        // # processes a Handshake packet.
                        //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.1
                        // # Endpoints MUST NOT send Initial packets after this point.
                        discard_initial_packet_space();
                        break;
                    }
                }
            }
        }

        if (!options.skip_qlog_commit) {
            COQUIC_SEND_PROFILE_TIMER(qlog_timer, commit_qlog_ns);
            if (qlog_session_ != nullptr) {
                const auto outbound_datagram_id =
                    std::optional<std::uint32_t>(qlog_session_->next_outbound_datagram_id());
                for (std::size_t index = 0; index < datagram_packets.size(); ++index) {
                    const auto qlog_sent_packet_number = std::visit(
                        [](const auto &packet_value) { return packet_value.packet_number; },
                        datagram_packets[index]);
                    auto snapshot = make_qlog_packet_snapshot(
                        datagram_packets[index],
                        qlog::PacketSnapshotContext{
                            .raw_length = datagram.packet_metadata[index].length,
                            .datagram_id = *outbound_datagram_id,
                            .trigger = pto_probe_burst_active
                                           ? std::optional<std::string>("pto_probe")
                                           : std::nullopt,
                        });
                    static_cast<void>(qlog_session_->write_event(
                        now, "quic:packet_sent", qlog::serialize_packet_snapshot(snapshot)));
                    auto snapshot_ptr = std::make_shared<qlog::PacketSnapshot>(snapshot);

                    for (auto *packet_space :
                         {&initial_space_, &handshake_space_, &application_space_}) {
                        auto *sent = packet_space->recovery.find_packet(qlog_sent_packet_number);
                        if (sent == nullptr) {
                            continue;
                        }

                        sent->qlog_packet_snapshot = snapshot_ptr;
                        sent->qlog_pto_probe = pto_probe_burst_active;
                        packet_space->recovery.note_packet_metadata_updated();
                    }
                }
            }
        }

        {
            COQUIC_SEND_PROFILE_TIMER(datagram_bookkeeping_timer, commit_datagram_bookkeeping_ns);
            if (options.path_challenge_path_id.has_value()) {
                mark_path_challenge_sent(*options.path_challenge_path_id, datagram.bytes.size());
            }
            note_outbound_datagram_bytes(datagram.bytes.size(), selected_send_path_id, now);
            last_drained_path_id_ = selected_send_path_id;
            last_drained_ecn_codepoint_ = outbound_ecn_codepoint_for_path(selected_send_path_id);
            last_drained_is_pmtu_probe_ = pmtu_probe_datagram;
            const bool continuation_has_pending_work =
                options.allow_send_continuation && has_pending_application_send();
            last_drained_allows_send_continuation_ =
                send_continuation_allowed(continuation_has_pending_work, options.bypass_burst_limit,
                                          options.unpaced_ack_eliciting_packets);
        }
        {
            COQUIC_SEND_PROFILE_TIMER(continuation_timer, commit_continuation_ns);
            if (send_profile_enabled()) {
                auto &profile = send_profile_counters();
                if (last_drained_allows_send_continuation_) {
                    ++profile.continuation_allowed;
                } else if (options.bypass_burst_limit) {
                    ++profile.continuation_denied_bypass;
                } else if (options.unpaced_ack_eliciting_packets == 0) {
                    ++profile.continuation_denied_not_ack_eliciting;
                } else if (!options.allow_send_continuation &&
                           options.pacing_controlled.has_value()) {
                    ++profile.continuation_denied_no_stream;
                }
            }
            if (last_drained_allows_send_continuation_) {
                last_send_continuation_time_ = now;
            } else {
                last_send_continuation_time_.reset();
            }
        }
        if (!options.skip_packet_inspection) {
            COQUIC_SEND_PROFILE_TIMER(inspection_timer, commit_inspection_ns);
            if (config_.enable_packet_inspection) {
                const auto datagram_id = next_packet_inspection_datagram_id_++;
                const auto inspection_count =
                    queue_outbound_packet_inspections(datagram, datagram_id);
                maybe_record_packet_inspection_datagram_id(
                    last_drained_packet_inspection_datagram_id_,
                    PacketInspectionDatagramId{datagram_id},
                    PacketInspectionCount{inspection_count});
            }
        }
        if (send_profile_enabled()) {
            COQUIC_SEND_PROFILE_TIMER(profile_accounting_timer, commit_profile_accounting_ns);
            auto &profile = send_profile_counters();
            ++profile.datagrams;
            profile.bytes += datagram.bytes.size();
            profile.max_datagram =
                std::max<std::uint64_t>(profile.max_datagram, datagram.bytes.size());
            profile.pmtu_probe_datagrams += static_cast<std::uint64_t>(pmtu_probe_datagram);
            profile.datagrams_le_1200 += static_cast<std::uint64_t>(datagram.bytes.size() <= 1200);
            profile.datagrams_le_1434 += static_cast<std::uint64_t>(datagram.bytes.size() <= 1434);
            profile.datagrams_le_1472 += static_cast<std::uint64_t>(datagram.bytes.size() <= 1472);
            profile.datagrams_gt_1472 += static_cast<std::uint64_t>(datagram.bytes.size() > 1472);
        }
        return std::move(datagram.bytes);
    };
    const auto fail_datagram_send = [&](bool preserve_pending_packets = false) -> DatagramBuffer {
        if (preserve_pending_packets && !preserve_pending_tracked_packets()) {
            mark_failed();
            return {};
        }
        mark_failed();
        return {};
    };
    const auto finalize_datagram =
        [&](const std::vector<ProtectedPacket> &datagram_packets) -> DatagramBuffer {
        auto datagram = serialize_candidate_datagram_with_metadata(datagram_packets);
        if (!datagram.has_value()) {
            return fail_datagram_send(/*preserve_pending_packets=*/true);
        }

        return commit_serialized_datagram(datagram_packets, std::move(datagram.value()));
    };
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        if (!closing_close_packet_pending_ || !can_send_connection_close_frame()) {
            return {};
        }
        const auto close_frame = connection_close_frame_for_send();
        if (!close_frame.has_value()) {
            return {};
        }
        const auto &base_close_frame = close_frame.value();
        const auto close_frame_for_long_header = [&]() -> Frame {
            const auto *application_close =
                std::get_if<ApplicationConnectionCloseFrame>(&base_close_frame);
            if (application_close == nullptr) {
                return Frame{base_close_frame};
            }

            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
            // # A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
            // # CONNECTION_CLOSE of type 0x1c when sending the frame in Initial
            // # or Handshake packets.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
            // # Endpoints MUST clear the value of the Reason Phrase field and
            // # SHOULD use the APPLICATION_ERROR code when converting to a
            // # CONNECTION_CLOSE of type 0x1c.
            return Frame{TransportConnectionCloseFrame{
                .error_code = static_cast<std::uint64_t>(QuicTransportErrorCode::application_error),
                .frame_type = 0,
                .reason = {},
            }};
        };
        struct ClosePacketCandidate {
            ProtectedPacket packet;
            PacketSpaceState *packet_space = nullptr;
        };
        std::vector<ClosePacketCandidate> close_candidates;
        close_candidates.reserve(3);
        const auto add_initial_close_packet = [&]() -> bool {
            if (initial_packet_space_discarded_) {
                return true;
            }
            const auto close_packet_number = reserve_packet_number(initial_space_);
            if (!close_packet_number.has_value()) {
                return false;
            }
            close_candidates.push_back(ClosePacketCandidate{
                .packet =
                    ProtectedInitialPacket{
                        .version = initial_packet_version,
                        .destination_connection_id = send_destination_connection_id,
                        .source_connection_id = config_.source_connection_id,
                        .token = initial_token,
                        .packet_number_length =
                            packet_number_length_for_send(initial_space_, *close_packet_number),
                        .packet_number = *close_packet_number,
                        .frames = std::vector<Frame>{close_frame_for_long_header()},
                    },
                .packet_space = &initial_space_,
            });
            return true;
        };
        const auto add_handshake_close_packet = [&]() -> bool {
            if (!handshake_space_.write_secret.has_value()) {
                return true;
            }
            const auto close_packet_number = reserve_packet_number(handshake_space_);
            if (!close_packet_number.has_value()) {
                return false;
            }
            close_candidates.push_back(ClosePacketCandidate{
                .packet =
                    ProtectedHandshakePacket{
                        .version = current_version_,
                        .destination_connection_id = send_destination_connection_id,
                        .source_connection_id = config_.source_connection_id,
                        .packet_number_length =
                            packet_number_length_for_send(handshake_space_, *close_packet_number),
                        .packet_number = *close_packet_number,
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.4
                        // # Handshake packets MAY contain
                        // # CONNECTION_CLOSE frames of type 0x1c.
                        .frames = std::vector<Frame>{close_frame_for_long_header()},
                    },
                .packet_space = &handshake_space_,
            });
            return true;
        };
        const auto add_application_close_packet = [&]() -> bool {
            if (!application_space_.write_secret.has_value()) {
                return true;
            }
            const auto close_packet_number = reserve_packet_number(application_space_);
            if (!close_packet_number.has_value()) {
                return false;
            }
            auto packet = make_application_protected_packet(
                /*use_zero_rtt_packet_protection=*/false, current_version_,
                application_destination_connection_id(), config_.source_connection_id,
                application_write_key_phase_,
                packet_number_length_for_send(application_space_, *close_packet_number),
                *close_packet_number, std::vector<Frame>{base_close_frame}, {});
            set_application_packet_spin_bit(packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            close_candidates.push_back(ClosePacketCandidate{
                .packet = std::move(packet),
                .packet_space = &application_space_,
            });
            return true;
        };
        const auto packet_destination_connection_id =
            [](const ProtectedPacket &packet) -> const ConnectionId & {
            if (const auto *initial = std::get_if<ProtectedInitialPacket>(&packet)) {
                return initial->destination_connection_id;
            }
            if (const auto *handshake = std::get_if<ProtectedHandshakePacket>(&packet)) {
                return handshake->destination_connection_id;
            }
            if (const auto *zero_rtt = std::get_if<ProtectedZeroRttPacket>(&packet)) {
                return zero_rtt->destination_connection_id;
            }
            return std::get<ProtectedOneRttPacket>(packet).destination_connection_id;
        };
        const auto reduce_close_candidates_to_strongest = [&]() {
            if (close_candidates.size() <= 1) {
                return;
            }
            auto strongest = std::move(close_candidates.back());
            close_candidates.clear();
            close_candidates.push_back(std::move(strongest));
        };
        if (application_space_.write_secret.has_value() && handshake_confirmed_) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
            // # After the handshake is confirmed (see Section 4.1.2 of
            // # [QUIC-TLS]), an endpoint MUST send any CONNECTION_CLOSE frames
            // # in a 1-RTT packet.
            if (!add_application_close_packet()) {
                return {};
            }
        } else if (application_space_.write_secret.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
            // # * Prior to confirming the handshake, a peer might be unable to
            // # process 1-RTT packets, so an endpoint SHOULD send a
            // # CONNECTION_CLOSE frame in both Handshake and 1-RTT packets.
            if (config_.role == EndpointRole::server) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
                // # A server SHOULD also send a CONNECTION_CLOSE frame in an
                // # Initial packet.
                static_cast<void>(add_initial_close_packet());
            }
            if (!add_handshake_close_packet() || !add_application_close_packet()) {
                return {};
            }
        } else if (handshake_space_.write_secret.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
            // # However, prior to confirming the handshake, it is possible that
            // # more advanced packet protection keys are not available to the
            // # peer, so another CONNECTION_CLOSE frame MAY be sent in a packet
            // # that uses a lower packet protection level.
            if (config_.role == EndpointRole::server) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
                // # Under these circumstances, a server SHOULD send a
                // # CONNECTION_CLOSE frame in both Handshake and Initial
                // # packets to ensure that at least one of them is processable
                // # by the client.
                static_cast<void>(add_initial_close_packet());
            }
            if (!add_handshake_close_packet()) {
                return {};
            }
        } else if (!add_initial_close_packet()) {
            return {};
        }
        if (close_candidates.empty()) {
            return {};
        }
        const auto &close_destination_connection_id =
            packet_destination_connection_id(close_candidates.front().packet);
        const bool coalesced_close_uses_one_destination_connection_id =
            std::ranges::all_of(close_candidates, [&](const auto &candidate_packet) {
                return packet_destination_connection_id(candidate_packet.packet) ==
                       close_destination_connection_id;
            });
        if (!coalesced_close_uses_one_destination_connection_id) {
            reduce_close_candidates_to_strongest();
        }
        std::vector<ProtectedPacket> close_packets;
        const auto rebuild_close_packets = [&]() {
            close_packets.clear();
            close_packets.reserve(close_candidates.size());
            for (auto &candidate_packet : close_candidates) {
                close_packets.push_back(candidate_packet.packet);
            }
        };
        rebuild_close_packets();
        auto candidate = serialize_candidate_datagram_with_metadata(close_packets);
        if (!candidate.has_value()) {
            return {};
        }
        if (candidate.value().packet_metadata.size() != close_candidates.size()) {
            return {};
        }
        if (candidate.value().bytes.size() > max_outbound_datagram_size) {
            if (close_candidates.size() > 1) {
                reduce_close_candidates_to_strongest();
                rebuild_close_packets();
                candidate = serialize_candidate_datagram_with_metadata(close_packets);
                if (!candidate.has_value()) {
                    return {};
                }
                if (candidate.value().packet_metadata.size() != close_candidates.size()) {
                    return {};
                }
                if (candidate.value().bytes.size() > max_outbound_datagram_size) {
                    return {};
                }
            } else {
                return {};
            }
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
        }
        for (std::size_t packet_index = 0; packet_index < close_candidates.size(); ++packet_index) {
            auto *packet_space = close_candidates[packet_index].packet_space;
            if (packet_space == nullptr) {
                return {};
            }
            queue_tracked_packet_at_index(
                *packet_space,
                SentPacketRecord{
                    .packet_number = packet_number_for_sent_record(close_packets[packet_index]),
                    .sent_time = now,
                    .ack_eliciting = false,
                    .in_flight = false,
                    .declared_lost = false,
                    .path_id = selected_send_path_id.value_or(0),
                    .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                },
                packet_index, candidate.value().packet_metadata[packet_index].length);
        }
        mark_connection_close_frame_sent(base_close_frame, now);
        last_drained_path_id_ = selected_send_path_id;
        last_drained_ecn_codepoint_ = outbound_ecn_codepoint_for_path(selected_send_path_id);
        last_drained_is_pmtu_probe_ = false;
        return commit_serialized_datagram(close_packets, std::move(candidate.value()));
    }
    const auto trim_crypto_ranges_to_fit = [&](auto &&serialize_with_crypto_ranges,
                                               auto &&restore_trimmed_crypto,
                                               std::vector<ByteRange> &crypto_ranges) {
        auto datagram = serialize_with_crypto_ranges(crypto_ranges);
        if (!datagram.has_value()) {
            return datagram;
        }

        while (datagram_size_or_zero(datagram) > max_outbound_datagram_size &&
               !crypto_ranges.empty()) {
            auto &last_range = crypto_ranges.back();
            const auto overshoot = datagram_size_or_zero(datagram) - max_outbound_datagram_size;
            const auto trim_bytes = std::min<std::size_t>(overshoot, last_range.bytes.size());
            if (trim_bytes == last_range.bytes.size()) {
                restore_trimmed_crypto(last_range.offset, last_range.bytes.size());
                crypto_ranges.pop_back();
            } else {
                const auto retained_bytes = last_range.bytes.size() - trim_bytes;
                restore_trimmed_crypto(last_range.offset + retained_bytes, trim_bytes);
                last_range.bytes.resize(retained_bytes);
            }

            datagram = serialize_with_crypto_ranges(crypto_ranges);
            if (!datagram.has_value()) {
                return datagram;
            }
        }

        return datagram;
    };

    auto initial_ack_frame =
        initial_packet_space_discarded_
            ? std::optional<AckFrame>{}
            : ((initial_space_.pending_probe_packet.has_value() &&
                initial_space_.pending_probe_packet->force_ack)
                   ? initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now,
                                                                     /*allow_non_pending=*/true)
                   : initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0,
                                                                     now));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
    // # ACK frames MUST only be carried in a packet that has the same packet
    // # number space as the packet being acknowledged; see Section 12.1.
    auto initial_crypto_ranges = std::vector<ByteRange>{};
    if (!initial_packet_space_discarded_ && !defer_server_compatible_negotiation_crypto) {
        //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
        // # The server cannot send CRYPTO frames until it has processed the
        // # client's transport parameters.
        initial_crypto_ranges =
            initial_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    const auto should_add_server_handshake_keepalive_ping =
        [&](const PacketSpaceState &packet_space) {
            return config_.role == EndpointRole::server && !handshake_confirmed_ &&
                   !packet_space.pending_probe_packet.has_value() &&
                   !has_in_flight_ack_eliciting_packet(packet_space);
        };
    const auto build_initial_frames = [&](std::span<const ByteRange> crypto_ranges) {
        std::vector<Frame> initial_frame_list;
        initial_frame_list.reserve(
            crypto_ranges.size() + (initial_ack_frame.has_value() ? 1u : 0u) +
            (initial_space_.pending_probe_packet.has_value()
                 ? initial_space_.pending_probe_packet->crypto_ranges.size() + 1u
                 : 0u));
        for (const auto &range : crypto_ranges) {
            initial_frame_list.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (initial_ack_frame.has_value() && crypto_ranges.empty()) {
            initial_frame_list.emplace_back(*initial_ack_frame);
        }
        if (initial_ack_frame.has_value() && !has_ack_eliciting_frame(initial_frame_list) &&
            should_add_server_handshake_keepalive_ping(initial_space_)) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
            // # In that case, an endpoint MUST NOT send an ack-eliciting frame
            // # in all packets that would otherwise be non-ack-eliciting, to
            // # avoid an infinite feedback loop of acknowledgments.
            initial_frame_list.emplace_back(PingFrame{});
        }
        if (!defer_server_compatible_negotiation_crypto &&
            initial_space_.pending_probe_packet.has_value() &&
            !has_ack_eliciting_frame(initial_frame_list)) {
            for (const auto &range : initial_space_.pending_probe_packet->crypto_ranges) {
                initial_frame_list.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(initial_frame_list)) {
                initial_frame_list.emplace_back(PingFrame{});
            }
        }

        return initial_frame_list;
    };
    auto initial_frames = initial_packet_space_discarded_
                              ? std::vector<Frame>{}
                              : build_initial_frames(initial_crypto_ranges);
    if (!initial_frames.empty()) {
        std::optional<std::uint64_t> initial_packet_number;
        const bool duplicate_compatible_negotiation_initial_crypto =
            duplicate_first_compatible_server_initial_crypto && !initial_crypto_ranges.empty();
        auto sent_initial_crypto_ranges = initial_crypto_ranges;
        const auto serialize_initial_candidate = [&](std::span<const ByteRange> crypto_ranges)
            -> CodecResult<SerializedProtectedDatagram> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = send_destination_connection_id,
                //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                // # The client MUST NOT change the Source Connection ID because the
                // # server could include the connection ID as part of its token
                // # validation logic; see Section 8.1.4.
                .source_connection_id = config_.source_connection_id,
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                // # The client MUST include the token in all Initial packets it
                // # sends, unless a Retry replaces the token with a newer one.
                .token = initial_token,
                .packet_number_length = packet_number_length_for_send(
                    initial_space_, initial_space_.next_send_packet_number),
                .packet_number = initial_space_.next_send_packet_number,
                .frames = build_initial_frames(crypto_ranges),
            });
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
            // # Specifically, the client
            // # MUST send an Initial packet in a UDP datagram that contains at least
            // # 1200 bytes if it does not have Handshake keys, and otherwise send a
            // # Handshake packet.
            return serialize_candidate_datagram_with_metadata(candidate_packets);
        };
        auto initial_candidate_datagram = trim_crypto_ranges_to_fit(
            serialize_initial_candidate,
            [&](std::uint64_t offset, std::size_t length) {
                initial_space_.send_crypto.mark_unsent(offset, length);
            },
            sent_initial_crypto_ranges);
        if (!initial_candidate_datagram.has_value()) {
            return fail_datagram_send(has_pending_tracked_packet());
        }
        auto sent_initial_frames = build_initial_frames(sent_initial_crypto_ranges);
        bool initial_ack_eliciting = has_ack_eliciting_frame(sent_initial_frames);
        bool initial_has_ping = std::ranges::any_of(sent_initial_frames, [](const Frame &frame) {
            return std::holds_alternative<PingFrame>(frame);
        });
        if (initial_candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
            const bool blocked_first_server_initial =
                (initial_space_.next_send_packet_number == 0) & initial_ack_eliciting;
            if (blocked_first_server_initial) {
                return {};
            }
        } else {
            bool bypass_congestion_window = initial_space_.pending_probe_packet.has_value();
            if (initial_ack_eliciting &&
                congestion_blocks_datagram(initial_candidate_datagram.value().bytes.size(),
                                           bypass_congestion_window)) {
                for (const auto &range : sent_initial_crypto_ranges) {
                    initial_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
                return {};
            }
            initial_packet_number = reserve_packet_number(initial_space_);
            if (!initial_packet_number.has_value()) {
                for (const auto &range : sent_initial_crypto_ranges) {
                    initial_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
                return {};
            }
            packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = send_destination_connection_id,
                //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                // # The client MUST NOT change the Source Connection ID because the
                // # server could include the connection ID as part of its token
                // # validation logic; see Section 8.1.4.
                .source_connection_id = config_.source_connection_id,
                .token = initial_token,
                .packet_number_length =
                    packet_number_length_for_send(initial_space_, *initial_packet_number),
                .packet_number = *initial_packet_number,
                .frames = sent_initial_frames,
            });
        }

        if (initial_candidate_datagram.value().bytes.size() <= max_outbound_datagram_size) {
            SentPacketRecord initial_sent_record{
                .packet_number = *initial_packet_number,
                .sent_time = now,
                .ack_eliciting = initial_ack_eliciting,
                .in_flight = initial_ack_eliciting,
                .declared_lost = false,
                .crypto_ranges = sent_initial_crypto_ranges,
                .has_ping = initial_has_ping,
                .largest_received_packet_number_acked =
                    largest_acknowledged_for_ack_eliciting_sent_record(initial_ack_eliciting,
                                                                       sent_initial_frames),
            };
            initial_sent_record.path_id = selected_send_path_id.value_or(0);
            initial_sent_record.ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
            if (!defer_server_compatible_negotiation_crypto &&
                initial_space_.pending_probe_packet.has_value() &&
                initial_sent_record.crypto_ranges.empty()) {
                initial_sent_record.crypto_ranges =
                    initial_space_.pending_probe_packet->crypto_ranges;
                initial_sent_record.has_ping = initial_space_.pending_probe_packet->has_ping;
            }
            queue_tracked_packet(initial_space_, initial_sent_record,
                                 initial_candidate_datagram.value().packet_metadata.back().length);
            if (track_client_handshake_keepalive_probes) {
                note_client_handshake_keepalive_probe(initial_sent_record);
            }
            if (initial_sent_record.ack_eliciting) {
                note_idle_ack_eliciting_send(now);
            }
            if (initial_space_.received_packets.has_ack_to_send()) {
                initial_space_.received_packets.on_ack_sent();
                initial_space_.pending_ack_deadline = std::nullopt;
                initial_space_.force_ack_send = false;
            }
            if (!defer_server_compatible_negotiation_crypto) {
                clear_probe_packet_after_send(initial_space_.pending_probe_packet);
            }

            if (duplicate_compatible_negotiation_initial_crypto) {
                const auto duplicate_candidate_packet_number =
                    initial_space_.next_send_packet_number;
                auto duplicate_candidate_packets = packets;
                duplicate_candidate_packets.emplace_back(ProtectedInitialPacket{
                    .version = initial_packet_version,
                    .destination_connection_id = send_destination_connection_id,
                    .source_connection_id = config_.source_connection_id,
                    .token = initial_token,
                    .packet_number_length = packet_number_length_for_send(
                        initial_space_, duplicate_candidate_packet_number),
                    .packet_number = duplicate_candidate_packet_number,
                    .frames = sent_initial_frames,
                });
                auto duplicate_candidate_datagram =
                    serialize_candidate_datagram_with_metadata(duplicate_candidate_packets);
                if (!duplicate_candidate_datagram.has_value()) {
                    return fail_datagram_send(/*preserve_pending_packets=*/true);
                }
                if (duplicate_candidate_datagram.value().bytes.size() <=
                    max_outbound_datagram_size) {
                    bool bypass_congestion_window = initial_space_.pending_probe_packet.has_value();
                    const bool duplicate_initial_congestion_blocked = congestion_blocks_datagram(
                        duplicate_candidate_datagram.value().bytes.size(),
                        bypass_congestion_window);
                    if (initial_ack_eliciting & duplicate_initial_congestion_blocked) {
                        return finalize_datagram(packets);
                    }
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.2
                    // # A server MAY send multiple Initial packets.
                    const auto duplicate_packet_number = reserve_packet_number(initial_space_);
                    if (!duplicate_packet_number.has_value()) {
                        return {};
                    }
                    duplicate_candidate_packets.back() = ProtectedInitialPacket{
                        .version = initial_packet_version,
                        .destination_connection_id = send_destination_connection_id,
                        .source_connection_id = config_.source_connection_id,
                        .token = initial_token,
                        .packet_number_length =
                            packet_number_length_for_send(initial_space_, *duplicate_packet_number),
                        .packet_number = *duplicate_packet_number,
                        .frames = sent_initial_frames,
                    };
                    packets = std::move(duplicate_candidate_packets);
                    queue_tracked_packet(
                        initial_space_,
                        SentPacketRecord{
                            .packet_number = *duplicate_packet_number,
                            .sent_time = now,
                            .ack_eliciting = initial_ack_eliciting,
                            .in_flight = initial_ack_eliciting,
                            .declared_lost = false,
                            .crypto_ranges = sent_initial_crypto_ranges,
                            .largest_received_packet_number_acked =
                                largest_acknowledged_for_ack_eliciting_sent_record(
                                    initial_ack_eliciting, sent_initial_frames),
                            .path_id = selected_send_path_id.value_or(0),
                            .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                        },
                        duplicate_candidate_datagram.value().packet_metadata.back().length);
                    note_idle_ack_eliciting_send(now);
                }
            }
        }
    }

    const auto max_handshake_crypto_bytes =
        std::numeric_limits<std::size_t>::max() *
        static_cast<std::size_t>(!defer_server_compatible_negotiation_crypto &
                                 !handshake_packet_space_discarded_);
    auto handshake_crypto_ranges =
        handshake_packet_space_discarded_
            ? std::vector<ByteRange>{}
            : handshake_space_.send_crypto.take_ranges(max_handshake_crypto_bytes);
    const auto build_handshake_frames = [&](std::span<const ByteRange> crypto_ranges,
                                            bool override_probe_crypto_ranges = false,
                                            std::span<const ByteRange> probe_crypto_ranges = {}) {
        const auto handshake_ack_delay_exponent = local_transport_parameters_.ack_delay_exponent;
        const auto handshake_ack_frame =
            (handshake_space_.pending_probe_packet.has_value() &&
             handshake_space_.pending_probe_packet->force_ack)
                ? handshake_space_.received_packets.build_ack_frame(handshake_ack_delay_exponent,
                                                                    now, /*allow_non_pending=*/true)
                : handshake_space_.received_packets.build_ack_frame(handshake_ack_delay_exponent,
                                                                    now);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        // # ACK frames MUST only be carried in a packet that has the same packet
        // # number space as the packet being acknowledged; see Section 12.1.
        std::vector<Frame> handshake_frame_list;
        handshake_frame_list.reserve(
            crypto_ranges.size() + (handshake_ack_frame.has_value() ? 1u : 0u) +
            (handshake_space_.pending_probe_packet.has_value()
                 ? handshake_space_.pending_probe_packet->crypto_ranges.size() + 1u
                 : 0u));
        if (handshake_ack_frame.has_value()) {
            handshake_frame_list.emplace_back(*handshake_ack_frame);
        }
        for (const auto &range : crypto_ranges) {
            handshake_frame_list.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (handshake_ack_frame.has_value() && !has_ack_eliciting_frame(handshake_frame_list) &&
            should_add_server_handshake_keepalive_ping(handshake_space_)) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
            // # In that case, an endpoint MUST NOT send an ack-eliciting frame
            // # in all packets that would otherwise be non-ack-eliciting, to
            // # avoid an infinite feedback loop of acknowledgments.
            handshake_frame_list.emplace_back(PingFrame{});
        }
        if (handshake_space_.pending_probe_packet.has_value() &&
            !has_ack_eliciting_frame(handshake_frame_list)) {
            const auto active_probe_crypto_ranges =
                override_probe_crypto_ranges
                    ? probe_crypto_ranges
                    : std::span<const ByteRange>(
                          handshake_space_.pending_probe_packet->crypto_ranges);
            for (const auto &range : active_probe_crypto_ranges) {
                handshake_frame_list.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(handshake_frame_list)) {
                handshake_frame_list.emplace_back(PingFrame{});
            }
        }

        return handshake_frame_list;
    };
    auto handshake_frames = handshake_packet_space_discarded_
                                ? std::vector<Frame>{}
                                : build_handshake_frames(handshake_crypto_ranges);
    if (!handshake_frames.empty()) {
        if (!handshake_space_.write_secret.has_value()) {
            mark_failed();
            return {};
        }

        auto sent_handshake_crypto_ranges = handshake_crypto_ranges;
        auto sent_handshake_probe_crypto_ranges =
            handshake_space_.pending_probe_packet.has_value()
                ? handshake_space_.pending_probe_packet->crypto_ranges
                : std::vector<ByteRange>{};
        const auto serialize_handshake_candidate = [&](std::span<const ByteRange> crypto_ranges)
            -> CodecResult<SerializedProtectedDatagram> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedHandshakePacket{
                //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
                // # The server MUST send all CRYPTO
                // # frames using the negotiated version.
                //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
                // # Both endpoints MUST send Handshake and 1-RTT packets using the
                // # negotiated version.
                .version = current_version_,
                .destination_connection_id = send_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .packet_number_length = packet_number_length_for_send(
                    handshake_space_, handshake_space_.next_send_packet_number),
                .packet_number = handshake_space_.next_send_packet_number,
                .frames = build_handshake_frames(crypto_ranges),
            });
            return serialize_candidate_datagram_with_metadata(candidate_packets);
        };
        const auto serialize_handshake_probe_candidate =
            [&](std::span<const ByteRange> probe_crypto_ranges)
            -> CodecResult<SerializedProtectedDatagram> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedHandshakePacket{
                //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
                // # The server MUST send all CRYPTO
                // # frames using the negotiated version.
                //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
                // # Both endpoints MUST send Handshake and 1-RTT packets using the
                // # negotiated version.
                .version = current_version_,
                .destination_connection_id = send_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .packet_number_length = packet_number_length_for_send(
                    handshake_space_, handshake_space_.next_send_packet_number),
                .packet_number = handshake_space_.next_send_packet_number,
                .frames = build_handshake_frames(sent_handshake_crypto_ranges,
                                                 /*override_probe_crypto_ranges=*/true,
                                                 probe_crypto_ranges),
            });
            return serialize_candidate_datagram_with_metadata(candidate_packets);
        };
        auto handshake_candidate_datagram =
            sent_handshake_crypto_ranges.empty() &&
                    handshake_space_.pending_probe_packet.has_value()
                ? trim_crypto_ranges_to_fit(
                      serialize_handshake_probe_candidate, [](std::uint64_t, std::size_t) {},
                      sent_handshake_probe_crypto_ranges)
                : trim_crypto_ranges_to_fit(
                      serialize_handshake_candidate,
                      [&](std::uint64_t offset, std::size_t length) {
                          handshake_space_.send_crypto.mark_unsent(offset, length);
                      },
                      sent_handshake_crypto_ranges);
        if (!handshake_candidate_datagram.has_value()) {
            for (const auto &range : sent_handshake_crypto_ranges) {
                handshake_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
            }
            if (is_empty_packet_payload_error(handshake_candidate_datagram) && !packets.empty()) {
                return finalize_datagram(packets);
            }
            return fail_datagram_send(has_pending_tracked_packet());
        }
        auto sent_handshake_frames =
            build_handshake_frames(sent_handshake_crypto_ranges,
                                   sent_handshake_crypto_ranges.empty() &&
                                       handshake_space_.pending_probe_packet.has_value(),
                                   sent_handshake_probe_crypto_ranges);
        bool handshake_has_ping =
            std::ranges::any_of(sent_handshake_frames, [](const Frame &frame) {
                return std::holds_alternative<PingFrame>(frame);
            });
        if (handshake_candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
            for (const auto &range : sent_handshake_crypto_ranges) {
                handshake_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
            }
            if (!packets.empty()) {
                return finalize_datagram(packets);
            }
            return {};
        }

        const auto handshake_ack_eliciting = has_ack_eliciting_frame(sent_handshake_frames);
        bool bypass_congestion_window = handshake_space_.pending_probe_packet.has_value();
        if (handshake_ack_eliciting &&
            congestion_blocks_datagram(handshake_candidate_datagram.value().bytes.size(),
                                       bypass_congestion_window)) {
            for (const auto &range : sent_handshake_crypto_ranges) {
                handshake_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
            }
            if (!packets.empty()) {
                return finalize_datagram(packets);
            }
            return {};
        }

        const auto handshake_packet_number = reserve_packet_number(handshake_space_);
        if (!handshake_packet_number.has_value()) {
            for (const auto &range : sent_handshake_crypto_ranges) {
                handshake_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
            }
            return {};
        }

        packets.emplace_back(ProtectedHandshakePacket{
            //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
            // # The server MUST send all CRYPTO
            // # frames using the negotiated version.
            //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
            // # Both endpoints MUST send Handshake and 1-RTT packets using the
            // # negotiated version.
            .version = current_version_,
            .destination_connection_id = send_destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .packet_number_length =
                packet_number_length_for_send(handshake_space_, *handshake_packet_number),
            .packet_number = *handshake_packet_number,
            .frames = sent_handshake_frames,
        });

        SentPacketRecord handshake_sent_record{
            .packet_number = *handshake_packet_number,
            .sent_time = now,
            .ack_eliciting = handshake_ack_eliciting,
            .in_flight = handshake_ack_eliciting,
            .declared_lost = false,
            .crypto_ranges = sent_handshake_crypto_ranges,
            .has_ping = handshake_has_ping,
            .largest_received_packet_number_acked =
                largest_acknowledged_for_ack_eliciting_sent_record(handshake_ack_eliciting,
                                                                   sent_handshake_frames),
        };
        handshake_sent_record.path_id = selected_send_path_id.value_or(0);
        handshake_sent_record.ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
        if (handshake_space_.pending_probe_packet.has_value() &&
            handshake_sent_record.crypto_ranges.empty()) {
            handshake_sent_record.crypto_ranges = sent_handshake_probe_crypto_ranges;
            handshake_sent_record.has_ping = handshake_space_.pending_probe_packet->has_ping;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
        // # Specifically, the client
        // # MUST send an Initial packet in a UDP datagram that contains at least
        // # 1200 bytes if it does not have Handshake keys, and otherwise send a
        // # Handshake packet.
        queue_tracked_packet(handshake_space_, handshake_sent_record,
                             handshake_candidate_datagram.value().packet_metadata.back().length);
        if (track_client_handshake_keepalive_probes) {
            note_client_handshake_keepalive_probe(handshake_sent_record);
        }
        if (handshake_sent_record.ack_eliciting) {
            note_idle_ack_eliciting_send(now);
        }
        if (handshake_space_.received_packets.has_ack_to_send()) {
            handshake_space_.received_packets.on_ack_sent();
            handshake_space_.pending_ack_deadline = std::nullopt;
            handshake_space_.force_ack_send = false;
        }
        clear_probe_packet_after_send(handshake_space_.pending_probe_packet);
    }

    auto application_crypto_ranges = std::vector<ByteRange>{};
    auto &application_crypto_frames = application_crypto_frame_scratch_;
    application_crypto_frames.clear();
    if (application_space_.write_secret.has_value()) {
        application_crypto_ranges =
            application_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    if (!application_crypto_ranges.empty()) {
        application_crypto_frames.reserve(application_crypto_ranges.size());
        for (const auto &range : application_crypto_ranges) {
            application_crypto_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
    }
    struct ApplicationCryptoFrameScratchGuard {
        std::vector<Frame> &frame_scratch;
        ~ApplicationCryptoFrameScratchGuard() {
            frame_scratch.clear();
        }
    } application_crypto_frame_scratch_guard{application_crypto_frames};

    bool use_zero_rtt_packet_protection = config_.role == EndpointRole::client &&
                                          status_ != HandshakeStatus::connected &&
                                          zero_rtt_space_.write_secret.has_value();
    bool can_send_one_rtt_packets = application_space_.write_secret.has_value();
    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        maybe_queue_stream_blocked_frame(stream);
    }
    maybe_queue_connection_blocked_frame();
    bool application_ack_due_now =
        application_space_.received_packets.has_ack_to_send() &&
        (application_space_.force_ack_send ||
         application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
    bool pending_application_send_after_blocked_queue = has_pending_application_send();
    const auto has_pending_path_validation_frame = [&]() {
        return has_pending_ack_only_path_validation_frame(paths_, current_send_path_id_);
    };
    bool has_pending_application_payload =
        application_ack_due_now | pending_application_send_after_blocked_queue |
        application_space_.pending_probe_packet.has_value() | !pending_new_token_frames_.empty() |
        !pending_new_connection_id_frames_.empty() | !pending_retire_connection_id_frames_.empty() |
        !application_crypto_frames.empty() | has_pending_path_validation_frame();
    if ((can_send_one_rtt_packets || use_zero_rtt_packet_protection) &&
        has_pending_application_payload) {
        const auto base_ack_frame =
            use_zero_rtt_packet_protection
                ? std::optional<OutboundAckHeader>{}
                : application_space_.received_packets.build_outbound_ack_header(
                      local_transport_parameters_.ack_delay_exponent, now);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        // # ACK frames MUST only be carried in a packet that has the same packet
        // # number space as the packet being acknowledged; see Section 12.1.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        // # For instance, packets that are protected with 1-RTT keys MUST be
        // # acknowledged in packets that are also protected with 1-RTT keys.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
        // # An acknowledgment for a 1-RTT packet MUST be carried in a 1-RTT packet.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
        // # Packets that a client sends with 0-RTT packet protection MUST be
        // # acknowledged by the server in packets protected by 1-RTT keys.
        const auto maybe_queue_client_ack_only_receive_keepalive_challenge = [&]() {
            const bool has_receive_interest = std::ranges::any_of(
                streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
            const bool has_pending_path_validation =
                std::ranges::any_of(paths_, [](const auto &entry) {
                    return entry.second.pending_response.has_value() ||
                           entry.second.challenge_pending;
                });
            const bool eligible =
                (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::connected) &
                base_ack_frame.has_value() & last_peer_activity_time_.has_value() &
                has_receive_interest & !pending_application_send_after_blocked_queue &
                !application_space_.pending_probe_packet.has_value() &
                pending_new_token_frames_.empty() & pending_new_connection_id_frames_.empty() &
                pending_retire_connection_id_frames_.empty() & application_crypto_frames.empty() &
                !has_pending_path_validation &
                (initial_packet_space_discarded_ ||
                 !has_in_flight_ack_eliciting_packet(initial_space_)) &
                (handshake_packet_space_discarded_ ||
                 !has_in_flight_ack_eliciting_packet(handshake_space_)) &
                !has_in_flight_ack_eliciting_packet(application_space_) &
                current_send_path_id_.has_value();
            if (!eligible) {
                return;
            }

            auto &path = ensure_path_state(*current_send_path_id_);
            if (!path.validated) {
                return;
            }

            application_space_.force_ack_send = true;
        };
        maybe_queue_client_ack_only_receive_keepalive_challenge();
        const auto reserve_application_packet_number =
            [&](bool using_one_rtt_packet_protection) -> std::optional<std::uint64_t> {
            const auto reserved_packet_number = application_space_.next_send_packet_number;
            if (using_one_rtt_packet_protection) {
                const auto largest_acked =
                    application_space_.recovery.largest_acked_packet_number();
                bool can_initiate_local_key_update =
                    local_key_update_requested_ & handshake_confirmed_ &
                    application_space_.read_secret.has_value() & !local_key_update_initiated_ &
                    current_write_phase_first_packet_number_.has_value() &
                    largest_acked.has_value();
                if (can_initiate_local_key_update) {
                    can_initiate_local_key_update =
                        *largest_acked >= *current_write_phase_first_packet_number_;
                }
                if (can_initiate_local_key_update) {
                    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
                    // # An endpoint MUST NOT initiate a key update prior to
                    // # having confirmed the handshake (Section 4.1.2).
                    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.1
                    // # An endpoint MUST NOT initiate a subsequent key update
                    // # unless it has received an acknowledgment for a packet
                    // # that was sent protected with keys from the current key
                    // # phase.
                    const auto next_read_secret =
                        derive_next_traffic_secret(*application_space_.read_secret);
                    if (!next_read_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_read_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }

                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }

                    retain_previous_application_read_secret(now);
                    application_space_.read_secret = next_read_secret.value();
                    application_read_key_phase_ = !application_read_key_phase_;
                    ++application_read_secret_generation_;
                    next_application_read_secret_.reset();
                    next_application_read_secret_source_generation_.reset();
                    reset_current_short_header_deserialize_context_cache();
                    const auto following_read_secret = refresh_next_application_read_secret();
                    if (!following_read_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret",
                                          following_read_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }
                    application_space_.write_secret = next_write_secret.value();
                    application_write_key_phase_ = !application_write_key_phase_;
                    reset_serialize_context_cache();
                    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
                    // # Endpoints MUST count the number of encrypted packets
                    // # for each set of keys.
                    current_application_write_key_encrypted_packets_ = 0;
                    ++current_application_write_key_generation_;
                    local_key_update_requested_ = false;
                    local_key_update_initiated_ = true;
                    current_write_phase_first_packet_number_ = reserved_packet_number;
                }
                if (!current_write_phase_first_packet_number_.has_value()) {
                    current_write_phase_first_packet_number_ = reserved_packet_number;
                }
            }

            if (!reserve_packet_number(application_space_).has_value()) {
                return std::nullopt;
            }
            return reserved_packet_number;
        };
        const auto try_send_simple_application_ack_only = [&]() -> std::optional<DatagramBuffer> {
            if (!can_try_simple_application_ack_only(SimpleApplicationAckOnlyEligibility{
                    .application_ack_due_now = application_ack_due_now,
                    .has_base_ack_frame = base_ack_frame.has_value(),
                    .packets_empty = packets.empty(),
                    .qlog_enabled = qlog_session_ != nullptr,
                    .use_zero_rtt_packet_protection = use_zero_rtt_packet_protection,
                    .can_send_one_rtt_packets = can_send_one_rtt_packets,
                    .pending_application_send_after_blocked_queue =
                        pending_application_send_after_blocked_queue,
                    .application_probe_pending =
                        application_space_.pending_probe_packet.has_value(),
                    .has_pending_new_token_frames = !pending_new_token_frames_.empty(),
                    .has_pending_new_connection_id_frames =
                        !pending_new_connection_id_frames_.empty(),
                    .has_pending_retire_connection_id_frames =
                        !pending_retire_connection_id_frames_.empty(),
                    .application_crypto_frames_empty = application_crypto_frames.empty(),
                    .has_current_send_path = current_send_path_id_.has_value(),
                    .has_pending_ack_only_path_validation_frame =
                        has_pending_ack_only_path_validation_frame(paths_, current_send_path_id_),
                })) {
                return std::nullopt;
            }

            selected_send_path_id = current_send_path_id_;
            const auto ack_only_destination_cid = application_destination_connection_id();
            const std::array<Frame, 1> ack_only_frames{
                Frame{OutboundAckFrame{
                    .history = &application_space_.received_packets,
                    .header = *base_ack_frame,
                }},
            };
            const auto candidate_size =
                one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
                    .spin_bit = outbound_spin_bit_for_path(selected_send_path_id),
                    .key_phase = application_write_key_phase_,
                    .destination_connection_id = ack_only_destination_cid,
                    .packet_number_length = packet_number_length_for_send(
                        application_space_, application_space_.next_send_packet_number),
                    .packet_number = application_space_.next_send_packet_number,
                    .frames = ack_only_frames,
                });
            if (!candidate_size.has_value() ||
                candidate_size.value() > max_outbound_datagram_size) {
                return std::nullopt;
            }

            const auto ack_only_packet_number =
                reserve_application_packet_number(/*using_one_rtt_packet_protection=*/true);
            if (!ack_only_packet_number.has_value()) {
                return DatagramBuffer{};
            }
            const auto ack_only_packet = ProtectedOneRttPacketFragmentView{
                .spin_bit = outbound_spin_bit_for_path(selected_send_path_id),
                .key_phase = application_write_key_phase_,
                .destination_connection_id = ack_only_destination_cid,
                .packet_number_length =
                    packet_number_length_for_send(application_space_, *ack_only_packet_number),
                .packet_number = *ack_only_packet_number,
                .frames = ack_only_frames,
            };
            auto ack_only_datagram =
                serialize_candidate_datagram_with_metadata(packets, nullptr, &ack_only_packet);
            if (!ack_only_datagram.has_value()) {
                return fail_datagram_send(has_pending_tracked_packet());
            }

            application_space_.received_packets.on_ack_sent();
            application_space_.pending_ack_deadline = std::nullopt;
            application_space_.force_ack_send = false;
            //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
            // # To avoid delaying their delivery to the peer, packets
            // # containing only ACK frames SHOULD therefore not be paced.
            return commit_serialized_datagram({}, std::move(ack_only_datagram.value()),
                                              CommitSerializedDatagramOptions{
                                                  .one_rtt_encrypted_packets = 1,
                                                  .unpaced_ack_eliciting_packets = 0,
                                              });
        };

        if (auto simple_ack = try_send_simple_application_ack_only(); simple_ack.has_value()) {
            return std::move(simple_ack.value());
        }
        struct PendingStreamControlFrames {
            std::vector<MaxStreamDataFrame> max_stream_data;
            std::vector<ResetStreamFrame> reset_stream;
            std::vector<StopSendingFrame> stop_sending;
            std::vector<StreamDataBlockedFrame> stream_data_blocked;
        };
        const auto take_pending_stream_control_frames =
            [&](auto &streams, bool defer_receive_credit,
                bool omit_retransmittable_control) -> PendingStreamControlFrames {
            PendingStreamControlFrames control_frames;
            if (defer_receive_credit && omit_retransmittable_control) {
                return control_frames;
            }
            if (stream_sendability_cache_.valid && !stream_sendability_cache_.has_pending_control) {
                return control_frames;
            }
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (!defer_receive_credit) {
                    if (const auto frame = stream.take_max_stream_data_frame()) {
                        control_frames.max_stream_data.push_back(*frame);
                    }
                }
                if (omit_retransmittable_control) {
                    continue;
                }
                if (const auto frame = stream.take_reset_frame()) {
                    control_frames.reset_stream.push_back(*frame);
                }
                if (const auto frame = stream.take_stop_sending_frame()) {
                    control_frames.stop_sending.push_back(*frame);
                }
                if (const auto frame = stream.take_stream_data_blocked_frame()) {
                    control_frames.stream_data_blocked.push_back(*frame);
                }
            }
            if (!control_frames.max_stream_data.empty() || !control_frames.reset_stream.empty() ||
                !control_frames.stop_sending.empty() ||
                !control_frames.stream_data_blocked.empty()) {
                invalidate_stream_sendability_cache();
            }

            return control_frames;
        };
        const auto take_max_streams_frames =
            [&](bool omit_retransmittable_control) -> std::vector<MaxStreamsFrame> {
            if (omit_retransmittable_control) {
                return {};
            }

            return local_stream_limit_state_.take_max_streams_frames();
        };
        const auto take_new_token_frames =
            [&](bool omit_retransmittable_control) -> std::vector<NewTokenFrame> {
            if (omit_retransmittable_control) {
                return {};
            }

            auto new_token_frame_list = std::move(pending_new_token_frames_);
            pending_new_token_frames_.clear();
            return new_token_frame_list;
        };
        const auto take_new_connection_id_frames =
            [&](bool omit_retransmittable_control) -> std::vector<NewConnectionIdFrame> {
            if (omit_retransmittable_control) {
                return {};
            }

            std::vector<NewConnectionIdFrame> new_connection_id_frame_list;
            while (const auto frame = take_pending_new_connection_id_frame()) {
                new_connection_id_frame_list.push_back(*frame);
            }
            return new_connection_id_frame_list;
        };
        const auto take_retire_connection_id_frames =
            [&](bool omit_retransmittable_control) -> std::vector<RetireConnectionIdFrame> {
            if (omit_retransmittable_control) {
                return {};
            }

            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
            // # An endpoint SHOULD allow for sending and tracking a number of
            // # RETIRE_CONNECTION_ID frames of at least twice the value of the
            // # active_connection_id_limit transport parameter.
            auto retire_connection_id_frame_list = std::move(pending_retire_connection_id_frames_);
            pending_retire_connection_id_frames_.clear();
            for (const auto &frame : retire_connection_id_frame_list) {
                if (auto peer = peer_connection_ids_.find(frame.sequence_number);
                    peer != peer_connection_ids_.end()) {
                    peer->second.retire_frame_in_flight = true;
                }
            }
            return retire_connection_id_frame_list;
        };
        const auto defer_retire_connection_id_frames =
            [&](std::vector<RetireConnectionIdFrame> &retire_frame_list) {
                if (retire_frame_list.empty()) {
                    return;
                }

                for (const auto &frame : retire_frame_list) {
                    if (auto peer = peer_connection_ids_.find(frame.sequence_number);
                        peer != peer_connection_ids_.end()) {
                        peer->second.retire_frame_in_flight = false;
                    }
                }
                pending_retire_connection_id_frames_.insert(
                    pending_retire_connection_id_frames_.begin(), retire_frame_list.begin(),
                    retire_frame_list.end());
                retire_frame_list.clear();
            };
        const auto mark_path_challenge_sent = [](auto &path) { path.challenge_pending = false; };
        const auto take_path_validation_frames =
            [&](bool omit_retransmittable_control) -> PendingPathValidationFrames {
            static_cast<void>(omit_retransmittable_control);

            const auto response_path =
                std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                    return entry.second.pending_response.has_value();
                });
            if (response_path != paths_.end()) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
                // # An endpoint MUST NOT delay transmission of a packet
                // # containing a PATH_RESPONSE frame unless constrained by
                // # congestion control.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
                // # A PATH_RESPONSE frame MUST be sent on the network path
                // # where the PATH_CHALLENGE frame was received.
                PendingPathValidationFrames pending_path_validation{
                    .path_id = response_path->first,
                    .response =
                        PathResponseFrame{
                            .data = *response_path->second.pending_response,
                        },
                };
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
                // # An endpoint MUST NOT send more than one PATH_RESPONSE frame in
                // # response to one PATH_CHALLENGE frame; see Section 13.3.
                response_path->second.pending_response.reset();
                if (response_path->second.challenge_pending &
                    response_path->second.outstanding_challenge.has_value()) {
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
                    // # However, an endpoint SHOULD NOT send multiple PATH_CHALLENGE
                    // # frames in a single packet.
                    pending_path_validation.challenge = PathChallengeFrame{
                        .data = *response_path->second.outstanding_challenge,
                    };
                    mark_path_challenge_sent(response_path->second);
                } else if (!response_path->second.validated &
                           !response_path->second.outstanding_challenge.has_value()) {
                    response_path->second.outstanding_challenge =
                        next_path_challenge_data(response_path->first);
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.2
                    // # The server MUST probe on the path toward the client from
                    // # its preferred address.
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.3
                    // # Servers SHOULD initiate path validation to the client's
                    // # new address upon receiving a probe packet from a
                    // # different address; see Section 8.
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
                    // # However, an endpoint SHOULD NOT send multiple PATH_CHALLENGE
                    // # frames in a single packet.
                    pending_path_validation.challenge = PathChallengeFrame{
                        .data = *response_path->second.outstanding_challenge,
                    };
                    mark_path_challenge_sent(response_path->second);
                }
                if (!response_path->second.validated &
                    current_send_path_id_ != response_path->first) {
                    if (current_send_path_id_.has_value()) {
                        previous_path_id_ = current_send_path_id_;
                        if (const auto current = paths_.find(*current_send_path_id_);
                            current != paths_.end()) {
                            current->second.is_current_send_path = false;
                        }
                    }
                    response_path->second.is_current_send_path = true;
                    current_send_path_id_ = response_path->first;
                }
                return pending_path_validation;
            }

            if (!current_send_path_id_.has_value()) {
                return {};
            }
            const auto build_challenge_frames =
                [&](auto &path_entry) -> PendingPathValidationFrames {
                PendingPathValidationFrames pending_path_validation{
                    .path_id = path_entry.first,
                };
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
                // # An endpoint SHOULD NOT probe a new path with packets containing a
                // # PATH_CHALLENGE frame more frequently than it would send an Initial
                // # packet.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3.3
                // # In response to an apparent migration, endpoints MUST validate the
                // # previously active path using a PATH_CHALLENGE frame.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
                // # However, an endpoint SHOULD NOT send multiple PATH_CHALLENGE frames in
                // # a single packet.
                pending_path_validation.challenge = PathChallengeFrame{
                    .data = *path_entry.second.outstanding_challenge,
                };
                mark_path_challenge_sent(path_entry.second);
                return pending_path_validation;
            };

            auto path = paths_.find(*current_send_path_id_);
            if (path != paths_.end() &&
                path->second.challenge_pending & path->second.outstanding_challenge.has_value()) {
                return build_challenge_frames(*path);
            }

            const auto challenge_path =
                std::find_if(paths_.begin(), paths_.end(), [&](const auto &entry) {
                    return entry.first != *current_send_path_id_ &&
                           entry.second.challenge_pending &&
                           entry.second.outstanding_challenge.has_value();
                });
            if (challenge_path != paths_.end()) {
                return build_challenge_frames(*challenge_path);
            }

            return PendingPathValidationFrames{
                .path_id = *current_send_path_id_,
            };
        };
        const auto take_stream_fragments = [&](auto &connection_flow, auto &streams,
                                               std::size_t max_wire_bytes, auto &last_stream_id,
                                               std::vector<StreamFrameSendFragment> &fragments,
                                               bool prefer_fresh_data = false) {
            fragments.clear();
            std::size_t selected_payload_bytes = 0;
            auto remaining_wire_bytes = max_wire_bytes;
            //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
            // # Senders MUST NOT send data in excess of either limit.
            auto remaining_connection_credit =
                connection_flow.peer_max_data > connection_flow.highest_sent
                    ? connection_flow.peer_max_data - connection_flow.highest_sent
                    : 0;
            const auto note_selected_payload_bytes = [&](std::size_t first_fragment_index) {
                for (std::size_t index = first_fragment_index; index < fragments.size(); ++index) {
                    selected_payload_bytes += fragments[index].bytes.size();
                }
            };
            const auto visit_round_robin = [&](auto &&visit) {
                const auto visit_range = [&](auto begin, auto end) {
                    for (auto it = begin; it != end; ++it) {
                        if (!visit(it)) {
                            return false;
                        }
                    }
                    return true;
                };

                if (streams.empty()) {
                    return;
                }
                if (!last_stream_id.has_value()) {
                    static_cast<void>(visit_range(streams.begin(), streams.end()));
                    return;
                }

                const auto start = config_.transport.send_stream_fairness
                                       ? streams.upper_bound(*last_stream_id)
                                       : streams.lower_bound(*last_stream_id);
                if (!visit_range(start, streams.end())) {
                    return;
                }
                static_cast<void>(visit_range(streams.begin(), start));
            };

            constexpr std::size_t kLargeDatagramFreshStreamBudgetBytes = std::size_t{8} * 1024u;
            const auto limit_fresh_streams_for_round = [&](std::size_t packet_budget,
                                                           std::size_t active_stream_count) {
                if (active_stream_count <= 1) {
                    return active_stream_count;
                }

                return std::min(active_stream_count,
                                std::max<std::size_t>(
                                    1u, packet_budget / kLargeDatagramFreshStreamBudgetBytes));
            };
            const auto can_try_single_fresh_stream_fast_path =
                prefer_fresh_data && remaining_wire_bytes != 0 && remaining_connection_credit != 0;
            const auto selected_fresh_stream_count =
                limit_fresh_streams_for_round(remaining_wire_bytes, streams.size());
            if (can_try_single_fresh_stream_fast_path && selected_fresh_stream_count == 1) {
                bool found_priority_work = false;
                decltype(streams.begin()) selected = streams.end();
                visit_round_robin([&](const auto it) {
                    auto &stream = it->second;
                    if (stream.reset_state != StreamControlFrameState::none) {
                        return true;
                    }
                    if (stream_fin_sendable(stream)) {
                        found_priority_work = true;
                        return false;
                    }
                    if (stream.sendable_bytes() != 0) {
                        selected = it;
                        return false;
                    }
                    return true;
                });
                if (!found_priority_work && selected != streams.end()) {
                    auto &stream = selected->second;
                    const auto stream_id = selected->first;
                    const auto previous_fresh_sendable_bytes =
                        fresh_sendable_bytes_for_cache(stream);
                    const auto previous_has_lost_send_data =
                        stream.reset_state == StreamControlFrameState::none &&
                        stream.send_buffer.has_lost_data();
                    const auto highest_sent_before = stream.flow_control.highest_sent;
                    const auto packet_share = std::min(
                        remaining_wire_bytes,
                        max_stream_frame_payload_for_wire_budget(
                            stream_id, stream.flow_control.highest_sent, remaining_wire_bytes));
                    if (packet_share == 0) {
                        return selected_payload_bytes;
                    }
                    const auto new_byte_share = std::min<std::uint64_t>(
                        remaining_connection_credit, static_cast<std::uint64_t>(packet_share));
                    const auto fragment_count_before = fragments.size();
                    stream.append_send_fragments(
                        StreamSendBudget{
                            .packet_bytes = packet_share,
                            .new_bytes = new_byte_share,
                            .prefer_fresh_data = true,
                        },
                        fragments);
                    const auto new_bytes_sent =
                        stream.flow_control.highest_sent - highest_sent_before;
                    connection_flow.highest_sent += new_bytes_sent;
                    if (fragments.size() != fragment_count_before) {
                        last_stream_id = stream_id;
                        note_selected_payload_bytes(fragment_count_before);
                    }
                    note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                                   previous_has_lost_send_data, stream);
                    return selected_payload_bytes;
                }
            }

            const auto append_selected_stream_fragments =
                [&](decltype(streams.begin()) selected, bool loss_phase_for_stream,
                    std::size_t wire_share, // NOLINT(bugprone-easily-swappable-parameters)
                    std::uint64_t new_byte_share) -> std::size_t {
                const auto stream_id = selected->first;
                auto &stream = selected->second;

                const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream);
                const auto previous_has_lost_send_data =
                    stream.reset_state == StreamControlFrameState::none &&
                    stream.send_buffer.has_lost_data();
                const auto highest_sent_before = stream.flow_control.highest_sent;
                auto packet_share =
                    loss_phase_for_stream
                        ? std::min(
                              remaining_wire_bytes,
                              max_stream_frame_payload_for_wire_budget(
                                  stream_id, stream.next_send_offset_for_budget(false), wire_share))
                        : std::min(remaining_wire_bytes,
                                   max_stream_frame_payload_for_wire_budget(
                                       stream_id, stream.flow_control.highest_sent, wire_share));
                const auto fin_sendable = stream_fin_sendable(stream);
                if (packet_share == 0) {
                    if (fin_only_stream_frame_cannot_fit(fin_sendable,
                                                         stream.send_final_size.has_value())) {
                        return 0;
                    }
                    const auto fin_only_wire_size =
                        stream_frame_header_wire_size(stream_id, *stream.send_final_size, 0);
                    if (fin_only_wire_size > remaining_wire_bytes) {
                        return 0;
                    }
                }
                const auto fragment_count_before = fragments.size();
                stream.append_send_fragments(
                    StreamSendBudget{
                        .packet_bytes = packet_share,
                        .new_bytes = new_byte_share,
                        .prefer_fresh_data = !loss_phase_for_stream,
                    },
                    fragments);
                const auto new_bytes_sent = stream.flow_control.highest_sent - highest_sent_before;
                connection_flow.highest_sent += new_bytes_sent;
                remaining_connection_credit -=
                    std::min<std::uint64_t>(remaining_connection_credit, new_bytes_sent);
                std::size_t selected_wire_bytes = 0;
                for (std::size_t index = fragment_count_before; index < fragments.size(); ++index) {
                    auto &fragment = fragments[index];
                    const auto fragment_wire_size = fragment.stream_frame_wire_size();
                    if (selected_wire_bytes + fragment_wire_size <= remaining_wire_bytes) {
                        selected_wire_bytes += fragment_wire_size;
                        continue;
                    }

                    const auto fragment_budget = remaining_wire_bytes - selected_wire_bytes;
                    trim_or_restore_oversized_stream_fragment(
                        streams, fragments,
                        StreamFragmentTrimTarget{
                            .index = index,
                            .budget = fragment_budget,
                        },
                        StreamFragmentTrimAccounting{
                            .connection_flow = connection_flow,
                            .remaining_connection_credit = remaining_connection_credit,
                            .selected_wire_bytes = selected_wire_bytes,
                        });
                    break;
                }
                remaining_wire_bytes -= selected_wire_bytes;
                const bool emitted_fragment = fragments.size() != fragment_count_before;
                if (emitted_fragment) {
                    last_stream_id = stream_id;
                    note_selected_payload_bytes(fragment_count_before);
                }
                note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                               previous_has_lost_send_data, stream);
                return emitted_fragment ? selected_wire_bytes : 0;
            };

            auto loss_phase = !prefer_fresh_data;
            auto switched_phase = false;
            if (loss_phase && !has_lost_application_stream_data()) {
                loss_phase = false;
                switched_phase = true;
            }

            for (;;) {
                if (remaining_wire_bytes == 0) {
                    break;
                }

                if (!loss_phase && switched_phase &&
                    limit_fresh_streams_for_round(remaining_wire_bytes, streams.size()) == 1) {
                    decltype(streams.begin()) selected = streams.end();
                    if (streams.size() == 1) {
                        auto only = streams.begin();
                        if (only->second.reset_state == StreamControlFrameState::none &&
                            (only->second.sendable_bytes() != 0 ||
                             stream_fin_sendable(only->second))) {
                            selected = only;
                        }
                    } else {
                        visit_round_robin([&](const auto it) {
                            auto &stream = it->second;
                            if (stream.reset_state != StreamControlFrameState::none) {
                                return true;
                            }
                            if (stream.sendable_bytes() != 0 || stream_fin_sendable(stream)) {
                                selected = it;
                                return false;
                            }
                            return true;
                        });
                    }

                    if (selected == streams.end()) {
                        break;
                    }

                    if (append_selected_stream_fragments(selected, /*loss_phase_for_stream=*/false,
                                                         remaining_wire_bytes,
                                                         remaining_connection_credit) == 0) {
                        break;
                    }
                    continue;
                }

                auto &active_streams = active_stream_iterator_scratch_;
                active_streams.clear();
                visit_round_robin([&](const auto it) {
                    auto &stream = it->second;
                    if (stream.reset_state != StreamControlFrameState::none) {
                        return true;
                    }

                    const auto fin_sendable = stream_fin_sendable(stream);
                    const auto active = loss_phase
                                            ? stream.send_buffer.has_lost_data() || fin_sendable
                                            : (stream.sendable_bytes() != 0) || fin_sendable;
                    if (active) {
                        active_streams.push_back(it);
                    }
                    return true;
                });

                if (active_streams.empty()) {
                    if (!switched_phase) {
                        loss_phase = !loss_phase;
                        switched_phase = true;
                        continue;
                    }

                    break;
                }

                std::size_t wire_bytes_sent_this_round = 0;
                bool emitted_fragment = false;
                const auto active_stream_count = active_streams.size();
                const auto selected_stream_count =
                    loss_phase
                        ? active_stream_count
                        : limit_fresh_streams_for_round(remaining_wire_bytes, active_stream_count);
                if (selected_stream_count != active_stream_count) {
                    active_streams.resize(selected_stream_count);
                }

                const bool use_remaining_round_share = selected_stream_count != active_stream_count;
                for (std::size_t stream_index = 0; stream_index < selected_stream_count;
                     ++stream_index) {
                    const auto it = active_streams[stream_index];
                    const auto round_divisor = use_remaining_round_share
                                                   ? selected_stream_count - stream_index
                                                   : selected_stream_count;
                    const auto wire_share =
                        std::max<std::size_t>(1u, remaining_wire_bytes / round_divisor);
                    const auto new_byte_share =
                        loss_phase || remaining_connection_credit == 0
                            ? 0
                            : std::max<std::uint64_t>(1,
                                                      remaining_connection_credit / round_divisor);
                    const auto emitted_wire_bytes = append_selected_stream_fragments(
                        it, loss_phase, wire_share, new_byte_share);
                    if (emitted_wire_bytes != 0) {
                        emitted_fragment = true;
                        wire_bytes_sent_this_round += emitted_wire_bytes;
                    }
                    if (remaining_wire_bytes == 0) {
                        break;
                    }
                }

                if (!static_cast<bool>(emitted_fragment & (wire_bytes_sent_this_round != 0))) {
                    break;
                }
            }
            return selected_payload_bytes;
        };
        auto append_application_crypto_frames = [](std::vector<Frame> &frame_list,
                                                   std::span<const ByteRange> crypto_ranges) {
            for (const auto &range : crypto_ranges) {
                frame_list.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
        };
        struct ApplicationCandidateFrameScratchGuard {
            std::vector<Frame> &frame_scratch;
            std::vector<Frame> &alternate_frame_scratch;
            ~ApplicationCandidateFrameScratchGuard() {
                frame_scratch.clear();
                alternate_frame_scratch.clear();
            }
        } application_candidate_frame_scratch_guard{application_candidate_frame_scratch_,
                                                    alternate_application_candidate_frame_scratch_};
        const auto serialize_application_candidate_from_frames =
            [&](std::span<const Frame> candidate_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool has_application_close, std::uint64_t candidate_packet_number,
                bool write_key_phase) -> CodecResult<SerializedProtectedDatagram> {
            const bool use_zero_rtt = use_zero_rtt_packet_protection & !has_application_close;
            if (has_application_close && !use_zero_rtt) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
                // # After the handshake is confirmed (see Section 4.1.2 of
                // # [QUIC-TLS]), an endpoint MUST send any CONNECTION_CLOSE frames
                // # in a 1-RTT packet.
            }
            if (!use_zero_rtt) {
                const auto candidate_destination_connection_id =
                    application_destination_connection_id();
                const auto candidate_packet = ProtectedOneRttPacketFragmentView{
                    .spin_bit = outbound_spin_bit_for_path(selected_send_path_id),
                    .key_phase = write_key_phase,
                    .destination_connection_id = candidate_destination_connection_id,
                    .packet_number_length =
                        packet_number_length_for_send(application_space_, candidate_packet_number),
                    .packet_number = candidate_packet_number,
                    .frames = candidate_frames,
                    .stream_fragments = stream_fragments,
                };
                auto candidate_datagram =
                    serialize_candidate_datagram_with_metadata(packets, nullptr, &candidate_packet);
                return candidate_datagram;
            }

            auto candidate_packet = make_application_protected_packet(
                use_zero_rtt, current_version_, application_destination_connection_id(),
                config_.source_connection_id, write_key_phase,
                packet_number_length_for_send(application_space_, candidate_packet_number),
                candidate_packet_number,
                std::vector<Frame>(candidate_frames.begin(), candidate_frames.end()),
                stream_fragments);
            set_application_packet_spin_bit(candidate_packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            auto candidate_datagram =
                serialize_candidate_datagram_with_metadata(packets, &candidate_packet);
            if (!candidate_datagram.has_value()) {
                return candidate_datagram;
            }
            return candidate_datagram;
        };
        const auto serialize_application_candidate =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &candidate_ack_header,
                const std::optional<MaxDataFrame> &candidate_max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &candidate_path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const StreamsBlockedFrame> streams_blocked_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                const std::optional<DatagramFrame> &datagram_frame,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping) -> CodecResult<SerializedProtectedDatagram> {
            std::vector<Frame> crypto_frames;
            crypto_frames.reserve(crypto_ranges.size());
            append_application_crypto_frames(crypto_frames, crypto_ranges);
            const auto candidate_frames = build_application_candidate_frames(
                application_candidate_frame_scratch_, application_space_.received_packets,
                crypto_frames, include_handshake_done, candidate_ack_header,
                candidate_max_data_frame, new_token_frames, new_connection_id_frames,
                retire_connection_id_frames, candidate_path_validation_frames,
                max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, datagram_frame, application_close_frame, include_ping);
            return serialize_application_candidate_from_frames(
                candidate_frames, stream_fragments, application_close_frame.has_value(),
                application_space_.next_send_packet_number, application_write_key_phase_);
        };
        const auto pad_path_validation_candidate_to_minimum_datagram =
            [&](CodecResult<SerializedProtectedDatagram> &candidate,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const Frame> candidate_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool has_application_close, std::uint64_t candidate_packet_number,
                bool write_key_phase, std::size_t datagram_size_limit) -> bool {
            if (!candidate.has_value()) {
                return true;
            }
            if (!path_validation_needs_minimum_datagram(path_validation_frames, paths_)) {
                return true;
            }
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.2
            // # However, an endpoint MUST NOT expand the
            // # datagram containing the PATH_RESPONSE if the resulting data exceeds
            // # the anti-amplification limit.
            if (datagram_size_limit < kMinimumInitialDatagramSize ||
                candidate.value().bytes.size() >= kMinimumInitialDatagramSize) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
                // # Unlike other cases where datagrams are expanded, endpoints
                // # MUST NOT discard datagrams that appear to be too small when
                // # they contain PATH_CHALLENGE or PATH_RESPONSE.
                return true;
            }

            auto frames_with_padding =
                std::vector<Frame>(candidate_frames.begin(), candidate_frames.end());
            std::size_t padding_length =
                kMinimumInitialDatagramSize - candidate.value().bytes.size();
            if (!maybe_add_pmtu_probe_padding(padding_length, frames_with_padding,
                                              padding_length)) {
                return true;
            }
            return retry_padded_pmtu_probe_serialization(
                candidate, frames_with_padding, kMinimumInitialDatagramSize, padding_length, [&] {
                    return serialize_application_candidate_from_frames(
                        frames_with_padding, stream_fragments, has_application_close,
                        candidate_packet_number, write_key_phase);
                });
        };
        const auto estimate_application_candidate_size_from_frames =
            [&](std::span<const Frame> candidate_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool has_application_close, std::uint64_t candidate_packet_number,
                bool write_key_phase) -> CodecResult<std::size_t> {
            if (send_profile_enabled()) {
                ++send_profile_counters().estimate_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(estimate_timer, estimate_ns);
            if (consume_connection_drain_countdown(
                    &ConnectionDrainTestHooks::
                        force_application_candidate_estimate_failure_countdown)) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch, 0);
            }
            const bool use_zero_rtt = use_zero_rtt_packet_protection & !has_application_close;
            if (!use_zero_rtt && packets.empty()) {
                const auto candidate_destination_connection_id =
                    application_destination_connection_id();
                const auto candidate_packet = ProtectedOneRttPacketFragmentView{
                    .spin_bit = outbound_spin_bit_for_path(selected_send_path_id),
                    .key_phase = write_key_phase,
                    .destination_connection_id = candidate_destination_connection_id,
                    .packet_number_length =
                        packet_number_length_for_send(application_space_, candidate_packet_number),
                    .packet_number = candidate_packet_number,
                    .frames = candidate_frames,
                    .stream_fragments = stream_fragments,
                };
                return one_rtt_packet_fragment_view_wire_size(candidate_packet);
            }

            auto candidate_packet = make_application_protected_packet(
                use_zero_rtt, current_version_, application_destination_connection_id(),
                config_.source_connection_id, write_key_phase,
                packet_number_length_for_send(application_space_, candidate_packet_number),
                candidate_packet_number,
                std::vector<Frame>(candidate_frames.begin(), candidate_frames.end()),
                stream_fragments);
            set_application_packet_spin_bit(candidate_packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            auto candidate_datagram =
                serialize_candidate_datagram_with_metadata(packets, &candidate_packet);
            if (!candidate_datagram.has_value()) {
                return CodecResult<std::size_t>::failure(candidate_datagram.error().code,
                                                         candidate_datagram.error().offset);
            }
            return CodecResult<std::size_t>::success(candidate_datagram.value().bytes.size());
        };
        const auto estimate_application_candidate_size =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &candidate_ack_header,
                const std::optional<MaxDataFrame> &candidate_max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &candidate_path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const StreamsBlockedFrame> streams_blocked_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                const std::optional<DatagramFrame> &datagram_frame,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping) -> CodecResult<std::size_t> {
            std::vector<Frame> crypto_frames;
            crypto_frames.reserve(crypto_ranges.size());
            append_application_crypto_frames(crypto_frames, crypto_ranges);
            const auto candidate_frames = build_application_candidate_frames(
                application_candidate_frame_scratch_, application_space_.received_packets,
                crypto_frames, include_handshake_done, candidate_ack_header,
                candidate_max_data_frame, new_token_frames, new_connection_id_frames,
                retire_connection_id_frames, candidate_path_validation_frames,
                max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, datagram_frame, application_close_frame, include_ping);
            return estimate_application_candidate_size_from_frames(
                candidate_frames, stream_fragments, application_close_frame.has_value(),
                application_space_.next_send_packet_number, application_write_key_phase_);
        };
        auto restore_application_fragment = [&](const StreamFrameSendFragment &fragment) {
            const bool releases_flow_control =
                fragment.consumes_flow_control & !fragment.bytes.empty();
            if (releases_flow_control) {
                connection_flow_control_.highest_sent -=
                    static_cast<std::uint64_t>(fragment.bytes.size());
            }
            auto &stream = streams_.at(fragment.stream_id);
            const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream);
            const auto previous_has_lost_send_data =
                stream.reset_state == StreamControlFrameState::none &&
                stream.send_buffer.has_lost_data();
            stream.restore_send_fragment(fragment);
            note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                           previous_has_lost_send_data, stream);
        };
        const auto restore_unsent_application_candidate =
            [&](const std::optional<MaxDataFrame> &max_data_to_restore,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &validation_frames_to_restore,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const StreamsBlockedFrame> streams_blocked_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments) {
                for (const auto &range : application_crypto_ranges) {
                    application_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
                if (max_data_to_restore.has_value()) {
                    connection_flow_control_.mark_max_data_frame_lost(*max_data_to_restore);
                }
                if (data_blocked_frame.has_value()) {
                    connection_flow_control_.mark_data_blocked_frame_lost(*data_blocked_frame);
                }
                pending_new_token_frames_.insert(pending_new_token_frames_.begin(),
                                                 new_token_frames.begin(), new_token_frames.end());
                pending_new_connection_id_frames_.insert(pending_new_connection_id_frames_.begin(),
                                                         new_connection_id_frames.begin(),
                                                         new_connection_id_frames.end());
                pending_retire_connection_id_frames_.insert(
                    pending_retire_connection_id_frames_.begin(),
                    retire_connection_id_frames.begin(), retire_connection_id_frames.end());
                if (validation_frames_to_restore.response.has_value()) {
                    auto &path = ensure_path_state(validation_frames_to_restore.path_id);
                    path.pending_response = validation_frames_to_restore.response->data;
                }
                if (validation_frames_to_restore.challenge.has_value()) {
                    auto &path = ensure_path_state(validation_frames_to_restore.path_id);
                    path.challenge_pending = true;
                }
                for (const auto &frame : max_stream_data_frames) {
                    streams_.at(frame.stream_id).mark_max_stream_data_frame_lost(frame);
                }
                for (const auto &frame : max_streams_frames) {
                    local_stream_limit_state_.mark_max_streams_frame_lost(frame);
                }
                for (const auto &frame : streams_blocked_frames) {
                    stream_open_limits_.mark_streams_blocked_frame_lost(frame);
                }
                for (const auto &frame : stream_data_blocked_frames) {
                    streams_.at(frame.stream_id).mark_stream_data_blocked_frame_lost(frame);
                }
                for (const auto &frame : reset_stream_frames) {
                    streams_.at(frame.stream_id).mark_reset_frame_lost(frame);
                }
                for (const auto &frame : stop_sending_frames) {
                    streams_.at(frame.stream_id).mark_stop_sending_frame_lost(frame);
                }
                if (!max_stream_data_frames.empty() || !stream_data_blocked_frames.empty() ||
                    !reset_stream_frames.empty() || !stop_sending_frames.empty()) {
                    invalidate_stream_sendability_cache();
                }
                for (const auto &fragment : stream_fragments) {
                    restore_application_fragment(fragment);
                }
            };
        const auto trim_application_ack_frame =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &candidate_ack_frame,
                const std::optional<MaxDataFrame> &candidate_max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &candidate_path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const StreamsBlockedFrame> streams_blocked_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                const std::optional<DatagramFrame> &datagram_frame,
                bool include_ping) -> std::optional<OutboundAckHeader> {
            if (send_profile_enabled()) {
                ++send_profile_counters().trim_ack_calls;
            }
            COQUIC_SEND_PROFILE_TIMER(trim_ack_timer, trim_ack_ns);
            if (!candidate_ack_frame.has_value()) {
                return std::nullopt;
            }
            if (candidate_ack_frame->additional_ranges.empty()) {
                return candidate_ack_frame;
            }
            auto candidate_size = estimate_application_candidate_size(
                crypto_ranges, include_handshake_done, candidate_ack_frame,
                candidate_max_data_frame, new_token_frames, new_connection_id_frames,
                retire_connection_id_frames, candidate_path_validation_frames,
                max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, datagram_frame, std::nullopt,
                include_ping);
            if (!candidate_size.has_value()) {
                fail_datagram_send(has_pending_tracked_packet());
                return std::nullopt;
            }
            if (candidate_size.value() <= max_outbound_datagram_size) {
                return candidate_ack_frame;
            }

            std::size_t retained_ranges_low = 0;
            std::size_t retained_ranges_high = candidate_ack_frame->additional_ranges.size();
            std::optional<OutboundAckHeader> best_trimmed_ack_frame;

            while (retained_ranges_low <= retained_ranges_high) {
                const auto retained_ranges =
                    retained_ranges_low + (retained_ranges_high - retained_ranges_low) / 2;
                auto trimmed_ack_frame = candidate_ack_frame;
                trimmed_ack_frame->additional_ranges.resize(retained_ranges);
                trimmed_ack_frame->additional_range_count =
                    trimmed_ack_frame->additional_ranges.size();

                candidate_size = estimate_application_candidate_size(
                    crypto_ranges, include_handshake_done, trimmed_ack_frame,
                    candidate_max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, candidate_path_validation_frames,
                    max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments, datagram_frame, std::nullopt,
                    include_ping);
                if (!candidate_size.has_value()) {
                    fail_datagram_send(has_pending_tracked_packet());
                    return std::nullopt;
                }

                if (candidate_size.value() <= max_outbound_datagram_size) {
                    best_trimmed_ack_frame = std::move(trimmed_ack_frame);
                    retained_ranges_low = retained_ranges + 1;
                    continue;
                }

                if (retained_ranges == 0) {
                    break;
                }
                retained_ranges_high = retained_ranges - 1;
            }

            return best_trimmed_ack_frame;
        };
        const auto *pending_application_probe = application_space_.pending_probe_packet.has_value()
                                                    ? &*application_space_.pending_probe_packet
                                                    : nullptr;
        const auto has_pending_application_stream_send = [&]() {
            return minimum_pending_application_stream_wire_bytes().has_value();
        };
        bool prefer_fresh_application_stream_data = pending_application_probe != nullptr &&
                                                    remaining_pto_probe_datagrams_ == 1 &&
                                                    has_pending_fresh_application_stream_send();
        const auto validation_only_path_id = [&]() -> std::optional<QuicPathId> {
            const auto response_path =
                std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                    return entry.second.pending_response.has_value();
                });
            if (response_path != paths_.end()) {
                return response_path->first;
            }
            return current_send_path_id_;
        };
        const auto path_send_is_validation_only = [&](QuicPathId path_id) {
            const auto validation_path = paths_.find(path_id);
            if (validation_path == paths_.end() || validation_path->second.validated) {
                return false;
            }
            //= https://www.rfc-editor.org/rfc/rfc9000#section-21.5.3
            // # A client MUST NOT send non-probing frames to a preferred address
            // # prior to validating that address; see Section 8.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.2
            // # The server MUST send non-probing packets from its original
            // # address until it receives a non-probing packet from the client
            // # at its preferred address and until the server has validated
            // # the new path.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3
            // # An endpoint MAY send data to an unvalidated peer address, but it
            // # MUST protect against potential attacks as described in Sections
            // # 9.3.1 and 9.3.2.
            return !handshake_confirmed_ || validation_path->second.preferred_address_path;
        };
        const auto validation_only_send_is_preferred_address =
            [&](std::optional<QuicPathId> path_id) {
                if (!path_id.has_value()) {
                    return false;
                }
                const auto validation_path = paths_.find(*path_id);
                return validation_path != paths_.end() && !validation_path->second.validated &&
                       validation_path->second.preferred_address_path;
            };
        const auto should_send_application_probe_first = [&]() {
            const auto path_id = validation_only_path_id();
            if (path_id.has_value() && path_send_is_validation_only(*path_id)) {
                return false;
            }
            if (pending_application_probe == nullptr) {
                return false;
            }

            const auto probe_has_path_validation = [&]() {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return true;
                }

                if (!current_send_path_id_.has_value()) {
                    return false;
                }

                const auto current_path = paths_.find(*current_send_path_id_);
                const bool has_current_path = current_path != paths_.end();
                const bool challenge_pending =
                    has_current_path ? current_path->second.challenge_pending : false;
                const bool has_outstanding_challenge =
                    has_current_path ? current_path->second.outstanding_challenge.has_value()
                                     : false;
                return static_cast<bool>(has_current_path & challenge_pending &
                                         has_outstanding_challenge);
            }();

            if (has_pending_application_stream_send()) {
                // If there is queued stream response data, don't let a control-only PTO probe
                // starve it; use the PTO opportunity to send the response.
                if (!pending_application_probe->is_pmtu_probe &&
                    !packet_has_stream_frames(*pending_application_probe)) {
                    return false;
                }

                // On the last datagram of a PTO burst, spend the remaining probe credit on
                // fresh queued stream data instead of retransmitting the same stream fragment
                // again.
                if (prefer_fresh_application_stream_data) {
                    return false;
                }
            }

            if (pending_application_probe->is_pmtu_probe) {
                return true;
            }

            const bool probe_is_retransmittable =
                (retransmittable_probe_frame_count(*pending_application_probe) != 0) |
                probe_has_path_validation;
            return static_cast<bool>(probe_is_retransmittable | !has_pending_application_send());
        };

        if (should_send_application_probe_first()) {
            const auto &probe_packet = *pending_application_probe;
            auto probe_max_data_frame = probe_packet.max_data_frame;
            std::optional<MaxDataFrame> fresh_probe_max_data_frame;
            auto probe_max_stream_data_frames = probe_packet.max_stream_data_frames;
            std::vector<MaxStreamDataFrame> fresh_probe_max_stream_data_frames;
            if (probe_packet.force_ack) {
                maybe_refresh_connection_receive_credit(/*force=*/true);
                if (!probe_max_data_frame.has_value() &
                    (connection_flow_control_.max_data_state == StreamControlFrameState::pending) &
                    connection_flow_control_.pending_max_data_frame.has_value()) {
                    fresh_probe_max_data_frame = connection_flow_control_.pending_max_data_frame;
                    probe_max_data_frame = fresh_probe_max_data_frame;
                }

                for (auto &[stream_id, stream] : streams_) {
                    static_cast<void>(stream_id);
                    maybe_refresh_stream_receive_credit(stream, /*force=*/true);
                    if ((stream.flow_control.max_stream_data_state !=
                         StreamControlFrameState::pending) |
                        !stream.flow_control.pending_max_stream_data_frame.has_value()) {
                        continue;
                    }

                    const auto frame = stream.flow_control.pending_max_stream_data_frame.value_or(
                        MaxStreamDataFrame{});
                    bool already_selected = std::ranges::any_of(
                        probe_max_stream_data_frames, [&](const MaxStreamDataFrame &selected) {
                            return (selected.stream_id == frame.stream_id) &
                                   (selected.maximum_stream_data == frame.maximum_stream_data);
                        });
                    if (already_selected) {
                        continue;
                    }

                    fresh_probe_max_stream_data_frames.push_back(frame);
                    probe_max_stream_data_frames.push_back(frame);
                }
            }
            const std::optional<OutboundAckHeader> probe_base_ack_frame =
                probe_packet.is_pmtu_probe
                    ? std::optional<OutboundAckHeader>{}
                    : (probe_packet.force_ack
                           ? application_space_.received_packets.build_outbound_ack_header(
                                 local_transport_parameters_.ack_delay_exponent, now,
                                 /*allow_non_pending=*/true)
                           : base_ack_frame);
            const std::span<const ByteRange> probe_crypto_ranges =
                probe_packet.is_pmtu_probe
                    ? std::span<const ByteRange>{}
                    : (application_crypto_ranges.empty()
                           ? std::span<const ByteRange>(probe_packet.crypto_ranges)
                           : std::span<const ByteRange>(application_crypto_ranges));
            auto include_ping = retransmittable_probe_frame_count(probe_packet) == 0;
            auto target_pmtu_probe_size =
                probe_packet.is_pmtu_probe ? probe_packet.pmtu_probe_size : std::size_t{0};
            std::size_t probe_padding_length = 0;
            auto restore_probe_path_validation_after_send_failure =
                [&](const PendingPathValidationFrames &validation_frames) {
                    restore_unsent_path_validation_frames_after_send_failure(
                        validation_frames, [&](QuicPathId path_id) -> PathState & {
                            return ensure_path_state(path_id);
                        });
                };
            const auto make_probe_stream_fragments = [&]() {
                auto fragments = probe_packet.stream_fragments;
                if (fragments.empty() && packet_has_stream_frames(probe_packet)) {
                    fragments.reserve(packet_stream_frame_count(probe_packet));
                    for_each_stream_frame_metadata(
                        probe_packet, [&](const StreamFrameSendMetadata &metadata) {
                            const auto stream = streams_.find(metadata.stream_id);
                            if (stream == streams_.end()) {
                                return;
                            }
                            const auto bytes = stream->second.send_buffer.bytes_for_range(
                                metadata.offset, metadata.length);
                            if (!bytes.has_value()) {
                                return;
                            }
                            auto &fragment = fragments.emplace_back(StreamFrameSendFragment{
                                .stream_id = metadata.stream_id,
                                .offset = metadata.offset,
                                .bytes = *bytes,
                                .fin = metadata.fin,
                                .consumes_flow_control = metadata.consumes_flow_control,
                            });
                            fragment.prime_stream_frame_header_cache();
                        });
                }
                for (auto &fragment : fragments) {
                    fragment.consumes_flow_control = false;
                }
                return fragments;
            };
            auto restore_probe_fragment = [&](const StreamFrameSendFragment &fragment) {
                const auto stream = streams_.find(fragment.stream_id);
                if (stream == streams_.end()) {
                    return;
                }

                const auto previous_fresh_sendable_bytes =
                    fresh_sendable_bytes_for_cache(stream->second);
                const auto previous_has_lost_send_data =
                    stream->second.reset_state == StreamControlFrameState::none &&
                    stream->second.send_buffer.has_lost_data();
                stream->second.mark_send_fragment_lost(fragment);
                note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                               previous_has_lost_send_data, stream->second);
            };
            auto mark_probe_fragments_sent =
                [&](std::span<const StreamFrameSendFragment> fragments) {
                    for (const auto &fragment : fragments) {
                        const auto stream = streams_.find(fragment.stream_id);
                        if (stream == streams_.end()) {
                            continue;
                        }

                        const auto previous_fresh_sendable_bytes =
                            fresh_sendable_bytes_for_cache(stream->second);
                        const auto previous_has_lost_send_data =
                            stream->second.reset_state == StreamControlFrameState::none &&
                            stream->second.send_buffer.has_lost_data();
                        stream->second.mark_send_fragment_sent(fragment);
                        note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                                       previous_has_lost_send_data, stream->second);
                    }
                };
            const auto restore_unsent_application_probe_candidate = [&]() {
                for (const auto &range : application_crypto_ranges) {
                    application_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
            };
            auto probe_path_validation_frames =
                take_path_validation_frames(/*ack_only_mode=*/false);
            selected_send_path_id = send_path_for_path_validation_frames(
                probe_path_validation_frames, current_send_path_id_);
            auto probe_stream_fragments = make_probe_stream_fragments();
            mark_probe_fragments_sent(probe_stream_fragments);
            auto probe_ack_frame = trim_application_ack_frame(
                probe_crypto_ranges, probe_packet.has_handshake_done, probe_base_ack_frame,
                probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                probe_max_stream_data_frames, probe_packet.max_streams_frames,
                probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                probe_packet.stream_data_blocked_frames, probe_stream_fragments, std::nullopt,
                include_ping);
            if (has_failed()) {
                return {};
            }

            auto datagram = serialize_application_candidate(
                probe_crypto_ranges, probe_packet.has_handshake_done, probe_ack_frame,
                probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                probe_max_stream_data_frames, probe_packet.max_streams_frames,
                probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                probe_packet.stream_data_blocked_frames, probe_stream_fragments, std::nullopt,
                std::nullopt, include_ping);
            if (!datagram.has_value()) {
                return fail_datagram_send(has_pending_tracked_packet());
            }
            if (path_validation_needs_minimum_datagram(probe_path_validation_frames, paths_) &&
                !probe_packet.is_pmtu_probe) {
                std::vector<Frame> probe_crypto_frames;
                append_application_crypto_frames(probe_crypto_frames, probe_crypto_ranges);
                std::vector<Frame> probe_frames_for_padding;
                const auto probe_frame_span = build_application_candidate_frames(
                    probe_frames_for_padding, application_space_.received_packets,
                    probe_crypto_frames, probe_packet.has_handshake_done, probe_ack_frame,
                    probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                    probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                    probe_packet.stream_data_blocked_frames, std::nullopt, std::nullopt,
                    include_ping);
                if (!pad_path_validation_candidate_to_minimum_datagram(
                        datagram, probe_path_validation_frames, probe_frame_span,
                        probe_stream_fragments, /*has_application_close=*/false,
                        application_space_.next_send_packet_number, application_write_key_phase_,
                        pmtu_probe_datagram_size_limit)) {
                    return fail_datagram_send(has_pending_tracked_packet());
                }
            }
            const auto pad_probe_datagram_to_target =
                [&](CodecResult<SerializedProtectedDatagram> &candidate,
                    const std::optional<OutboundAckHeader> &candidate_ack_frame,
                    std::span<const StreamFrameSendFragment> fragments) -> bool {
                if (pmtu_probe_padding_already_satisfied(target_pmtu_probe_size,
                                                         candidate.value().bytes.size())) {
                    return true;
                }
                const auto padding = target_pmtu_probe_size - candidate.value().bytes.size();
                std::vector<Frame> crypto_frames;
                append_application_crypto_frames(crypto_frames, probe_crypto_ranges);
                std::vector<Frame> frames_with_padding_storage;
                static_cast<void>(build_application_candidate_frames(
                    frames_with_padding_storage, application_space_.received_packets, crypto_frames,
                    probe_packet.has_handshake_done, candidate_ack_frame, probe_max_data_frame, {},
                    {}, {}, probe_path_validation_frames, probe_max_stream_data_frames,
                    probe_packet.max_streams_frames, probe_packet.streams_blocked_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    std::nullopt, std::nullopt, include_ping));
                static_cast<void>(maybe_add_pmtu_probe_padding(padding, frames_with_padding_storage,
                                                               probe_padding_length));

                return retry_padded_pmtu_probe_serialization(
                    candidate, frames_with_padding_storage, target_pmtu_probe_size,
                    probe_padding_length, [&] {
                        return serialize_application_candidate_from_frames(
                            frames_with_padding_storage, fragments, /*has_application_close=*/false,
                            application_space_.next_send_packet_number,
                            application_write_key_phase_);
                    });
            };
            if (!pad_probe_datagram_to_target(datagram, probe_ack_frame, probe_stream_fragments)) {
                return fail_datagram_send(has_pending_tracked_packet());
            }
            if (probe_ack_frame.has_value() &&
                datagram.value().bytes.size() > pmtu_probe_datagram_size_limit) {
                auto no_ack_datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, std::nullopt,
                    probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                    probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                    probe_packet.stream_data_blocked_frames, probe_stream_fragments, std::nullopt,
                    std::nullopt, include_ping);
                if (!no_ack_datagram.has_value()) {
                    return fail_datagram_send(has_pending_tracked_packet());
                }
                if (no_ack_datagram.value().bytes.size() <= pmtu_probe_datagram_size_limit) {
                    probe_ack_frame = std::nullopt;
                    datagram = std::move(no_ack_datagram);
                }
            }
            const auto trim_probe_candidate_to_fit =
                [&](const std::optional<OutboundAckHeader> &candidate_ack_frame,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().bytes.size() > pmtu_probe_datagram_size_limit &&
                       !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_probe_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot =
                            datagram.value().bytes.size() - pmtu_probe_datagram_size_limit;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_probe_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = false,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            last_fragment.prime_stream_frame_header_cache();
                            tail_fragment.prime_stream_frame_header_cache();
                            restore_probe_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, candidate_ack_frame,
                        probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                        probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                        probe_packet.stream_data_blocked_frames, fragments, std::nullopt,
                        std::nullopt, include_ping);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().bytes.size() <= pmtu_probe_datagram_size_limit;
            };
            if (!trim_probe_candidate_to_fit(probe_ack_frame, probe_stream_fragments)) {
                if (has_failed()) {
                    return {};
                }

                if (probe_ack_frame.has_value()) {
                    probe_ack_frame = std::nullopt;
                    probe_stream_fragments = make_probe_stream_fragments();
                    mark_probe_fragments_sent(probe_stream_fragments);
                    datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, probe_ack_frame,
                        probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                        probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                        probe_packet.stream_data_blocked_frames, probe_stream_fragments,
                        std::nullopt, std::nullopt, include_ping);
                    if (!datagram.has_value()) {
                        return fail_datagram_send(has_pending_tracked_packet());
                    }
                    static_cast<void>(
                        trim_probe_candidate_to_fit(probe_ack_frame, probe_stream_fragments));
                }
            }
            const auto retry_probe_candidate_without_fresh_receive_credit = [&]() -> bool {
                if (!fresh_probe_max_data_frame.has_value() &&
                    fresh_probe_max_stream_data_frames.empty()) {
                    return true;
                }

                probe_max_data_frame = probe_packet.max_data_frame;
                probe_max_stream_data_frames = probe_packet.max_stream_data_frames;
                fresh_probe_max_data_frame = std::nullopt;
                fresh_probe_max_stream_data_frames.clear();
                probe_stream_fragments = make_probe_stream_fragments();
                mark_probe_fragments_sent(probe_stream_fragments);
                datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, probe_ack_frame,
                    probe_max_data_frame, {}, {}, {}, probe_path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.streams_blocked_frames, probe_packet.reset_stream_frames,
                    probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                    probe_packet.stream_data_blocked_frames, probe_stream_fragments, std::nullopt,
                    std::nullopt, include_ping);
                if (!datagram.has_value()) {
                    fail_datagram_send(has_pending_tracked_packet());
                    return false;
                }
                return trim_probe_candidate_to_fit(probe_ack_frame, probe_stream_fragments);
            };
            auto probe_datagram_size = datagram_size_or_zero(datagram);
            if (probe_datagram_size > pmtu_probe_datagram_size_limit) {
                probe_padding_length = 0;
                if (should_fail_after_probe_credit_retry(
                        retry_probe_candidate_without_fresh_receive_credit(), has_failed())) {
                    return {};
                }
                probe_datagram_size = datagram_size_or_zero(datagram);
            }
            if (probe_datagram_size > pmtu_probe_datagram_size_limit) {
                restore_unsent_application_probe_candidate();
                restore_probe_path_validation_after_send_failure(probe_path_validation_frames);
                if (!packets.empty()) {
                    return finalize_datagram(packets);
                }
                if (pmtu_probe_datagram_size_limit == kMaximumDatagramSize) {
                    mark_failed();
                    return {};
                }
                return {};
            }

            std::vector<Frame> probe_frames;
            probe_frames.reserve(
                probe_crypto_ranges.size() + (probe_ack_frame.has_value() ? 1u : 0u) +
                (probe_packet.has_handshake_done ? 1u : 0u) +
                (probe_max_data_frame.has_value() ? 1u : 0u) +
                static_cast<std::size_t>(probe_path_validation_frames.response.has_value()) +
                static_cast<std::size_t>(probe_path_validation_frames.challenge.has_value()) +
                probe_max_stream_data_frames.size() + probe_packet.max_streams_frames.size() +
                probe_packet.reset_stream_frames.size() + probe_packet.stop_sending_frames.size() +
                (probe_packet.data_blocked_frame.has_value() ? 1u : 0u) +
                probe_packet.stream_data_blocked_frames.size() + (include_ping ? 1u : 0u));
            append_application_crypto_frames(probe_frames, probe_crypto_ranges);
            append_application_ack_frame(probe_frames, application_space_.received_packets,
                                         probe_ack_frame);
            if (probe_packet.has_handshake_done) {
                probe_frames.emplace_back(HandshakeDoneFrame{});
            }
            if (probe_max_data_frame.has_value()) {
                probe_frames.emplace_back(*probe_max_data_frame);
            }
            if (probe_path_validation_frames.response.has_value()) {
                probe_frames.emplace_back(*probe_path_validation_frames.response);
            }
            if (probe_path_validation_frames.challenge.has_value()) {
                probe_frames.emplace_back(*probe_path_validation_frames.challenge);
            }
            for (const auto &frame : probe_max_stream_data_frames) {
                probe_frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.max_streams_frames) {
                probe_frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.reset_stream_frames) {
                probe_frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.stop_sending_frames) {
                probe_frames.emplace_back(frame);
            }
            if (probe_packet.data_blocked_frame.has_value()) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
                // # To keep the
                // # connection from closing, a sender that is flow control limited SHOULD
                // # periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it
                // # has no ack-eliciting packets in flight.
                probe_frames.emplace_back(*probe_packet.data_blocked_frame);
            }
            for (const auto &frame : probe_packet.stream_data_blocked_frames) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
                // # To keep the
                // # connection from closing, a sender that is flow control limited SHOULD
                // # periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it
                // # has no ack-eliciting packets in flight.
                probe_frames.emplace_back(frame);
            }
            if (include_ping) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.7
                // # To avoid a deadlock, a sender SHOULD ensure that other frames are sent
                // # periodically in addition to PADDING frames to elicit acknowledgments
                // # from the receiver.
                probe_frames.emplace_back(PingFrame{});
            }
            if (probe_padding_length != 0) {
                probe_frames.emplace_back(PaddingFrame{.length = probe_padding_length});
            }

            const auto probe_packet_number =
                reserve_application_packet_number(!use_zero_rtt_packet_protection);
            if (!probe_packet_number.has_value()) {
                return {};
            }
            auto protected_probe_packet = make_application_protected_packet(
                use_zero_rtt_packet_protection, current_version_,
                application_destination_connection_id(), config_.source_connection_id,
                application_write_key_phase_,
                packet_number_length_for_send(application_space_, *probe_packet_number),
                *probe_packet_number, std::move(probe_frames), probe_stream_fragments);
            set_application_packet_spin_bit(protected_probe_packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            packets.emplace_back(std::move(protected_probe_packet));
            if (!datagram.has_value()) {
                return fail_datagram_send(has_pending_tracked_packet());
            }
            if (probe_max_data_frame.has_value() &&
                max_data_frame_matches(connection_flow_control_.pending_max_data_frame,
                                       *probe_max_data_frame)) {
                static_cast<void>(connection_flow_control_.take_max_data_frame());
            }
            bool sent_max_stream_data = false;
            for (const auto &frame : probe_max_stream_data_frames) {
                auto stream = streams_.find(frame.stream_id);
                if (stream == streams_.end()) {
                    continue;
                }
                if (!max_stream_data_frame_matches(
                        stream->second.flow_control.pending_max_stream_data_frame, frame)) {
                    continue;
                }

                const bool was_pending = stream->second.flow_control.max_stream_data_state ==
                                         StreamControlFrameState::pending;
                static_cast<void>(stream->second.take_max_stream_data_frame());
                sent_max_stream_data |= was_pending;
            }
            if (sent_max_stream_data) {
                invalidate_stream_sendability_cache();
            }

            queue_tracked_packet(
                application_space_,
                SentPacketRecord{
                    .packet_number = *probe_packet_number,
                    .sent_time = now,
                    .ack_eliciting = true,
                    .in_flight = true,
                    .declared_lost = false,
                    .has_handshake_done = probe_packet.has_handshake_done,
                    .crypto_ranges = std::vector<ByteRange>(probe_crypto_ranges.begin(),
                                                            probe_crypto_ranges.end()),
                    .reset_stream_frames = probe_packet.reset_stream_frames,
                    .stop_sending_frames = probe_packet.stop_sending_frames,
                    .max_data_frame = probe_max_data_frame,
                    .max_stream_data_frames = probe_max_stream_data_frames,
                    .max_streams_frames = probe_packet.max_streams_frames,
                    .data_blocked_frame = probe_packet.data_blocked_frame,
                    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
                    .stream_fragments = probe_stream_fragments,
                    .has_ping = include_ping,
                    .bytes_in_flight = datagram.value().bytes.size(),
                    .largest_received_packet_number_acked =
                        probe_ack_frame.has_value()
                            ? std::optional<std::uint64_t>{probe_ack_frame->largest_acknowledged}
                            : std::nullopt,
                    .path_id = selected_send_path_id.value_or(0),
                    .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                    .is_pmtu_probe = probe_packet.is_pmtu_probe,
                    .pmtu_probe_size = probe_packet.pmtu_probe_size,
                },
                datagram.value().packet_metadata.back().length);
            note_idle_ack_eliciting_send(now);
            if (probe_packet.has_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (probe_ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            if (!preserve_pto_probe_packets && probe_path_validation_frames.challenge.has_value()) {
                this->mark_path_challenge_sent(probe_path_validation_frames.path_id,
                                               datagram.value().bytes.size());
            }
            if (preserve_pto_probe_packets) {
                restore_probe_path_validation_after_send_failure(probe_path_validation_frames);
            }
            if (track_client_receive_keepalive_probes && probe_packet.force_ack) {
                last_client_receive_keepalive_probe_time_ = now;
            }
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        } else {
            const auto include_handshake_done =
                !use_zero_rtt_packet_protection && config_.role == EndpointRole::server &&
                handshake_done_state_ == StreamControlFrameState::pending;
            //= https://www.rfc-editor.org/rfc/rfc9001#section-4.1.2
            // # The server MUST send a HANDSHAKE_DONE frame as soon as the
            // # handshake is complete.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-19.20
            // # Servers MUST NOT send a HANDSHAKE_DONE frame before completing
            // # the handshake.
            const auto selected_validation_only_path_id = validation_only_path_id();
            const bool validation_only_send = [&]() {
                if (!selected_validation_only_path_id.has_value()) {
                    return false;
                }
                return path_send_is_validation_only(*selected_validation_only_path_id);
            }();
            const bool suppress_ack_for_preferred_address_validation =
                validation_only_send_is_preferred_address(selected_validation_only_path_id);
            auto application_close_frame = pending_application_close_;
            bool send_application_close_only = application_close_frame.has_value();
            if (application_close_frame.has_value() && !can_send_one_rtt_packets) {
                return {};
            }
            const auto application_candidate_crypto_ranges =
                send_application_close_only ? std::span<const ByteRange>{}
                                            : std::span<const ByteRange>(application_crypto_ranges);
            const auto send_application_ack_only =
                [&](const OutboundAckHeader &ack_header) -> DatagramBuffer {
                auto restore_ack_path_validation_after_send_failure =
                    [&](const PendingPathValidationFrames &validation_frames) {
                        restore_unsent_path_validation_frames_after_send_failure(
                            validation_frames, [&](QuicPathId path_id) -> PathState & {
                                return ensure_path_state(path_id);
                            });
                    };
                auto ack_only_path_validation_frames =
                    take_path_validation_frames(/*ack_only_mode=*/false);
                selected_send_path_id = send_path_for_path_validation_frames(
                    ack_only_path_validation_frames, current_send_path_id_);
                std::vector<Frame> ack_only_frames;
                append_application_ack_frame(ack_only_frames, application_space_.received_packets,
                                             std::optional<OutboundAckHeader>{ack_header});
                if (ack_only_path_validation_frames.response.has_value()) {
                    ack_only_frames.emplace_back(*ack_only_path_validation_frames.response);
                }
                if (ack_only_path_validation_frames.challenge.has_value()) {
                    ack_only_frames.emplace_back(*ack_only_path_validation_frames.challenge);
                }
                const auto ack_only_packet_number =
                    reserve_application_packet_number(!use_zero_rtt_packet_protection);
                if (!ack_only_packet_number.has_value()) {
                    restore_ack_path_validation_after_send_failure(ack_only_path_validation_frames);
                    return {};
                }
                auto ack_only_datagram = serialize_application_candidate_from_frames(
                    ack_only_frames, {}, /*has_application_close=*/false, *ack_only_packet_number,
                    application_write_key_phase_);
                if (!ack_only_datagram.has_value()) {
                    restore_ack_path_validation_after_send_failure(ack_only_path_validation_frames);
                    return fail_datagram_send(has_pending_tracked_packet());
                }
                if (path_validation_needs_minimum_datagram(ack_only_path_validation_frames,
                                                           paths_) &&
                    max_outbound_datagram_size >= kMinimumInitialDatagramSize &&
                    ack_only_datagram.value().bytes.size() < kMinimumInitialDatagramSize) {
                    std::size_t padding_length =
                        kMinimumInitialDatagramSize - ack_only_datagram.value().bytes.size();
                    if (maybe_add_pmtu_probe_padding(padding_length, ack_only_frames,
                                                     padding_length) &&
                        !retry_padded_pmtu_probe_serialization(
                            ack_only_datagram, ack_only_frames, kMinimumInitialDatagramSize,
                            padding_length, [&] {
                                return serialize_application_candidate_from_frames(
                                    ack_only_frames, {}, /*has_application_close=*/false,
                                    *ack_only_packet_number, application_write_key_phase_);
                            })) {
                        restore_ack_path_validation_after_send_failure(
                            ack_only_path_validation_frames);
                        return fail_datagram_send(has_pending_tracked_packet());
                    }
                }
                auto ack_only_packet = make_application_protected_packet(
                    use_zero_rtt_packet_protection, current_version_,
                    application_destination_connection_id(), config_.source_connection_id,
                    application_write_key_phase_,
                    packet_number_length_for_send(application_space_, *ack_only_packet_number),
                    *ack_only_packet_number, std::move(ack_only_frames), {});
                set_application_packet_spin_bit(ack_only_packet,
                                                outbound_spin_bit_for_path(selected_send_path_id));
                packets.emplace_back(std::move(ack_only_packet));
                maybe_queue_ack_only_path_validation_packet(ack_only_path_validation_frames, [&] {
                    const bool path_validation_ack_eliciting =
                        ack_only_path_validation_is_ack_eliciting(ack_only_path_validation_frames);
                    queue_tracked_packet(
                        application_space_,
                        SentPacketRecord{
                            .packet_number = *ack_only_packet_number,
                            .sent_time = now,
                            .ack_eliciting = path_validation_ack_eliciting,
                            .in_flight = path_validation_ack_eliciting,
                            .bytes_in_flight = ack_only_datagram.value().bytes.size(),
                            .largest_received_packet_number_acked =
                                ack_largest_for_path_validation_sent_record(
                                    path_validation_ack_eliciting, ack_header),
                            .path_id = selected_send_path_id.value_or(0),
                            .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                        },
                        ack_only_datagram.value().packet_metadata.back().length);
                    maybe_note_path_validation_ack_eliciting_send(
                        path_validation_ack_eliciting, [&] { note_idle_ack_eliciting_send(now); });
                });
                //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
                // # Since packets containing only ACK frames are not congestion
                // # controlled, an endpoint MUST NOT send more than one such
                // # packet in response to receiving an ack-eliciting packet.
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
                return commit_serialized_datagram(
                    packets, std::move(ack_only_datagram.value()),
                    CommitSerializedDatagramOptions{
                        .path_challenge_path_id =
                            path_challenge_path_id(ack_only_path_validation_frames),
                    });
            };
            auto force_ack_due = application_space_.force_ack_send & base_ack_frame.has_value();
            auto ack_only_mode =
                (force_ack_due | validation_only_send) & !send_application_close_only;
            auto defer_flow_credit = validation_only_send | send_application_close_only;
            auto application_max_data_frame = defer_flow_credit
                                                  ? std::optional<MaxDataFrame>{}
                                                  : connection_flow_control_.take_max_data_frame();
            auto data_blocked_frame = (ack_only_mode || send_application_close_only)
                                          ? std::optional<DataBlockedFrame>{}
                                          : connection_flow_control_.take_data_blocked_frame();
            auto stream_control_frames = take_pending_stream_control_frames(
                streams_, defer_flow_credit, ack_only_mode || send_application_close_only);
            auto &max_stream_data_frames = stream_control_frames.max_stream_data;
            auto max_streams_frames = send_application_close_only
                                          ? std::vector<MaxStreamsFrame>{}
                                          : take_max_streams_frames(ack_only_mode);
            auto streams_blocked_frames = (ack_only_mode || send_application_close_only)
                                              ? std::vector<StreamsBlockedFrame>{}
                                              : stream_open_limits_.take_streams_blocked_frames();
            auto new_token_frames = send_application_close_only
                                        ? std::vector<NewTokenFrame>{}
                                        : take_new_token_frames(ack_only_mode);
            auto new_connection_id_frames = take_new_connection_id_frames(ack_only_mode);
            auto retire_connection_id_frames = take_retire_connection_id_frames(ack_only_mode);
            //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3.3
            // # An endpoint that receives a PATH_CHALLENGE on an active path
            // # SHOULD send a non-probing packet in response.
            auto application_path_validation_frames = take_path_validation_frames(ack_only_mode);
            if (application_path_validation_frames.response.has_value()) {
                defer_retire_connection_id_frames(retire_connection_id_frames);
            }
            selected_send_path_id = send_path_for_path_validation_frames(
                application_path_validation_frames, current_send_path_id_);
            auto &reset_stream_frames = stream_control_frames.reset_stream;
            auto &stop_sending_frames = stream_control_frames.stop_sending;
            auto &stream_data_blocked_frames = stream_control_frames.stream_data_blocked;
            auto congestion_limited_datagram_size = [&]() {
                if (application_space_.pending_probe_packet.has_value() ||
                    send_application_close_only) {
                    return max_outbound_datagram_size;
                }
                const auto cwnd = congestion_controller_.send_window();
                const auto bytes_in_flight = congestion_controller_.bytes_in_flight();
                if (bytes_in_flight >= cwnd) {
                    return std::size_t{0};
                }
                return std::min(max_outbound_datagram_size, cwnd - bytes_in_flight);
            }();
            auto base_application_stream_budget = application_stream_frame_budget(
                congestion_limited_datagram_size, application_destination_connection_id().size(),
                packet_number_length_for_send(application_space_,
                                              application_space_.next_send_packet_number));
            const auto pending_application_stream_priority = [&]() -> std::optional<std::int32_t> {
                std::optional<std::int32_t> highest;
                for (const auto &[stream_id, stream] : streams_) {
                    if (stream.reset_state != StreamControlFrameState::none) {
                        continue;
                    }
                    if (stream.sendable_bytes() == 0 && !stream.send_buffer.has_lost_data() &&
                        !stream_fin_sendable(stream)) {
                        continue;
                    }
                    const auto priority_it = stream_send_priorities_.find(stream_id);
                    const auto priority =
                        priority_it == stream_send_priorities_.end() ? 0 : priority_it->second;
                    highest = highest.has_value() ? std::max(*highest, priority) : priority;
                }
                return highest;
            }();
            std::optional<DatagramFrame> selected_datagram_frame;
            std::optional<std::size_t> selected_datagram_queue_index;
            bool can_select_datagram_frame = !ack_only_mode && !send_application_close_only &&
                                             !validation_only_send &&
                                             !pending_datagram_send_queue_.empty();
            if (can_select_datagram_frame) {
                for (std::size_t index = 0; index < pending_datagram_send_queue_.size(); ++index) {
                    const auto &pending_datagram = pending_datagram_send_queue_[index];
                    const auto datagram_wire_size = datagram_frame_wire_size(
                        pending_datagram.bytes.size(), /*has_length=*/true);
                    const bool peer_limit_allows_datagram =
                        peer_transport_parameters_.has_value() &&
                        peer_transport_parameters_->max_datagram_frame_size != 0 &&
                        datagram_wire_size <= peer_transport_parameters_->max_datagram_frame_size;
                    if (pending_application_stream_priority.has_value() &&
                        pending_datagram.priority < *pending_application_stream_priority) {
                        //= https://www.rfc-editor.org/rfc/rfc9221#section-5.1
                        // # QUIC implementations SHOULD present an API to applications to assign
                        // # relative priorities to DATAGRAM frames with respect to each other and
                        // # to QUIC streams.
                        continue;
                    }
                    if (!peer_limit_allows_datagram ||
                        datagram_wire_size > base_application_stream_budget) {
                        continue;
                    }
                    if (selected_datagram_queue_index.has_value()) {
                        const auto &selected =
                            pending_datagram_send_queue_[*selected_datagram_queue_index];
                        if (pending_datagram.priority < selected.priority ||
                            (pending_datagram.priority == selected.priority &&
                             pending_datagram.sequence > selected.sequence)) {
                            continue;
                        }
                    }
                    selected_datagram_queue_index = index;
                    selected_datagram_frame = DatagramFrame{
                        .has_length = true,
                        .data = pending_datagram.bytes.to_vector(),
                    };
                }
            }
            auto candidate_last_stream_id = last_application_send_stream_id_;
            auto &stream_fragments = application_stream_fragment_scratch_;
            stream_fragments.clear();
            std::size_t application_stream_payload_bytes = 0;
            struct ApplicationStreamScratchGuard {
                std::vector<StreamFrameSendFragment> &fragments;
                std::vector<std::map<std::uint64_t, StreamState>::iterator> &active_streams;
                ~ApplicationStreamScratchGuard() {
                    fragments.clear();
                    active_streams.clear();
                }
            } application_stream_scratch_guard{stream_fragments, active_stream_iterator_scratch_};
            std::optional<OutboundAckHeader> selected_ack_frame;
            if (!send_application_close_only && !suppress_ack_for_preferred_address_validation &&
                base_ack_frame.has_value()) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2
                // # When sending a packet for any reason, an endpoint SHOULD attempt to
                // # include an ACK frame if one has not been sent recently.
                selected_ack_frame =
                    base_ack_frame->additional_ranges.empty()
                        ? base_ack_frame
                        : trim_application_ack_frame(
                              application_candidate_crypto_ranges, include_handshake_done,
                              base_ack_frame, application_max_data_frame, new_token_frames,
                              new_connection_id_frames, retire_connection_id_frames,
                              application_path_validation_frames, max_stream_data_frames,
                              max_streams_frames, streams_blocked_frames, reset_stream_frames,
                              stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                              stream_fragments, selected_datagram_frame,
                              /*include_ping=*/false);
            }
            if (has_failed()) {
                return {};
            }

            //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
            // # An endpoint SHOULD include multiple frames in a single packet if
            // # they are to be sent at the same encryption level, instead of
            // # coalescing multiple packets at the same encryption level.
            ApplicationCandidateFrameBuilder application_candidate_frames{
                ApplicationCandidateFrameBuilder::Args{
                    .scratch = application_candidate_frame_scratch_,
                    .alternate_scratch = alternate_application_candidate_frame_scratch_,
                    .received_packets = application_space_.received_packets,
                    .crypto_frames = selectable_application_crypto_frames(
                        send_application_close_only, application_crypto_frames),
                    .include_handshake_done = include_handshake_done,
                    .ack_header = selected_ack_frame,
                    .max_data_frame = application_max_data_frame,
                    .new_token_frames = new_token_frames,
                    .new_connection_id_frames = new_connection_id_frames,
                    .retire_connection_id_frames = retire_connection_id_frames,
                    .path_validation_frames = application_path_validation_frames,
                    .max_stream_data_frames = max_stream_data_frames,
                    .max_streams_frames = max_streams_frames,
                    .streams_blocked_frames = streams_blocked_frames,
                    .reset_stream_frames = reset_stream_frames,
                    .stop_sending_frames = stop_sending_frames,
                    .data_blocked_frame = data_blocked_frame,
                    .stream_data_blocked_frames = stream_data_blocked_frames,
                    .datagram_frame = selected_datagram_frame,
                    .application_close_frame = application_close_frame,
                }};

            const auto application_stream_send_pacing_ready = [&]() {
                if (continue_paced_burst) {
                    return true;
                }

                const auto pacing_bytes = application_stream_pacing_deadline_bytes(
                    minimum_pending_application_datagram_datagram_bytes());
                const auto application_stream_send_deadline = congestion_controller_.next_send_time(
                    pacing_bytes.value_or(max_outbound_datagram_size));
                return !application_stream_send_deadline.has_value() ||
                       now >= *application_stream_send_deadline;
            };
            bool application_stream_pacing_ready = application_stream_send_pacing_ready();
            if (!application_stream_pacing_ready && send_profile_enabled()) {
                ++send_profile_counters().application_select_pacing_blocked;
            }
            const bool select_application_stream_data =
                !ack_only_mode && !send_application_close_only && application_stream_pacing_ready;

            if (select_application_stream_data) {
                auto application_stream_budget = base_application_stream_budget;
                auto control_candidate_size = estimate_application_candidate_size_from_frames(
                    application_candidate_frames.current(), stream_fragments,
                    application_close_frame.has_value(), application_space_.next_send_packet_number,
                    application_write_key_phase_);
                const auto minimum_stream_wire_bytes =
                    selected_ack_frame.has_value() ? minimum_pending_application_stream_wire_bytes()
                                                   : std::optional<std::size_t>{};
                if (ack_can_be_trimmed_for_stream_budget(
                        selected_ack_frame, minimum_stream_wire_bytes, control_candidate_size,
                        congestion_limited_datagram_size)) {
                    const auto remaining_stream_budget =
                        control_candidate_size.value() >= congestion_limited_datagram_size
                            ? std::size_t{0}
                            : congestion_limited_datagram_size - control_candidate_size.value();
                    if (remaining_stream_budget < *minimum_stream_wire_bytes) {
                        const auto no_ack_control_candidate_frames =
                            application_candidate_frames.alternate(std::nullopt);
                        auto no_ack_control_candidate_size =
                            estimate_application_candidate_size_from_frames(
                                no_ack_control_candidate_frames, stream_fragments,
                                application_close_frame.has_value(),
                                application_space_.next_send_packet_number,
                                application_write_key_phase_);
                        if (!no_ack_control_candidate_size.has_value()) {
                            if (no_ack_control_candidate_size.error().code !=
                                CodecErrorCode::empty_packet_payload) {
                                return fail_datagram_send(has_pending_tracked_packet());
                            }
                            static_cast<void>(maybe_select_empty_no_ack_candidate(
                                base_application_stream_budget, *minimum_stream_wire_bytes,
                                selected_ack_frame, application_stream_budget,
                                control_candidate_size, no_ack_control_candidate_size));
                            application_candidate_frames.invalidate();
                        } else if (maybe_select_sized_no_ack_candidate(
                                       congestion_limited_datagram_size, *minimum_stream_wire_bytes,
                                       selected_ack_frame, application_stream_budget,
                                       control_candidate_size, no_ack_control_candidate_size)) {
                            application_candidate_frames.invalidate();
                        }
                    }
                }
                if (!control_candidate_size.has_value()) {
                    if (control_candidate_size.error().code !=
                        CodecErrorCode::empty_packet_payload) {
                        return fail_datagram_send(has_pending_tracked_packet());
                    }
                } else if (control_candidate_size.value() >= congestion_limited_datagram_size) {
                    application_stream_budget = 0;
                } else {
                    application_stream_budget =
                        congestion_limited_datagram_size - control_candidate_size.value();
                }

                COQUIC_SEND_PROFILE_TIMER(stream_select_timer, stream_select_ns);
                application_stream_payload_bytes =
                    take_stream_fragments(connection_flow_control_, streams_,
                                          application_stream_budget, candidate_last_stream_id,
                                          stream_fragments, prefer_fresh_application_stream_data);
                if (send_profile_enabled()) {
                    auto &profile = send_profile_counters();
                    ++profile.application_select_stream_attempts;
                    profile.application_select_stream_empty +=
                        static_cast<std::uint64_t>(stream_fragments.empty());
                    profile.application_select_stream_bytes += application_stream_payload_bytes;
                }
            }

            const auto finalize_existing_packets_or_empty = [&]() -> DatagramBuffer {
                if (packets.empty()) {
                    return {};
                }
                selected_send_path_id = current_send_path_id_;
                return finalize_datagram(packets);
            };
            const auto fallback_to_existing_packets_or_ack_only =
                [&](bool require_due_ack_only) -> DatagramBuffer {
                if (!packets.empty()) {
                    return finalize_existing_packets_or_empty();
                }
                const bool can_send_ack_only = !require_due_ack_only || application_ack_due_now ||
                                               has_pending_path_validation_frame();
                if (selected_ack_frame.has_value() && can_send_ack_only) {
                    return send_application_ack_only(*selected_ack_frame);
                }
                return {};
            };
            const auto trace_application_send_blocked = [&](std::string_view reason,
                                                            std::size_t bytes) {
                if (!traces_this_connection) {
                    return;
                }
                std::cerr << "quic-packet-trace send-blocked scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " reason=" << reason << " size=" << bytes
                          << " current=" << format_optional_path_id(current_send_path_id_)
                          << " previous=" << format_optional_path_id(previous_path_id_)
                          << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                          << " current_path={"
                          << format_path_state_summary(
                                 find_path_state(paths_, current_send_path_id_))
                          << "} cwnd=" << congestion_controller_.congestion_window()
                          << " bif=" << congestion_controller_.bytes_in_flight()
                          << " pending_send=" << static_cast<int>(has_pending_application_send())
                          << " probe="
                          << static_cast<int>(application_space_.pending_probe_packet.has_value())
                          << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                          << '\n';
            };
            const auto note_application_congestion_blocked = [&](std::size_t bytes) {
                trace_application_send_blocked("congestion", bytes);
                if (send_profile_enabled()) {
                    auto &profile = send_profile_counters();
                    ++profile.congestion_blocks;
                    const auto cwnd = congestion_controller_.congestion_window();
                    const auto bif = congestion_controller_.bytes_in_flight();
                    profile.congestion_block_cwnd_sum += cwnd;
                    profile.congestion_block_bif_sum += bif;
                    profile.congestion_block_max_cwnd =
                        std::max<std::uint64_t>(profile.congestion_block_max_cwnd, cwnd);
                    profile.congestion_block_min_cwnd =
                        profile.congestion_block_min_cwnd == 0
                            ? cwnd
                            : std::min<std::uint64_t>(profile.congestion_block_min_cwnd, cwnd);
                }
            };
            const auto note_application_pacing_blocked = [&](std::size_t bytes) {
                trace_application_send_blocked("pacing", bytes);
                if (send_profile_enabled()) {
                    ++send_profile_counters().pacing_blocks;
                }
            };
            const auto note_application_burst_blocked = [&](std::size_t bytes) {
                trace_application_send_blocked("burst", bytes);
            };
            const auto restore_and_fallback_blocked_application_candidate =
                [&]() -> DatagramBuffer {
                restore_unsent_application_candidate(
                    application_max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, application_path_validation_frames,
                    max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments);
                return fallback_to_existing_packets_or_ack_only(/*require_due_ack_only=*/true);
            };
            const auto application_candidate_is_ack_eliciting = [&]() {
                return !selectable_application_crypto_frames(send_application_close_only,
                                                             application_crypto_frames)
                            .empty() ||
                       application_ack_eliciting_frame_count(
                           new_token_frames, include_handshake_done, application_max_data_frame,
                           new_connection_id_frames, retire_connection_id_frames,
                           application_path_validation_frames.response.has_value(),
                           application_path_validation_frames.challenge.has_value(),
                           max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                           reset_stream_frames, stop_sending_frames, data_blocked_frame,
                           stream_data_blocked_frames, selected_datagram_frame,
                           stream_fragments) != 0;
            };
            const auto application_candidate_bypasses_congestion_window = [&]() {
                const bool has_non_pmtu_application_probe =
                    application_space_.pending_probe_packet.has_value() &&
                    !application_space_.pending_probe_packet->is_pmtu_probe;
                //= https://www.rfc-editor.org/rfc/rfc9002#section-7.5
                // # Probe packets MUST NOT be blocked by the congestion
                // # controller.
                return has_non_pmtu_application_probe ||
                       (application_path_validation_frames.challenge.has_value() &&
                        stream_fragments.empty());
            };
            auto candidate_application_write_key_phase = application_write_key_phase_;
            const auto serialize_application_profiled =
                [&](std::span<const Frame> candidate_frames,
                    const std::vector<StreamFrameSendFragment> &fragments, bool force_one_rtt,
                    std::uint64_t packet_number,
                    bool key_phase) -> CodecResult<SerializedProtectedDatagram> {
                if (send_profile_enabled()) {
                    ++send_profile_counters().application_candidate_serializations;
                }
                return serialize_application_candidate_from_frames(
                    candidate_frames, fragments, force_one_rtt, packet_number, key_phase);
            };

            auto candidate_application_datagram = serialize_application_profiled(
                application_candidate_frames.current(), stream_fragments,
                application_close_frame.has_value(), application_space_.next_send_packet_number,
                application_write_key_phase_);
            if (!candidate_application_datagram.has_value()) {
                if (is_empty_packet_payload_error(candidate_application_datagram)) {
                    if (packet_trace_matches_connection(config_.source_connection_id)) {
                        std::cerr << "quic-packet-trace app-empty scid="
                                  << format_connection_id_hex(config_.source_connection_id)
                                  << " packets=" << packets.size()
                                  << " stream_fragments=" << stream_fragments.size()
                                  << " stream_bytes=" << application_stream_payload_bytes
                                  << " ack=" << static_cast<int>(selected_ack_frame.has_value())
                                  << " hsdone=" << static_cast<int>(include_handshake_done) << "\n";
                    }
                    return finalize_existing_packets_or_empty();
                }
                return fail_datagram_send(has_pending_tracked_packet());
            }
            if (!pad_path_validation_candidate_to_minimum_datagram(
                    candidate_application_datagram, application_path_validation_frames,
                    application_candidate_frames.current(), stream_fragments,
                    application_close_frame.has_value(), application_space_.next_send_packet_number,
                    application_write_key_phase_, max_outbound_datagram_size)) {
                return fail_datagram_send(has_pending_tracked_packet());
            }
            if (selected_ack_frame.has_value() &&
                candidate_application_datagram.value().bytes.size() > max_outbound_datagram_size) {
                if (send_profile_enabled()) {
                    ++send_profile_counters().application_no_ack_candidate_attempts;
                }
                auto no_ack_candidate = serialize_application_profiled(
                    application_candidate_frames.alternate(std::nullopt), stream_fragments,
                    application_close_frame.has_value(), application_space_.next_send_packet_number,
                    application_write_key_phase_);
                if (!no_ack_candidate.has_value()) {
                    if (!is_empty_packet_payload_error(no_ack_candidate)) {
                        return fail_datagram_send(has_pending_tracked_packet());
                    }
                } else if (no_ack_candidate.value().bytes.size() <= max_outbound_datagram_size) {
                    selected_ack_frame = std::nullopt;
                    application_candidate_frames.invalidate();
                    candidate_application_datagram = std::move(no_ack_candidate);
                    if (send_profile_enabled()) {
                        ++send_profile_counters().application_no_ack_candidate_used;
                    }
                }
            }

            const auto trim_candidate_to_fit =
                [&](CodecResult<SerializedProtectedDatagram> &datagram,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                if (!datagram.has_value()) {
                    return false;
                }
                if (send_profile_enabled()) {
                    ++send_profile_counters().application_trim_candidate_calls;
                }
                while (datagram.value().bytes.size() > max_outbound_datagram_size &&
                       !fragments.empty()) {
                    if (send_profile_enabled()) {
                        ++send_profile_counters().application_trim_candidate_iterations;
                    }
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_application_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot =
                            datagram.value().bytes.size() - max_outbound_datagram_size;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            application_stream_payload_bytes -= last_fragment.bytes.size();
                            restore_application_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = last_fragment.consumes_flow_control,
                            };
                            application_stream_payload_bytes -= trim_bytes;
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            last_fragment.prime_stream_frame_header_cache();
                            tail_fragment.prime_stream_frame_header_cache();
                            restore_application_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_profiled(
                        application_candidate_frames.current(), fragments,
                        application_close_frame.has_value(),
                        application_space_.next_send_packet_number, application_write_key_phase_);
                    if (!datagram.has_value()) {
                        if (is_empty_packet_payload_error(datagram)) {
                            return false;
                        }
                        fail_datagram_send(has_pending_tracked_packet());
                        return false;
                    }
                }

                return datagram.value().bytes.size() <= max_outbound_datagram_size;
            };

            if (!trim_candidate_to_fit(candidate_application_datagram, stream_fragments)) {
                if (has_failed()) {
                    return {};
                }
                if (selected_ack_frame.has_value()) {
                    if (send_profile_enabled()) {
                        ++send_profile_counters().application_no_ack_retry_attempts;
                    }
                    restore_unsent_application_candidate(
                        application_max_data_frame, new_token_frames, new_connection_id_frames,
                        retire_connection_id_frames, application_path_validation_frames,
                        max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments);

                    application_max_data_frame = connection_flow_control_.take_max_data_frame();
                    data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                    stream_control_frames =
                        take_pending_stream_control_frames(streams_,
                                                           /*defer_flow_credit=*/false,
                                                           /*omit_retransmittable_control=*/false);
                    max_streams_frames = take_max_streams_frames(/*ack_only_mode=*/false);
                    streams_blocked_frames = stream_open_limits_.take_streams_blocked_frames();
                    new_token_frames = take_new_token_frames(/*ack_only_mode=*/false);
                    new_connection_id_frames =
                        take_new_connection_id_frames(/*ack_only_mode=*/false);
                    retire_connection_id_frames =
                        take_retire_connection_id_frames(/*ack_only_mode=*/false);
                    application_path_validation_frames =
                        take_path_validation_frames(/*ack_only_mode=*/false);
                    if (application_path_validation_frames.response.has_value()) {
                        defer_retire_connection_id_frames(retire_connection_id_frames);
                    }
                    selected_send_path_id = send_path_for_path_validation_frames(
                        application_path_validation_frames, current_send_path_id_);
                    candidate_last_stream_id = last_application_send_stream_id_;
                    COQUIC_SEND_PROFILE_TIMER(stream_select_timer, stream_select_ns);
                    application_stream_payload_bytes = 0;
                    if (select_application_stream_data) {
                        application_stream_payload_bytes = take_stream_fragments(
                            connection_flow_control_, streams_, base_application_stream_budget,
                            candidate_last_stream_id, stream_fragments,
                            prefer_fresh_application_stream_data);
                    }
                    selected_ack_frame = std::nullopt;
                    application_candidate_frames.invalidate();
                    candidate_application_datagram = serialize_application_profiled(
                        application_candidate_frames.current(), stream_fragments,
                        application_close_frame.has_value(),
                        application_space_.next_send_packet_number, application_write_key_phase_);
                    if (should_fail_non_empty_packet_payload_candidate(
                            candidate_application_datagram)) {
                        return fail_datagram_send(has_pending_tracked_packet());
                    }
                    if (!pad_path_validation_candidate_to_minimum_datagram(
                            candidate_application_datagram, application_path_validation_frames,
                            application_candidate_frames.current(), stream_fragments,
                            application_close_frame.has_value(),
                            application_space_.next_send_packet_number,
                            application_write_key_phase_, max_outbound_datagram_size)) {
                        return fail_datagram_send(has_pending_tracked_packet());
                    }
                    static_cast<void>(
                        trim_candidate_to_fit(candidate_application_datagram, stream_fragments));
                }
                if (!candidate_application_datagram.has_value()) {
                    return fallback_to_existing_packets_or_ack_only(/*require_due_ack_only=*/false);
                }
            }
            const auto retry_candidate_without_receive_credit = [&]() {
                if (!application_max_data_frame.has_value() && max_stream_data_frames.empty()) {
                    return;
                }

                if (send_profile_enabled()) {
                    ++send_profile_counters().application_receive_credit_retry_attempts;
                }
                restore_unsent_application_candidate(
                    application_max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, application_path_validation_frames,
                    max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments);
                application_max_data_frame = std::nullopt;
                data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                stream_control_frames =
                    take_pending_stream_control_frames(streams_, /*defer_flow_credit=*/true,
                                                       /*omit_retransmittable_control=*/false);
                max_streams_frames = take_max_streams_frames(/*ack_only_mode=*/false);
                streams_blocked_frames = stream_open_limits_.take_streams_blocked_frames();
                new_token_frames = take_new_token_frames(/*ack_only_mode=*/false);
                new_connection_id_frames = take_new_connection_id_frames(/*ack_only_mode=*/false);
                retire_connection_id_frames =
                    take_retire_connection_id_frames(/*ack_only_mode=*/false);
                application_path_validation_frames =
                    take_path_validation_frames(/*ack_only_mode=*/false);
                if (application_path_validation_frames.response.has_value()) {
                    defer_retire_connection_id_frames(retire_connection_id_frames);
                }
                selected_send_path_id = send_path_for_path_validation_frames(
                    application_path_validation_frames, current_send_path_id_);
                candidate_last_stream_id = last_application_send_stream_id_;
                COQUIC_SEND_PROFILE_TIMER(stream_select_timer, stream_select_ns);
                application_stream_payload_bytes = 0;
                if (select_application_stream_data) {
                    application_stream_payload_bytes = take_stream_fragments(
                        connection_flow_control_, streams_, base_application_stream_budget,
                        candidate_last_stream_id, stream_fragments,
                        prefer_fresh_application_stream_data);
                }
                application_candidate_frames.invalidate();
                candidate_application_datagram = serialize_application_profiled(
                    application_candidate_frames.current(), stream_fragments,
                    application_close_frame.has_value(), application_space_.next_send_packet_number,
                    application_write_key_phase_);
                if (!candidate_application_datagram.has_value()) {
                    if (should_fail_non_empty_packet_payload_candidate(
                            candidate_application_datagram)) {
                        fail_datagram_send(has_pending_tracked_packet());
                    }
                    return;
                }
                if (!pad_path_validation_candidate_to_minimum_datagram(
                        candidate_application_datagram, application_path_validation_frames,
                        application_candidate_frames.current(), stream_fragments,
                        application_close_frame.has_value(),
                        application_space_.next_send_packet_number, application_write_key_phase_,
                        max_outbound_datagram_size)) {
                    fail_datagram_send(has_pending_tracked_packet());
                    return;
                }
                static_cast<void>(
                    trim_candidate_to_fit(candidate_application_datagram, stream_fragments));
            };
            const auto retry_application_close_without_reason = [&]() -> bool {
                if (!send_application_close_only) {
                    return false;
                }

                auto &retry_close_frame = *application_close_frame;
                if (retry_close_frame.reason.bytes.empty()) {
                    return false;
                }

                if (send_profile_enabled()) {
                    ++send_profile_counters().application_close_reason_retry_attempts;
                }
                retry_close_frame.reason.bytes.clear();
                application_candidate_frames.invalidate();
                candidate_application_datagram = serialize_application_profiled(
                    application_candidate_frames.current(), stream_fragments,
                    application_close_frame.has_value(), application_space_.next_send_packet_number,
                    application_write_key_phase_);
                if (!candidate_application_datagram.has_value()) {
                    // A close-only retry still carries the close frame, so any serialization error
                    // is fatal.
                    fail_datagram_send(has_pending_tracked_packet());
                    return false;
                }
                return candidate_application_datagram.value().bytes.size() <=
                       max_outbound_datagram_size;
            };
            const auto split_small_terminal_stream_fin_candidate = [&]() -> bool {
                if (!candidate_application_datagram.has_value() || stream_fragments.empty()) {
                    return true;
                }
                if (!stream_terminal_data_fin_can_be_split(
                        stream_fragments.back(), max_outbound_datagram_size,
                        candidate_application_datagram.value().bytes.size())) {
                    return true;
                }

                auto &last_fragment = stream_fragments.back();
                const auto stream_id = last_fragment.stream_id;
                last_fragment.fin = false;
                last_fragment.prime_stream_frame_header_cache();
                mark_stream_terminal_fin_pending(streams_, stream_id);

                candidate_application_datagram = serialize_application_profiled(
                    application_candidate_frames.current(), stream_fragments,
                    application_close_frame.has_value(), application_space_.next_send_packet_number,
                    application_write_key_phase_);
                if (!candidate_application_datagram.has_value()) {
                    return false;
                }
                return candidate_application_datagram.value().bytes.size() <=
                       max_outbound_datagram_size;
            };
            const auto mark_application_close_unusable = [&]() {
                if (!send_application_close_only) {
                    return;
                }
                pending_application_close_.reset();
                local_application_close_sent_ = true;
                enter_closing_state(now, QuicConnectionTerminalState::closed);
            };
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
            // # All QUIC packets that are not sent in a PMTU probe SHOULD be
            // # sized to fit within the maximum datagram size to avoid the
            // # datagram being fragmented or dropped [RFC8085].
            auto candidate_datagram_size = datagram_size_or_zero(candidate_application_datagram);
            if (candidate_datagram_size > max_outbound_datagram_size) {
                retry_candidate_without_receive_credit();
                if (has_failed()) {
                    return {};
                }
                if (!candidate_application_datagram.has_value()) {
                    return fallback_to_existing_packets_or_ack_only(/*require_due_ack_only=*/false);
                }
            }
            if (!split_small_terminal_stream_fin_candidate()) {
                return fail_datagram_send(has_pending_tracked_packet());
            }
            candidate_datagram_size = datagram_size_or_zero(candidate_application_datagram);
            if (candidate_datagram_size > max_outbound_datagram_size &&
                retry_application_close_without_reason()) {
                candidate_datagram_size = datagram_size_or_zero(candidate_application_datagram);
            }
            if (has_failed()) {
                return {};
            }
            if (candidate_datagram_size > max_outbound_datagram_size) {
                restore_unsent_application_candidate(
                    application_max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, application_path_validation_frames,
                    max_stream_data_frames, max_streams_frames, streams_blocked_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments);
                if (!packets.empty()) {
                    selected_send_path_id = current_send_path_id_;
                    return finalize_datagram(packets);
                }
                if (max_outbound_datagram_size == kMaximumDatagramSize) {
                    mark_application_close_unusable();
                    if (!send_application_close_only) {
                        mark_failed();
                    }
                    return {};
                }
                return fallback_to_existing_packets_or_ack_only(/*require_due_ack_only=*/false);
            }
            auto ack_eliciting = false;
            auto bypass_congestion_window = false;
            std::optional<QuicCoreTimePoint> send_pacing_deadline;
            ack_eliciting = application_candidate_is_ack_eliciting();
            bypass_congestion_window = application_candidate_bypasses_congestion_window();
            send_pacing_deadline =
                ack_eliciting && !bypass_congestion_window
                    ? congestion_controller_.next_send_time(candidate_datagram_size)
                    : std::nullopt;
            if (ack_eliciting && !bypass_congestion_window &&
                !congestion_controller_.can_send_ack_eliciting(candidate_datagram_size)) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.21
                // # Extension frames MUST be congestion controlled and MUST cause an ACK
                // # frame to be sent.
                //= https://www.rfc-editor.org/rfc/rfc9002#section-7
                // # An endpoint MUST NOT send a packet if it would cause bytes_in_flight
                // # (see Appendix B.2) to be larger than the congestion window, unless
                // # the packet is sent on a PTO timer expiration (see Section 6.2) or
                // # when entering recovery (see Section 7.3.2).
                //= https://www.rfc-editor.org/rfc/rfc9221#section-5.4
                // # The sender MUST either delay sending the frame until the
                // # controller allows it or drop the frame without sending it (at
                // # which point it MAY notify the application).
                note_application_congestion_blocked(candidate_datagram_size);
                return restore_and_fallback_blocked_application_candidate();
            }
            if (send_pacing_deadline.has_value() && now < *send_pacing_deadline) {
                //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
                // # A sender SHOULD pace sending of all in-flight packets
                // # based on input from the congestion controller.
                note_application_pacing_blocked(candidate_datagram_size);
                return restore_and_fallback_blocked_application_candidate();
            }
            if (!non_paced_burst_allows_send(ack_eliciting, bypass_congestion_window,
                                             send_pacing_deadline.has_value())) {
                //= https://www.rfc-editor.org/rfc/rfc9002#section-7.7
                // # Senders MUST either use pacing or limit such bursts.
                note_application_burst_blocked(candidate_datagram_size);
                return restore_and_fallback_blocked_application_candidate();
            }
            last_application_send_stream_id_ = candidate_last_stream_id;
            if (send_profile_enabled()) {
                send_profile_counters().stream_bytes += application_stream_payload_bytes;
            }

            const bool has_application_close = application_close_frame.has_value();
            auto application_packet_number = reserve_application_packet_number(
                (!use_zero_rtt_packet_protection) | has_application_close);
            if (!application_packet_number.has_value()) {
                if (application_path_validation_frames.response.has_value()) {
                    auto &path = ensure_path_state(application_path_validation_frames.path_id);
                    path.pending_response = application_path_validation_frames.response->data;
                }
                if (application_path_validation_frames.challenge.has_value()) {
                    auto &path = ensure_path_state(application_path_validation_frames.path_id);
                    path.challenge_pending = true;
                }
                return {};
            }
            const bool use_fast_serialized_one_rtt_commit =
                use_fast_serialized_one_rtt_commit_for_packet(
                    config_.role, packets.empty(), qlog_session_.get(),
                    use_zero_rtt_packet_protection, has_application_close);
            std::vector<Frame> final_frames;
            bool write_key_phase_changed =
                application_write_key_phase_ != candidate_application_write_key_phase;
            if (write_key_phase_changed || !use_fast_serialized_one_rtt_commit) {
                const auto final_frame_span = application_candidate_frames.current();
                final_frames.assign(final_frame_span.begin(), final_frame_span.end());
            }
            if (write_key_phase_changed) {
                if (send_profile_enabled()) {
                    ++send_profile_counters().application_write_key_phase_reserializes;
                }
                auto final_candidate_datagram = serialize_application_profiled(
                    final_frames, stream_fragments, has_application_close,
                    *application_packet_number, application_write_key_phase_);
                if (!final_candidate_datagram.has_value()) {
                    return fail_datagram_send(has_pending_tracked_packet());
                }
                candidate_application_datagram = std::move(final_candidate_datagram);
            }
            const auto stream_bytes = application_stream_payload_bytes;
            bool has_stream_fragments = !stream_fragments.empty();
            bool track_stream_payload_in_recovery = !use_fast_serialized_one_rtt_commit;
            if (packet_trace_matches_connection(config_.source_connection_id)) {
                const auto ack_trace_value = static_cast<int>(selected_ack_frame.has_value());
                const auto handshake_done_trace_value = static_cast<int>(include_handshake_done);
                std::cerr << "quic-packet-trace send scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " pn=" << *application_packet_number << " ack=" << ack_trace_value
                          << " hsdone=" << handshake_done_trace_value << " stream=" << stream_bytes
                          << " max_data=" << optional_frame_trace_value(application_max_data_frame)
                          << " max_stream_data=" << max_stream_data_frames.size()
                          << " data_blocked=" << optional_frame_trace_value(data_blocked_frame)
                          << " stream_data_blocked=" << stream_data_blocked_frames.size()
                          << " bytes=" << candidate_application_datagram.value().bytes.size()
                          << '\n';
            }
            const auto serialized_packet_index = packets.size();
            std::optional<std::size_t> queued_simple_stream_packet_length;
            if (!use_fast_serialized_one_rtt_commit) {
                auto application_packet = make_application_protected_packet(
                    use_zero_rtt_packet_protection & !has_application_close, current_version_,
                    application_destination_connection_id(), config_.source_connection_id,
                    application_write_key_phase_,
                    packet_number_length_for_send(application_space_, *application_packet_number),
                    *application_packet_number, std::move(final_frames), stream_fragments);
                set_application_packet_spin_bit(application_packet,
                                                outbound_spin_bit_for_path(selected_send_path_id));
                packets.emplace_back(std::move(application_packet));
            }
            if (ack_eliciting) {
                const auto selected_ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
                const bool can_queue_simple_stream_packet =
                    use_fast_serialized_one_rtt_commit && has_stream_fragments &&
                    application_candidate_crypto_ranges.empty() && new_token_frames.empty() &&
                    reset_stream_frames.empty() && stop_sending_frames.empty() &&
                    new_connection_id_frames.empty() && retire_connection_id_frames.empty() &&
                    !application_max_data_frame.has_value() && max_stream_data_frames.empty() &&
                    max_streams_frames.empty() && streams_blocked_frames.empty() &&
                    !data_blocked_frame.has_value() && stream_data_blocked_frames.empty() &&
                    !include_handshake_done && !selected_ack_frame.has_value() &&
                    !selected_datagram_frame.has_value() &&
                    !application_path_validation_frames.response.has_value() &&
                    !application_path_validation_frames.challenge.has_value() &&
                    !has_application_close;
                if (can_queue_simple_stream_packet) {
                    queued_simple_stream_packet_length =
                        candidate_application_datagram.value().packet_metadata.back().length;
                    queue_simple_stream_packet_at_index(
                        application_space_, *application_packet_number, stream_fragments,
                        serialized_packet_index, *queued_simple_stream_packet_length,
                        selected_send_path_id.value_or(0), selected_ecn,
                        current_application_write_key_generation_);
                } else {
                    SentPacketRecord application_sent_record{
                        .packet_number = *application_packet_number,
                        .sent_time = now,
                        .ack_eliciting = ack_eliciting,
                        .in_flight = ack_eliciting,
                        .declared_lost = false,
                        .has_handshake_done = include_handshake_done,
                        .crypto_ranges =
                            std::vector<ByteRange>(application_candidate_crypto_ranges.begin(),
                                                   application_candidate_crypto_ranges.end()),
                        .new_token_frames = new_token_frames,
                        .reset_stream_frames = reset_stream_frames,
                        .stop_sending_frames = stop_sending_frames,
                        .new_connection_id_frames = new_connection_id_frames,
                        .retire_connection_id_frames = retire_connection_id_frames,
                        .max_data_frame = application_max_data_frame,
                        .max_stream_data_frames = max_stream_data_frames,
                        .max_streams_frames = max_streams_frames,
                        .streams_blocked_frames = streams_blocked_frames,
                        .data_blocked_frame = data_blocked_frame,
                        .stream_data_blocked_frames = stream_data_blocked_frames,
                        .stream_fragments = {},
                        .bytes_in_flight = candidate_application_datagram.value().bytes.size(),
                        .largest_received_packet_number_acked =
                            selected_ack_frame.has_value()
                                ? std::optional<std::uint64_t>{selected_ack_frame
                                                                   ->largest_acknowledged}
                                : std::nullopt,
                        .path_id = selected_send_path_id.value_or(0),
                        .ecn = selected_ecn,
                        .protection_key_update_generation =
                            current_application_write_key_generation_,
                    };
                    if (track_stream_payload_in_recovery) {
                        application_sent_record.stream_fragments = std::move(stream_fragments);
                    } else {
                        assign_stream_frame_metadata(application_sent_record, stream_fragments);
                    }
                    queue_tracked_packet_at_index(
                        application_space_, std::move(application_sent_record),
                        serialized_packet_index,
                        candidate_application_datagram.value().packet_metadata.back().length);
                }
                note_idle_ack_eliciting_send(now);
            }
            if (include_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (selected_ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            if (!validation_only_send) {
                clear_probe_packet_after_send(application_space_.pending_probe_packet);
            }
            if (application_close_frame.has_value()) {
                pending_application_close_.reset();
                local_application_close_sent_ = true;
                mark_connection_close_frame_sent(*application_close_frame, now);
            }
            if (use_fast_serialized_one_rtt_commit) {
                if (send_profile_enabled()) {
                    ++send_profile_counters().application_fast_serialized_commits;
                }
                auto committed = commit_serialized_datagram(
                    {}, std::move(candidate_application_datagram.value()),
                    CommitSerializedDatagramOptions{
                        .one_rtt_encrypted_packets = one_rtt_encrypted_packet_count_for_commit(
                            has_application_close, use_zero_rtt_packet_protection),
                        .unpaced_ack_eliciting_packets = static_cast<std::size_t>(ack_eliciting),
                        .single_simple_stream_packet_length = queued_simple_stream_packet_length,
                        .bypass_burst_limit = bypass_congestion_window,
                        .pacing_controlled = send_pacing_deadline.has_value(),
                        .allow_send_continuation = has_stream_fragments,
                        .skip_pmtu_probe_scan = true,
                        .skip_qlog_commit = true,
                        .skip_packet_inspection = true,
                        .path_challenge_path_id =
                            path_challenge_path_id(application_path_validation_frames),
                    });
                if (should_consume_selected_datagram_frame_after_commit(
                        committed.empty(), selected_datagram_frame.has_value())) {
                    if (selected_datagram_queue_index.has_value() &&
                        *selected_datagram_queue_index < pending_datagram_send_queue_.size()) {
                        pending_datagram_send_queue_.erase(
                            pending_datagram_send_queue_.begin() +
                            static_cast<std::ptrdiff_t>(*selected_datagram_queue_index));
                    }
                }
                return committed;
            }
            if (send_profile_enabled()) {
                ++send_profile_counters().application_slow_commits;
            }
            auto committed = commit_serialized_datagram(
                packets, std::move(candidate_application_datagram.value()),
                CommitSerializedDatagramOptions{
                    .unpaced_ack_eliciting_packets = static_cast<std::size_t>(ack_eliciting),
                    .bypass_burst_limit = bypass_congestion_window,
                    .pacing_controlled = send_pacing_deadline.has_value(),
                    .allow_send_continuation = has_stream_fragments,
                    .path_challenge_path_id =
                        path_challenge_path_id(application_path_validation_frames),
                });
            if (should_consume_selected_datagram_frame_after_commit(
                    committed.empty(), selected_datagram_frame.has_value())) {
                if (selected_datagram_queue_index.has_value() &&
                    *selected_datagram_queue_index < pending_datagram_send_queue_.size()) {
                    pending_datagram_send_queue_.erase(
                        pending_datagram_send_queue_.begin() +
                        static_cast<std::ptrdiff_t>(*selected_datagram_queue_index));
                }
            }
            return committed;
        }
    }

    if (packets.empty()) {
        if (traces_this_connection & (has_pending_application_send() |
                                      application_space_.pending_probe_packet.has_value())) {
            std::cerr << "quic-packet-trace send-empty scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " max=" << max_outbound_datagram_size
                      << " current=" << format_optional_path_id(current_send_path_id_)
                      << " previous=" << format_optional_path_id(previous_path_id_)
                      << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                      << " current_path={"
                      << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                      << "} inbound_path={"
                      << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                      << "} pending_send=" << static_cast<int>(has_pending_application_send())
                      << " probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << " pto_count=" << pto_count_
                      << " cwnd=" << congestion_controller_.congestion_window()
                      << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
        }
        if (send_profile_enabled()) {
            ++send_profile_counters().empty_drains;
        }
        return {};
    }

    return finalize_datagram(packets);
}

} // namespace coquic::quic

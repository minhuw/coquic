#include "src/quic/connection/connection.h"
#include "src/quic/connection/connection_internal.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace coquic::quic {

namespace {

bool is_valid_utf8(std::string_view text) {
    std::uint32_t codepoint = 0;
    std::uint8_t continuation_bytes = 0;
    std::uint8_t minimum_continuation_bytes = 0;
    for (const unsigned char byte : text) {
        if (continuation_bytes == 0) {
            if (byte <= 0x7fu) {
                continue;
            }
            if (byte >= 0xc2u && byte <= 0xdfu) {
                codepoint = byte & 0x1fu;
                continuation_bytes = 1;
                minimum_continuation_bytes = 1;
                continue;
            }
            if (byte >= 0xe0u && byte <= 0xefu) {
                codepoint = byte & 0x0fu;
                continuation_bytes = 2;
                minimum_continuation_bytes = 2;
                continue;
            }
            if (byte >= 0xf0u && byte <= 0xf4u) {
                codepoint = byte & 0x07u;
                continuation_bytes = 3;
                minimum_continuation_bytes = 3;
                continue;
            }
            return false;
        }

        if ((byte & 0xc0u) != 0x80u) {
            return false;
        }
        codepoint = (codepoint << 6u) | (byte & 0x3fu);
        --continuation_bytes;
        if (continuation_bytes != 0) {
            continue;
        }
        if ((minimum_continuation_bytes == 2 && codepoint < 0x800u) ||
            (minimum_continuation_bytes == 3 && codepoint < 0x10000u) ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu) || codepoint > 0x10ffffu) {
            return false;
        }
    }
    return continuation_bytes == 0;
}

std::vector<std::byte> connection_close_reason_bytes(std::string_view reason_phrase) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.19
    // # This SHOULD be a UTF-8 encoded string [RFC3629], though the frame does
    // # not carry information, such as language tags, that would aid
    // # comprehension by any entity other than the one that created the text.
    if (!is_valid_utf8(reason_phrase)) {
        return {};
    }
    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(reason_phrase.data()),
                                  reinterpret_cast<const std::byte *>(reason_phrase.data()) +
                                      reason_phrase.size());
}

} // namespace

StreamStateResult<bool> QuicConnection::queue_stream_send(std::uint64_t stream_id,
                                                          std::span<const std::byte> bytes,
                                                          bool fin, std::int32_t priority,
                                                          QuicCoreTimePoint now) {
    auto result = queue_stream_send_impl(stream_id, bytes, std::nullopt, fin, priority);
    if (result.has_value() && status_ != HandshakeStatus::failed) {
        note_application_stream_send(stream_id, fin, bytes.size(), now);
    }
    return result;
}

StreamStateResult<bool> QuicConnection::queue_stream_send_shared(std::uint64_t stream_id,
                                                                 SharedBytes bytes, bool fin,
                                                                 std::int32_t priority,
                                                                 QuicCoreTimePoint now) {
    const auto byte_count = bytes.size();
    auto result = queue_stream_send_impl(stream_id, {}, std::move(bytes), fin, priority);
    if (result.has_value() && status_ != HandshakeStatus::failed) {
        note_application_stream_send(stream_id, fin, byte_count, now);
    }
    return result;
}

void QuicConnection::note_application_stream_send(std::uint64_t stream_id, bool fin,
                                                  std::size_t bytes, QuicCoreTimePoint now) {
    const auto coalescing_delay = config_.transport.underfilled_packet_coalescing_delay;
    if (fin) {
        if (coalescing_delay > QuicCoreDuration::zero() && send_profile_enabled()) {
            ++send_profile_counters().coalescing_heuristic_fin_bypasses;
        }
        return;
    }
    if (bytes == 0) {
        return;
    }

    if (coalescing_delay == QuicCoreDuration::zero() && send_profile_enabled()) {
        ++send_profile_counters().coalescing_heuristic_disabled;
    }

    if (recent_application_send_time_.has_value() && now < *recent_application_send_time_) {
        if (coalescing_delay > QuicCoreDuration::zero() && send_profile_enabled()) {
            ++send_profile_counters().coalescing_heuristic_stale;
        }
        recent_application_send_stream_id_.reset();
        recent_application_send_time_.reset();
        underfilled_packet_coalescing_candidate_.reset();
        return;
    }

    if (underfilled_packet_coalescing_deadline_.has_value()) {
        recent_application_send_stream_id_ = stream_id;
        recent_application_send_time_ = now;
        underfilled_packet_coalescing_candidate_.reset();
        return;
    }

    // RFC 9000 Section 13 permits application behavior or heuristics to choose whether and
    // how long to wait. Repeated writes to one stream within the configured cap are
    // conservative evidence that the application is producing a burst.
    const bool same_stream_recently = recent_application_send_stream_id_.has_value() &&
                                      *recent_application_send_stream_id_ == stream_id &&
                                      recent_application_send_time_.has_value();
    if (coalescing_delay > QuicCoreDuration::zero() && send_profile_enabled()) {
        auto &profile = send_profile_counters();
        if (!recent_application_send_stream_id_.has_value() ||
            !recent_application_send_time_.has_value()) {
            ++profile.coalescing_heuristic_isolated;
        } else if (!same_stream_recently) {
            ++profile.coalescing_heuristic_cross_stream;
        } else if (now - *recent_application_send_time_ > coalescing_delay) {
            ++profile.coalescing_heuristic_stale;
        }
    }
    underfilled_packet_coalescing_candidate_ =
        same_stream_recently && coalescing_delay > QuicCoreDuration::zero() &&
                now - *recent_application_send_time_ <= coalescing_delay
            ? std::optional<QuicCoreTimePoint>{now}
            : std::nullopt;
    if (underfilled_packet_coalescing_candidate_.has_value() && send_profile_enabled()) {
        ++send_profile_counters().coalescing_heuristic_candidates;
    }
    recent_application_send_stream_id_ = stream_id;
    recent_application_send_time_ = now;
}

CodecResult<bool> QuicConnection::queue_datagram_send(std::span<const std::byte> bytes,
                                                      std::int32_t priority) {
    return queue_datagram_send_shared(
        SharedBytes(std::vector<std::byte>(bytes.begin(), bytes.end())), priority);
}

StreamStateResult<bool> QuicConnection::queue_stop_sending(const LocalStopSendingCommand &command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_existing_receive_stream(command.stream_id);
    if (!stream_state.has_value()) {
        return StreamStateResult<bool>::failure(stream_state.error().code,
                                                stream_state.error().stream_id);
    }

    auto *stream = stream_state.value();
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # If the stream is in the "Recv" or "Size Known" state, the transport
    // # SHOULD signal this by sending a STOP_SENDING frame to prompt closure
    // # of the stream in the opposite direction.
    const auto validated = stream->validate_local_stop_sending(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }
    invalidate_stream_sendability_cache();

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool>
QuicConnection::queue_application_close(const LocalApplicationCloseCommand &command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    pending_application_close_ = ApplicationConnectionCloseFrame{
        .error_code = command.application_error_code,
        .reason =
            ConnectionCloseReason{
                .bytes = connection_close_reason_bytes(command.reason_phrase),
            },
    };
    clear_migration_recovery_retention();
    local_application_close_sent_ = false;
    return StreamStateResult<bool>::success(true);
}

void QuicConnection::queue_new_token(std::vector<std::byte> token) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.7
    // # Clients MUST NOT send NEW_TOKEN frames.
    if (status_ == HandshakeStatus::failed || config_.role != EndpointRole::server ||
        token.empty()) {
        return;
    }

    pending_new_token_frames_.push_back(NewTokenFrame{
        .token = std::move(token),
    });
}

void QuicConnection::request_key_update() {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-6
    // # Once the handshake is confirmed (see Section 4.1.2), an endpoint MAY
    // # initiate a key update.
    local_key_update_requested_ = true;
    if (!local_key_update_initiated_) {
        current_write_phase_first_packet_number_ = application_space_.next_send_packet_number;
    }
}

std::optional<QuicCoreReceiveStreamData> QuicConnection::take_received_stream_data() {
    if (status_ == HandshakeStatus::failed || pending_stream_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_stream_receive_effects_.front());
    pending_stream_receive_effects_.pop_front();
    maybe_retire_stream(next.stream_id);
    return next;
}

std::optional<QuicCoreReceiveDatagramData> QuicConnection::take_received_datagram_data() {
    if (status_ == HandshakeStatus::failed || pending_datagram_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_datagram_receive_effects_.front());
    pending_datagram_receive_effects_.pop_front();
    return next;
}

std::optional<QuicCorePeerResetStream> QuicConnection::take_peer_reset_stream() {
    if (status_ == HandshakeStatus::failed || pending_peer_reset_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_reset_effects_.front();
    pending_peer_reset_effects_.pop_front();
    return next;
}

std::optional<QuicCorePeerStopSending> QuicConnection::take_peer_stop_sending() {
    if (status_ == HandshakeStatus::failed || pending_peer_stop_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_stop_effects_.front();
    pending_peer_stop_effects_.pop_front();
    return next;
}

std::optional<QuicCoreStateChange> QuicConnection::take_state_change() {
    if (pending_state_changes_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_state_changes_.front();
    pending_state_changes_.pop_front();
    return next;
}

std::optional<QuicCorePeerPreferredAddressAvailable>
QuicConnection::take_peer_preferred_address_available() {
    auto next = pending_preferred_address_effect_;
    pending_preferred_address_effect_.reset();
    return next;
}

std::optional<QuicCoreResumptionStateAvailable> QuicConnection::take_resumption_state_available() {
    auto next = std::move(pending_resumption_state_effect_);
    pending_resumption_state_effect_.reset();
    return next;
}

std::optional<QuicCoreZeroRttStatusEvent> QuicConnection::take_zero_rtt_status_event() {
    auto next = pending_zero_rtt_status_event_;
    pending_zero_rtt_status_event_.reset();
    return next;
}

std::optional<QuicConnectionTerminalState> QuicConnection::take_terminal_state() {
    if (!pending_terminal_state_.has_value()) {
        return std::nullopt;
    }

    const auto next = pending_terminal_state_;
    pending_terminal_state_.reset();
    return next;
}

std::optional<QuicCorePacketInspection> QuicConnection::take_packet_inspection() {
    if (pending_packet_inspections_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_packet_inspections_.front());
    pending_packet_inspections_.pop_front();
    return next;
}

std::optional<std::vector<std::byte>> QuicConnection::take_new_token() {
    if (pending_received_new_tokens_.empty()) {
        return std::nullopt;
    }

    auto token = std::move(pending_received_new_tokens_.front());
    pending_received_new_tokens_.pop_front();
    return token;
}

std::optional<QuicPathId> QuicConnection::last_drained_path_id() const {
    return last_drained_path_id_;
}

QuicEcnCodepoint QuicConnection::last_drained_ecn_codepoint() const {
    return last_drained_ecn_codepoint_;
}

bool QuicConnection::last_drained_is_pmtu_probe() const {
    return last_drained_is_pmtu_probe_;
}

bool QuicConnection::last_drained_allows_send_continuation() const {
    return last_drained_allows_send_continuation_;
}

std::uint64_t QuicConnection::last_drained_packet_inspection_datagram_id() const {
    return last_drained_packet_inspection_datagram_id_;
}

std::vector<ConnectionId> QuicConnection::active_local_connection_ids() const {
    std::vector<ConnectionId> connection_ids;
    connection_ids.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # When an endpoint issues a connection ID, it MUST accept packets that
        // # carry this connection ID for the duration of the connection or until
        // # its peer invalidates the connection ID via a RETIRE_CONNECTION_ID
        // # frame (Section 19.16).
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
        // # The endpoint SHOULD continue to accept the previously issued
        // # connection IDs until they are retired by the peer.
        connection_ids.push_back(record.connection_id);
    }
    return connection_ids;
}

std::vector<StatelessResetTokenRecord> QuicConnection::active_local_stateless_reset_tokens() const {
    std::vector<StatelessResetTokenRecord> tokens;
    tokens.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = record.connection_id,
            .stateless_reset_token = record.stateless_reset_token,
        });
    }
    return tokens;
}

std::vector<StatelessResetTokenRecord> QuicConnection::peer_stateless_reset_tokens() const {
    std::vector<StatelessResetTokenRecord> tokens;
    tokens.reserve(
        peer_connection_ids_.size() +
        static_cast<std::size_t>(peer_transport_parameters_.has_value() &&
                                 peer_transport_parameters_->stateless_reset_token.has_value()));
    if (peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->stateless_reset_token.has_value()) {
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = config_.initial_destination_connection_id,
            .stateless_reset_token = *peer_transport_parameters_->stateless_reset_token,
        });
    }
    for (const auto &[sequence_number, record] : peer_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.locally_retired) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
            // # An endpoint MUST NOT check for any stateless reset tokens
            // # associated with connection IDs it has not used or for connection
            // # IDs that have been retired.
            continue;
        }
        if (!record.stateless_reset_token.has_value()) {
            continue;
        }
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = record.connection_id,
            .stateless_reset_token = *record.stateless_reset_token,
        });
    }
    return tokens;
}

std::uint64_t QuicConnection::endpoint_route_generation() const {
    return endpoint_route_generation_;
}

void QuicConnection::note_endpoint_route_state_changed() {
    ++endpoint_route_generation_;
    if (endpoint_route_generation_ == 0) {
        endpoint_route_generation_ = 1;
    }
}

} // namespace coquic::quic

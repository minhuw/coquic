#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace coquic::quic {

struct QuicResumptionState {
    // Opaque state blob produced by coquic and later supplied back through
    // QuicCoreConfig::resumption_state on resumed client connections.
    std::vector<std::byte> serialized;
};

struct QuicZeroRttConfig {
    // Client-side intent to attempt 0-RTT when usable resumption state exists.
    // Ignored for server roles.
    bool attempt = false;
    // Server-side policy knob that gates whether 0-RTT may be accepted.
    // Ignored for client roles.
    bool allow = false;
    // Caller-defined compatibility blob recorded into resumption state and
    // compared on later connections before 0-RTT is accepted.
    std::vector<std::byte> application_context;
};

enum class QuicZeroRttStatus : std::uint8_t {
    // No usable resumption state was available for this connection attempt.
    unavailable,
    // The connection proceeded without sending 0-RTT application data.
    not_attempted,
    // 0-RTT was attempted and a final accept/reject outcome is still pending.
    attempted,
    // 0-RTT was accepted by the peer and the early data stands.
    accepted,
    // 0-RTT was rejected and affected writes must fall back to 1-RTT.
    rejected,
};

// QuicCore effect emitted when new resumption material becomes available for
// the caller. If multiple values are emitted for one connection, the latest
// value supersedes earlier ones.
struct QuicCoreResumptionStateAvailable {
    QuicResumptionState state;
};

// QuicCore effect emitted when the connection learns a 0-RTT status update.
// Callers may observe `attempted` followed later by `accepted` or `rejected`.
struct QuicCoreZeroRttStatusEvent {
    QuicZeroRttStatus status = QuicZeroRttStatus::not_attempted;
};

} // namespace coquic::quic

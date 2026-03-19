#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/tls_adapter.h"

namespace coquic::quic {

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::optional<TlsIdentity> identity;
};

using QuicCoreClock = std::chrono::steady_clock;
using QuicCoreTimePoint = QuicCoreClock::time_point;

enum class QuicCoreStateChange : std::uint8_t {
    handshake_ready,
    failed,
};

struct QuicCoreStart {};

struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
};

struct QuicCoreQueueApplicationData {
    std::vector<std::byte> bytes;
};

struct QuicCoreTimerExpired {};

using QuicCoreInput = std::variant<QuicCoreStart, QuicCoreInboundDatagram,
                                   QuicCoreQueueApplicationData, QuicCoreTimerExpired>;

struct QuicCoreSendDatagram {
    std::vector<std::byte> bytes;
};

struct QuicCoreReceiveApplicationData {
    std::vector<std::byte> bytes;
};

struct QuicCoreStateEvent {
    QuicCoreStateChange change;
};

using QuicCoreEffect =
    std::variant<QuicCoreSendDatagram, QuicCoreReceiveApplicationData, QuicCoreStateEvent>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
};

class QuicConnection;

class QuicCore {
  public:
    explicit QuicCore(QuicCoreConfig config);
    ~QuicCore();

    QuicCore(const QuicCore &) = delete;
    QuicCore &operator=(const QuicCore &) = delete;
    QuicCore(QuicCore &&) noexcept;
    QuicCore &operator=(QuicCore &&) noexcept;

    QuicCoreResult advance(QuicCoreInput input, QuicCoreTimePoint now);

    [[deprecated("Use advance(...)")]]
    std::vector<std::byte> receive(std::vector<std::byte> bytes);
    [[deprecated("Use advance(...)")]]
    void queue_application_data(std::vector<std::byte> bytes);
    [[deprecated("Use advance(...)")]]
    std::vector<std::byte> take_received_application_data();
    bool is_handshake_complete() const;
    bool has_failed() const;

  private:
    std::unique_ptr<QuicConnection> connection_;
};

} // namespace coquic::quic

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

enum class QuicCoreLocalErrorCode : std::uint8_t {
    invalid_stream_id,
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
};

struct QuicCoreLocalError {
    QuicCoreLocalErrorCode code;
    std::optional<std::uint64_t> stream_id;
};

struct QuicCoreStart {};

struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
};

struct QuicCoreSendStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCoreResetStream {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStopSending {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreTimerExpired {};

using QuicCoreInput = std::variant<QuicCoreStart, QuicCoreInboundDatagram, QuicCoreSendStreamData,
                                   QuicCoreResetStream, QuicCoreStopSending, QuicCoreTimerExpired>;

struct QuicCoreSendDatagram {
    std::vector<std::byte> bytes;
};

struct QuicCoreReceiveStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCorePeerResetStream {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
    std::uint64_t final_size = 0;
};

struct QuicCorePeerStopSending {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStateEvent {
    QuicCoreStateChange change;
};

using QuicCoreEffect =
    std::variant<QuicCoreSendDatagram, QuicCoreReceiveStreamData, QuicCorePeerResetStream,
                 QuicCorePeerStopSending, QuicCoreStateEvent>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
    std::optional<QuicCoreLocalError> local_error;
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
    bool is_handshake_complete() const;
    bool has_failed() const;

  private:
    std::unique_ptr<QuicConnection> connection_;
};

} // namespace coquic::quic

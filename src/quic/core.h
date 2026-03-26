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

struct QuicTransportConfig {
    std::uint64_t max_idle_timeout = 0;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;
    std::uint64_t initial_max_data = 1 << 20;
    std::uint64_t initial_max_stream_data_bidi_local = 256 << 10;
    std::uint64_t initial_max_stream_data_bidi_remote = 256 << 10;
    std::uint64_t initial_max_stream_data_uni = 256 << 10;
    std::uint64_t initial_max_streams_bidi = 16;
    std::uint64_t initial_max_streams_uni = 16;
};

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
};

using QuicCoreClock = std::chrono::steady_clock;
using QuicCoreTimePoint = QuicCoreClock::time_point;

enum class QuicCoreStateChange : std::uint8_t {
    handshake_ready,
    failed,
};

enum class QuicCoreLocalErrorCode : std::uint8_t {
    unsupported_operation,
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

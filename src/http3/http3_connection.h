#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "src/http3/http3_protocol.h"
#include "src/http3/http3_qpack.h"

namespace coquic::http3 {

struct Http3ConnectionPeerUniStreamAccess;
struct Http3ConnectionPeerRequestStreamAccess;

struct Http3ConnectionConfig {
    Http3ConnectionRole role = Http3ConnectionRole::client;
    Http3SettingsSnapshot local_settings;
};

class Http3Connection {
  public:
    explicit Http3Connection(Http3ConnectionConfig config);

    Http3EndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                       quic::QuicCoreTimePoint now);
    Http3EndpointUpdate poll(quic::QuicCoreTimePoint now);

    const Http3ConnectionState &state() const;
    const Http3SettingsSnapshot &local_settings() const;
    const Http3SettingsSnapshot &peer_settings() const;
    bool peer_settings_received() const;
    bool is_closed() const;

  private:
    friend struct Http3ConnectionPeerUniStreamAccess;
    friend struct Http3ConnectionPeerRequestStreamAccess;

    enum class PeerUniStreamKind : std::uint8_t {
        control,
        qpack_encoder,
        qpack_decoder,
        ignored,
    };

    enum class RequestFieldSectionKind : std::uint8_t {
        initial_headers,
        trailers,
    };

    struct PeerUniStreamState {
        std::vector<std::byte> buffer;
        std::optional<PeerUniStreamKind> kind;
    };

    struct PeerRequestStreamState {
        std::vector<std::byte> buffer;
        bool fin_received = false;
        bool initial_headers_received = false;
        bool trailing_headers_received = false;
        bool terminal = false;
        std::optional<RequestFieldSectionKind> blocked_field_section;
        std::optional<std::uint64_t> expected_content_length;
        std::uint64_t body_bytes_received = 0;
    };

    Http3EndpointUpdate drain_pending_inputs(bool terminal_failure = false);
    void queue_startup_streams();
    void flush_qpack_decoder_instructions();
    void queue_connection_close(Http3ErrorCode code, std::string detail);
    void queue_stream_error(std::uint64_t stream_id, Http3ErrorCode code);
    void handle_receive_stream_data(const quic::QuicCoreReceiveStreamData &received);
    void handle_peer_reset_stream(const quic::QuicCorePeerResetStream &reset);
    void handle_peer_stop_sending(const quic::QuicCorePeerStopSending &stop);
    void handle_peer_bidi_stream(std::uint64_t stream_id, std::span<const std::byte> bytes,
                                 bool fin);
    void handle_peer_uni_stream_data(std::uint64_t stream_id, std::span<const std::byte> bytes,
                                     bool fin);
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void register_peer_uni_stream(std::uint64_t stream_id, std::uint64_t stream_type);
    void process_control_stream(std::uint64_t stream_id, PeerUniStreamState &stream);
    void process_qpack_encoder_stream(std::uint64_t stream_id, PeerUniStreamState &stream);
    void process_qpack_decoder_stream(std::uint64_t stream_id, PeerUniStreamState &stream);
    void process_request_stream(std::uint64_t stream_id);
    void handle_request_frame(std::uint64_t stream_id, const Http3Frame &frame);
    void handle_request_headers_frame(std::uint64_t stream_id, const Http3HeadersFrame &frame);
    void handle_request_data_frame(std::uint64_t stream_id, const Http3DataFrame &frame);
    void apply_request_field_section(std::uint64_t stream_id, RequestFieldSectionKind kind,
                                     Http3Headers headers);
    void handle_unblocked_request_field_section(const Http3DecodedFieldSection &decoded);
    void finalize_request_stream(std::uint64_t stream_id);
    void handle_control_frame(std::uint64_t stream_id, const Http3Frame &frame);
    void apply_remote_settings(const Http3SettingsFrame &frame);
    void queue_send(std::uint64_t stream_id, std::span<const std::byte> bytes);
    std::uint64_t next_local_uni_stream_id() const;
    bool is_remote_critical_stream(std::uint64_t stream_id) const;
    bool is_local_critical_stream(std::uint64_t stream_id) const;

    Http3ConnectionConfig config_;
    Http3ConnectionState state_;
    Http3SettingsSnapshot peer_settings_;
    Http3QpackEncoderContext encoder_;
    Http3QpackDecoderContext decoder_;
    bool transport_ready_ = false;
    bool startup_streams_queued_ = false;
    bool closed_ = false;
    std::deque<quic::QuicCoreInput> pending_core_inputs_;
    std::deque<Http3EndpointEvent> pending_events_;
    std::unordered_map<std::uint64_t, PeerUniStreamState> peer_uni_streams_;
    std::unordered_map<std::uint64_t, PeerRequestStreamState> peer_request_streams_;
    std::unordered_set<std::uint64_t> terminated_peer_request_streams_;
};

} // namespace coquic::http3

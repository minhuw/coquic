#pragma once

#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#if !defined(COQUIC_WASM_NO_FILESYSTEM)
#include <fstream>
#endif
#include <initializer_list>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic::test {

struct ConnectionCoverageTestPeer {
    static QuicConnection make_connected_client(QuicCoreConfig config,
                                                std::optional<std::size_t> pmtud_ceiling) {
        if (pmtud_ceiling.has_value()) {
            config.max_outbound_datagram_size = *pmtud_ceiling;
            config.transport.max_udp_payload_size = *pmtud_ceiling;
            config.transport.pmtud_enabled = true;
            config.transport.pmtud_base_datagram_size = 1200;
            config.transport.pmtud_max_datagram_size = *pmtud_ceiling;
        }

        QuicConnection connection(std::move(config));
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_source_connection_id_ = {std::byte{0xa1}, std::byte{0xb2}};
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret =
            make_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
        connection.application_space_.write_secret =
            make_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_max_data = connection.config_.transport.initial_max_data,
            .initial_max_stream_data_bidi_local =
                connection.config_.transport.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote =
                connection.config_.transport.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = connection.config_.transport.initial_max_stream_data_uni,
            .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
            .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
            .initial_source_connection_id = connection.peer_source_connection_id_,
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.initialize_peer_flow_control_from_transport_parameters();
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &path = connection.ensure_path_state(0);
        path.validated = true;
        path.is_current_send_path = true;
        connection.application_space_.recovery.rtt_state() = connection.recovery_rtt_state_;
        return connection;
    }

    static std::vector<std::byte> serialize_one_rtt_packet(const QuicConnection &connection,
                                                           std::uint64_t packet_number,
                                                           std::span<const Frame> frames) {
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = std::vector<Frame>(frames.begin(), frames.end()),
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        if (!encoded.has_value()) {
            return {};
        }
        return encoded.value();
    }

    static PacketSpaceState &application_space(QuicConnection &connection) {
        return connection.application_space_;
    }

    static PathState &ensure_path_state(QuicConnection &connection, QuicPathId path_id) {
        return connection.ensure_path_state(path_id);
    }

    static std::map<QuicPathId, PathState> &paths(QuicConnection &connection) {
        return connection.paths_;
    }

    static void push_deferred_protected_datagram(QuicConnection &connection,
                                                 DeferredProtectedDatagram datagram) {
        connection.deferred_protected_packets_.push_back(std::move(datagram));
    }

    static bool deferred_protected_packets_empty(const QuicConnection &connection) {
        return connection.deferred_protected_packets_.empty();
    }

    static std::optional<std::uint64_t>
    application_largest_authenticated_packet_number(const QuicConnection &connection) {
        return connection.application_space_.largest_authenticated_packet_number;
    }

    static bool application_received_packets_contains(const QuicConnection &connection,
                                                      std::uint64_t packet_number) {
        return connection.application_space_.received_packets.contains(packet_number);
    }

    static bool pending_stream_receive_effects_empty(const QuicConnection &connection) {
        return connection.pending_stream_receive_effects_.empty();
    }

    static void mark_resumption_state_emitted(QuicConnection &connection) {
        connection.resumption_state_emitted_ = true;
    }

    static QuicInboundDatagramResult process_inbound_datagram(
        QuicConnection &connection, std::shared_ptr<std::vector<std::byte>> storage,
        std::size_t begin, std::size_t end, QuicCoreTimePoint now, QuicPathId path_id,
        QuicEcnCodepoint ecn, std::optional<std::uint32_t> inbound_datagram_id, bool replay_trigger,
        bool count_inbound_bytes, bool allow_in_place_receive_decode) {
        return connection.process_inbound_datagram(
            std::move(storage), begin, end, now, path_id, ecn, inbound_datagram_id, replay_trigger,
            count_inbound_bytes, allow_in_place_receive_decode);
    }

    static void track_application_sent_packet(QuicConnection &connection, SentPacketRecord packet) {
        connection.track_sent_packet(connection.application_space_, std::move(packet));
    }

    static bool
    process_simple_stream_ack_ecn(QuicConnection &connection,
                                  std::span<const AckedStreamPacketSample> samples,
                                  const std::optional<AckEcnCounts> &ecn_counts,
                                  std::optional<QuicCoreTimePoint> &latest_ecn_ce_sent_time) {
        return connection.process_simple_stream_ack_ecn(connection.application_space_, samples,
                                                        ecn_counts, latest_ecn_ce_sent_time);
    }

    static bool process_single_path_simple_stream_ack_ecn(
        QuicConnection &connection,
        QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
        std::uint64_t newly_acked_ect0, std::uint64_t newly_acked_ect1,
        QuicCoreTimePoint latest_marked_sent_time, const std::optional<AckEcnCounts> &ecn_counts,
        std::optional<QuicCoreTimePoint> &latest_ecn_ce_sent_time) {
        return connection.process_single_path_simple_stream_ack_ecn(
            connection.application_space_, path_id, newly_acked_ect0, newly_acked_ect1,
            latest_marked_sent_time, ecn_counts, latest_ecn_ce_sent_time);
    }

    static CodecResult<bool> process_inbound_application(QuicConnection &connection,
                                                         std::span<const Frame> frames,
                                                         QuicCoreTimePoint now,
                                                         bool allow_preconnected_frames = false,
                                                         QuicPathId path_id = 0) {
        return connection.process_inbound_application(frames, now, allow_preconnected_frames,
                                                      path_id);
    }

    static CodecResult<bool> process_inbound_received_application(
        QuicConnection &connection, std::span<const ReceivedFrame> frames, QuicCoreTimePoint now,
        bool allow_preconnected_frames = false, QuicPathId path_id = 0) {
        return connection.process_inbound_received_application(frames, now,
                                                               allow_preconnected_frames, path_id);
    }

    static CodecResult<bool>
    process_inbound_received_application_stream(QuicConnection &connection,
                                                const ReceivedStreamFrame &stream_frame,
                                                bool require_connected) {
        return connection.process_inbound_received_application_stream(stream_frame,
                                                                      require_connected);
    }

    static void retire_peer_bidi_range(QuicConnection &connection, std::uint64_t first_index,
                                       std::uint64_t last_index, std::uint64_t receive_final_size,
                                       std::uint64_t send_final_size) {
        connection.retired_peer_bidi_stream_ranges_.emplace(
            first_index, QuicConnection::RetiredPeerStreamRange{
                             .first_index = first_index,
                             .last_index = last_index,
                             .receive_final_size = receive_final_size,
                             .send_final_size = send_final_size,
                             .peer_max_stream_data = send_final_size,
                             .local_receive_window = receive_final_size,
                             .advertised_max_stream_data = receive_final_size,
                         });
    }

  private:
    static TrafficSecret make_traffic_secret(CipherSuite cipher_suite, std::byte fill) {
        const std::size_t secret_size =
            cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
        return TrafficSecret{
            .cipher_suite = cipher_suite,
            .secret = std::vector<std::byte>(secret_size, fill),
        };
    }
};

namespace {

class ScopedEnvVarForTests {
  public:
    ScopedEnvVarForTests(const char *name, std::optional<std::string_view> value) : name_(name) {
        if (const char *existing = std::getenv(name_); existing != nullptr) {
            previous_ = std::string(existing);
            had_previous_ = true;
        }

        if (value.has_value()) {
            static_cast<void>(::setenv(name_, std::string(*value).c_str(), 1));
        } else {
            static_cast<void>(::unsetenv(name_));
        }
    }

    ~ScopedEnvVarForTests() {
        if (had_previous_) {
            static_cast<void>(::setenv(name_, previous_.c_str(), 1));
            return;
        }

        static_cast<void>(::unsetenv(name_));
    }

    ScopedEnvVarForTests(const ScopedEnvVarForTests &) = delete;
    ScopedEnvVarForTests &operator=(const ScopedEnvVarForTests &) = delete;

  private:
    const char *name_;
    std::string previous_;
    bool had_previous_ = false;
};

std::vector<std::byte> bytes_from_ints_for_tests(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

TrafficSecret
make_test_traffic_secret(CipherSuite cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
                         std::byte fill = std::byte{0x11}) {
    const std::size_t secret_size = cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
    return TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, fill),
    };
}

CipherSuite invalid_cipher_suite_for_tests() {
    constexpr std::uint8_t raw = 0xff;
    CipherSuite value{};
    std::memcpy(&value, &raw, sizeof(value));
    return value;
}

QuicCoreConfig make_client_core_config_for_connection_coverage() {
    return QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id =
            {
                std::byte{0x83},
                std::byte{0x94},
                std::byte{0xc8},
                std::byte{0xf0},
                std::byte{0x3e},
                std::byte{0x51},
                std::byte{0x57},
                std::byte{0x08},
            },
        .verify_peer = false,
        .server_name = "localhost",
    };
}

#if !defined(COQUIC_WASM_NO_FILESYSTEM)
std::string read_text_file_for_connection_coverage(std::string_view path) {
    std::ifstream input(std::string(path), std::ios::binary);
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

bool drive_tls_handshake_for_connection_coverage(TlsAdapter &client, TlsAdapter &server) {
    struct TlsTransfer {
        TlsAdapter &source;
        TlsAdapter &destination;
    };
    const auto transfer_pending = [](TlsTransfer transfer, EncryptionLevel level) {
        const auto pending = transfer.source.take_pending(level);
        if (pending.empty()) {
            return true;
        }
        return transfer.destination.provide(level, pending).has_value();
    };

    if (!client.start().has_value()) {
        return false;
    }
    if (!transfer_pending(TlsTransfer{client, server}, EncryptionLevel::initial)) {
        return false;
    }

    for (int index = 0; index < 32; ++index) {
        if (!transfer_pending(TlsTransfer{client, server}, EncryptionLevel::initial) ||
            !transfer_pending(TlsTransfer{server, client}, EncryptionLevel::initial) ||
            !transfer_pending(TlsTransfer{server, client}, EncryptionLevel::handshake) ||
            !transfer_pending(TlsTransfer{client, server}, EncryptionLevel::handshake)) {
            return false;
        }

        const auto client_poll_result = client.poll();
        const auto server_handshake_poll = server.poll();
        if (!client_poll_result.has_value() || !server_handshake_poll.has_value()) {
            return false;
        }
        if (client.handshake_complete() && server.handshake_complete()) {
            return true;
        }
    }

    return client.handshake_complete() && server.handshake_complete();
}
#endif

QuicConnection make_connected_client_connection_for_connection_coverage(QuicCoreConfig config) {
    return ConnectionCoverageTestPeer::make_connected_client(std::move(config), std::nullopt);
}

QuicConnection make_connected_client_connection_for_connection_coverage() {
    return make_connected_client_connection_for_connection_coverage(
        make_client_core_config_for_connection_coverage());
}

QuicConnection make_connected_pmtud_client_connection_for_connection_coverage() {
    return ConnectionCoverageTestPeer::make_connected_client(
        make_client_core_config_for_connection_coverage(), 4096);
}

bool connection_coverage_check(bool &ok, const char *label, bool condition) {
    if (!condition) {
        std::cerr << "connection_key_update_and_probe_coverage_for_tests failed: " << label << '\n';
    }
    ok &= condition;
    return condition;
}

std::vector<std::byte> serialize_one_rtt_packet_for_connection_coverage(
    const QuicConnection &connection, std::uint64_t packet_number,
    std::span<const Frame> frames = std::span<const Frame>{}) {
    return ConnectionCoverageTestPeer::serialize_one_rtt_packet(connection, packet_number, frames);
}

} // namespace

} // namespace coquic::quic::test

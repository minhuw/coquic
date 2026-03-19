#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#define private public
#include "src/quic/connection.h"
#undef private
#include "src/quic/demo_channel.h"

namespace coquic::quic::test {

inline std::string read_text_file(const char *path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

inline std::vector<std::byte> sample_transport_parameters() {
    return {
        std::byte{0x0f}, std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x0e}, std::byte{0x01}, std::byte{0x02},
    };
}

inline QuicCoreConfig make_client_core_config() {
    return QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .verify_peer = false,
        .server_name = "localhost",
    };
}

inline QuicCoreConfig make_server_core_config() {
    return QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .verify_peer = false,
        .server_name = "localhost",
        .identity =
            TlsIdentity{
                .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
                .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
            },
    };
}

inline QuicCoreTimePoint test_time(std::int64_t ms = 0) {
    return QuicCoreTimePoint{} + std::chrono::milliseconds(ms);
}

inline std::vector<std::vector<std::byte>> send_datagrams_from(const QuicCoreResult &result) {
    std::vector<std::vector<std::byte>> out;
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            out.push_back(send->bytes);
        }
    }

    return out;
}

inline std::vector<QuicCoreStateChange> state_changes_from(const QuicCoreResult &result) {
    std::vector<QuicCoreStateChange> out;
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect)) {
            out.push_back(event->change);
        }
    }

    return out;
}

inline std::size_t count_state_change(std::span<const QuicCoreStateChange> changes,
                                      QuicCoreStateChange change) {
    std::size_t count = 0;
    for (const auto value : changes) {
        if (value == change) {
            ++count;
        }
    }

    return count;
}

inline std::vector<std::byte> received_application_data_from(const QuicCoreResult &result) {
    std::vector<std::byte> out;
    for (const auto &effect : result.effects) {
        if (const auto *received = std::get_if<QuicCoreReceiveApplicationData>(&effect)) {
            out.insert(out.end(), received->bytes.begin(), received->bytes.end());
        }
    }

    return out;
}

inline QuicCoreResult relay_send_datagrams_to_peer(const QuicCoreResult &result, QuicCore &peer,
                                                   QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (auto datagram : send_datagrams_from(result)) {
        auto step = peer.advance(QuicCoreInboundDatagram{std::move(datagram)}, now);
        combined.effects.insert(combined.effects.end(),
                                std::make_move_iterator(step.effects.begin()),
                                std::make_move_iterator(step.effects.end()));
        combined.next_wakeup = step.next_wakeup;
    }

    return combined;
}

inline void drive_quic_handshake(QuicCore &client, QuicCore &server, QuicCoreTimePoint now,
                                 std::vector<QuicCoreStateChange> *client_events = nullptr,
                                 std::vector<QuicCoreStateChange> *server_events = nullptr) {
    const auto append_state_changes = [](const QuicCoreResult &result,
                                         std::vector<QuicCoreStateChange> *events) {
        if (events == nullptr) {
            return;
        }
        auto changes = state_changes_from(result);
        events->insert(events->end(), changes.begin(), changes.end());
    };

    auto to_server = client.advance(QuicCoreStart{}, now);
    append_state_changes(to_server, client_events);

    for (int i = 0; i < 16 && !(client.is_handshake_complete() && server.is_handshake_complete());
         ++i) {
        const auto to_client = relay_send_datagrams_to_peer(to_server, server, now);
        append_state_changes(to_client, server_events);
        if (client.is_handshake_complete() && server.is_handshake_complete()) {
            break;
        }
        to_server = relay_send_datagrams_to_peer(to_client, client, now);
        append_state_changes(to_server, client_events);
    }
}

inline void flush_demo_channels(QuicDemoChannel &left, QuicDemoChannel &right) {
    auto to_left = std::vector<std::byte>{};
    auto to_right = std::vector<std::byte>{};
    bool saw_empty_round = false;
    for (int i = 0; i < 64; ++i) {
        to_right = left.on_datagram(to_left);
        to_left = right.on_datagram(to_right);
        if (to_left.empty() && to_right.empty()) {
            if (saw_empty_round) {
                break;
            }
            saw_empty_round = true;
        } else {
            saw_empty_round = false;
        }
    }
}

inline std::vector<std::byte> bytes_from_string(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const auto character : text) {
        bytes.push_back(static_cast<std::byte>(character));
    }
    return bytes;
}

inline std::string string_from_bytes(std::span<const std::byte> bytes) {
    std::string text;
    text.reserve(bytes.size());
    for (const auto byte : bytes) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return text;
}

inline StreamFrame make_inbound_application_stream_frame(std::string_view text,
                                                         std::uint64_t offset = 0,
                                                         std::uint64_t stream_id = 0,
                                                         bool fin = false, bool has_offset = true,
                                                         bool has_length = true) {
    return StreamFrame{
        .fin = fin,
        .has_offset = has_offset,
        .has_length = has_length,
        .stream_id = stream_id,
        .offset = has_offset ? std::optional<std::uint64_t>(offset) : std::nullopt,
        .stream_data = bytes_from_string(text),
    };
}

struct QuicConnectionTestPeer {
    static void set_handshake_status(QuicConnection &connection, HandshakeStatus status) {
        connection.status_ = status;
    }

    static bool inject_inbound_one_rtt_frames(QuicConnection &connection, std::vector<Frame> frames,
                                              std::uint64_t packet_number = 0) {
        const auto processed = connection.process_inbound_packet(ProtectedOneRttPacket{
            .destination_connection_id = {},
            .packet_number_length = 2,
            .packet_number = packet_number,
            .frames = std::move(frames),
        });
        if (!processed.has_value()) {
            connection.status_ = HandshakeStatus::failed;
            return false;
        }

        return true;
    }
};

} // namespace coquic::quic::test

#pragma once

#include <cstddef>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#define private public
#include "src/quic/connection.h"
#undef private

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

inline void flush_pending_datagrams(QuicCore &left, QuicCore &right) {
    auto to_right = left.receive({});
    auto to_left = std::vector<std::byte>{};
    while (!to_right.empty()) {
        to_left = right.receive(to_right);
        if (to_left.empty()) {
            break;
        }
        to_right = left.receive(to_left);
    }
}

inline void drive_quic_handshake(QuicCore &client, QuicCore &server) {
    auto to_server = client.receive({});
    auto to_client = std::vector<std::byte>{};

    for (int i = 0; i < 16 && !(client.is_handshake_complete() && server.is_handshake_complete());
         ++i) {
        if (!to_server.empty()) {
            to_client = server.receive(to_server);
        }
        if (client.is_handshake_complete() && server.is_handshake_complete()) {
            break;
        }
        to_server = client.receive(to_client);
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

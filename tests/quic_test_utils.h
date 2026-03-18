#pragma once

#include <cstddef>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "src/quic/core.h"

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

} // namespace coquic::quic::test

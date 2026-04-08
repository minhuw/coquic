#pragma once

#include <gtest/gtest.h>

#define private public
#include "src/quic/core.h"
#undef private
#include "tests/support/core/connection_test_fixtures.h"

namespace coquic::quic::test_support {

inline QuicCoreEndpointConfig make_client_endpoint_config() {
    return QuicCoreEndpointConfig{
        .role = EndpointRole::client,
        .supported_versions = {kQuicVersion1},
        .verify_peer = false,
        .application_protocol = "coquic",
    };
}

inline QuicCoreEndpointConfig make_server_endpoint_config() {
    return QuicCoreEndpointConfig{
        .role = EndpointRole::server,
        .supported_versions = {kQuicVersion1},
        .verify_peer = false,
        .application_protocol = "hq-interop",
        .identity =
            TlsIdentity{
                .certificate_pem = test::read_text_file("tests/fixtures/quic-server-cert.pem"),
                .private_key_pem = test::read_text_file("tests/fixtures/quic-server-key.pem"),
            },
    };
}

inline QuicCoreClientConnectionConfig make_client_open_config(std::uint64_t index = 1) {
    return QuicCoreClientConnectionConfig{
        .source_connection_id =
            ConnectionId{
                std::byte{0xc1},
                std::byte{static_cast<std::uint8_t>(index)},
            },
        .initial_destination_connection_id =
            ConnectionId{
                std::byte{0x83},
                std::byte{static_cast<std::uint8_t>(0x40u + index)},
            },
        .server_name = "localhost",
    };
}

inline std::vector<QuicCoreConnectionLifecycleEvent>
lifecycle_events_from(const QuicCoreResult &result) {
    std::vector<QuicCoreConnectionLifecycleEvent> out;
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect)) {
            out.push_back(*event);
        }
    }
    return out;
}

inline std::vector<QuicCoreSendDatagram> send_effects_from(const QuicCoreResult &result) {
    std::vector<QuicCoreSendDatagram> out;
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            out.push_back(*send);
        }
    }
    return out;
}

} // namespace coquic::quic::test_support

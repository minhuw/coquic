#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/codec/protected_codec.h"
#include "src/quic/crypto/packet_crypto_test_hooks.h"
#include "src/quic/version.h"

namespace {

constexpr std::size_t kMaxInputSize = 4096;
constexpr std::size_t kMaxPayloadSize = 512;
constexpr std::uint64_t kLargestApplicationPacketNumber = 0xa82f30eaULL;

std::vector<std::byte> fallback_bytes(std::vector<std::byte> bytes, std::byte fallback) {
    if (bytes.empty()) {
        bytes.push_back(fallback);
    }
    return bytes;
}

coquic::quic::ConnectionId connection_id_from(coquic::fuzz::InputReader &reader,
                                              std::byte fallback) {
    auto bytes = reader.read_sized_bytes(16);
    if (bytes.empty()) {
        bytes.push_back(fallback);
    }
    return bytes;
}

coquic::quic::CipherSuite cipher_suite_from(std::uint8_t value) {
    switch (value % 3u) {
    case 1:
        return coquic::quic::CipherSuite::tls_aes_256_gcm_sha384;
    case 2:
        return coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256;
    default:
        return coquic::quic::CipherSuite::tls_aes_128_gcm_sha256;
    }
}

std::size_t secret_size(coquic::quic::CipherSuite suite) {
    return suite == coquic::quic::CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
}

std::vector<std::byte> make_secret(coquic::fuzz::InputReader &reader,
                                   coquic::quic::CipherSuite suite, std::byte fallback) {
    auto secret = reader.read_bytes(secret_size(suite));
    secret.resize(secret_size(suite), fallback);
    return secret;
}

coquic::quic::TrafficSecret make_traffic_secret(coquic::fuzz::InputReader &reader,
                                                coquic::quic::CipherSuite suite,
                                                std::byte fallback) {
    return coquic::quic::TrafficSecret{
        .cipher_suite = suite,
        .secret = make_secret(reader, suite, fallback),
    };
}

coquic::quic::SerializeProtectionContext
make_serialize_context(coquic::fuzz::InputReader &reader, coquic::quic::EndpointRole role,
                       const coquic::quic::ConnectionId &initial_dcid,
                       coquic::quic::CipherSuite suite) {
    return coquic::quic::SerializeProtectionContext{
        .local_role = role,
        .client_initial_destination_connection_id = initial_dcid,
        .handshake_secret = make_traffic_secret(reader, suite, std::byte{0x11}),
        .zero_rtt_secret = make_traffic_secret(reader, suite, std::byte{0x22}),
        .one_rtt_secret = make_traffic_secret(reader, suite, std::byte{0x33}),
        .one_rtt_key_phase = reader.read_bool(),
        .grease_quic_bit = reader.read_bool(),
        .grease_quic_bit_seed = reader.read_u64(),
    };
}

coquic::quic::DeserializeProtectionContext
make_deserialize_context(coquic::fuzz::InputReader &reader, coquic::quic::EndpointRole peer_role,
                         const coquic::quic::ConnectionId &initial_dcid,
                         coquic::quic::CipherSuite suite, std::size_t one_rtt_dcid_length) {
    return coquic::quic::DeserializeProtectionContext{
        .peer_role = peer_role,
        .client_initial_destination_connection_id = initial_dcid,
        .handshake_secret = make_traffic_secret(reader, suite, std::byte{0x11}),
        .zero_rtt_secret = make_traffic_secret(reader, suite, std::byte{0x22}),
        .one_rtt_secret = make_traffic_secret(reader, suite, std::byte{0x33}),
        .one_rtt_key_phase = reader.read_bool(),
        .largest_authenticated_initial_packet_number = reader.read_u64() % 4096u,
        .largest_authenticated_handshake_packet_number = reader.read_u64() % 4096u,
        .largest_authenticated_application_packet_number = kLargestApplicationPacketNumber,
        .one_rtt_destination_connection_id_length = one_rtt_dcid_length,
        .accept_greased_quic_bit = reader.read_bool(),
    };
}

coquic::quic::Frame make_frame(coquic::fuzz::InputReader &reader, bool handshake_space) {
    switch (reader.read_u8() % (handshake_space ? 4u : 10u)) {
    case 0:
        return coquic::quic::PingFrame{};
    case 1:
        return coquic::quic::CryptoFrame{
            .offset = reader.read_u64() % 1024u,
            .crypto_data =
                fallback_bytes(reader.read_sized_bytes(kMaxPayloadSize), std::byte{0x01}),
        };
    case 2:
        return coquic::quic::PaddingFrame{.length = reader.read_size(64)};
    case 3:
        return coquic::quic::TransportConnectionCloseFrame{
            .error_code = reader.read_u64() & 0xffffu,
            .frame_type = reader.read_u64() & 0xffu,
            .reason = fallback_bytes(reader.read_sized_bytes(64), std::byte{0x63}),
        };
    case 4:
        return coquic::quic::AckFrame{
            .largest_acknowledged = reader.read_u64() % 256u,
            .ack_delay = reader.read_u64() % 1024u,
            .first_ack_range = reader.read_u64() % 32u,
        };
    case 5:
        return coquic::quic::StreamFrame{
            .fin = reader.read_bool(),
            .has_offset = true,
            .has_length = true,
            .stream_id = reader.read_u64() % 64u,
            .offset = reader.read_u64() % 1024u,
            .stream_data =
                fallback_bytes(reader.read_sized_bytes(kMaxPayloadSize), std::byte{0x51}),
        };
    case 6:
        return coquic::quic::MaxDataFrame{.maximum_data = reader.read_u64() % (1u << 20u)};
    case 7:
        return coquic::quic::MaxStreamDataFrame{
            .stream_id = reader.read_u64() % 64u,
            .maximum_stream_data = reader.read_u64() % (1u << 20u),
        };
    case 8:
        return coquic::quic::PathChallengeFrame{
            .data = {std::byte{reader.read_u8()}, std::byte{reader.read_u8()},
                     std::byte{reader.read_u8()}, std::byte{reader.read_u8()},
                     std::byte{reader.read_u8()}, std::byte{reader.read_u8()},
                     std::byte{reader.read_u8()}, std::byte{reader.read_u8()}},
        };
    default:
        return coquic::quic::HandshakeDoneFrame{};
    }
}

std::vector<coquic::quic::Frame> make_frames(coquic::fuzz::InputReader &reader,
                                             bool handshake_space) {
    std::vector<coquic::quic::Frame> frames;
    const auto count = 1u + reader.read_size(6);
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.push_back(make_frame(reader, handshake_space));
    }
    return frames;
}

coquic::quic::ProtectedPacket make_packet(coquic::fuzz::InputReader &reader,
                                          const coquic::quic::ConnectionId &one_rtt_dcid) {
    const auto packet_number_length = static_cast<std::uint8_t>(1u + reader.read_size(4));
    switch (reader.read_u8() % 4u) {
    case 0:
        return coquic::quic::ProtectedInitialPacket{
            .version =
                reader.read_bool() ? coquic::quic::kQuicVersion2 : coquic::quic::kQuicVersion1,
            .destination_connection_id = connection_id_from(reader, std::byte{0x83}),
            .source_connection_id = connection_id_from(reader, std::byte{0xc1}),
            .token = reader.read_sized_bytes(64),
            .packet_number_length = packet_number_length,
            .packet_number = reader.read_u64() % 4096u,
            .frames = make_frames(reader, /*handshake_space=*/true),
        };
    case 1:
        return coquic::quic::ProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection_id_from(reader, std::byte{0x84}),
            .source_connection_id = connection_id_from(reader, std::byte{0xc2}),
            .packet_number_length = packet_number_length,
            .packet_number = reader.read_u64() % 4096u,
            .frames = make_frames(reader, /*handshake_space=*/true),
        };
    case 2:
        return coquic::quic::ProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection_id_from(reader, std::byte{0x85}),
            .source_connection_id = connection_id_from(reader, std::byte{0xc3}),
            .packet_number_length = packet_number_length,
            .packet_number = reader.read_u64() % 4096u,
            .frames = make_frames(reader, /*handshake_space=*/false),
        };
    default:
        return coquic::quic::ProtectedOneRttPacket{
            .spin_bit = reader.read_bool(),
            .key_phase = reader.read_bool(),
            .destination_connection_id = one_rtt_dcid,
            .packet_number_length = packet_number_length,
            .packet_number = kLargestApplicationPacketNumber + 1u + (reader.read_u64() % 1024u),
            .frames = make_frames(reader, /*handshake_space=*/false),
        };
    }
}

void exercise_decode(std::span<const std::byte> bytes,
                     const coquic::quic::DeserializeProtectionContext &context) {
    const auto decoded = coquic::quic::deserialize_received_protected_datagram(bytes, context);
    if (!decoded.has_value()) {
        coquic::fuzz::require_error_offset(decoded.error(), bytes.size());
        return;
    }

    for (const auto &packet : decoded.value()) {
        std::visit(
            [](const auto &value) {
                coquic::fuzz::require(value.packet_number_length >= 1 &&
                                          value.packet_number_length <= 4,
                                      "decoded protected packet number length is invalid");
            },
            packet);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (size > kMaxInputSize) {
        return 0;
    }

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    coquic::fuzz::InputReader reader(coquic::fuzz::byte_span(bytes));

    const auto role = reader.read_bool() ? coquic::quic::EndpointRole::server
                                         : coquic::quic::EndpointRole::client;
    const auto peer_role = role == coquic::quic::EndpointRole::client
                               ? coquic::quic::EndpointRole::server
                               : coquic::quic::EndpointRole::client;
    const auto suite = cipher_suite_from(reader.read_u8());
    const auto initial_dcid = connection_id_from(reader, std::byte{0x83});
    const auto one_rtt_dcid = connection_id_from(reader, std::byte{0xde});

    auto serialize_reader = reader;
    auto deserialize_reader = reader;
    const auto serialize_context =
        make_serialize_context(serialize_reader, role, initial_dcid, suite);
    const auto deserialize_context = make_deserialize_context(
        deserialize_reader, role, initial_dcid, suite, one_rtt_dcid.size());

    exercise_decode(coquic::fuzz::byte_span(bytes), deserialize_context);

    std::vector<coquic::quic::ProtectedPacket> packets;
    const auto packet_count = 1u + reader.read_size(4);
    packets.reserve(packet_count);
    for (std::size_t i = 0; i < packet_count; ++i) {
        packets.push_back(make_packet(reader, one_rtt_dcid));
    }

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, serialize_context);
    if (!encoded.has_value()) {
        coquic::fuzz::require_error_offset(encoded.error(), size);
        return 0;
    }

    auto decode_context = deserialize_context;
    decode_context.peer_role = role;
    const auto redecode =
        coquic::quic::deserialize_received_protected_datagram(encoded.value(), decode_context);
    if (!redecode.has_value()) {
        coquic::fuzz::require_error_offset(redecode.error(), encoded.value().size());
        return 0;
    }

    coquic::fuzz::require(!redecode.value().empty(), "encoded protected datagram decoded empty");
    return 0;
}

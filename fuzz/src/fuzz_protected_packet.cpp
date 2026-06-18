#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/codec/protected_codec.h"
#include "src/quic/crypto/packet_crypto_test_hooks.h"
#include "src/quic/version.h"

namespace {

constexpr std::size_t kMaxInputSize = 4096;
constexpr std::size_t kMaxPayloadSize = 512;
constexpr std::size_t kMaxReasonSize = 64;
constexpr std::uint64_t kLargestApplicationPacketNumber = 0xa82f30eaULL;
constexpr std::uint64_t kMaxFuzzControlValue = 1u << 20u;
constexpr std::uint64_t kMaxFuzzStreamId = 64;

enum class GeneratedPacketSpace : std::uint8_t {
    handshake,
    zero_rtt,
    one_rtt,
};

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

coquic::quic::ConnectionId frame_connection_id_from(coquic::fuzz::InputReader &reader,
                                                    std::byte fallback) {
    auto bytes = reader.read_sized_bytes(20);
    if (bytes.empty()) {
        bytes.push_back(fallback);
    }
    return bytes;
}

std::array<std::byte, 8> path_data_from(coquic::fuzz::InputReader &reader) {
    std::array<std::byte, 8> data{};
    for (auto &byte : data) {
        byte = std::byte{reader.read_u8()};
    }
    return data;
}

std::array<std::byte, 16> stateless_reset_token_from(coquic::fuzz::InputReader &reader) {
    std::array<std::byte, 16> token{};
    for (auto &byte : token) {
        byte = std::byte{reader.read_u8()};
    }
    return token;
}

coquic::quic::StreamLimitType stream_limit_type_from(coquic::fuzz::InputReader &reader) {
    return reader.read_bool() ? coquic::quic::StreamLimitType::unidirectional
                              : coquic::quic::StreamLimitType::bidirectional;
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

coquic::quic::AckFrame make_ack_frame(coquic::fuzz::InputReader &reader) {
    const auto largest_acknowledged = reader.read_u64() % 256u;
    const auto first_ack_range = reader.read_u64() % (largest_acknowledged + 1u);

    coquic::quic::AckFrame frame{
        .largest_acknowledged = largest_acknowledged,
        .ack_delay = reader.read_u64() % 1024u,
        .first_ack_range = first_ack_range,
    };
    if (largest_acknowledged >= first_ack_range + 2u && reader.read_bool()) {
        frame.additional_ranges.push_back(coquic::quic::AckRange{.gap = 0, .range_length = 0});
    }
    if (reader.read_bool()) {
        frame.ecn_counts = coquic::quic::AckEcnCounts{
            .ect0 = reader.read_u64() % 256u,
            .ect1 = reader.read_u64() % 256u,
            .ecn_ce = reader.read_u64() % 256u,
        };
    }
    return frame;
}

coquic::quic::CryptoFrame make_crypto_frame(coquic::fuzz::InputReader &reader) {
    return coquic::quic::CryptoFrame{
        .offset = reader.read_u64() % 1024u,
        .crypto_data = fallback_bytes(reader.read_sized_bytes(kMaxPayloadSize), std::byte{0x01}),
    };
}

coquic::quic::StreamFrame make_stream_frame(coquic::fuzz::InputReader &reader) {
    const auto has_offset = reader.read_bool();
    return coquic::quic::StreamFrame{
        .fin = reader.read_bool(),
        .has_offset = has_offset,
        .has_length = true,
        .stream_id = reader.read_u64() % kMaxFuzzStreamId,
        .offset =
            has_offset ? std::optional<std::uint64_t>{reader.read_u64() % 1024u} : std::nullopt,
        .stream_data = fallback_bytes(reader.read_sized_bytes(kMaxPayloadSize), std::byte{0x51}),
    };
}

coquic::quic::DatagramFrame make_datagram_frame(coquic::fuzz::InputReader &reader) {
    return coquic::quic::DatagramFrame{
        .has_length = true,
        .data = fallback_bytes(reader.read_sized_bytes(kMaxPayloadSize), std::byte{0xd1}),
    };
}

coquic::quic::TransportConnectionCloseFrame
make_transport_close_frame(coquic::fuzz::InputReader &reader) {
    return coquic::quic::TransportConnectionCloseFrame{
        .error_code = reader.read_u64() & 0xffffu,
        .frame_type = reader.read_u64() & 0xffu,
        .reason = {.bytes =
                       fallback_bytes(reader.read_sized_bytes(kMaxReasonSize), std::byte{0x63})},
    };
}

coquic::quic::ApplicationConnectionCloseFrame
make_application_close_frame(coquic::fuzz::InputReader &reader) {
    return coquic::quic::ApplicationConnectionCloseFrame{
        .error_code = reader.read_u64() & 0xffffu,
        .reason = {.bytes =
                       fallback_bytes(reader.read_sized_bytes(kMaxReasonSize), std::byte{0x61})},
    };
}

coquic::quic::NewConnectionIdFrame make_new_connection_id_frame(coquic::fuzz::InputReader &reader) {
    const auto sequence_number = reader.read_u64() % 64u;
    const auto retire_candidate = reader.read_u64();
    return coquic::quic::NewConnectionIdFrame{
        .sequence_number = sequence_number,
        .retire_prior_to = sequence_number == 0 ? 0 : retire_candidate % (sequence_number + 1u),
        .connection_id = frame_connection_id_from(reader, std::byte{0xc1}),
        .stateless_reset_token = stateless_reset_token_from(reader),
    };
}

coquic::quic::Frame make_handshake_frame(coquic::fuzz::InputReader &reader, std::uint8_t choice) {
    switch (choice) {
    case 0:
        return coquic::quic::PaddingFrame{.length = 1u + reader.read_size(64)};
    case 1:
        return coquic::quic::PingFrame{};
    case 2:
        return make_ack_frame(reader);
    case 3:
        return make_crypto_frame(reader);
    default:
        return make_transport_close_frame(reader);
    }
}

coquic::quic::Frame make_zero_rtt_frame(coquic::fuzz::InputReader &reader, std::uint8_t choice) {
    switch (choice) {
    case 0:
        return coquic::quic::PaddingFrame{.length = 1u + reader.read_size(64)};
    case 1:
        return coquic::quic::PingFrame{};
    case 2:
        return coquic::quic::ResetStreamFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .application_protocol_error_code = reader.read_u64() & 0xffffu,
            .final_size = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 3:
        return coquic::quic::StopSendingFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .application_protocol_error_code = reader.read_u64() & 0xffffu,
        };
    case 4:
        return make_stream_frame(reader);
    case 5:
        return make_datagram_frame(reader);
    case 6:
        return coquic::quic::MaxDataFrame{.maximum_data = reader.read_u64() % kMaxFuzzControlValue};
    case 7:
        return coquic::quic::MaxStreamDataFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .maximum_stream_data = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 8:
        return coquic::quic::MaxStreamsFrame{
            .stream_type = stream_limit_type_from(reader),
            .maximum_streams = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 9:
        return coquic::quic::DataBlockedFrame{.maximum_data =
                                                  reader.read_u64() % kMaxFuzzControlValue};
    case 10:
        return coquic::quic::StreamDataBlockedFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .maximum_stream_data = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 11:
        return coquic::quic::StreamsBlockedFrame{
            .stream_type = stream_limit_type_from(reader),
            .maximum_streams = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 12:
        return make_new_connection_id_frame(reader);
    case 13:
        return coquic::quic::PathChallengeFrame{.data = path_data_from(reader)};
    case 14:
        return make_transport_close_frame(reader);
    default:
        return make_application_close_frame(reader);
    }
}

coquic::quic::Frame make_one_rtt_frame(coquic::fuzz::InputReader &reader, std::uint8_t choice) {
    switch (choice) {
    case 0:
        return coquic::quic::PaddingFrame{.length = 1u + reader.read_size(64)};
    case 1:
        return coquic::quic::PingFrame{};
    case 2:
        return make_ack_frame(reader);
    case 3:
        return coquic::quic::ResetStreamFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .application_protocol_error_code = reader.read_u64() & 0xffffu,
            .final_size = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 4:
        return coquic::quic::StopSendingFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .application_protocol_error_code = reader.read_u64() & 0xffffu,
        };
    case 5:
        return make_crypto_frame(reader);
    case 6:
        return coquic::quic::NewTokenFrame{
            .token = fallback_bytes(reader.read_sized_bytes(kMaxPayloadSize), std::byte{0x74}),
        };
    case 7:
        return make_stream_frame(reader);
    case 8:
        return make_datagram_frame(reader);
    case 9:
        return coquic::quic::MaxDataFrame{.maximum_data = reader.read_u64() % kMaxFuzzControlValue};
    case 10:
        return coquic::quic::MaxStreamDataFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .maximum_stream_data = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 11:
        return coquic::quic::MaxStreamsFrame{
            .stream_type = stream_limit_type_from(reader),
            .maximum_streams = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 12:
        return coquic::quic::DataBlockedFrame{.maximum_data =
                                                  reader.read_u64() % kMaxFuzzControlValue};
    case 13:
        return coquic::quic::StreamDataBlockedFrame{
            .stream_id = reader.read_u64() % kMaxFuzzStreamId,
            .maximum_stream_data = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 14:
        return coquic::quic::StreamsBlockedFrame{
            .stream_type = stream_limit_type_from(reader),
            .maximum_streams = reader.read_u64() % kMaxFuzzControlValue,
        };
    case 15:
        return make_new_connection_id_frame(reader);
    case 16:
        return coquic::quic::RetireConnectionIdFrame{.sequence_number = reader.read_u64() % 64u};
    case 17:
        return coquic::quic::PathChallengeFrame{.data = path_data_from(reader)};
    case 18:
        return coquic::quic::PathResponseFrame{.data = path_data_from(reader)};
    case 19:
        return make_transport_close_frame(reader);
    case 20:
        return make_application_close_frame(reader);
    default:
        return coquic::quic::HandshakeDoneFrame{};
    }
}

std::uint8_t frame_choice_count(GeneratedPacketSpace packet_space) {
    switch (packet_space) {
    case GeneratedPacketSpace::handshake:
        return 5;
    case GeneratedPacketSpace::zero_rtt:
        return 16;
    case GeneratedPacketSpace::one_rtt:
        return 22;
    }
    return 1;
}

coquic::quic::Frame make_frame(coquic::fuzz::InputReader &reader,
                               GeneratedPacketSpace packet_space) {
    const auto choice =
        static_cast<std::uint8_t>(reader.read_u8() % frame_choice_count(packet_space));
    switch (packet_space) {
    case GeneratedPacketSpace::handshake:
        return make_handshake_frame(reader, choice);
    case GeneratedPacketSpace::zero_rtt:
        return make_zero_rtt_frame(reader, choice);
    case GeneratedPacketSpace::one_rtt:
        return make_one_rtt_frame(reader, choice);
    }
    return coquic::quic::PingFrame{};
}

std::vector<coquic::quic::Frame> make_frames(coquic::fuzz::InputReader &reader,
                                             GeneratedPacketSpace packet_space) {
    std::vector<coquic::quic::Frame> frames;
    const auto count = 1u + reader.read_size(6);
    frames.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        frames.push_back(make_frame(reader, packet_space));
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
            .frames = make_frames(reader, GeneratedPacketSpace::handshake),
        };
    case 1:
        return coquic::quic::ProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection_id_from(reader, std::byte{0x84}),
            .source_connection_id = connection_id_from(reader, std::byte{0xc2}),
            .packet_number_length = packet_number_length,
            .packet_number = reader.read_u64() % 4096u,
            .frames = make_frames(reader, GeneratedPacketSpace::handshake),
        };
    case 2:
        return coquic::quic::ProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection_id_from(reader, std::byte{0x85}),
            .source_connection_id = connection_id_from(reader, std::byte{0xc3}),
            .packet_number_length = packet_number_length,
            .packet_number = reader.read_u64() % 4096u,
            .frames = make_frames(reader, GeneratedPacketSpace::zero_rtt),
        };
    default:
        return coquic::quic::ProtectedOneRttPacket{
            .spin_bit = reader.read_bool(),
            .key_phase = reader.read_bool(),
            .destination_connection_id = one_rtt_dcid,
            .packet_number_length = packet_number_length,
            .packet_number = kLargestApplicationPacketNumber + 1u + (reader.read_u64() % 1024u),
            .frames = make_frames(reader, GeneratedPacketSpace::one_rtt),
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
    const auto initial_deserialize_context = make_deserialize_context(
        deserialize_reader, role, initial_dcid, suite, one_rtt_dcid.size());

    exercise_decode(coquic::fuzz::byte_span(bytes), initial_deserialize_context);

    std::vector<coquic::quic::ProtectedPacket> packets;
    const auto generated_packet_count = 1u + reader.read_size(4);
    packets.reserve(generated_packet_count);
    for (std::size_t i = 0; i < generated_packet_count; ++i) {
        packets.push_back(make_packet(reader, one_rtt_dcid));
    }

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, serialize_context);
    if (!encoded.has_value()) {
        coquic::fuzz::require_error_offset(encoded.error(), size);
        return 0;
    }

    auto decode_context = initial_deserialize_context;
    decode_context.peer_role = role;
    const auto decoded_round_trip =
        coquic::quic::deserialize_received_protected_datagram(encoded.value(), decode_context);
    if (!decoded_round_trip.has_value()) {
        coquic::fuzz::require_error_offset(decoded_round_trip.error(), encoded.value().size());
        return 0;
    }

    coquic::fuzz::require(!decoded_round_trip.value().empty(),
                          "encoded protected datagram decoded empty");
    return 0;
}

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "src/quic/codec/frame.h"
#include "src/quic/codec/packet.h"
#include "src/quic/codec/plaintext_codec.h"
#include "src/quic/codec/varint.h"
#include "src/quic/transport/transport_parameters.h"
#include "src/quic/version.h"

namespace {

using coquic::quic::AckEcnCounts;
using coquic::quic::AckFrame;
using coquic::quic::AckRange;
using coquic::quic::ApplicationConnectionCloseFrame;
using coquic::quic::ConnectionCloseReason;
using coquic::quic::ConnectionId;
using coquic::quic::CryptoFrame;
using coquic::quic::DataBlockedFrame;
using coquic::quic::DatagramFrame;
using coquic::quic::Frame;
using coquic::quic::HandshakeDoneFrame;
using coquic::quic::HandshakePacket;
using coquic::quic::InitialPacket;
using coquic::quic::MaxDataFrame;
using coquic::quic::MaxStreamDataFrame;
using coquic::quic::MaxStreamsFrame;
using coquic::quic::NewConnectionIdFrame;
using coquic::quic::NewTokenFrame;
using coquic::quic::OneRttPacket;
using coquic::quic::Packet;
using coquic::quic::PaddingFrame;
using coquic::quic::PathChallengeFrame;
using coquic::quic::PathResponseFrame;
using coquic::quic::PingFrame;
using coquic::quic::PreferredAddress;
using coquic::quic::ResetStreamFrame;
using coquic::quic::RetireConnectionIdFrame;
using coquic::quic::RetryPacket;
using coquic::quic::StopSendingFrame;
using coquic::quic::StreamDataBlockedFrame;
using coquic::quic::StreamFrame;
using coquic::quic::StreamLimitType;
using coquic::quic::StreamsBlockedFrame;
using coquic::quic::TransportConnectionCloseFrame;
using coquic::quic::TransportParameters;
using coquic::quic::VersionInformation;
using coquic::quic::VersionNegotiationPacket;
using coquic::quic::ZeroRttPacket;

std::vector<std::byte> bytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> output;
    output.reserve(values.size());
    for (const auto value : values) {
        output.push_back(static_cast<std::byte>(value));
    }
    return output;
}

std::array<std::byte, 8> path_data(unsigned base) {
    return {
        static_cast<std::byte>(base + 0), static_cast<std::byte>(base + 1),
        static_cast<std::byte>(base + 2), static_cast<std::byte>(base + 3),
        static_cast<std::byte>(base + 4), static_cast<std::byte>(base + 5),
        static_cast<std::byte>(base + 6), static_cast<std::byte>(base + 7),
    };
}

std::array<std::byte, 16> token(unsigned base) {
    return {
        static_cast<std::byte>(base + 0),  static_cast<std::byte>(base + 1),
        static_cast<std::byte>(base + 2),  static_cast<std::byte>(base + 3),
        static_cast<std::byte>(base + 4),  static_cast<std::byte>(base + 5),
        static_cast<std::byte>(base + 6),  static_cast<std::byte>(base + 7),
        static_cast<std::byte>(base + 8),  static_cast<std::byte>(base + 9),
        static_cast<std::byte>(base + 10), static_cast<std::byte>(base + 11),
        static_cast<std::byte>(base + 12), static_cast<std::byte>(base + 13),
        static_cast<std::byte>(base + 14), static_cast<std::byte>(base + 15),
    };
}

void write_seed(const std::filesystem::path &root, const std::string &target,
                const std::string &name, std::span<const std::byte> data) {
    const auto dir = root / target;
    std::filesystem::create_directories(dir);
    std::ofstream output(dir / name, std::ios::binary);
    if (!output) {
        throw std::runtime_error("failed to open generated seed output");
    }
    for (const auto byte : data) {
        output.put(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
}

void write_seed(const std::filesystem::path &root, const std::string &target,
                const std::string &name, const std::vector<std::byte> &data) {
    write_seed(root, target, name, std::span<const std::byte>(data.data(), data.size()));
}

void write_encoded_frame(const std::filesystem::path &root, const std::string &name,
                         const Frame &frame) {
    const auto encoded = coquic::quic::serialize_frame(frame);
    if (!encoded.has_value()) {
        throw std::runtime_error("failed to serialize generated frame seed: " + name);
    }
    write_seed(root, "fuzz_frame", name, encoded.value());
}

void write_encoded_packet(const std::filesystem::path &root, const std::string &target,
                          const std::string &name, const Packet &packet) {
    const auto encoded = coquic::quic::serialize_packet(packet);
    if (!encoded.has_value()) {
        throw std::runtime_error("failed to serialize generated packet seed: " + target + "/" +
                                 name);
    }
    write_seed(root, target, name, encoded.value());
}

void write_encoded_transport_parameters(const std::filesystem::path &root, const std::string &name,
                                        const TransportParameters &parameters) {
    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    if (!encoded.has_value()) {
        throw std::runtime_error("failed to serialize generated transport parameter seed: " + name);
    }
    write_seed(root, "fuzz_transport_parameters", name, encoded.value());
}

PreferredAddress preferred_address() {
    return PreferredAddress{
        .ipv4_address = {std::byte{0xc0}, std::byte{0x00}, std::byte{0x02}, std::byte{0x0a}},
        .ipv4_port = 443,
        .ipv6_address = {std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x42}},
        .ipv6_port = 8443,
        .connection_id = bytes({0xde, 0xad, 0xbe, 0xef}),
        .stateless_reset_token = token(0x20),
    };
}

std::vector<Frame> one_rtt_frames() {
    return {
        PingFrame{},
        AckFrame{
            .largest_acknowledged = 42,
            .ack_delay = 3,
            .first_ack_range = 4,
            .additional_ranges = {AckRange{.gap = 1, .range_length = 2}},
            .ecn_counts = AckEcnCounts{.ect0 = 10, .ect1 = 2, .ecn_ce = 1},
        },
        StreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 4,
            .offset = 9,
            .stream_data = bytes({0xca, 0xfe, 0xba, 0xbe}),
        },
        DatagramFrame{
            .has_length = true,
            .data = bytes({0xde, 0xad, 0xbe, 0xef}),
        },
    };
}

std::vector<Frame> zero_rtt_frames() {
    return {
        PingFrame{},
        StreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 4,
            .offset = 9,
            .stream_data = bytes({0xca, 0xfe, 0xba, 0xbe}),
        },
        DatagramFrame{
            .has_length = true,
            .data = bytes({0xde, 0xad, 0xbe, 0xef}),
        },
    };
}

void generate_varint_seeds(const std::filesystem::path &root) {
    const std::vector<std::uint64_t> values = {
        0, 1, 63, 64, 15293, 16383, 16384, 1073741823, 1073741824, 4611686018427387903ull,
    };
    for (const auto value : values) {
        const auto encoded = coquic::quic::encode_varint(value);
        if (!encoded.has_value()) {
            throw std::runtime_error("failed to encode generated varint seed");
        }
        write_seed(root, "fuzz_varint", "generated_" + std::to_string(value), encoded.value());
    }
}

void generate_frame_seeds(const std::filesystem::path &root) {
    write_encoded_frame(root, "generated_padding_run", PaddingFrame{.length = 8});
    write_encoded_frame(root, "generated_ping", PingFrame{});
    write_encoded_frame(root, "generated_ack_ecn",
                        AckFrame{
                            .largest_acknowledged = 42,
                            .ack_delay = 7,
                            .first_ack_range = 3,
                            .additional_ranges =
                                {
                                    AckRange{.gap = 1, .range_length = 0},
                                    AckRange{.gap = 0, .range_length = 1},
                                },
                            .ecn_counts =
                                AckEcnCounts{
                                    .ect0 = 9,
                                    .ect1 = 3,
                                    .ecn_ce = 1,
                                },
                        });
    write_encoded_frame(root, "generated_reset_stream",
                        ResetStreamFrame{
                            .stream_id = 4,
                            .application_protocol_error_code = 7,
                            .final_size = 1024,
                        });
    write_encoded_frame(root, "generated_stop_sending",
                        StopSendingFrame{
                            .stream_id = 4,
                            .application_protocol_error_code = 7,
                        });
    write_encoded_frame(root, "generated_crypto",
                        CryptoFrame{
                            .offset = 9,
                            .crypto_data = bytes({0x01, 0x02, 0x03}),
                        });
    write_encoded_frame(root, "generated_new_token", NewTokenFrame{.token = bytes({0xaa, 0xbb})});
    write_encoded_frame(root, "generated_stream_full",
                        StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 8,
                            .offset = 4,
                            .stream_data = bytes({0xca, 0xfe}),
                        });
    write_encoded_frame(root, "generated_stream_terminal",
                        StreamFrame{
                            .has_length = false,
                            .stream_id = 9,
                            .stream_data = bytes({0x11, 0x22}),
                        });
    write_encoded_frame(root, "generated_datagram_len",
                        DatagramFrame{
                            .has_length = true,
                            .data = bytes({0xde, 0xad}),
                        });
    write_encoded_frame(root, "generated_datagram_terminal",
                        DatagramFrame{
                            .has_length = false,
                            .data = bytes({0xbe, 0xef}),
                        });
    write_encoded_frame(root, "generated_max_data", MaxDataFrame{.maximum_data = 4096});
    write_encoded_frame(root, "generated_max_stream_data",
                        MaxStreamDataFrame{
                            .stream_id = 4,
                            .maximum_stream_data = 4096,
                        });
    write_encoded_frame(
        root, "generated_max_streams_bidi",
        MaxStreamsFrame{.stream_type = StreamLimitType::bidirectional, .maximum_streams = 16});
    write_encoded_frame(
        root, "generated_max_streams_uni",
        MaxStreamsFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 16});
    write_encoded_frame(root, "generated_data_blocked", DataBlockedFrame{.maximum_data = 4096});
    write_encoded_frame(root, "generated_stream_data_blocked",
                        StreamDataBlockedFrame{
                            .stream_id = 4,
                            .maximum_stream_data = 4096,
                        });
    write_encoded_frame(
        root, "generated_streams_blocked_bidi",
        StreamsBlockedFrame{.stream_type = StreamLimitType::bidirectional, .maximum_streams = 16});
    write_encoded_frame(
        root, "generated_streams_blocked_uni",
        StreamsBlockedFrame{.stream_type = StreamLimitType::unidirectional, .maximum_streams = 16});
    write_encoded_frame(root, "generated_new_connection_id",
                        NewConnectionIdFrame{
                            .sequence_number = 3,
                            .retire_prior_to = 1,
                            .connection_id = bytes({0xaa, 0xbb, 0xcc}),
                            .stateless_reset_token = token(0x30),
                        });
    write_encoded_frame(root, "generated_retire_connection_id",
                        RetireConnectionIdFrame{.sequence_number = 3});
    write_encoded_frame(root, "generated_path_challenge", PathChallengeFrame{.data = path_data(1)});
    write_encoded_frame(root, "generated_path_response", PathResponseFrame{.data = path_data(9)});
    write_encoded_frame(root, "generated_transport_close",
                        TransportConnectionCloseFrame{
                            .error_code = 0x010c,
                            .frame_type = 0x06,
                            .reason = {.bytes = bytes({0x65})},
                        });
    write_encoded_frame(root, "generated_application_close",
                        ApplicationConnectionCloseFrame{
                            .error_code = 42,
                            .reason = {.bytes = bytes({0x61})},
                        });
    write_encoded_frame(root, "generated_handshake_done", HandshakeDoneFrame{});
}

void generate_packet_seeds(const std::filesystem::path &root) {
    const auto initial_v1 = Packet{InitialPacket{
        .version = coquic::quic::kQuicVersion1,
        .destination_connection_id = bytes({0xaa, 0xbb}),
        .source_connection_id = bytes({0xcc}),
        .token = bytes({0x01, 0x02}),
        .packet_number_length = 2,
        .truncated_packet_number = 0x1234,
        .frames = {CryptoFrame{.offset = 0, .crypto_data = bytes({0x01, 0x02, 0x03})}},
    }};
    const auto initial_v2 = Packet{InitialPacket{
        .version = coquic::quic::kQuicVersion2,
        .destination_connection_id = bytes({0xaa}),
        .source_connection_id = bytes({0xbb}),
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {CryptoFrame{.offset = 0, .crypto_data = bytes({0x01})}},
    }};
    const auto zero_rtt = Packet{ZeroRttPacket{
        .version = coquic::quic::kQuicVersion1,
        .destination_connection_id = bytes({0xaa}),
        .source_connection_id = bytes({0xbb}),
        .packet_number_length = 2,
        .truncated_packet_number = 9,
        .frames = zero_rtt_frames(),
    }};
    const auto handshake = Packet{HandshakePacket{
        .version = coquic::quic::kQuicVersion1,
        .destination_connection_id = bytes({0xaa}),
        .source_connection_id = bytes({0xbb}),
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames = {CryptoFrame{.offset = 3, .crypto_data = bytes({0x04})}, PingFrame{}},
    }};
    const auto retry = Packet{RetryPacket{
        .version = 0x180102aau,
        .retry_unused_bits = 0x0b,
        .destination_connection_id = std::vector<std::byte>(24, std::byte{0xaa}),
        .source_connection_id = std::vector<std::byte>(24, std::byte{0xbb}),
        .retry_token = bytes({0x74, 0x6f, 0x6b, 0x65, 0x6e}),
        .retry_integrity_tag = token(0x40),
    }};
    const auto version_negotiation = Packet{VersionNegotiationPacket{
        .destination_connection_id = bytes({0xaa}),
        .source_connection_id = bytes({0xbb}),
        .supported_versions = {coquic::quic::kQuicVersion1, coquic::quic::kQuicVersion2},
    }};
    const auto one_rtt_dcid_0 = Packet{OneRttPacket{
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PingFrame{}},
    }};
    const auto one_rtt_dcid_8 = Packet{OneRttPacket{
        .spin_bit = true,
        .key_phase = true,
        .destination_connection_id = bytes({0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}),
        .packet_number_length = 4,
        .truncated_packet_number = 0x12345678,
        .frames = one_rtt_frames(),
    }};

    const std::vector<std::pair<std::string, Packet>> packet_seeds = {
        {"generated_initial_v1", initial_v1},
        {"generated_initial_v2", initial_v2},
        {"generated_zero_rtt", zero_rtt},
        {"generated_handshake", handshake},
        {"generated_retry_non_v1_long_cid", retry},
        {"generated_version_negotiation", version_negotiation},
        {"generated_one_rtt_dcid_0", one_rtt_dcid_0},
        {"generated_one_rtt_dcid_8", one_rtt_dcid_8},
    };

    for (const auto &[name, packet] : packet_seeds) {
        write_encoded_packet(root, "fuzz_plaintext_packet", name, packet);
    }
    for (const auto &[name, packet] : packet_seeds) {
        if (std::holds_alternative<OneRttPacket>(packet)) {
            write_encoded_packet(root, "fuzz_short_header_packet", name, packet);
        } else {
            write_encoded_packet(root, "fuzz_long_header_packet", name, packet);
        }
    }

    const std::array datagram_packets = {
        initial_v1,
        handshake,
        version_negotiation,
    };
    const auto encoded_datagram = coquic::quic::serialize_datagram(datagram_packets);
    if (!encoded_datagram.has_value()) {
        throw std::runtime_error("failed to serialize generated datagram seed");
    }
    write_seed(root, "fuzz_datagram", "generated_coalesced_long_headers", encoded_datagram.value());
    write_encoded_packet(root, "fuzz_datagram", "generated_one_rtt_dcid_8", one_rtt_dcid_8);
}

void generate_transport_parameter_seeds(const std::filesystem::path &root) {
    write_encoded_transport_parameters(root, "generated_minimal",
                                       TransportParameters{
                                           .max_udp_payload_size = 1200,
                                           .active_connection_id_limit = 2,
                                           .initial_source_connection_id = bytes({0xc1, 0x01}),
                                       });
    write_encoded_transport_parameters(
        root, "generated_retry_context",
        TransportParameters{
            .original_destination_connection_id = bytes({0x83, 0x94}),
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 4,
            .initial_source_connection_id = bytes({0x53, 0x01}),
            .retry_source_connection_id = bytes({0xaa, 0xbb}),
        });
    write_encoded_transport_parameters(root, "generated_limits",
                                       TransportParameters{
                                           .max_idle_timeout = 180000,
                                           .max_udp_payload_size = 1452,
                                           .active_connection_id_limit = 8,
                                           .ack_delay_exponent = 5,
                                           .max_ack_delay = 42,
                                           .initial_max_data = 65536,
                                           .initial_max_stream_data_bidi_local = 4096,
                                           .initial_max_stream_data_bidi_remote = 4096,
                                           .initial_max_stream_data_uni = 2048,
                                           .initial_max_streams_bidi = 16,
                                           .initial_max_streams_uni = 8,
                                           .initial_source_connection_id = bytes({0xc1}),
                                           .max_datagram_frame_size = 1200,
                                       });
    write_encoded_transport_parameters(
        root, "generated_preferred_address",
        TransportParameters{
            .original_destination_connection_id = bytes({0x83, 0x94}),
            .stateless_reset_token = token(0x50),
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 4,
            .disable_active_migration = true,
            .initial_source_connection_id = bytes({0x53, 0x01}),
            .preferred_address = preferred_address(),
        });
    write_encoded_transport_parameters(root, "generated_version_information",
                                       TransportParameters{
                                           .max_udp_payload_size = 1200,
                                           .active_connection_id_limit = 2,
                                           .initial_source_connection_id = bytes({0xc1, 0x01}),
                                           .version_information =
                                               VersionInformation{
                                                   .chosen_version = coquic::quic::kQuicVersion2,
                                                   .available_versions =
                                                       {
                                                           coquic::quic::kQuicVersion2,
                                                           coquic::quic::kQuicVersion1,
                                                       },
                                               },
                                           .grease_quic_bit = true,
                                       });
}

void generate(const std::filesystem::path &root) {
    generate_varint_seeds(root);
    generate_frame_seeds(root);
    generate_packet_seeds(root);
    generate_transport_parameter_seeds(root);
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <output-dir>\n";
        return EXIT_FAILURE;
    }

    try {
        generate(std::filesystem::path(argv[1]));
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

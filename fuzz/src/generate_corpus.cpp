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

std::vector<std::byte> counted_bytes(unsigned base, std::size_t count) {
    std::vector<std::byte> output;
    output.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        output.push_back(static_cast<std::byte>((base + index) & 0xffu));
    }
    return output;
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

class FuzzInputBuilder {
  public:
    void write_u8(unsigned value) {
        data_.push_back(static_cast<std::byte>(value & 0xffu));
    }

    void write_u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            write_u8(static_cast<unsigned>((value >> shift) & 0xffu));
        }
    }

    void write_size(std::uint64_t value) {
        write_u64(value);
    }

    void write_sized_bytes(std::span<const std::byte> data) {
        write_size(data.size());
        data_.insert(data_.end(), data.begin(), data.end());
    }

    std::vector<std::byte> finish() && {
        return std::move(data_);
    }

  private:
    std::vector<std::byte> data_;
};

enum class ProtectedSeedPacketSpace : std::uint8_t {
    handshake,
    zero_rtt,
    one_rtt,
};

void write_common_protected_seed_prefix(FuzzInputBuilder &seed) {
    seed.write_u8(0); // endpoint role
    seed.write_u8(0); // cipher suite
    seed.write_sized_bytes(bytes({0x83}));
    seed.write_sized_bytes(bytes({0xde, 0xad, 0xbe, 0xef}));
    seed.write_size(0); // generate one packet
    seed.write_size(0); // one-byte packet number
}

std::vector<std::byte> protected_packet_seed(ProtectedSeedPacketSpace packet_space,
                                             std::uint8_t frame_choice) {
    FuzzInputBuilder seed;
    write_common_protected_seed_prefix(seed);

    switch (packet_space) {
    case ProtectedSeedPacketSpace::handshake:
        seed.write_u8(1); // ProtectedHandshakePacket
        seed.write_sized_bytes(bytes({0x84}));
        seed.write_sized_bytes(bytes({0xc2}));
        seed.write_u64(0); // packet number
        break;
    case ProtectedSeedPacketSpace::zero_rtt:
        seed.write_u8(2); // ProtectedZeroRttPacket
        seed.write_sized_bytes(bytes({0x85}));
        seed.write_sized_bytes(bytes({0xc3}));
        seed.write_u64(0); // packet number
        break;
    case ProtectedSeedPacketSpace::one_rtt:
        seed.write_u8(3);  // ProtectedOneRttPacket
        seed.write_u8(0);  // spin bit
        seed.write_u8(0);  // key phase
        seed.write_u64(0); // packet number delta
        break;
    }

    seed.write_size(0); // generate one frame
    seed.write_u8(frame_choice);
    return std::move(seed).finish();
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

void generate_protected_packet_seeds(const std::filesystem::path &root) {
    static constexpr std::array<const char *, 5> handshake_frames = {
        "padding", "ping", "ack", "crypto", "transport_close",
    };
    static constexpr std::array<const char *, 16> zero_rtt_frames = {
        "padding",
        "ping",
        "reset_stream",
        "stop_sending",
        "stream",
        "datagram",
        "max_data",
        "max_stream_data",
        "max_streams",
        "data_blocked",
        "stream_data_blocked",
        "streams_blocked",
        "new_connection_id",
        "path_challenge",
        "transport_close",
        "application_close",
    };
    static constexpr std::array<const char *, 22> one_rtt_frames = {
        "padding",
        "ping",
        "ack",
        "reset_stream",
        "stop_sending",
        "crypto",
        "new_token",
        "stream",
        "datagram",
        "max_data",
        "max_stream_data",
        "max_streams",
        "data_blocked",
        "stream_data_blocked",
        "streams_blocked",
        "new_connection_id",
        "retire_connection_id",
        "path_challenge",
        "path_response",
        "transport_close",
        "application_close",
        "handshake_done",
    };

    for (std::size_t i = 0; i < handshake_frames.size(); ++i) {
        write_seed(root, "fuzz_protected_packet",
                   "generated_handshake_" + std::string(handshake_frames[i]),
                   protected_packet_seed(ProtectedSeedPacketSpace::handshake,
                                         static_cast<std::uint8_t>(i)));
    }
    for (std::size_t i = 0; i < zero_rtt_frames.size(); ++i) {
        write_seed(root, "fuzz_protected_packet",
                   "generated_zero_rtt_" + std::string(zero_rtt_frames[i]),
                   protected_packet_seed(ProtectedSeedPacketSpace::zero_rtt,
                                         static_cast<std::uint8_t>(i)));
    }
    for (std::size_t i = 0; i < one_rtt_frames.size(); ++i) {
        write_seed(
            root, "fuzz_protected_packet", "generated_one_rtt_" + std::string(one_rtt_frames[i]),
            protected_packet_seed(ProtectedSeedPacketSpace::one_rtt, static_cast<std::uint8_t>(i)));
    }
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

void write_stream_state_seed(const std::filesystem::path &root, const std::string &name,
                             FuzzInputBuilder seed) {
    write_seed(root, "fuzz_stream_state", name, std::move(seed).finish());
}

void write_stream_state_prefix(FuzzInputBuilder &seed, bool server, std::uint64_t stream_id,
                               std::uint64_t initial_peer_limit,
                               std::uint64_t initial_receive_limit) {
    seed.write_u8(server ? 1u : 0u);
    seed.write_u64(stream_id);
    seed.write_u64(initial_peer_limit);
    seed.write_u64(initial_receive_limit);
}

void stream_state_append_payload(FuzzInputBuilder &seed, std::span<const std::byte> payload,
                                 bool fin) {
    seed.write_u8(0);
    seed.write_sized_bytes(payload);
    seed.write_u8(fin ? 1u : 0u);
}

void stream_state_peer_max_stream_data(FuzzInputBuilder &seed, std::uint64_t maximum) {
    seed.write_u8(1);
    seed.write_u64(maximum);
}

void stream_state_data_blocked(FuzzInputBuilder &seed, bool acknowledge) {
    seed.write_u8(2);
    seed.write_u8(acknowledge ? 1u : 0u);
}

void stream_state_max_stream_data(FuzzInputBuilder &seed, std::uint64_t maximum, bool acknowledge) {
    seed.write_u8(3);
    seed.write_u64(maximum);
    seed.write_u8(acknowledge ? 1u : 0u);
}

void stream_state_take_fragments(FuzzInputBuilder &seed, std::size_t packet_bytes,
                                 std::uint64_t new_bytes, bool prefer_fresh,
                                 std::initializer_list<unsigned> fragment_actions) {
    seed.write_u8(4);
    seed.write_size(packet_bytes == 0 ? 0 : packet_bytes - 1u);
    seed.write_u64(new_bytes);
    seed.write_u8(prefer_fresh ? 1u : 0u);
    for (const auto action : fragment_actions) {
        seed.write_u8(action);
    }
}

void stream_state_receive_range(FuzzInputBuilder &seed, std::uint64_t offset, std::size_t length,
                                bool fin) {
    seed.write_u8(5);
    seed.write_u64(offset);
    seed.write_size(length);
    seed.write_u8(fin ? 1u : 0u);
}

void stream_state_peer_reset(FuzzInputBuilder &seed, std::uint64_t application_error_code,
                             std::uint64_t final_size) {
    seed.write_u8(6);
    seed.write_u64(application_error_code);
    seed.write_u64(final_size);
}

void stream_state_peer_stop_sending(FuzzInputBuilder &seed, std::uint64_t error_code) {
    seed.write_u8(7);
    seed.write_u64(error_code);
}

void stream_state_local_reset(FuzzInputBuilder &seed, std::uint64_t error_code, bool acknowledge) {
    seed.write_u8(8);
    seed.write_u64(error_code);
    seed.write_u8(acknowledge ? 1u : 0u);
}

void stream_state_local_stop_sending(FuzzInputBuilder &seed, std::uint64_t error_code,
                                     bool acknowledge) {
    seed.write_u8(9);
    seed.write_u64(error_code);
    seed.write_u8(acknowledge ? 1u : 0u);
}

void stream_state_peer_final_size(FuzzInputBuilder &seed, std::uint64_t final_size) {
    seed.write_u8(10);
    seed.write_u64(final_size);
}

void stream_state_classify(FuzzInputBuilder &seed, std::uint64_t stream_id) {
    seed.write_u8(11);
    seed.write_u64(stream_id);
}

void stream_state_open_limits(FuzzInputBuilder &seed, std::uint64_t bidi, std::uint64_t uni,
                              std::uint64_t stream_id) {
    seed.write_u8(12);
    seed.write_u64(bidi);
    seed.write_u64(uni);
    seed.write_u64(stream_id);
}

void stream_state_peer_open_limits(FuzzInputBuilder &seed, std::uint64_t stream_id,
                                   std::uint64_t bidi, std::uint64_t uni) {
    seed.write_u8(13);
    seed.write_u64(stream_id);
    seed.write_u64(bidi);
    seed.write_u64(uni);
}

void stream_state_snapshot(FuzzInputBuilder &seed, bool prefer_fresh) {
    seed.write_u8(14);
    seed.write_u8(prefer_fresh ? 1u : 0u);
}

void generate_stream_state_seeds(const std::filesystem::path &root) {
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 0, 8, 128);
        stream_state_append_payload(seed, counted_bytes(0x10, 48), false);
        stream_state_take_fragments(seed, 64, 64, true, {0, 2, 3, 1});
        stream_state_data_blocked(seed, false);
        stream_state_peer_max_stream_data(seed, 128);
        stream_state_take_fragments(seed, 80, 80, false, {0, 1});
        stream_state_snapshot(seed, false);
        write_stream_state_seed(root, "generated_stream_flow_blocked_recovery", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 0, 4096, 4096);
        stream_state_append_payload(seed, counted_bytes(0x40, 96), false);
        stream_state_take_fragments(seed, 24, 24, true, {0});
        stream_state_take_fragments(seed, 24, 24, false, {2});
        stream_state_take_fragments(seed, 48, 48, true, {3});
        stream_state_take_fragments(seed, 128, 128, false, {1});
        stream_state_snapshot(seed, true);
        write_stream_state_seed(root, "generated_stream_fragment_send_loss_restore",
                                std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 0, 1024, 128);
        stream_state_receive_range(seed, 0, 32, false);
        stream_state_receive_range(seed, 64, 32, false);
        stream_state_receive_range(seed, 32, 32, false);
        stream_state_receive_range(seed, 96, 0, true);
        stream_state_peer_final_size(seed, 96);
        stream_state_peer_reset(seed, 0x100, 96);
        stream_state_peer_reset(seed, 0x101, 64);
        write_stream_state_seed(root, "generated_stream_receive_gap_final_reset", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, true, 1, 2048, 2048);
        stream_state_append_payload(seed, counted_bytes(0x80, 32), true);
        stream_state_local_reset(seed, 0x10, false);
        stream_state_local_reset(seed, 0x10, true);
        stream_state_local_stop_sending(seed, 0x20, false);
        stream_state_local_stop_sending(seed, 0x20, true);
        stream_state_peer_stop_sending(seed, 0x30);
        stream_state_snapshot(seed, false);
        write_stream_state_seed(root, "generated_stream_local_reset_stop_loss_ack",
                                std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 0, 256, 32);
        stream_state_max_stream_data(seed, 64, false);
        stream_state_max_stream_data(seed, 128, true);
        stream_state_max_stream_data(seed, 16, false);
        stream_state_receive_range(seed, 0, 16, false);
        stream_state_receive_range(seed, 16, 16, true);
        write_stream_state_seed(root, "generated_stream_max_stream_data_retransmit",
                                std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, true, 3, 512, 512);
        stream_state_append_payload(seed, counted_bytes(0xa0, 40), true);
        stream_state_take_fragments(seed, 32, 32, true, {0, 1});
        stream_state_take_fragments(seed, 64, 64, false, {2, 3});
        stream_state_classify(seed, 3);
        stream_state_classify(seed, 7);
        write_stream_state_seed(root, "generated_stream_server_uni_send", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 3, 0, 256);
        stream_state_receive_range(seed, 0, 24, false);
        stream_state_receive_range(seed, 24, 24, true);
        stream_state_local_stop_sending(seed, 0x77, false);
        stream_state_local_stop_sending(seed, 0x77, true);
        stream_state_peer_reset(seed, 0x88, 48);
        write_stream_state_seed(root, "generated_stream_client_peer_uni_receive_stop",
                                std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 0, 1024, 1024);
        for (std::uint64_t stream_id = 0; stream_id < 16; ++stream_id) {
            stream_state_classify(seed, stream_id);
        }
        stream_state_open_limits(seed, 0, 0, 0);
        stream_state_open_limits(seed, 1, 1, 4);
        stream_state_open_limits(seed, 63, 63, 252);
        stream_state_peer_open_limits(seed, 0, 0, 0);
        stream_state_peer_open_limits(seed, 5, 1, 0);
        stream_state_peer_open_limits(seed, 254, 63, 63);
        write_stream_state_seed(root, "generated_stream_client_limits_matrix", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, true, 1, 1024, 1024);
        for (std::uint64_t stream_id = 0; stream_id < 16; ++stream_id) {
            stream_state_classify(seed, stream_id);
        }
        stream_state_open_limits(seed, 0, 0, 1);
        stream_state_open_limits(seed, 2, 1, 9);
        stream_state_open_limits(seed, 63, 63, 253);
        stream_state_peer_open_limits(seed, 1, 0, 0);
        stream_state_peer_open_limits(seed, 4, 1, 0);
        stream_state_peer_open_limits(seed, 255, 63, 63);
        write_stream_state_seed(root, "generated_stream_server_limits_matrix", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 0, 64, 64);
        stream_state_append_payload(seed, counted_bytes(0xc0, 16), false);
        stream_state_peer_max_stream_data(seed, 16);
        stream_state_take_fragments(seed, 8, 8, true, {0});
        stream_state_peer_max_stream_data(seed, 32);
        stream_state_append_payload(seed, counted_bytes(0xd0, 16), true);
        stream_state_take_fragments(seed, 12, 12, false, {0, 2, 3, 1});
        stream_state_peer_final_size(seed, 32);
        write_stream_state_seed(root, "generated_stream_fin_after_flow_growth", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, true, 0, 128, 128);
        stream_state_receive_range(seed, 0, 0, false);
        stream_state_receive_range(seed, 0, 64, true);
        stream_state_peer_final_size(seed, 63);
        stream_state_peer_reset(seed, 0x55, 64);
        stream_state_local_stop_sending(seed, 0x66, false);
        stream_state_snapshot(seed, true);
        write_stream_state_seed(root, "generated_stream_peer_bidi_receive_edges", std::move(seed));
    }
    {
        FuzzInputBuilder seed;
        write_stream_state_prefix(seed, false, 2, 256, 256);
        stream_state_append_payload(seed, counted_bytes(0xe0, 56), true);
        stream_state_take_fragments(seed, 16, 16, true, {0});
        stream_state_local_reset(seed, 0xaa, false);
        stream_state_peer_stop_sending(seed, 0xbb);
        stream_state_take_fragments(seed, 96, 96, false, {2, 3, 1});
        write_stream_state_seed(root, "generated_stream_client_uni_reset_after_send",
                                std::move(seed));
    }
}

void generate_state_machine_seeds(const std::filesystem::path &root) {
    generate_stream_state_seeds(root);
    write_seed(root, "fuzz_stream_state", "generated_stream_send_fin",
               bytes({
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x05, 0x68,
                   0x65, 0x6c, 0x6c, 0x6f, 0x04, 0x00, 0x00, 0x00, 0x40,
               }));
    write_seed(root, "fuzz_recovery_ack", "generated_ack_loss",
               bytes({
                   0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x04, 0xb0,
                   0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0xb0,
                   0x06, 0x00, 0x00, 0x00, 0x05, 0x02, 0x05, 0x04, 0x02, 0x01, 0x00, 0x01,
               }));
    write_seed(root, "fuzz_congestion", "generated_cubic_loss",
               bytes({
                   0x01, 0x04, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                   0x00, 0x01, 0x04, 0xb0, 0x02, 0x01, 0x00, 0x00, 0x00, 0x20, 0x01,
                   0x04, 0xb0, 0x05, 0x01, 0x00, 0x00, 0x00, 0x30, 0x01, 0x04, 0xb0,
               }));
}

void generate(const std::filesystem::path &root) {
    generate_varint_seeds(root);
    generate_frame_seeds(root);
    generate_packet_seeds(root);
    generate_protected_packet_seeds(root);
    generate_transport_parameter_seeds(root);
    generate_state_machine_seeds(root);
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

#pragma once

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "src/quic/protected_codec.h"
#include "src/quic/varint.h"
#include "tests/support/quic_test_utils.h"

namespace coquic::quic::test_support {

inline std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

inline std::uint32_t read_u32_be_at(std::span<const std::byte> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 24) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3]));
}

inline std::uint8_t hex_nibble_or_terminate(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(10 + (value - 'a'));
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(10 + (value - 'A'));
    }

    std::abort();
}

inline std::vector<std::byte> bytes_from_hex(std::string_view hex) {
    if ((hex.size() % 2u) != 0u) {
        std::abort();
    }

    std::vector<std::byte> bytes;
    bytes.reserve(hex.size() / 2u);
    for (std::size_t index = 0; index < hex.size(); index += 2u) {
        const auto high = hex_nibble_or_terminate(hex[index]);
        const auto low = hex_nibble_or_terminate(hex[index + 1u]);
        bytes.push_back(static_cast<std::byte>((high << 4u) | low));
    }

    return bytes;
}

template <typename T> T optional_value_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

template <typename T> T &optional_ref_or_terminate(std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

inline std::size_t tracked_packet_count(const PacketSpaceState &packet_space) {
    return packet_space.recovery.tracked_packet_count();
}

inline const SentPacketRecord *tracked_packet_or_null(const PacketSpaceState &packet_space,
                                                      std::uint64_t packet_number) {
    return packet_space.recovery.find_packet(packet_number);
}

inline const SentPacketRecord &tracked_packet_or_terminate(const PacketSpaceState &packet_space,
                                                           std::uint64_t packet_number) {
    const auto *packet = tracked_packet_or_null(packet_space, packet_number);
    if (packet == nullptr) {
        std::abort();
    }
    return *packet;
}

inline const SentPacketRecord &first_tracked_packet(const PacketSpaceState &packet_space) {
    const auto handle = packet_space.recovery.oldest_tracked_packet();
    if (!handle.has_value()) {
        std::abort();
    }

    const auto *packet = packet_space.recovery.packet_for_handle(*handle);
    if (packet == nullptr) {
        std::abort();
    }
    return *packet;
}

inline const SentPacketRecord &last_tracked_packet(const PacketSpaceState &packet_space) {
    const auto handle = packet_space.recovery.newest_tracked_packet();
    if (!handle.has_value()) {
        std::abort();
    }

    const auto *packet = packet_space.recovery.packet_for_handle(*handle);
    if (packet == nullptr) {
        std::abort();
    }
    return *packet;
}

inline std::vector<SentPacketRecord> tracked_packet_snapshot(const PacketSpaceState &packet_space) {
    std::vector<SentPacketRecord> packets;
    for (const auto handle : packet_space.recovery.tracked_packets()) {
        const auto *packet = packet_space.recovery.packet_for_handle(handle);
        if (packet == nullptr) {
            std::abort();
        }
        packets.push_back(*packet);
    }
    return packets;
}

class ScopedEnvVar {
  public:
    ScopedEnvVar(std::string name, std::optional<std::string> value) : name_(std::move(name)) {
        if (const char *existing = std::getenv(name_.c_str()); existing != nullptr) {
            previous_ = std::string(existing);
            had_previous_ = true;
        }

        if (value.has_value()) {
            EXPECT_EQ(::setenv(name_.c_str(), value->c_str(), 1), 0);
        } else {
            EXPECT_EQ(::unsetenv(name_.c_str()), 0);
        }
    }

    ~ScopedEnvVar() {
        if (had_previous_) {
            ::setenv(name_.c_str(), previous_.c_str(), 1);
            return;
        }

        ::unsetenv(name_.c_str());
    }

    ScopedEnvVar(const ScopedEnvVar &) = delete;
    ScopedEnvVar &operator=(const ScopedEnvVar &) = delete;

  private:
    std::string name_;
    std::string previous_;
    bool had_previous_ = false;
};

inline CipherSuite invalid_cipher_suite() {
    constexpr std::uint8_t raw = 0xff;
    CipherSuite value{};
    std::memcpy(&value, &raw, sizeof(value));
    return value;
}

inline TrafficSecret
make_test_traffic_secret(CipherSuite cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
                         std::byte fill = std::byte{0x11}) {
    const std::size_t secret_size = cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
    return TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, fill),
    };
}

inline QuicConnection make_connected_client_connection() {
    QuicConnection connection(test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = HandshakeStatus::connected;
    connection.handshake_confirmed_ = true;
    connection.peer_source_connection_id_ = {std::byte{0xa1}, std::byte{0xb2}};
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.application_space_.read_secret =
        make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret =
        make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
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
    return connection;
}

inline QuicConnection make_connected_server_connection() {
    QuicConnection connection(test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = HandshakeStatus::connected;
    connection.handshake_confirmed_ = true;
    connection.peer_address_validated_ = true;
    connection.peer_source_connection_id_ = {std::byte{0xc1}, std::byte{0x01}};
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    connection.local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = connection.client_initial_destination_connection_id_,
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
        .initial_source_connection_id = connection.config_.source_connection_id,
    };
    connection.initialize_local_flow_control();
    connection.application_space_.read_secret =
        make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret =
        make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
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
    return connection;
}

inline PreferredAddress make_test_preferred_address() {
    return PreferredAddress{
        .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
        .ipv4_port = 4444,
        .connection_id = bytes_from_ints({0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
        .stateless_reset_token =
            {
                std::byte{0x00},
                std::byte{0x01},
                std::byte{0x02},
                std::byte{0x03},
                std::byte{0x04},
                std::byte{0x05},
                std::byte{0x06},
                std::byte{0x07},
                std::byte{0x08},
                std::byte{0x09},
                std::byte{0x0a},
                std::byte{0x0b},
                std::byte{0x0c},
                std::byte{0x0d},
                std::byte{0x0e},
                std::byte{0x0f},
            },
    };
}

inline QuicConnection make_connected_server_connection_with_preferred_address() {
    auto config = test::make_server_core_config();
    config.transport.preferred_address = make_test_preferred_address();

    QuicConnection connection(config);
    connection.started_ = true;
    connection.status_ = HandshakeStatus::connected;
    connection.handshake_confirmed_ = true;
    connection.peer_address_validated_ = true;
    connection.peer_source_connection_id_ = {std::byte{0xc1}, std::byte{0x01}};
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    connection.local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = connection.client_initial_destination_connection_id_,
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
        .initial_source_connection_id = connection.config_.source_connection_id,
        .preferred_address = connection.config_.transport.preferred_address,
    };
    connection.initialize_local_flow_control();
    connection.application_space_.read_secret =
        make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret =
        make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
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
    return connection;
}

inline std::vector<ProtectedPacket> decode_sender_datagram(const QuicConnection &connection,
                                                           std::span<const std::byte> datagram) {
    const auto decoded = deserialize_protected_datagram(
        datagram, DeserializeProtectionContext{
                      .peer_role = connection.config_.role,
                      .client_initial_destination_connection_id =
                          connection.client_initial_destination_connection_id(),
                      .handshake_secret = connection.handshake_space_.write_secret,
                      .zero_rtt_secret = connection.zero_rtt_space_.write_secret,
                      .one_rtt_secret = connection.application_space_.write_secret,
                      .one_rtt_key_phase = connection.application_write_key_phase_,
                      .largest_authenticated_initial_packet_number =
                          connection.initial_space_.largest_authenticated_packet_number,
                      .largest_authenticated_handshake_packet_number =
                          connection.handshake_space_.largest_authenticated_packet_number,
                      .largest_authenticated_application_packet_number =
                          connection.application_space_.largest_authenticated_packet_number,
                      .one_rtt_destination_connection_id_length =
                          connection.config_.source_connection_id.size(),
                  });
    EXPECT_TRUE(decoded.has_value());
    if (!decoded.has_value()) {
        return {};
    }

    return decoded.value();
}

inline std::optional<std::vector<ConnectionId>> protected_datagram_destination_connection_ids(
    std::span<const std::byte> datagram, std::size_t one_rtt_destination_connection_id_length) {
    std::vector<ConnectionId> destination_connection_ids;
    std::size_t offset = 0;
    while (offset < datagram.size()) {
        if ((std::to_integer<std::uint8_t>(datagram[offset]) & 0x80u) == 0) {
            if (offset + 1u + one_rtt_destination_connection_id_length > datagram.size()) {
                return std::nullopt;
            }

            destination_connection_ids.emplace_back(
                datagram.subspan(offset + 1u, one_rtt_destination_connection_id_length).begin(),
                datagram.subspan(offset + 1u, one_rtt_destination_connection_id_length).end());
            break;
        }

        if (offset + 6u > datagram.size()) {
            return std::nullopt;
        }

        const auto version = read_u32_be_at(datagram, offset + 1u);
        const auto destination_connection_id_length =
            static_cast<std::size_t>(std::to_integer<std::uint8_t>(datagram[offset + 5u]));
        const auto destination_connection_id_offset = offset + 6u;
        const auto source_connection_id_length_offset =
            destination_connection_id_offset + destination_connection_id_length;
        if (source_connection_id_length_offset >= datagram.size()) {
            return std::nullopt;
        }

        destination_connection_ids.emplace_back(
            datagram.subspan(destination_connection_id_offset, destination_connection_id_length)
                .begin(),
            datagram.subspan(destination_connection_id_offset, destination_connection_id_length)
                .end());

        const auto source_connection_id_length = static_cast<std::size_t>(
            std::to_integer<std::uint8_t>(datagram[source_connection_id_length_offset]));
        auto cursor = source_connection_id_length_offset + 1u + source_connection_id_length;
        if (cursor > datagram.size()) {
            return std::nullopt;
        }

        const auto packet_type = (std::to_integer<std::uint8_t>(datagram[offset]) >> 4u) & 0x03u;
        const bool initial_packet =
            version == kQuicVersion2 ? packet_type == 0x01u : packet_type == 0x00u;
        if (initial_packet) {
            const auto token_length = decode_varint_bytes(datagram.subspan(cursor));
            if (!token_length.has_value()) {
                return std::nullopt;
            }
            cursor += token_length.value().bytes_consumed +
                      static_cast<std::size_t>(token_length.value().value);
            if (cursor > datagram.size()) {
                return std::nullopt;
            }
        }

        const auto packet_length = decode_varint_bytes(datagram.subspan(cursor));
        if (!packet_length.has_value()) {
            return std::nullopt;
        }
        cursor += packet_length.value().bytes_consumed;
        const auto packet_end = cursor + static_cast<std::size_t>(packet_length.value().value);
        if (packet_end > datagram.size()) {
            return std::nullopt;
        }

        offset = packet_end;
    }

    return destination_connection_ids;
}

inline std::optional<std::size_t> protected_next_packet_length(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return bytes.size();
    }

    if (bytes.size() < 6u) {
        return std::nullopt;
    }

    const auto version = read_u32_be_at(bytes, 1u);
    const auto destination_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[5u]));
    const auto destination_connection_id_offset = 6u;
    const auto source_connection_id_length_offset =
        destination_connection_id_offset + destination_connection_id_length;
    if (source_connection_id_length_offset >= bytes.size()) {
        return std::nullopt;
    }

    const auto source_connection_id_length = static_cast<std::size_t>(
        std::to_integer<std::uint8_t>(bytes[source_connection_id_length_offset]));
    auto cursor = source_connection_id_length_offset + 1u + source_connection_id_length;
    if (cursor > bytes.size()) {
        return std::nullopt;
    }

    const auto packet_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    const auto is_initial_long_header_type = [](std::uint32_t packet_version,
                                                std::uint8_t long_header_type) {
        if (packet_version == kQuicVersion2) {
            return long_header_type == 0x01u;
        }
        return long_header_type == 0x00u;
    };
    if (is_initial_long_header_type(version, packet_type)) {
        const auto token_length = decode_varint_bytes(bytes.subspan(cursor));
        if (!token_length.has_value()) {
            return std::nullopt;
        }
        cursor += token_length.value().bytes_consumed +
                  static_cast<std::size_t>(token_length.value().value);
        if (cursor > bytes.size()) {
            return std::nullopt;
        }
    }

    const auto payload_length = decode_varint_bytes(bytes.subspan(cursor));
    if (!payload_length.has_value()) {
        return std::nullopt;
    }
    cursor += payload_length.value().bytes_consumed +
              static_cast<std::size_t>(payload_length.value().value);
    if (cursor > bytes.size()) {
        return std::nullopt;
    }

    return cursor;
}

enum class ProtectedPacketKind : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

inline std::optional<std::vector<ProtectedPacketKind>>
protected_datagram_packet_kinds(std::span<const std::byte> datagram) {
    std::vector<ProtectedPacketKind> packet_kinds;
    std::size_t offset = 0;
    while (offset < datagram.size()) {
        const auto first_byte = std::to_integer<std::uint8_t>(datagram[offset]);
        if ((first_byte & 0x80u) == 0) {
            packet_kinds.push_back(ProtectedPacketKind::one_rtt);
            break;
        }

        if (offset + 5u > datagram.size()) {
            return std::nullopt;
        }

        const auto version = read_u32_be_at(datagram, offset + 1u);
        const auto packet_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
        const auto is_initial_long_header_type = [](std::uint32_t packet_version,
                                                    std::uint8_t long_header_type) {
            if (packet_version == kQuicVersion2) {
                return long_header_type == 0x01u;
            }
            return long_header_type == 0x00u;
        };
        const auto is_zero_rtt_long_header_type = [](std::uint32_t packet_version,
                                                     std::uint8_t long_header_type) {
            if (packet_version == kQuicVersion2) {
                return long_header_type == 0x02u;
            }
            return long_header_type == 0x01u;
        };
        const auto is_handshake_long_header_type = [](std::uint32_t packet_version,
                                                      std::uint8_t long_header_type) {
            if (packet_version == kQuicVersion2) {
                return long_header_type == 0x03u;
            }
            return long_header_type == 0x02u;
        };
        if (is_initial_long_header_type(version, packet_type)) {
            packet_kinds.push_back(ProtectedPacketKind::initial);
        } else if (is_zero_rtt_long_header_type(version, packet_type)) {
            packet_kinds.push_back(ProtectedPacketKind::zero_rtt);
        } else if (is_handshake_long_header_type(version, packet_type)) {
            packet_kinds.push_back(ProtectedPacketKind::handshake);
        } else {
            return std::nullopt;
        }

        const auto packet_length = protected_next_packet_length(datagram.subspan(offset));
        if (!packet_length.has_value()) {
            return std::nullopt;
        }
        offset += packet_length.value();
    }

    return packet_kinds;
}

inline bool ack_frame_acks_packet_number_for_tests(const AckFrame &ack,
                                                   std::uint64_t packet_number) {
    if (packet_number > ack.largest_acknowledged) {
        return false;
    }
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return false;
    }

    auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
    if (packet_number >= range_smallest) {
        return true;
    }

    auto previous_smallest = range_smallest;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return false;
        }

        const auto range_largest = previous_smallest - range.gap - 2;
        if (range_largest < range.range_length) {
            return false;
        }

        range_smallest = range_largest - range.range_length;
        if (packet_number >= range_smallest && packet_number <= range_largest) {
            return true;
        }

        previous_smallest = range_smallest;
    }

    return false;
}

inline std::vector<std::uint64_t>
application_stream_ids_from_datagram(const QuicConnection &connection,
                                     std::span<const std::byte> datagram) {
    const auto packets = decode_sender_datagram(connection, datagram);
    std::vector<std::uint64_t> stream_ids;
    for (const auto &packet : packets) {
        const auto *application = std::get_if<ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            if (std::find(stream_ids.begin(), stream_ids.end(), stream->stream_id) ==
                stream_ids.end()) {
                stream_ids.push_back(stream->stream_id);
            }
        }
    }

    return stream_ids;
}

inline bool datagram_has_application_ack(const QuicConnection &connection,
                                         std::span<const std::byte> datagram) {
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *application = std::get_if<ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }

        for (const auto &frame : application->frames) {
            if (std::holds_alternative<AckFrame>(frame)) {
                return true;
            }
        }
    }

    return false;
}

inline bool datagram_has_application_stream(const QuicConnection &connection,
                                            std::span<const std::byte> datagram) {
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *application = std::get_if<ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }

        for (const auto &frame : application->frames) {
            if (std::holds_alternative<StreamFrame>(frame)) {
                return true;
            }
        }
    }

    return false;
}

inline std::optional<std::size_t> find_application_probe_payload_size_that_drops_ack() {
    for (std::size_t payload_size = 1200; payload_size >= 1; --payload_size) {
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/1, /*ack_eliciting=*/true, test::test_time(0));
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 41,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments =
                {
                    StreamFrameSendFragment{
                        .stream_id = 0,
                        .offset = 0,
                        .bytes = std::vector<std::byte>(payload_size, std::byte{0x50}),
                        .fin = false,
                    },
                },
        };

        const auto datagram = connection.drain_outbound_datagram(test::test_time(1));
        if (datagram.empty() || connection.has_failed()) {
            if (payload_size == 1) {
                break;
            }
            continue;
        }

        if (!datagram_has_application_ack(connection, datagram) &&
            datagram_has_application_stream(connection, datagram) &&
            connection.application_space_.received_packets.has_ack_to_send()) {
            return payload_size;
        }

        if (payload_size == 1) {
            break;
        }
    }

    return std::nullopt;
}

inline std::optional<std::size_t> find_application_send_payload_size_that_drops_ack() {
    for (std::size_t payload_size = 1200; payload_size >= 1; --payload_size) {
        auto connection = make_connected_client_connection();
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/2, /*ack_eliciting=*/true, test::test_time(0));
        if (!connection
                 .queue_stream_send(0, std::vector<std::byte>(payload_size, std::byte{0x53}), false)
                 .has_value()) {
            if (payload_size == 1) {
                break;
            }
            continue;
        }

        const auto datagram = connection.drain_outbound_datagram(test::test_time(1));
        if (datagram.empty() || connection.has_failed()) {
            if (payload_size == 1) {
                break;
            }
            continue;
        }

        if (!datagram_has_application_ack(connection, datagram) &&
            datagram_has_application_stream(connection, datagram) &&
            connection.application_space_.received_packets.has_ack_to_send()) {
            return payload_size;
        }

        if (payload_size == 1) {
            break;
        }
    }

    return std::nullopt;
}

inline void expect_local_error(const QuicCoreResult &result, QuicCoreLocalErrorCode code,
                               std::uint64_t stream_id) {
    const auto local_error = result.local_error;
    ASSERT_TRUE(local_error.has_value());
    if (!local_error.has_value()) {
        return;
    }

    const auto &local_error_value = optional_ref_or_terminate(local_error);
    EXPECT_EQ(local_error_value.code, code);
    ASSERT_TRUE(local_error_value.stream_id.has_value());
    if (!local_error_value.stream_id.has_value()) {
        return;
    }

    EXPECT_EQ(optional_value_or_terminate(local_error_value.stream_id), stream_id);
}

} // namespace coquic::quic::test_support

#include "src/quic/connection.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/frame.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/protected_codec.h"
#include "src/quic/qlog/json.h"
#include "src/quic/qlog/session.h"

namespace coquic::quic {

namespace {

constexpr std::size_t kMinimumInitialDatagramSize = 1200;
constexpr std::size_t kMaximumDatagramSize = 1200;
constexpr std::size_t kMaximumDeferredProtectedPackets = 32;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;
constexpr std::uint64_t kCompatibilityStreamId = 0;
constexpr std::uint32_t kPersistentCongestionThreshold = 3;
constexpr std::size_t kMaximumImmediateApplicationDatagramsPerBurst = 21;
constexpr auto kApplicationBurstResumeDelay = std::chrono::milliseconds(1);

bool is_ect_codepoint(QuicEcnCodepoint ecn) {
    return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1;
}

std::size_t ecn_packet_space_index(const PacketSpaceState &packet_space,
                                   std::span<const PacketSpaceState *const, 3> packet_spaces) {
    if (packet_spaces[0] == &packet_space) {
        return 0;
    }
    if (packet_spaces[1] == &packet_space) {
        return 1;
    }

    return 2;
}

bool packet_trace_enabled() {
    const char *value = std::getenv("COQUIC_PACKET_TRACE");
    return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
}

std::string format_connection_id_hex(std::span<const std::byte> connection_id) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (const auto byte : connection_id) {
        hex << std::setw(2) << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
    }
    return hex.str();
}

ConnectionId make_issued_connection_id(std::span<const std::byte> base_connection_id,
                                       std::uint64_t sequence_number) {
    ConnectionId connection_id(base_connection_id.begin(), base_connection_id.end());
    if (connection_id.empty()) {
        return connection_id;
    }

    for (std::size_t i = 0; i < connection_id.size(); ++i) {
        const auto sequence_shift = static_cast<unsigned>((i % sizeof(sequence_number)) * 8u);
        auto mixed = static_cast<std::uint8_t>((sequence_number >> sequence_shift) & 0xffu);
        mixed ^= static_cast<std::uint8_t>(0x5au + static_cast<unsigned>(i * 17u));
        connection_id[connection_id.size() - 1u - i] ^= std::byte{mixed};
    }

    return connection_id;
}

std::array<std::byte, 16> make_stateless_reset_token(std::span<const std::byte> connection_id,
                                                     std::uint64_t sequence_number) {
    std::array<std::byte, 16> token{};
    for (std::size_t i = 0; i < token.size(); ++i) {
        const auto sequence_shift = static_cast<unsigned>((i % sizeof(sequence_number)) * 8u);
        auto mixed = static_cast<std::uint8_t>((sequence_number >> sequence_shift) & 0xffu);
        mixed ^= static_cast<std::uint8_t>(0xa5u + static_cast<unsigned>(i * 13u));
        if (!connection_id.empty()) {
            mixed ^= std::to_integer<std::uint8_t>(connection_id[i % connection_id.size()]);
        }
        token[i] = std::byte{mixed};
    }

    return token;
}

std::array<std::byte, 8> make_path_challenge_data(std::span<const std::byte> local_connection_id,
                                                  QuicPathId path_id,
                                                  std::uint64_t sequence_number) {
    std::array<std::byte, 8> challenge{};
    for (std::size_t index = 0; index < challenge.size(); ++index) {
        const auto path_shift = static_cast<unsigned>((index % sizeof(path_id)) * 8u);
        const auto sequence_shift = static_cast<unsigned>(index * 8u);
        auto mixed = static_cast<std::uint8_t>(((path_id >> path_shift) & 0xffu) ^
                                               ((sequence_number >> sequence_shift) & 0xffu) ^
                                               static_cast<std::uint64_t>(0x31u + index));
        if (!local_connection_id.empty()) {
            mixed ^= std::to_integer<std::uint8_t>(
                local_connection_id[(local_connection_id.size() - 1u - index) %
                                    local_connection_id.size()]);
        }
        challenge[index] = std::byte{mixed};
    }
    return challenge;
}

std::size_t count_active_connection_ids(
    const std::map<std::uint64_t, LocalConnectionIdRecord> &connection_ids) {
    return static_cast<std::size_t>(
        std::count_if(connection_ids.begin(), connection_ids.end(),
                      [](const auto &entry) { return !entry.second.retired; }));
}

bool packet_trace_matches_connection(std::span<const std::byte> local_connection_id) {
    if (!packet_trace_enabled()) {
        return false;
    }

    const char *filter = std::getenv("COQUIC_PACKET_TRACE_SCID");
    if (filter == nullptr || filter[0] == '\0') {
        return true;
    }

    const auto formatted_connection_id = format_connection_id_hex(local_connection_id);
    return std::string_view(filter) == formatted_connection_id;
}

std::string format_optional_path_id(std::optional<QuicPathId> path_id) {
    if (!path_id.has_value()) {
        return "-";
    }
    return std::to_string(*path_id);
}

const PathState *find_path_state(const std::map<QuicPathId, PathState> &paths,
                                 std::optional<QuicPathId> path_id) {
    if (!path_id.has_value()) {
        return nullptr;
    }
    const auto it = paths.find(*path_id);
    return it == paths.end() ? nullptr : &it->second;
}

std::string format_path_state_summary(const PathState *path) {
    if (path == nullptr) {
        return "-";
    }

    std::ostringstream summary;
    summary << "id=" << path->id << " val=" << static_cast<int>(path->validated)
            << " cur=" << static_cast<int>(path->is_current_send_path)
            << " chal=" << static_cast<int>(path->challenge_pending)
            << " out=" << static_cast<int>(path->outstanding_challenge.has_value())
            << " resp=" << static_cast<int>(path->pending_response.has_value())
            << " recv=" << path->anti_amplification_received_bytes
            << " sent=" << path->anti_amplification_sent_bytes;
    return summary.str();
}

std::string format_ack_ranges(const AckFrame &ack) {
    std::ostringstream ranges;
    ranges << '[';
    if (ack.largest_acknowledged < ack.first_ack_range) {
        ranges << "invalid";
    } else {
        auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
        ranges << range_smallest << '-' << ack.largest_acknowledged;
        auto previous_smallest = range_smallest;
        for (const auto &range : ack.additional_ranges) {
            if (previous_smallest < range.gap + 2) {
                ranges << ",invalid";
                break;
            }

            const auto range_largest = previous_smallest - range.gap - 2;
            if (range_largest < range.range_length) {
                ranges << ",invalid";
                break;
            }

            range_smallest = range_largest - range.range_length;
            ranges << ',' << range_smallest << '-' << range_largest;
            previous_smallest = range_smallest;
        }
    }
    ranges << ']';
    return ranges.str();
}

std::string summarize_packets(std::span<const SentPacketRecord> packets) {
    if (packets.empty()) {
        return "count=0";
    }

    auto [first_packet, last_packet] =
        std::minmax_element(packets.begin(), packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.packet_number < rhs.packet_number;
                            });

    std::size_t stream_fragment_count = 0;
    std::optional<std::uint64_t> first_stream_offset;
    for (const auto &packet : packets) {
        stream_fragment_count += packet.stream_fragments.size();
        if (!first_stream_offset.has_value() && !packet.stream_fragments.empty()) {
            first_stream_offset = packet.stream_fragments.front().offset;
        }
    }

    std::ostringstream summary;
    summary << "count=" << packets.size() << " pn=" << first_packet->packet_number << '-'
            << last_packet->packet_number << " stream_fragments=" << stream_fragment_count;
    if (first_stream_offset.has_value()) {
        summary << " first_stream_offset=" << *first_stream_offset;
    }
    return summary.str();
}

bool supports_version(std::span<const std::uint32_t> supported_versions, std::uint32_t version) {
    return std::find(supported_versions.begin(), supported_versions.end(), version) !=
           supported_versions.end();
}

bool supports_quic_v2(std::span<const std::uint32_t> supported_versions) {
    return supports_version(supported_versions, kQuicVersion2);
}

CodecResult<bool> prime_traffic_secret_cache(const std::optional<TrafficSecret> &secret) {
    if (!secret.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto expanded = expand_traffic_secret(secret.value());
    if (!expanded.has_value()) {
        return CodecResult<bool>::failure(expanded.error().code, expanded.error().offset);
    }

    return CodecResult<bool>::success(true);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x01u;
    }
    return packet_type == 0x00u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_handshake_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x03u;
    }
    return packet_type == 0x02u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_zero_rtt_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x02u;
    }
    return packet_type == 0x01u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_bufferable_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    return is_initial_long_header_type(version, packet_type) |
           is_zero_rtt_long_header_type(version, packet_type) |
           is_handshake_long_header_type(version, packet_type);
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes);

bool packet_is_bufferable(std::span<const std::byte> packet_bytes) {
    const auto first_byte = std::to_integer<std::uint8_t>(packet_bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return true;
    }

    if (packet_bytes.size() < 5) {
        return false;
    }

    const auto version = read_u32_be(packet_bytes.subspan(1, 4));
    return is_bufferable_long_header_type(version,
                                          static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
}

bool datagram_starts_with_initial_packet(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0 || (first_byte & 0x40u) == 0) {
        return false;
    }

    const auto version = read_u32_be(bytes.subspan(1, 4));
    if (!is_supported_quic_version(version)) {
        return false;
    }

    return is_initial_long_header_type(version,
                                       static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
}

std::optional<VersionInformation>
make_local_version_information(std::span<const std::uint32_t> supported_versions,
                               std::uint32_t chosen_version) {
    if (!supports_quic_v2(supported_versions)) {
        return std::nullopt;
    }

    return VersionInformation{
        .chosen_version = chosen_version,
        .available_versions =
            std::vector<std::uint32_t>(supported_versions.begin(), supported_versions.end()),
    };
}

std::optional<VersionInformation>
version_information_for_handshake(std::span<const std::uint32_t> supported_versions,
                                  std::uint32_t chosen_version,
                                  const std::optional<ConnectionId> &retry_source_connection_id,
                                  std::uint32_t original_version, std::uint32_t current_version) {
    if (retry_source_connection_id.has_value() && current_version == original_version) {
        return std::nullopt;
    }

    return make_local_version_information(supported_versions, chosen_version);
}

std::uint32_t select_server_version(std::span<const std::uint32_t> supported_versions,
                                    std::uint32_t client_initial_version) {
    if (client_initial_version == kQuicVersion1 && supports_quic_v2(supported_versions)) {
        return kQuicVersion2;
    }
    if (supports_version(supported_versions, client_initial_version)) {
        return client_initial_version;
    }

    return client_initial_version;
}

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

std::vector<std::byte> application_protocol_bytes(std::string_view protocol) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(protocol.data()),
        reinterpret_cast<const std::byte *>(protocol.data() + protocol.size()));
}

void log_codec_failure(std::string_view where, const CodecError &error) {
    static_cast<void>(where);
    static_cast<void>(error);
}

std::size_t datagram_size_or_zero(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *value = std::get_if<std::vector<std::byte>>(&datagram.storage);
    return value == nullptr ? 0 : value->size();
}

std::size_t datagram_size_or_zero(const CodecResult<SerializedProtectedDatagram> &datagram) {
    const auto *value = std::get_if<SerializedProtectedDatagram>(&datagram.storage);
    return value == nullptr ? 0 : value->bytes.size();
}

bool is_empty_packet_payload_error(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *error = std::get_if<CodecError>(&datagram.storage);
    return error != nullptr && error->code == CodecErrorCode::empty_packet_payload;
}

bool is_empty_packet_payload_error(const CodecResult<SerializedProtectedDatagram> &datagram) {
    const auto *error = std::get_if<CodecError>(&datagram.storage);
    return error != nullptr && error->code == CodecErrorCode::empty_packet_payload;
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }

    return value;
}

void append_u32_be(std::vector<std::byte> &output, std::uint32_t value) {
    output.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    output.push_back(static_cast<std::byte>(value & 0xffu));
}

void append_length_prefixed_bytes(std::vector<std::byte> &output,
                                  std::span<const std::byte> bytes) {
    append_u32_be(output, static_cast<std::uint32_t>(bytes.size()));
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_length_prefixed_text(std::vector<std::byte> &output, std::string_view text) {
    append_u32_be(output, static_cast<std::uint32_t>(text.size()));
    output.insert(output.end(), reinterpret_cast<const std::byte *>(text.data()),
                  reinterpret_cast<const std::byte *>(text.data() + text.size()));
}

std::optional<std::span<const std::byte>>
read_length_prefixed_bytes(std::span<const std::byte> bytes, std::size_t &offset) {
    if (offset + 4 > bytes.size()) {
        return std::nullopt;
    }

    const auto length = read_u32_be(bytes.subspan(offset, 4));
    offset += 4;
    if (offset + length > bytes.size()) {
        return std::nullopt;
    }

    const auto value = bytes.subspan(offset, length);
    offset += length;
    return value;
}

std::vector<std::byte> encode_resumption_state(std::span<const std::byte> tls_state,
                                               std::uint32_t quic_version,
                                               std::string_view application_protocol,
                                               const TransportParameters &peer_transport_parameters,
                                               std::span<const std::byte> application_context) {
    std::vector<std::byte> encoded;
    const auto serialized_transport_parameters =
        serialize_transport_parameters(peer_transport_parameters);
    if (!serialized_transport_parameters.has_value()) {
        return encoded;
    }

    encoded.push_back(std::byte{0x01});
    append_u32_be(encoded, quic_version);
    append_length_prefixed_bytes(encoded, tls_state);
    append_length_prefixed_text(encoded, application_protocol);
    append_length_prefixed_bytes(encoded, serialized_transport_parameters.value());
    append_length_prefixed_bytes(encoded, application_context);
    return encoded;
}

std::optional<StoredClientResumptionState>
decode_resumption_state(std::span<const std::byte> bytes) {
    if (bytes.size() < 5 || bytes.front() != std::byte{0x01}) {
        return std::nullopt;
    }

    std::size_t offset = 1;
    const auto quic_version = read_u32_be(bytes.subspan(offset, 4));
    offset += 4;

    const auto tls_state_bytes = read_length_prefixed_bytes(bytes, offset);
    const auto application_protocol_bytes = read_length_prefixed_bytes(bytes, offset);
    const auto transport_parameters_bytes = read_length_prefixed_bytes(bytes, offset);
    const auto application_context_bytes = read_length_prefixed_bytes(bytes, offset);
    if (!tls_state_bytes.has_value() || !application_protocol_bytes.has_value() ||
        !transport_parameters_bytes.has_value() || !application_context_bytes.has_value() ||
        offset != bytes.size()) {
        return std::nullopt;
    }

    const auto peer_transport_parameters =
        deserialize_transport_parameters(*transport_parameters_bytes);
    if (!peer_transport_parameters.has_value()) {
        return std::nullopt;
    }

    StoredClientResumptionState state{
        .tls_state = std::vector<std::byte>(tls_state_bytes->begin(), tls_state_bytes->end()),
        .quic_version = quic_version,
        .application_protocol =
            std::string(reinterpret_cast<const char *>(application_protocol_bytes->data()),
                        application_protocol_bytes->size()),
        .peer_transport_parameters = peer_transport_parameters.value(),
        .application_context = std::vector<std::byte>(application_context_bytes->begin(),
                                                      application_context_bytes->end()),
    };
    return state;
}

PacketSpaceState &packet_space_for_level(EncryptionLevel level, PacketSpaceState &initial_space,
                                         PacketSpaceState &handshake_space,
                                         PacketSpaceState &zero_rtt_space,
                                         PacketSpaceState &application_space) {
    if (level == EncryptionLevel::initial) {
        return initial_space;
    }
    if (level == EncryptionLevel::handshake) {
        return handshake_space;
    }
    if (level == EncryptionLevel::zero_rtt) {
        return zero_rtt_space;
    }

    return application_space;
}

bool is_padding_frame(const Frame &frame) {
    return std::holds_alternative<PaddingFrame>(frame);
}

bool is_ack_eliciting_frame(const Frame &frame) {
    constexpr auto kAckElicitingByFrameIndex = std::to_array<bool>({
        false, // PaddingFrame
        true,  // PingFrame
        false, // AckFrame
        true,  // ResetStreamFrame
        true,  // StopSendingFrame
        true,  // CryptoFrame
        true,  // NewTokenFrame
        true,  // StreamFrame
        true,  // MaxDataFrame
        true,  // MaxStreamDataFrame
        true,  // MaxStreamsFrame
        true,  // DataBlockedFrame
        true,  // StreamDataBlockedFrame
        true,  // StreamsBlockedFrame
        true,  // NewConnectionIdFrame
        true,  // RetireConnectionIdFrame
        true,  // PathChallengeFrame
        true,  // PathResponseFrame
        false, // TransportConnectionCloseFrame
        false, // ApplicationConnectionCloseFrame
        true,  // HandshakeDoneFrame
    });

    return kAckElicitingByFrameIndex[frame.index()];
}

bool has_ack_eliciting_frame(std::span<const Frame> frames) {
    for (const auto &frame : frames) {
        if (is_ack_eliciting_frame(frame)) {
            return true;
        }
    }

    return false;
}

std::optional<DeadlineTrackedPacket>
latest_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    return packet_space.recovery.latest_in_flight_ack_eliciting_packet();
}

std::optional<DeadlineTrackedPacket> earliest_loss_packet(const PacketSpaceState &packet_space) {
    return packet_space.recovery.earliest_loss_packet();
}

bool has_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    return latest_in_flight_ack_eliciting_packet(packet_space).has_value();
}

void schedule_application_ack_deadline(PacketSpaceState &packet_space, QuicCoreTimePoint now,
                                       std::uint64_t max_ack_delay_ms, QuicEcnCodepoint ecn) {
    if (ecn == QuicEcnCodepoint::ce) {
        packet_space.pending_ack_deadline = now;
        packet_space.force_ack_send = true;
        return;
    }

    if (packet_space.received_packets.requests_immediate_ack()) {
        packet_space.pending_ack_deadline = now;
        return;
    }

    if (!packet_space.pending_ack_deadline.has_value()) {
        packet_space.pending_ack_deadline = now + std::chrono::milliseconds(max_ack_delay_ms);
    }
}

bool requires_connected_application_state_for_inbound_frame(const Frame &frame) {
    return std::holds_alternative<ResetStreamFrame>(frame) |
           std::holds_alternative<StopSendingFrame>(frame) |
           std::holds_alternative<MaxDataFrame>(frame) |
           std::holds_alternative<MaxStreamDataFrame>(frame) |
           std::holds_alternative<MaxStreamsFrame>(frame) |
           std::holds_alternative<DataBlockedFrame>(frame) |
           std::holds_alternative<StreamDataBlockedFrame>(frame) |
           std::holds_alternative<StreamsBlockedFrame>(frame);
}

bool should_defer_protected_one_rtt_packet(const ProtectedOneRttPacket &packet,
                                           HandshakeStatus status) {
    if (status != HandshakeStatus::in_progress) {
        return false;
    }

    return std::ranges::any_of(packet.frames, [](const Frame &frame) {
        return requires_connected_application_state_for_inbound_frame(frame);
    });
}

bool is_discardable_short_header_packet_error(CodecErrorCode code) {
    static constexpr std::array kDiscardableErrors = {
        CodecErrorCode::invalid_fixed_bit,
        CodecErrorCode::invalid_packet_protection_state,
        CodecErrorCode::packet_length_mismatch,
        CodecErrorCode::packet_decryption_failed,
        CodecErrorCode::header_protection_failed,
        CodecErrorCode::header_protection_sample_too_short,
    };
    return std::ranges::find(kDiscardableErrors, code) != kDiscardableErrors.end();
}

bool is_discardable_packet_length_error(CodecErrorCode code) {
    static constexpr std::array kDiscardableErrors = {
        CodecErrorCode::invalid_fixed_bit,
        CodecErrorCode::unsupported_packet_type,
    };
    return std::ranges::find(kDiscardableErrors, code) != kDiscardableErrors.end();
}

CodecResult<std::size_t>
peek_discardable_long_header_packet_length(std::span<const std::byte> bytes) {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<std::size_t>::failure(first_byte.error().code,
                                                 first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<std::size_t>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id_length.error().code,
                                                 destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id.error().code,
                                                 destination_connection_id.error().offset);
    }

    const auto source_connection_id_length = reader.read_byte();
    if (!source_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id_length.error().code,
                                                 source_connection_id_length.error().offset);
    }
    const auto source_connection_id_length_value =
        std::to_integer<std::uint8_t>(source_connection_id_length.value());
    if (source_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto source_connection_id = reader.read_exact(source_connection_id_length_value);
    if (!source_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id.error().code,
                                                 source_connection_id.error().offset);
    }

    const auto packet_type = static_cast<std::uint8_t>((header_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version_value, packet_type)) {
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<std::size_t>::failure(token_length.error().code,
                                                     token_length.error().offset);
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     reader.offset());
        }
        static_cast<void>(reader.read_exact(static_cast<std::size_t>(token_length.value().value)));
    } else if (!is_zero_rtt_long_header_type(version_value, packet_type) &&
               !is_handshake_long_header_type(version_value, packet_type)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto payload_length = decode_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<std::size_t>::failure(payload_length.error().code,
                                                 payload_length.error().offset);
    }
    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                 reader.offset());
    }

    return CodecResult<std::size_t>::success(
        reader.offset() + static_cast<std::size_t>(payload_length.value().value));
}

bool should_discard_corrupted_long_header_packet(bool short_header_packet, CodecErrorCode code) {
    return !short_header_packet && (code == CodecErrorCode::invalid_fixed_bit ||
                                    code == CodecErrorCode::unsupported_packet_type);
}

std::uint64_t saturating_subtract(std::uint64_t limit, std::uint64_t used) {
    return limit - std::min(limit, used);
}

bool application_frame_requires_connected_state(bool require_connected, HandshakeStatus status) {
    return require_connected & (status != HandshakeStatus::connected);
}

bool should_adopt_supported_client_version(EndpointRole role, std::uint32_t packet_version,
                                           std::uint32_t current_version) {
    return (role == EndpointRole::client) & is_supported_quic_version(packet_version) &
           (packet_version != current_version);
}

std::optional<QuicCoreTimePoint>
earliest_of(std::initializer_list<std::optional<QuicCoreTimePoint>> deadlines) {
    std::optional<QuicCoreTimePoint> earliest;
    for (const auto &deadline : deadlines) {
        if (!deadline.has_value()) {
            continue;
        }

        if (!earliest.has_value() || *deadline < *earliest) {
            earliest = deadline;
        }
    }

    return earliest;
}

std::chrono::milliseconds decode_ack_delay(const AckFrame &ack, std::uint64_t ack_delay_exponent) {
    if (ack_delay_exponent >= std::numeric_limits<std::uint64_t>::digits) {
        return std::chrono::milliseconds(0);
    }

    const auto max_microseconds =
        static_cast<std::uint64_t>(std::numeric_limits<std::chrono::microseconds::rep>::max()) >>
        ack_delay_exponent;
    const auto bounded_ack_delay = std::min<std::uint64_t>(ack.ack_delay, max_microseconds);
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::microseconds(bounded_ack_delay << ack_delay_exponent));
}

std::size_t stream_fragment_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.bytes.size();
    }

    return total;
}

std::vector<StreamFrameView>
make_stream_frame_views(std::span<const StreamFrameSendFragment> fragments) {
    std::vector<StreamFrameView> views;
    views.reserve(fragments.size());
    for (const auto &fragment : fragments) {
        views.push_back(StreamFrameView{
            .fin = fragment.fin,
            .stream_id = fragment.stream_id,
            .offset = fragment.offset,
            .storage = fragment.bytes.storage(),
            .begin = fragment.bytes.begin_offset(),
            .end = fragment.bytes.end_offset(),
        });
    }

    return views;
}

void append_stream_fragments_to_frames(std::vector<Frame> &frames,
                                       std::span<const StreamFrameSendFragment> fragments) {
    for (const auto &fragment : fragments) {
        frames.emplace_back(StreamFrame{
            .fin = fragment.fin,
            .has_offset = true,
            .has_length = true,
            .stream_id = fragment.stream_id,
            .offset = fragment.offset,
            .stream_data = fragment.bytes.to_vector(),
        });
    }
}

ProtectedPacket make_application_protected_packet(
    bool use_zero_rtt_packet_protection, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    bool one_rtt_key_phase, std::uint8_t packet_number_length, std::uint64_t packet_number,
    std::vector<Frame> frames, std::span<const StreamFrameSendFragment> stream_fragments) {
    if (use_zero_rtt_packet_protection) {
        append_stream_fragments_to_frames(frames, stream_fragments);
        return ProtectedZeroRttPacket{
            .version = version,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
            .packet_number_length = packet_number_length,
            .packet_number = packet_number,
            .frames = std::move(frames),
        };
    }

    return ProtectedOneRttPacket{
        .key_phase = one_rtt_key_phase,
        .destination_connection_id = destination_connection_id,
        .packet_number_length = packet_number_length,
        .packet_number = packet_number,
        .frames = std::move(frames),
        .stream_frame_views = make_stream_frame_views(stream_fragments),
    };
}

CodecResult<std::vector<std::byte>> serialize_locally_validated_transport_parameters(
    EndpointRole local_role, const TransportParameters &parameters,
    const TransportParametersValidationContext &validation_context) {
    const auto validation =
        validate_peer_transport_parameters(local_role, parameters, validation_context);
    if (!validation.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(validation.error().code,
                                                            validation.error().offset);
    }

    return serialize_transport_parameters(parameters);
}

bool max_data_frame_matches(const std::optional<MaxDataFrame> &candidate,
                            const MaxDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool data_blocked_frame_matches(const std::optional<DataBlockedFrame> &candidate,
                                const DataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool reset_stream_frame_matches(const std::optional<ResetStreamFrame> &candidate,
                                const ResetStreamFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code,
                    candidate->final_size) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code, frame.final_size);
}

bool stop_sending_frame_matches(const std::optional<StopSendingFrame> &candidate,
                                const StopSendingFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code);
}

bool max_stream_data_frame_matches(const std::optional<MaxStreamDataFrame> &candidate,
                                   const MaxStreamDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool max_streams_frame_matches(const std::optional<MaxStreamsFrame> &candidate,
                               const MaxStreamsFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_type, candidate->maximum_streams) ==
           std::tie(frame.stream_type, frame.maximum_streams);
}

bool stream_data_blocked_frame_matches(const std::optional<StreamDataBlockedFrame> &candidate,
                                       const StreamDataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool should_refresh_receive_window(std::uint64_t delivered_bytes, std::uint64_t advertised_limit,
                                   std::uint64_t window, bool force) {
    if (window == 0 || advertised_limit < delivered_bytes) {
        return false;
    }

    if (force) {
        return true;
    }

    const auto remaining = advertised_limit - delivered_bytes;
    if (window <= 1) {
        return remaining == 0;
    }

    return remaining < (window / 2);
}

bool packet_space_is_application(const PacketSpaceState &packet_space,
                                 const PacketSpaceState &application_space) {
    return &packet_space == &application_space;
}

bool stream_fin_sendable(const StreamState &stream) {
    if (stream.send_fin_state != StreamSendFinState::pending ||
        !stream.send_final_size.has_value()) {
        return false;
    }

    return *stream.send_final_size <= stream.flow_control.peer_max_stream_data &&
           !stream.send_buffer.has_pending_data();
}

bool stream_receive_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_receive | stream.peer_fin_delivered |
           stream.peer_reset_received;
}

bool stream_send_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_send |
           (stream.send_fin_state == StreamSendFinState::acknowledged) |
           (stream.reset_state == StreamControlFrameState::acknowledged);
}

std::vector<std::uint64_t>
round_robin_stream_order(const std::map<std::uint64_t, StreamState> &streams,
                         std::optional<std::uint64_t> last_stream_id) {
    std::vector<std::uint64_t> order;
    order.reserve(streams.size());
    if (streams.empty()) {
        return order;
    }

    auto append_order = [&](auto begin, auto end) {
        for (auto it = begin; it != end; ++it) {
            order.push_back(it->first);
        }
    };

    if (!last_stream_id.has_value()) {
        append_order(streams.begin(), streams.end());
        return order;
    }

    const auto start = streams.upper_bound(*last_stream_id);
    append_order(start, streams.end());
    append_order(streams.begin(), start);
    return order;
}

std::vector<SentPacketRecord>
ack_eliciting_in_flight_losses(std::span<const SentPacketRecord> packets) {
    std::vector<SentPacketRecord> filtered;
    filtered.reserve(packets.size());
    for (const auto &packet : packets) {
        if (!packet.ack_eliciting || packet.bytes_in_flight == 0) {
            continue;
        }

        filtered.push_back(packet);
    }

    return filtered;
}

QuicCoreTimePoint latest_packet_sent_time(std::span<const SentPacketRecord> packets) {
    return std::max_element(packets.begin(), packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.sent_time < rhs.sent_time;
                            })
        ->sent_time;
}

std::size_t retransmittable_probe_frame_count(const SentPacketRecord &packet) {
    return packet.crypto_ranges.size() + packet.reset_stream_frames.size() +
           packet.stop_sending_frames.size() + packet.max_stream_data_frames.size() +
           packet.max_streams_frames.size() + packet.stream_data_blocked_frames.size() +
           packet.stream_fragments.size() + static_cast<std::size_t>(packet.has_handshake_done) +
           static_cast<std::size_t>(packet.max_data_frame.has_value()) +
           static_cast<std::size_t>(packet.data_blocked_frame.has_value());
}

bool stream_fragment_is_probe_worthy(const StreamState &stream,
                                     const StreamFrameSendFragment &fragment) {
    if (stream.reset_state != StreamControlFrameState::none) {
        return false;
    }

    if (stream.send_buffer.has_outstanding_range(fragment.offset, fragment.bytes.size())) {
        return true;
    }

    const bool missing_fin = !fragment.fin;
    const bool fin_already_acknowledged = stream.send_fin_state == StreamSendFinState::acknowledged;
    if (missing_fin | fin_already_acknowledged) {
        return false;
    }
    const auto fragment_end = fragment.offset + static_cast<std::uint64_t>(fragment.bytes.size());
    return stream.send_final_size == std::optional<std::uint64_t>{fragment_end};
}

std::size_t application_ack_eliciting_frame_count(
    bool include_handshake_done, const std::optional<MaxDataFrame> &max_data_frame,
    std::span<const NewConnectionIdFrame> new_connection_id_frames,
    std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
    bool has_path_response_frame, bool has_path_challenge_frame,
    std::span<const MaxStreamDataFrame> max_stream_data_frames,
    std::span<const MaxStreamsFrame> max_streams_frames,
    std::span<const ResetStreamFrame> reset_stream_frames,
    std::span<const StopSendingFrame> stop_sending_frames,
    const std::optional<DataBlockedFrame> &data_blocked_frame,
    std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
    std::span<const StreamFrameSendFragment> stream_fragments) {
    return new_connection_id_frames.size() + retire_connection_id_frames.size() +
           max_stream_data_frames.size() + max_streams_frames.size() + reset_stream_frames.size() +
           stop_sending_frames.size() + stream_data_blocked_frames.size() +
           stream_fragments.size() + static_cast<std::size_t>(include_handshake_done) +
           static_cast<std::size_t>(has_path_response_frame) +
           static_cast<std::size_t>(has_path_challenge_frame) +
           static_cast<std::size_t>(max_data_frame.has_value()) +
           static_cast<std::size_t>(data_blocked_frame.has_value());
}

bool establishes_persistent_congestion(std::span<const SentPacketRecord> lost_packets,
                                       const RecoveryRttState &rtt,
                                       std::chrono::milliseconds max_ack_delay) {
    if (!rtt.latest_rtt.has_value()) {
        return false;
    }

    const auto [first_loss, last_loss] =
        std::minmax_element(lost_packets.begin(), lost_packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.sent_time < rhs.sent_time;
                            });
    if (last_loss->sent_time <= first_loss->sent_time) {
        return false;
    }

    const auto persistent_congestion_duration =
        (rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) + max_ack_delay) *
        kPersistentCongestionThreshold;
    return last_loss->sent_time - first_loss->sent_time >= persistent_congestion_duration;
}

bool ack_frame_acks_packet(const AckFrame &ack, std::uint64_t packet_number) {
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

void discard_packet_space_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.read_secret = std::nullopt;
    packet_space.write_secret = std::nullopt;
    packet_space.send_crypto = ReliableSendBuffer{};
    packet_space.receive_crypto = ReliableReceiveBuffer{};
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.sent_packets.clear();
    packet_space.declared_lost_packets.clear();
    packet_space.recovery = PacketSpaceRecovery{};
    packet_space.pending_probe_packet = std::nullopt;
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

void reset_packet_space_receive_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

} // namespace

std::uint64_t ConnectionFlowControlState::sendable_bytes(std::uint64_t queued_bytes) const {
    const auto remaining_credit = peer_max_data > highest_sent ? peer_max_data - highest_sent : 0;
    const auto unsent_bytes = queued_bytes > highest_sent ? queued_bytes - highest_sent : 0;
    return std::min(remaining_credit, unsent_bytes);
}

bool ConnectionFlowControlState::should_send_data_blocked(std::uint64_t queued_bytes) const {
    return queued_bytes > peer_max_data;
}

void ConnectionFlowControlState::note_peer_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= peer_max_data) {
        return;
    }

    peer_max_data = maximum_data;
}

void ConnectionFlowControlState::queue_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= advertised_max_data) {
        return;
    }

    advertised_max_data = maximum_data;
    pending_max_data_frame = MaxDataFrame{
        .maximum_data = maximum_data,
    };
    max_data_state = StreamControlFrameState::pending;
}

std::optional<MaxDataFrame> ConnectionFlowControlState::take_max_data_frame() {
    if (max_data_state != StreamControlFrameState::pending || !pending_max_data_frame.has_value()) {
        return std::nullopt;
    }

    max_data_state = StreamControlFrameState::sent;
    return pending_max_data_frame;
}

void ConnectionFlowControlState::acknowledge_max_data_frame(const MaxDataFrame &frame) {
    if (max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_max_data_frame_lost(const MaxDataFrame &frame) {
    if (max_data_state != StreamControlFrameState::acknowledged &&
        max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::pending;
    }
}

void ConnectionFlowControlState::queue_data_blocked(std::uint64_t maximum_data) {
    if (pending_data_blocked_frame.has_value() &&
        pending_data_blocked_frame->maximum_data == maximum_data &&
        data_blocked_state != StreamControlFrameState::none) {
        return;
    }

    pending_data_blocked_frame = DataBlockedFrame{
        .maximum_data = maximum_data,
    };
    data_blocked_state = StreamControlFrameState::pending;
}

std::optional<DataBlockedFrame> ConnectionFlowControlState::take_data_blocked_frame() {
    if (data_blocked_state != StreamControlFrameState::pending ||
        !pending_data_blocked_frame.has_value()) {
        return std::nullopt;
    }

    data_blocked_state = StreamControlFrameState::sent;
    return pending_data_blocked_frame;
}

void ConnectionFlowControlState::acknowledge_data_blocked_frame(const DataBlockedFrame &frame) {
    if (data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_data_blocked_frame_lost(const DataBlockedFrame &frame) {
    if (data_blocked_state != StreamControlFrameState::acknowledged &&
        data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::pending;
    }
}

void LocalStreamLimitState::initialize(PeerStreamOpenLimits limits) {
    advertised_max_streams_bidi = limits.bidirectional;
    advertised_max_streams_uni = limits.unidirectional;
    pending_max_streams_bidi_frame = std::nullopt;
    max_streams_bidi_state = StreamControlFrameState::none;
    pending_max_streams_uni_frame = std::nullopt;
    max_streams_uni_state = StreamControlFrameState::none;
}

void LocalStreamLimitState::queue_max_streams(StreamLimitType stream_type,
                                              std::uint64_t maximum_streams) {
    auto *advertised_limit = &advertised_max_streams_bidi;
    auto *pending_frame = &pending_max_streams_bidi_frame;
    auto *state = &max_streams_bidi_state;
    if (stream_type == StreamLimitType::unidirectional) {
        advertised_limit = &advertised_max_streams_uni;
        pending_frame = &pending_max_streams_uni_frame;
        state = &max_streams_uni_state;
    }

    if (maximum_streams <= *advertised_limit) {
        return;
    }

    *advertised_limit = maximum_streams;
    *pending_frame = MaxStreamsFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams,
    };
    *state = StreamControlFrameState::pending;
}

std::vector<MaxStreamsFrame> LocalStreamLimitState::take_max_streams_frames() {
    std::vector<MaxStreamsFrame> frames;
    if (max_streams_bidi_state == StreamControlFrameState::pending &&
        pending_max_streams_bidi_frame.has_value()) {
        max_streams_bidi_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_bidi_frame);
    }
    if (max_streams_uni_state == StreamControlFrameState::pending &&
        pending_max_streams_uni_frame.has_value()) {
        max_streams_uni_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_uni_frame);
    }

    return frames;
}

StreamControlFrameState *max_streams_state_for(LocalStreamLimitState &state,
                                               StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.max_streams_bidi_state
                                                         : &state.max_streams_uni_state;
}

std::optional<MaxStreamsFrame> *pending_max_streams_frame_for(LocalStreamLimitState &state,
                                                              StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.pending_max_streams_bidi_frame
                                                         : &state.pending_max_streams_uni_frame;
}

void LocalStreamLimitState::acknowledge_max_streams_frame(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::acknowledged;
}

void LocalStreamLimitState::mark_max_streams_frame_lost(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none ||
        *state == StreamControlFrameState::acknowledged) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::pending;
}

QuicConnection::QuicConnection(QuicCoreConfig config)
    : config_(std::move(config)), original_version_(config_.original_version),
      current_version_(config_.initial_version),
      congestion_controller_(std::max(kMaximumDatagramSize, config_.max_outbound_datagram_size)) {
    if (config_.supported_versions.empty()) {
        config_.supported_versions.push_back(current_version_);
    }
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .preferred_address = config_.transport.preferred_address,
    };
    initialize_local_flow_control();
    local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                         .sequence_number = 0,
                                         .connection_id = config_.source_connection_id,
                                         .stateless_reset_token = make_stateless_reset_token(
                                             config_.source_connection_id, /*sequence_number=*/0),
                                     });
    if (config_.transport.preferred_address.has_value()) {
        // RFC 9000 reserves sequence number 1 for the preferred-address CID.
        local_connection_ids_.emplace(
            1,
            LocalConnectionIdRecord{
                .sequence_number = 1,
                .connection_id = config_.transport.preferred_address->connection_id,
                .stateless_reset_token = config_.transport.preferred_address->stateless_reset_token,
            });
        next_local_connection_id_sequence_ = 2;
    }
    peer_address_validated_ = config_.role == EndpointRole::client;
}

QuicConnection::~QuicConnection() = default;

QuicConnection::QuicConnection(QuicConnection &&) noexcept = default;

QuicConnection &QuicConnection::operator=(QuicConnection &&) noexcept = default;

void QuicConnection::start() {
    start(QuicCoreTimePoint{});
}

void QuicConnection::start(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    start_client_if_needed(now);
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                              QuicCoreTimePoint now, QuicPathId path_id,
                                              QuicEcnCodepoint ecn) {
    const auto inbound_datagram_id =
        qlog_session_ != nullptr
            ? std::optional<std::uint32_t>(qlog_session_->next_inbound_datagram_id())
            : std::nullopt;
    process_inbound_datagram(bytes, now, path_id, ecn, inbound_datagram_id,
                             /*replay_trigger=*/false, /*count_inbound_bytes=*/true);
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                              QuicCoreTimePoint now, QuicPathId path_id,
                                              QuicEcnCodepoint ecn,
                                              std::optional<std::uint32_t> inbound_datagram_id,
                                              bool replay_trigger, bool count_inbound_bytes) {
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        return;
    }
    last_inbound_path_id_ = path_id;
    if (!current_send_path_id_.has_value()) {
        current_send_path_id_ = path_id;
        ensure_path_state(path_id).is_current_send_path = true;
    }

    maybe_discard_server_zero_rtt_packet_space(now);

    if (count_inbound_bytes) {
        const auto accounted_inbound_bytes =
            datagram_starts_with_initial_packet(bytes)
                ? std::max(bytes.size(), kMinimumInitialDatagramSize)
                : bytes.size();
        note_inbound_datagram_bytes(accounted_inbound_bytes);
    }

    if (!started_) {
        if (config_.role != EndpointRole::server) {
            mark_failed();
            return;
        }

        const auto initial_destination_connection_id =
            peek_client_initial_destination_connection_id(bytes);
        if (!initial_destination_connection_id.has_value()) {
            log_codec_failure("peek_client_initial_destination_connection_id",
                              initial_destination_connection_id.error());
            mark_failed();
            return;
        }

        start_server_if_needed(initial_destination_connection_id.value(), now,
                               read_u32_be(bytes.subspan(1, 4)));
    }

    auto synced = sync_tls_state();
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        mark_failed();
        return;
    }

    const auto packet_requires_connected_state = [](std::span<const std::byte> packet_bytes) {
        return (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
    };
    const auto defer_packet =
        [&](std::span<const std::byte> packet_bytes, QuicPathId deferred_path_id,
            std::optional<std::uint32_t> deferred_datagram_id, QuicEcnCodepoint deferred_ecn) {
            auto deferred = DeferredProtectedDatagram{
                std::vector<std::byte>(packet_bytes.begin(), packet_bytes.end()),
                deferred_path_id,
                deferred_datagram_id,
                deferred_ecn,
            };
            if (std::find_if(deferred_protected_packets_.begin(), deferred_protected_packets_.end(),
                             [&](const DeferredProtectedDatagram &candidate) {
                                 return candidate.path_id == deferred.path_id &&
                                        candidate.bytes == deferred.bytes;
                             }) != deferred_protected_packets_.end()) {
                return;
            }
            if (deferred_protected_packets_.size() >= kMaximumDeferredProtectedPackets) {
                deferred_protected_packets_.erase(deferred_protected_packets_.begin());
            }
            deferred_protected_packets_.push_back(std::move(deferred));
        };
    std::size_t offset = 0;
    bool processed_any_packet = false;
    const auto make_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> CodecResult<DeserializeProtectionContext> {
        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.read_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(
                handshake_ready.error().code, handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.read_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(
                zero_rtt_ready.error().code, zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                      one_rtt_ready.error().offset);
        }

        return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.read_secret,
            .zero_rtt_secret = zero_rtt_space_.read_secret,
            .one_rtt_secret = application_secret,
            .one_rtt_key_phase = application_key_phase,
            .largest_authenticated_initial_packet_number =
                initial_space_.largest_authenticated_packet_number,
            .largest_authenticated_handshake_packet_number =
                handshake_space_.largest_authenticated_packet_number,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
        });
    };
    const auto process_packet_bytes = [&](std::span<const std::byte> packet_bytes, bool allow_defer,
                                          QuicPathId packet_path_id, QuicEcnCodepoint packet_ecn,
                                          std::optional<std::uint32_t> datagram_id,
                                          bool packet_replay_trigger) -> bool {
        const auto current_context =
            make_deserialize_context(application_space_.read_secret, application_read_key_phase_);
        if (!current_context.has_value()) {
            log_codec_failure("expand_traffic_secret", current_context.error());
            mark_failed();
            return false;
        }

        auto packets = deserialize_protected_datagram(packet_bytes, current_context.value());
        const bool short_header_packet =
            (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
        bool used_previous_application_read_secret = false;
        bool processed_current_read_phase_packet = false;
        if (!packets.has_value() && short_header_packet &&
            previous_application_read_secret_.has_value()) {
            const auto previous_context = make_deserialize_context(
                previous_application_read_secret_, previous_application_read_key_phase_);
            if (!previous_context.has_value()) {
                log_codec_failure("expand_traffic_secret", previous_context.error());
                mark_failed();
                return false;
            }

            auto previous_packets =
                deserialize_protected_datagram(packet_bytes, previous_context.value());
            if (previous_packets.has_value()) {
                packets = std::move(previous_packets);
                used_previous_application_read_secret = true;
            }
        }
        if (!packets.has_value()) {
            const bool retry_with_next_key_phase =
                (packets.error().code == CodecErrorCode::invalid_packet_protection_state) &
                short_header_packet & application_space_.read_secret.has_value() &
                application_space_.write_secret.has_value();
            if (retry_with_next_key_phase) {
                const auto next_read_secret =
                    derive_next_traffic_secret(*application_space_.read_secret).value();
                const auto next_context =
                    make_deserialize_context(next_read_secret, !application_read_key_phase_);
                if (!next_context.has_value()) {
                    log_codec_failure("expand_traffic_secret", next_context.error());
                    mark_failed();
                    return false;
                }

                auto updated_packets =
                    deserialize_protected_datagram(packet_bytes, next_context.value());
                if (updated_packets.has_value()) {
                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        mark_failed();
                        return false;
                    }

                    application_space_.read_secret = next_read_secret;
                    application_space_.write_secret = next_write_secret.value();
                    application_read_key_phase_ = !application_read_key_phase_;
                    application_write_key_phase_ = !application_write_key_phase_;
                    current_write_phase_first_packet_number_ = std::nullopt;
                    if (!local_key_update_initiated_) {
                        local_key_update_requested_ = false;
                    }
                    packets = std::move(updated_packets);
                }
            }
        }
        if (!packets.has_value()) {
            const bool should_ignore_packet_for_discarded_space =
                (packets.error().code == CodecErrorCode::missing_crypto_context) &&
                packet_targets_discarded_long_header_space(packet_bytes);
            if (should_ignore_packet_for_discarded_space) {
                return true;
            }
            const bool should_defer_packet =
                allow_defer & (packets.error().code == CodecErrorCode::missing_crypto_context) &
                packet_is_bufferable(packet_bytes);
            if (should_defer_packet) {
                // Later packets in the same datagram can depend on keys unlocked by an earlier
                // packet, so buffer them even after partial progress.
                defer_packet(packet_bytes, packet_path_id, datagram_id, packet_ecn);
                return true;
            }
            const bool should_discard_short_header_packet =
                short_header_packet &
                is_discardable_short_header_packet_error(packets.error().code);
            const bool should_discard_packet =
                should_discard_short_header_packet |
                coquic::quic::should_discard_corrupted_long_header_packet(short_header_packet,
                                                                          packets.error().code);
            if (should_discard_packet) {
                const bool should_trace_discarded_short_header_packet =
                    short_header_packet &
                    packet_trace_matches_connection(config_.source_connection_id);
                if (should_trace_discarded_short_header_packet) {
                    std::cerr << "quic-packet-trace discard scid="
                              << format_connection_id_hex(config_.source_connection_id)
                              << " size=" << packet_bytes.size()
                              << " code=" << static_cast<int>(packets.error().code) << '\n';
                }
                return true;
            }
            if (processed_any_packet) {
                return true;
            }
            log_codec_failure("deserialize_protected_datagram", packets.error());
            mark_failed();
            return false;
        }

        for (const auto &packet : packets.value()) {
            const auto *protected_one_rtt_packet = std::get_if<ProtectedOneRttPacket>(&packet);
            const bool protected_one_rtt_requires_defer =
                protected_one_rtt_packet != nullptr
                    ? should_defer_protected_one_rtt_packet(*protected_one_rtt_packet, status_)
                    : false;
            const bool defer_protected_app_packet = allow_defer & protected_one_rtt_requires_defer;
            if (defer_protected_app_packet) {
                defer_packet(packet_bytes, packet_path_id, datagram_id, packet_ecn);
                return true;
            }

            if (qlog_session_ != nullptr && datagram_id.has_value()) {
                static_cast<void>(qlog_session_->write_event(
                    now, "quic:packet_received",
                    qlog::serialize_packet_snapshot(make_qlog_packet_snapshot(
                        packet, qlog::PacketSnapshotContext{
                                    .raw_length = packet_bytes.size(),
                                    .datagram_id = *datagram_id,
                                    .trigger = packet_replay_trigger
                                                   ? std::optional<std::string>("keys_available")
                                                   : std::nullopt,
                                }))));
            }
            const auto processed = process_inbound_packet(packet, now, packet_ecn);
            if (!processed.has_value()) {
                if (protected_one_rtt_packet != nullptr &&
                    packet_trace_matches_connection(config_.source_connection_id)) {
                    std::cerr << "quic-packet-trace fail scid="
                              << format_connection_id_hex(config_.source_connection_id)
                              << " pn=" << protected_one_rtt_packet->packet_number
                              << " code=" << static_cast<int>(processed.error().code) << '\n';
                }
                if (processed_any_packet) {
                    return true;
                }
                log_codec_failure("process_inbound_packet", processed.error());
                mark_failed();
                return false;
            }
            if (protected_one_rtt_packet != nullptr && !used_previous_application_read_secret) {
                processed_current_read_phase_packet = true;
            }

            synced = sync_tls_state();
            if (!synced.has_value()) {
                log_codec_failure("sync_tls_state", synced.error());
                mark_failed();
                return false;
            }
        }

        if (processed_current_read_phase_packet) {
            previous_application_read_secret_ = std::nullopt;
        }

        return true;
    };
    const auto replay_deferred_packets = [&]() -> bool {
        if (deferred_protected_packets_.empty()) {
            return true;
        }

        auto deferred_packets = std::move(deferred_protected_packets_);
        deferred_protected_packets_.clear();
        for (const auto &deferred_packet : deferred_packets) {
            if (packet_requires_connected_state(deferred_packet.bytes) &&
                status_ != HandshakeStatus::connected) {
                defer_packet(deferred_packet.bytes, deferred_packet.path_id,
                             deferred_packet.datagram_id, deferred_packet.ecn);
                continue;
            }
            if (!process_packet_bytes(deferred_packet.bytes, /*allow_defer=*/true,
                                      deferred_packet.path_id, deferred_packet.ecn,
                                      deferred_packet.datagram_id,
                                      /*packet_replay_trigger=*/true)) {
                return false;
            }
        }

        return true;
    };
    if (!replay_deferred_packets()) {
        return;
    }
    while (offset < bytes.size()) {
        const auto packet_length = peek_next_packet_length(bytes.subspan(offset));
        if (!packet_length.has_value()) {
            if (packet_length.error().code == CodecErrorCode::invalid_fixed_bit) {
                const auto discardable_length =
                    peek_discardable_long_header_packet_length(bytes.subspan(offset));
                if (discardable_length.has_value()) {
                    offset += discardable_length.value();
                    continue;
                }
            }
            if (is_discardable_packet_length_error(packet_length.error().code)) {
                return;
            }
            if (processed_any_packet) {
                return;
            }
            log_codec_failure("peek_next_packet_length", packet_length.error());
            mark_failed();
            return;
        }

        const auto packet_bytes = bytes.subspan(offset, packet_length.value());
        if (!process_packet_bytes(packet_bytes, /*allow_defer=*/true, path_id, ecn,
                                  inbound_datagram_id, replay_trigger)) {
            return;
        }
        processed_any_packet = true;
        if (!replay_deferred_packets()) {
            return;
        }

        offset += packet_length.value();
    }
}

StreamStateResult<bool> QuicConnection::queue_stream_send(std::uint64_t stream_id,
                                                          std::span<const std::byte> bytes,
                                                          bool fin) {
    if (status_ == HandshakeStatus::failed || (bytes.empty() && !fin)) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_send(fin);
    if (!validated.has_value()) {
        return validated;
    }

    if (!bytes.empty()) {
        stream->send_buffer.append(bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(bytes.size());
    }
    if (fin) {
        stream->send_final_size = stream->send_flow_control_committed;
        stream->send_fin_state = StreamSendFinState::pending;
    }

    const bool should_emit_zero_rtt_attempt =
        (config_.role == EndpointRole::client) & config_.zero_rtt.attempt &
        decoded_resumption_state_.has_value() & zero_rtt_space_.write_secret.has_value() &
        (status_ != HandshakeStatus::connected) & !zero_rtt_attempted_event_emitted_;
    if (should_emit_zero_rtt_attempt) {
        pending_zero_rtt_status_event_ =
            QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::attempted};
        zero_rtt_attempted_event_emitted_ = true;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stream_reset(LocalResetCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(command.stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(command.stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            command.stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_reset(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stop_sending(LocalStopSendingCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_existing_receive_stream(command.stream_id);
    if (!stream_state.has_value()) {
        return StreamStateResult<bool>::failure(stream_state.error().code,
                                                stream_state.error().stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_stop_sending(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }

    return StreamStateResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::request_connection_migration(QuicPathId path_id,
                                                               QuicMigrationRequestReason reason) {
    const bool peer_disables_active_migration =
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->disable_active_migration;
    if (reason == QuicMigrationRequestReason::active && peer_disables_active_migration) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }

    maybe_switch_to_path(path_id, /*initiated_locally=*/true);
    if (reason == QuicMigrationRequestReason::preferred_address &&
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->preferred_address.has_value()) {
        const auto &preferred_address = peer_transport_parameters_->preferred_address.value();
        ensure_path_state(path_id).destination_connection_id_override =
            preferred_address.connection_id;
    }
    return CodecResult<bool>::success(true);
}

StreamStateResult<bool>
QuicConnection::queue_application_close(LocalApplicationCloseCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    pending_application_close_ = ApplicationConnectionCloseFrame{
        .error_code = command.application_error_code,
        .reason =
            ConnectionCloseReason{
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte *>(command.reason_phrase.data()),
                    reinterpret_cast<const std::byte *>(command.reason_phrase.data()) +
                        command.reason_phrase.size()),
            },
    };
    local_application_close_sent_ = false;
    return StreamStateResult<bool>::success(true);
}

void QuicConnection::request_key_update() {
    local_key_update_requested_ = true;
    if (!local_key_update_initiated_) {
        current_write_phase_first_packet_number_ = application_space_.next_send_packet_number;
    }
}

std::vector<std::byte> QuicConnection::drain_outbound_datagram(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return {};
    }
    last_drained_path_id_.reset();
    last_drained_ecn_codepoint_ = QuicEcnCodepoint::not_ect;

    if (send_burst_resume_deadline_.has_value() && now >= *send_burst_resume_deadline_) {
        send_burst_resume_deadline_.reset();
        send_burst_reference_time_.reset();
        send_burst_datagrams_sent_ = 0;
    }

    const auto has_urgent_application_control_send = [&]() {
        if (application_space_.pending_probe_packet.has_value()) {
            return true;
        }
        return std::any_of(paths_.begin(), paths_.end(), [](const auto &entry) {
            return entry.second.pending_response.has_value() || entry.second.challenge_pending;
        });
    };
    const auto should_limit_stream_send_burst = [&]() {
        return status_ == HandshakeStatus::connected &&
               has_pending_fresh_application_stream_send() &&
               !has_urgent_application_control_send();
    };

    if (send_burst_resume_deadline_.has_value() && now < *send_burst_resume_deadline_ &&
        should_limit_stream_send_burst()) {
        return {};
    }
    if (!send_burst_reference_time_.has_value() || *send_burst_reference_time_ != now) {
        send_burst_reference_time_ = now;
        send_burst_datagrams_sent_ = 0;
    }
    if (should_limit_stream_send_burst() &&
        send_burst_datagrams_sent_ >= kMaximumImmediateApplicationDatagramsPerBurst) {
        send_burst_resume_deadline_ = now + kApplicationBurstResumeDelay;
        return {};
    }

    const auto synced = sync_tls_state();
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        mark_failed();
        return {};
    }

    if (!deferred_protected_packets_.empty()) {
        replay_deferred_protected_packets(now);
        if (status_ == HandshakeStatus::failed) {
            return {};
        }
    }

    auto datagram = flush_outbound_datagram(now);
    if (datagram.empty()) {
        if (!has_pending_fresh_application_stream_send()) {
            send_burst_resume_deadline_.reset();
            send_burst_reference_time_.reset();
            send_burst_datagrams_sent_ = 0;
        }
        return {};
    }

    if (should_limit_stream_send_burst()) {
        ++send_burst_datagrams_sent_;
        if (send_burst_datagrams_sent_ >= kMaximumImmediateApplicationDatagramsPerBurst &&
            has_pending_fresh_application_stream_send()) {
            send_burst_resume_deadline_ = now + kApplicationBurstResumeDelay;
        }
    } else {
        send_burst_resume_deadline_.reset();
        send_burst_reference_time_.reset();
        send_burst_datagrams_sent_ = 0;
    }

    return datagram;
}

void QuicConnection::on_timeout(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    maybe_discard_server_zero_rtt_packet_space(now);

    if (current_send_path_id_.has_value() &&
        path_validation_timed_out(*current_send_path_id_, now) &&
        last_validated_path_id_.has_value()) {
        auto &current = paths_.at(*current_send_path_id_);
        current.is_current_send_path = false;
        current.challenge_pending = false;
        current.validation_initiated_locally = false;
        current.outstanding_challenge.reset();
        current.validation_deadline.reset();
        previous_path_id_ = current_send_path_id_;
        current_send_path_id_ = last_validated_path_id_;
        ensure_path_state(*last_validated_path_id_).is_current_send_path = true;
    }

    if (const auto deadline = loss_deadline(); deadline.has_value() && now >= *deadline) {
        detect_lost_packets(now);
    }

    const auto initial_ack_deadline =
        initial_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= initial_ack_deadline) {
        initial_space_.force_ack_send = true;
    }
    const auto handshake_ack_deadline =
        handshake_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= handshake_ack_deadline) {
        handshake_space_.force_ack_send = true;
    }
    const auto application_ack_deadline =
        application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= application_ack_deadline) {
        application_space_.force_ack_send = true;
    }

    if (const auto deadline = pto_deadline(); deadline.has_value() && now >= *deadline) {
        arm_pto_probe(now);
        if (packet_trace_matches_connection(config_.source_connection_id)) {
            const auto in_flight_ack_eliciting_count = [](const PacketSpaceState &packet_space) {
                return std::count_if(packet_space.sent_packets.begin(),
                                     packet_space.sent_packets.end(), [](const auto &entry) {
                                         return entry.second.ack_eliciting & entry.second.in_flight;
                                     });
            };
            std::cerr << "quic-packet-trace timeout scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " status=" << static_cast<int>(status_)
                      << " confirmed=" << static_cast<int>(handshake_confirmed_)
                      << " initial_if=" << in_flight_ack_eliciting_count(initial_space_)
                      << " handshake_if=" << in_flight_ack_eliciting_count(handshake_space_)
                      << " application_if=" << in_flight_ack_eliciting_count(application_space_)
                      << " initial_probe="
                      << static_cast<int>(initial_space_.pending_probe_packet.has_value())
                      << " handshake_probe="
                      << static_cast<int>(handshake_space_.pending_probe_packet.has_value())
                      << " application_probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << " pto_count=" << pto_count_ << '\n';
        }
    }
}

std::optional<QuicCoreReceiveStreamData> QuicConnection::take_received_stream_data() {
    if (status_ == HandshakeStatus::failed || pending_stream_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_stream_receive_effects_.front());
    pending_stream_receive_effects_.erase(pending_stream_receive_effects_.begin());
    maybe_retire_stream(next.stream_id);
    return next;
}

std::optional<QuicCorePeerResetStream> QuicConnection::take_peer_reset_stream() {
    if (status_ == HandshakeStatus::failed || pending_peer_reset_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_reset_effects_.front();
    pending_peer_reset_effects_.erase(pending_peer_reset_effects_.begin());
    return next;
}

std::optional<QuicCorePeerStopSending> QuicConnection::take_peer_stop_sending() {
    if (status_ == HandshakeStatus::failed || pending_peer_stop_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_stop_effects_.front();
    pending_peer_stop_effects_.erase(pending_peer_stop_effects_.begin());
    return next;
}

std::optional<QuicCoreStateChange> QuicConnection::take_state_change() {
    if (pending_state_changes_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_state_changes_.front();
    pending_state_changes_.erase(pending_state_changes_.begin());
    return next;
}

std::optional<QuicCorePeerPreferredAddressAvailable>
QuicConnection::take_peer_preferred_address_available() {
    auto next = pending_preferred_address_effect_;
    pending_preferred_address_effect_.reset();
    return next;
}

std::optional<QuicCoreResumptionStateAvailable> QuicConnection::take_resumption_state_available() {
    auto next = std::move(pending_resumption_state_effect_);
    pending_resumption_state_effect_.reset();
    return next;
}

std::optional<QuicCoreZeroRttStatusEvent> QuicConnection::take_zero_rtt_status_event() {
    auto next = pending_zero_rtt_status_event_;
    pending_zero_rtt_status_event_.reset();
    return next;
}

std::optional<QuicConnectionTerminalState> QuicConnection::take_terminal_state() {
    if (!pending_terminal_state_.has_value()) {
        return std::nullopt;
    }

    const auto next = pending_terminal_state_;
    pending_terminal_state_.reset();
    return next;
}

std::optional<QuicPathId> QuicConnection::last_drained_path_id() const {
    return last_drained_path_id_;
}

QuicEcnCodepoint QuicConnection::last_drained_ecn_codepoint() const {
    return last_drained_ecn_codepoint_;
}

std::optional<QuicCoreTimePoint> QuicConnection::next_wakeup() const {
    if (status_ == HandshakeStatus::failed) {
        return std::nullopt;
    }

    return earliest_of({loss_deadline(), pto_deadline(), ack_deadline(),
                        send_burst_resume_deadline_, zero_rtt_discard_deadline()});
}

std::vector<ConnectionId> QuicConnection::active_local_connection_ids() const {
    std::vector<ConnectionId> connection_ids;
    connection_ids.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        connection_ids.push_back(record.connection_id);
    }
    return connection_ids;
}

std::optional<QuicCoreTimePoint> QuicConnection::loss_deadline() const {
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto packet_space_loss_deadline =
        [&](const PacketSpaceState &packet_space) -> std::optional<QuicCoreTimePoint> {
        const auto tracked_packet = earliest_loss_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return std::nullopt;
        }

        return compute_time_threshold_deadline(shared_rtt_state, tracked_packet->sent_time);
    };

    return earliest_of({packet_space_loss_deadline(initial_space_),
                        packet_space_loss_deadline(handshake_space_),
                        packet_space_loss_deadline(application_space_)});
}

std::optional<QuicCoreTimePoint> QuicConnection::pto_deadline() const {
    const auto application_max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState &packet_space) {
        if (config_.role != EndpointRole::client || handshake_confirmed_ ||
            &packet_space != &initial_space_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    const auto packet_space_pto_deadline =
        [&](const PacketSpaceState &packet_space,
            std::chrono::milliseconds max_ack_delay) -> std::optional<QuicCoreTimePoint> {
        const auto tracked_packet = latest_in_flight_ack_eliciting_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return std::nullopt;
        }

        return compute_pto_deadline(shared_rtt_state, max_ack_delay, tracked_packet->sent_time,
                                    effective_pto_count(packet_space));
    };

    const auto regular_deadline =
        earliest_of({packet_space_pto_deadline(initial_space_, std::chrono::milliseconds(0)),
                     packet_space_pto_deadline(handshake_space_, std::chrono::milliseconds(0)),
                     allow_application_pto
                         ? packet_space_pto_deadline(application_space_, application_max_ack_delay)
                         : std::nullopt});
    if (regular_deadline.has_value()) {
        return regular_deadline;
    }

    const auto client_handshake_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = (config_.role == EndpointRole::client) &
                              (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                              last_peer_activity_time_.has_value() &
                              !has_in_flight_ack_eliciting_packet(initial_space_) &
                              !has_in_flight_ack_eliciting_packet(handshake_space_) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    const bool client_handshake_keepalive_space_available =
        client_handshake_keepalive_reference_time.has_value() &&
        (!initial_packet_space_discarded_ || handshake_space_.write_secret.has_value());
    if (!client_handshake_keepalive_space_available) {
        const auto client_receive_keepalive_reference_time =
            [this]() -> std::optional<QuicCoreTimePoint> {
            const bool has_receive_interest = std::ranges::any_of(
                streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
            const bool eligible = (config_.role == EndpointRole::client) & handshake_confirmed_ &
                                  last_peer_activity_time_.has_value() & has_receive_interest &
                                  !has_in_flight_ack_eliciting_packet(initial_space_) &
                                  !has_in_flight_ack_eliciting_packet(handshake_space_) &
                                  !has_in_flight_ack_eliciting_packet(application_space_);
            if (!eligible) {
                return std::nullopt;
            }

            return last_peer_activity_time_;
        }();
        if (!client_receive_keepalive_reference_time.has_value()) {
            return std::nullopt;
        }

        return compute_pto_deadline(shared_rtt_state, application_max_ack_delay,
                                    *client_receive_keepalive_reference_time, pto_count_);
    }

    return compute_pto_deadline(shared_rtt_state, std::chrono::milliseconds(0),
                                *client_handshake_keepalive_reference_time,
                                std::min(pto_count_, 2u));
}

std::optional<QuicCoreTimePoint> QuicConnection::ack_deadline() const {
    return earliest_of({initial_space_.pending_ack_deadline, handshake_space_.pending_ack_deadline,
                        application_space_.pending_ack_deadline});
}

void QuicConnection::detect_lost_packets(QuicCoreTimePoint now) {
    detect_lost_packets(initial_space_, now);
    detect_lost_packets(handshake_space_, now);
    detect_lost_packets(application_space_, now);
}

void QuicConnection::detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now) {
    const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
    if (!largest_acked.has_value()) {
        return;
    }

    const auto &shared_rtt_state = shared_recovery_rtt_state();

    std::vector<SentPacketRecord> lost_packets;
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (!packet.in_flight || packet.packet_number >= *largest_acked) {
            continue;
        }
        if (!is_time_threshold_lost(shared_rtt_state, packet.sent_time, now)) {
            continue;
        }

        lost_packets.push_back(packet);
    }

    if (lost_packets.empty()) {
        return;
    }

    for (const auto &packet : lost_packets) {
        emit_qlog_packet_lost(packet, "time_threshold", now);
        mark_lost_packet(packet_space, packet);
    }
    const auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(lost_packets);
    if (packet_space_is_application(packet_space, application_space_) &&
        !ack_eliciting_lost_packets.empty()) {
        const auto application_max_ack_delay = std::chrono::milliseconds(
            peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                                   : TransportParameters{}.max_ack_delay);
        congestion_controller_.on_loss_event(now,
                                             latest_packet_sent_time(ack_eliciting_lost_packets));
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              application_max_ack_delay)) {
            congestion_controller_.on_persistent_congestion();
        }
    }
    maybe_emit_qlog_recovery_metrics(now);
}

void QuicConnection::arm_pto_probe(QuicCoreTimePoint now) {
    PacketSpaceState *selected_packet_space = nullptr;
    std::optional<QuicCoreTimePoint> selected_deadline;
    const auto application_max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState &packet_space) {
        if (config_.role != EndpointRole::client || handshake_confirmed_ ||
            &packet_space != &initial_space_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    const auto client_handshake_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = (config_.role == EndpointRole::client) &
                              (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                              last_peer_activity_time_.has_value() &
                              !has_in_flight_ack_eliciting_packet(initial_space_) &
                              !has_in_flight_ack_eliciting_packet(handshake_space_) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    const bool client_handshake_keepalive_eligible =
        client_handshake_keepalive_reference_time.has_value() &&
        (!initial_packet_space_discarded_ || handshake_space_.write_secret.has_value());
    PacketSpaceState *client_handshake_keepalive_space =
        !client_handshake_keepalive_eligible
            ? nullptr
            : (initial_packet_space_discarded_ ? &handshake_space_ : &initial_space_);
    auto client_handshake_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_handshake_keepalive_eligible) {
        client_handshake_keepalive_deadline = compute_pto_deadline(
            shared_rtt_state, std::chrono::milliseconds(0),
            *client_handshake_keepalive_reference_time, std::min(pto_count_, 2u));
    }
    const bool client_handshake_keepalive_due = client_handshake_keepalive_deadline.has_value() &&
                                                now >= *client_handshake_keepalive_deadline;
    const auto client_receive_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool has_receive_interest = std::ranges::any_of(
            streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
        const bool eligible = (config_.role == EndpointRole::client) & handshake_confirmed_ &
                              last_peer_activity_time_.has_value() & has_receive_interest &
                              !has_in_flight_ack_eliciting_packet(initial_space_) &
                              !has_in_flight_ack_eliciting_packet(handshake_space_) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        return last_peer_activity_time_;
    }();
    const bool client_receive_keepalive_eligible =
        client_receive_keepalive_reference_time.has_value();
    PacketSpaceState *client_receive_keepalive_space =
        client_receive_keepalive_eligible ? &application_space_ : nullptr;
    auto client_receive_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_receive_keepalive_reference_time.has_value()) {
        client_receive_keepalive_deadline =
            compute_pto_deadline(shared_rtt_state, application_max_ack_delay,
                                 *client_receive_keepalive_reference_time, pto_count_);
    }
    const bool client_receive_keepalive_due =
        client_receive_keepalive_deadline.has_value() && now >= *client_receive_keepalive_deadline;
    const auto consider_packet_space = [&](PacketSpaceState &packet_space,
                                           std::chrono::milliseconds max_ack_delay) {
        std::optional<QuicCoreTimePoint> packet_space_deadline;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            const bool skip_packet = !packet.ack_eliciting | !packet.in_flight;
            if (skip_packet) {
                continue;
            }

            const auto candidate =
                compute_pto_deadline(shared_rtt_state, max_ack_delay, packet.sent_time,
                                     effective_pto_count(packet_space));
            const auto current_packet_space_deadline = packet_space_deadline.value_or(candidate);
            if (!packet_space_deadline.has_value() | (candidate > current_packet_space_deadline)) {
                packet_space_deadline = candidate;
            }
        }

        const bool deadline_due =
            packet_space_deadline.has_value() && now >= *packet_space_deadline;
        if (!deadline_due) {
            return;
        }

        const auto current_selected_deadline = selected_deadline.value_or(*packet_space_deadline);
        if (!selected_deadline.has_value() | (*packet_space_deadline < current_selected_deadline)) {
            selected_deadline = packet_space_deadline;
            selected_packet_space = &packet_space;
        }
    };

    consider_packet_space(initial_space_, std::chrono::milliseconds(0));
    consider_packet_space(handshake_space_, std::chrono::milliseconds(0));
    if (allow_application_pto) {
        consider_packet_space(application_space_, application_max_ack_delay);
    }

    if (selected_packet_space == nullptr) {
        if (!client_handshake_keepalive_due && !client_receive_keepalive_due) {
            return;
        }
        if (client_handshake_keepalive_due) {
            selected_packet_space = client_handshake_keepalive_space;
            selected_deadline = client_handshake_keepalive_deadline;
        } else {
            selected_packet_space = client_receive_keepalive_space;
            selected_deadline = client_receive_keepalive_deadline;
        }
    }

    ++pto_count_;
    remaining_pto_probe_datagrams_ = 0;
    bool armed_pto_probe = false;
    if (current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        if (!path.validated && path.outstanding_challenge.has_value()) {
            path.challenge_pending = true;
        }
    }
    const auto arm_packet_space_probe = [&](PacketSpaceState &packet_space) {
        const bool allow_client_handshake_keepalive_probe =
            client_handshake_keepalive_due && &packet_space == client_handshake_keepalive_space;
        const bool allow_client_receive_keepalive_probe =
            client_receive_keepalive_due && &packet_space == client_receive_keepalive_space;
        if (!allow_client_handshake_keepalive_probe && !allow_client_receive_keepalive_probe &&
            !has_in_flight_ack_eliciting_packet(packet_space)) {
            return;
        }

        if (&packet_space != &application_space_ && packet_space.send_crypto.has_pending_data()) {
            return;
        }

        packet_space.pending_probe_packet = select_pto_probe(packet_space);
        if ((allow_client_handshake_keepalive_probe | allow_client_receive_keepalive_probe) &
            packet_space.pending_probe_packet.has_value()) {
            packet_space.pending_probe_packet->force_ack = true;
        }
        if (allow_client_receive_keepalive_probe & packet_space.pending_probe_packet.has_value()) {
            if ((&packet_space == &application_space_) & current_send_path_id_.has_value()) {
                auto &path = ensure_path_state(*current_send_path_id_);
                if (path.validated) {
                    if (!path.outstanding_challenge.has_value()) {
                        path.outstanding_challenge =
                            next_path_challenge_data(*current_send_path_id_);
                    }
                    path.challenge_pending = true;
                }
            }
        }
        armed_pto_probe |= packet_space.pending_probe_packet.has_value();
    };

    arm_packet_space_probe(*selected_packet_space);

    const auto arm_coalesced_probe = [&](PacketSpaceState &packet_space) {
        if (&packet_space == selected_packet_space) {
            return;
        }

        arm_packet_space_probe(packet_space);
    };

    arm_coalesced_probe(initial_space_);
    arm_coalesced_probe(handshake_space_);
    if (allow_application_pto) {
        arm_coalesced_probe(application_space_);
    }

    if (armed_pto_probe) {
        remaining_pto_probe_datagrams_ = 2;
    }

    if (packet_trace_matches_connection(config_.source_connection_id)) {
        constexpr std::array<const char *, 4> kPacketSpaceNames = {
            "none",
            "initial",
            "handshake",
            "application",
        };
        const auto selected_packet_space_index =
            static_cast<std::size_t>(selected_packet_space == &initial_space_) +
            static_cast<std::size_t>(selected_packet_space == &handshake_space_) * 2u +
            static_cast<std::size_t>(selected_packet_space == &application_space_) * 3u;
        const char *selected_packet_space_name = kPacketSpaceNames[selected_packet_space_index];

        std::cerr << "quic-packet-trace arm-pto scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " selected=" << selected_packet_space_name
                  << " client_hs_due=" << static_cast<int>(client_handshake_keepalive_due)
                  << " client_recv_due=" << static_cast<int>(client_receive_keepalive_due)
                  << " armed=" << static_cast<int>(armed_pto_probe) << " initial_probe="
                  << static_cast<int>(initial_space_.pending_probe_packet.has_value())
                  << " handshake_probe="
                  << static_cast<int>(handshake_space_.pending_probe_packet.has_value())
                  << " application_probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_ << '\n';
    }
    maybe_emit_qlog_recovery_metrics(now);
}

std::optional<SentPacketRecord>
QuicConnection::select_pto_probe(const PacketSpaceState &packet_space) const {
    std::optional<SentPacketRecord> ping_fallback;
    std::optional<SentPacketRecord> best_probe;
    int best_probe_priority = -1;
    for (auto it = packet_space.sent_packets.rbegin(); it != packet_space.sent_packets.rend();
         ++it) {
        const auto &[packet_number, packet] = *it;
        static_cast<void>(packet_number);
        if (!packet.ack_eliciting || !packet.in_flight) {
            continue;
        }

        ping_fallback = ping_fallback.value_or(SentPacketRecord{
            .packet_number = packet.packet_number,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        });

        auto probe = packet;
        std::erase_if(probe.crypto_ranges, [&](const ByteRange &range) {
            return !packet_space.send_crypto.has_outstanding_range(range.offset,
                                                                   range.bytes.size());
        });
        std::erase_if(probe.reset_stream_frames, [&](const ResetStreamFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool reset_acknowledged =
                stream->second.reset_state == StreamControlFrameState::acknowledged;
            const bool reset_frame_mismatch =
                !reset_stream_frame_matches(stream->second.pending_reset_frame, frame);
            return static_cast<bool>(reset_acknowledged | reset_frame_mismatch);
        });
        std::erase_if(probe.stop_sending_frames, [&](const StopSendingFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stop_sending_acknowledged =
                stream->second.stop_sending_state == StreamControlFrameState::acknowledged;
            const bool stop_sending_frame_mismatch =
                !stop_sending_frame_matches(stream->second.pending_stop_sending_frame, frame);
            return static_cast<bool>(stop_sending_acknowledged | stop_sending_frame_mismatch);
        });
        std::erase_if(probe.max_stream_data_frames, [&](const MaxStreamDataFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool max_stream_data_acknowledged =
                stream->second.flow_control.max_stream_data_state ==
                StreamControlFrameState::acknowledged;
            const bool max_stream_data_frame_mismatch = !max_stream_data_frame_matches(
                stream->second.flow_control.pending_max_stream_data_frame, frame);
            return static_cast<bool>(max_stream_data_acknowledged | max_stream_data_frame_mismatch);
        });
        std::erase_if(probe.max_streams_frames, [&](const MaxStreamsFrame &frame) {
            const bool frame_acknowledged =
                frame.stream_type == StreamLimitType::bidirectional
                    ? local_stream_limit_state_.max_streams_bidi_state ==
                          StreamControlFrameState::acknowledged
                    : local_stream_limit_state_.max_streams_uni_state ==
                          StreamControlFrameState::acknowledged;
            const auto &pending_frame =
                frame.stream_type == StreamLimitType::bidirectional
                    ? *local_stream_limit_state_.pending_max_streams_bidi_frame
                    : *local_stream_limit_state_.pending_max_streams_uni_frame;
            const bool frame_mismatch =
                std::tie(pending_frame.stream_type, pending_frame.maximum_streams) !=
                std::tie(frame.stream_type, frame.maximum_streams);
            return static_cast<bool>(frame_acknowledged | frame_mismatch);
        });
        std::erase_if(probe.stream_data_blocked_frames, [&](const StreamDataBlockedFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stream_data_blocked_acknowledged =
                stream->second.flow_control.stream_data_blocked_state ==
                StreamControlFrameState::acknowledged;
            const bool stream_data_blocked_frame_mismatch = !stream_data_blocked_frame_matches(
                stream->second.flow_control.pending_stream_data_blocked_frame, frame);
            return static_cast<bool>(stream_data_blocked_acknowledged |
                                     stream_data_blocked_frame_mismatch);
        });
        std::erase_if(probe.stream_fragments, [&](const StreamFrameSendFragment &fragment) {
            const auto stream = streams_.find(fragment.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            return !stream_fragment_is_probe_worthy(stream->second, fragment);
        });

        if (probe.max_data_frame.has_value()) {
            const bool max_data_acknowledged =
                connection_flow_control_.max_data_state == StreamControlFrameState::acknowledged;
            const bool max_data_frame_mismatch = !max_data_frame_matches(
                connection_flow_control_.pending_max_data_frame, *probe.max_data_frame);
            if (max_data_acknowledged | max_data_frame_mismatch) {
                probe.max_data_frame = std::nullopt;
            }
        }
        if (probe.data_blocked_frame.has_value()) {
            const bool data_blocked_acknowledged = connection_flow_control_.data_blocked_state ==
                                                   StreamControlFrameState::acknowledged;
            const bool data_blocked_frame_mismatch = !data_blocked_frame_matches(
                connection_flow_control_.pending_data_blocked_frame, *probe.data_blocked_frame);
            if (data_blocked_acknowledged | data_blocked_frame_mismatch) {
                probe.data_blocked_frame = std::nullopt;
            }
        }
        if (probe.has_handshake_done &&
            handshake_done_state_ == StreamControlFrameState::acknowledged) {
            probe.has_handshake_done = false;
        }

        const auto frame_count = retransmittable_probe_frame_count(probe);
        if (frame_count == 0 && !probe.has_ping) {
            continue;
        }

        int probe_priority = 0;
        if (!probe.stream_fragments.empty()) {
            probe_priority = 3;
        } else if (!probe.crypto_ranges.empty()) {
            probe_priority = 2;
        } else if (frame_count != 0) {
            probe_priority = 1;
        }

        if (!best_probe.has_value() || probe_priority > best_probe_priority) {
            best_probe = std::move(probe);
            best_probe_priority = probe_priority;
        }
        if (best_probe_priority == 3) {
            break;
        }
    }

    if (best_probe.has_value()) {
        return best_probe;
    }
    if (ping_fallback.has_value()) {
        return ping_fallback;
    }

    return SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
}

void QuicConnection::queue_server_handshake_recovery_probes() {
    if ((config_.role != EndpointRole::server) | (status_ != HandshakeStatus::in_progress) |
        handshake_confirmed_) {
        return;
    }

    if (handshake_space_.pending_probe_packet.has_value() ||
        handshake_space_.send_crypto.has_pending_data()) {
        return;
    }

    handshake_space_.pending_probe_packet = select_pto_probe(handshake_space_);
}

const RecoveryRttState &QuicConnection::shared_recovery_rtt_state() const {
    if (recovery_rtt_state_.latest_rtt.has_value()) {
        return recovery_rtt_state_;
    }
    if (initial_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return initial_space_.recovery.rtt_state();
    }
    if (handshake_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return handshake_space_.recovery.rtt_state();
    }
    if (application_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return application_space_.recovery.rtt_state();
    }

    return recovery_rtt_state_;
}

std::optional<QuicCoreTimePoint> QuicConnection::zero_rtt_discard_deadline() const {
    if (config_.role != EndpointRole::server || !zero_rtt_space_.read_secret.has_value()) {
        return std::nullopt;
    }

    return server_zero_rtt_discard_deadline_;
}

void QuicConnection::arm_server_zero_rtt_discard_deadline(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::server || !zero_rtt_space_.read_secret.has_value() ||
        server_zero_rtt_discard_deadline_.has_value()) {
        return;
    }

    const auto max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.value_or(TransportParameters{}).max_ack_delay);
    const auto single_pto = compute_pto_deadline(shared_recovery_rtt_state(), max_ack_delay, now,
                                                 /*pto_count=*/0) -
                            now;
    server_zero_rtt_discard_deadline_ = now + single_pto * 3;
}

void QuicConnection::maybe_discard_server_zero_rtt_packet_space(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::server || !server_zero_rtt_discard_deadline_.has_value() ||
        now < *server_zero_rtt_discard_deadline_) {
        return;
    }

    discard_packet_space_state(zero_rtt_space_);
    server_zero_rtt_discard_deadline_.reset();
}

void QuicConnection::synchronize_recovery_rtt_state() {
    if (!recovery_rtt_state_.latest_rtt.has_value()) {
        recovery_rtt_state_ = shared_recovery_rtt_state();
    }

    const auto shared_rtt_state = shared_recovery_rtt_state();
    initial_space_.recovery.rtt_state() = shared_rtt_state;
    handshake_space_.recovery.rtt_state() = shared_rtt_state;
    application_space_.recovery.rtt_state() = shared_rtt_state;
}

bool QuicConnection::is_handshake_complete() const {
    return status_ == HandshakeStatus::connected;
}

bool QuicConnection::has_processed_peer_packet() const {
    return processed_peer_packet_;
}

bool QuicConnection::has_failed() const {
    return status_ == HandshakeStatus::failed;
}

void QuicConnection::maybe_open_qlog_session(QuicCoreTimePoint now, const ConnectionId &odcid) {
    if (qlog_session_ != nullptr || !config_.qlog.has_value()) {
        return;
    }

    qlog_session_ = qlog::Session::try_open(*config_.qlog, config_.role, odcid, now);
}

void QuicConnection::emit_local_qlog_startup_events(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    if (qlog_session_->mark_local_version_information_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:version_information",
            qlog::serialize_version_information(config_.role, config_.supported_versions,
                                                current_version_)));
    }
    if (qlog_session_->mark_local_alpn_information_emitted()) {
        const std::vector<std::vector<std::byte>> alpns = {
            application_protocol_bytes(config_.application_protocol),
        };
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::span<const std::vector<std::byte>>(alpns),
                                             std::nullopt, std::nullopt, config_.role)));
    }
    if (qlog_session_->mark_local_parameters_set_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:parameters_set",
            qlog::serialize_parameters_set("local", local_transport_parameters_)));
    }
}

void QuicConnection::maybe_emit_remote_qlog_parameters(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !peer_transport_parameters_.has_value()) {
        return;
    }
    if (!qlog_session_->mark_remote_parameters_set_emitted()) {
        return;
    }

    static_cast<void>(qlog_session_->write_event(
        now, "quic:parameters_set",
        qlog::serialize_parameters_set("remote", *peer_transport_parameters_)));
}

void QuicConnection::maybe_emit_qlog_alpn_information(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !tls_.has_value()) {
        return;
    }

    const auto &selected = tls_->selected_application_protocol();
    if (!selected.has_value()) {
        return;
    }

    if (config_.role == EndpointRole::server) {
        const auto &client_alpns = tls_->peer_offered_application_protocols();
        if (!client_alpns.empty() && qlog_session_->mark_server_alpn_selection_emitted()) {
            const std::vector<std::vector<std::byte>> server_alpns = {
                application_protocol_bytes(config_.application_protocol),
            };
            static_cast<void>(qlog_session_->write_event(
                now, "quic:alpn_information",
                qlog::serialize_alpn_information(
                    std::span<const std::vector<std::byte>>(server_alpns),
                    std::span<const std::vector<std::byte>>(client_alpns),
                    std::span<const std::byte>(*selected), EndpointRole::server)));
        }
        return;
    }

    if (qlog_session_->mark_client_chosen_alpn_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::nullopt, std::nullopt,
                                             std::span<const std::byte>(*selected),
                                             EndpointRole::client)));
    }
}

qlog::PacketSnapshot
QuicConnection::make_qlog_packet_snapshot(const ProtectedPacket &packet,
                                          const qlog::PacketSnapshotContext &context) const {
    return std::visit(
        [&](const auto &protected_packet) -> qlog::PacketSnapshot {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            qlog::PacketSnapshot snapshot;
            snapshot.raw_length = context.raw_length;
            snapshot.datagram_id = context.datagram_id;
            snapshot.trigger = context.trigger;
            snapshot.frames = protected_packet.frames;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                snapshot.header.packet_type = "initial";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.token = protected_packet.token;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                snapshot.header.packet_type = "handshake";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                snapshot.header.packet_type = "0RTT";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else {
                snapshot.header.packet_type = "1RTT";
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.spin_bit = protected_packet.spin_bit;
                snapshot.header.key_phase = protected_packet.key_phase ? 1u : 0u;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            }
            return snapshot;
        },
        packet);
}

qlog::RecoveryMetricsSnapshot QuicConnection::current_qlog_recovery_metrics() const {
    const auto &rtt = shared_recovery_rtt_state();
    return qlog::RecoveryMetricsSnapshot{
        .min_rtt_ms = rtt.min_rtt.has_value()
                          ? std::optional<double>(static_cast<double>(rtt.min_rtt->count()))
                          : std::nullopt,
        .smoothed_rtt_ms = static_cast<double>(rtt.smoothed_rtt.count()),
        .latest_rtt_ms = rtt.latest_rtt.has_value()
                             ? std::optional<double>(static_cast<double>(rtt.latest_rtt->count()))
                             : std::nullopt,
        .rtt_variance_ms = static_cast<double>(rtt.rttvar.count()),
        .pto_count = static_cast<std::uint16_t>(pto_count_),
        .congestion_window = static_cast<std::uint64_t>(congestion_controller_.congestion_window()),
        .bytes_in_flight = static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight()),
    };
}

void QuicConnection::maybe_emit_qlog_recovery_metrics(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    static_cast<void>(
        qlog_session_->maybe_write_recovery_metrics(now, current_qlog_recovery_metrics()));
}

void QuicConnection::emit_qlog_packet_lost(const SentPacketRecord &packet, std::string_view trigger,
                                           QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || packet.qlog_packet_snapshot == nullptr) {
        return;
    }

    auto snapshot = *packet.qlog_packet_snapshot;
    snapshot.trigger = std::string(trigger);
    static_cast<void>(qlog_session_->write_event(now, "quic:packet_lost",
                                                 qlog::serialize_packet_snapshot(snapshot)));
}

void QuicConnection::start_client_if_needed() {
    start_client_if_needed(QuicCoreTimePoint{});
}

void QuicConnection::start_client_if_needed(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::client || started_) {
        return;
    }

    maybe_open_qlog_session(now, config_.original_destination_connection_id.value_or(
                                     client_initial_destination_connection_id()));
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .preferred_address = config_.transport.preferred_address,
        .version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_),
    };
    initialize_local_flow_control();

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = std::nullopt,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_client_transport_parameters",
                          serialized_transport_parameters.error());
        mark_failed();
        return;
    }

    std::optional<std::vector<std::byte>> tls_resumption_state;
    bool enable_zero_rtt_attempt = false;
    if (config_.resumption_state.has_value()) {
        decoded_resumption_state_ = decode_resumption_state(config_.resumption_state->serialized);
        if (decoded_resumption_state_.has_value()) {
            tls_resumption_state = decoded_resumption_state_->tls_state;
            enable_zero_rtt_attempt =
                config_.zero_rtt.attempt &
                (decoded_resumption_state_->quic_version == current_version_) &
                (decoded_resumption_state_->application_protocol == config_.application_protocol) &
                (decoded_resumption_state_->application_context ==
                 config_.zero_rtt.application_context);
            if (enable_zero_rtt_attempt) {
                peer_transport_parameters_ = decoded_resumption_state_->peer_transport_parameters;
                initialize_peer_flow_control_from_transport_parameters();
            } else if (config_.zero_rtt.attempt) {
                pending_zero_rtt_status_event_ =
                    QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::unavailable};
            }
        }
        const bool report_unavailable_zero_rtt_attempt =
            !decoded_resumption_state_.has_value() & config_.zero_rtt.attempt;
        if (report_unavailable_zero_rtt_attempt) {
            pending_zero_rtt_status_event_ =
                QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::unavailable};
        }
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
        .resumption_state = std::move(tls_resumption_state),
        .attempt_zero_rtt = enable_zero_rtt_attempt,
        .accept_zero_rtt = false,
        .zero_rtt_context = config_.zero_rtt.application_context,
        .tls_keylog_path = config_.tls_keylog_path,
    });
    const auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        mark_failed();
        return;
    }

    static_cast<void>(sync_tls_state().value());
    emit_local_qlog_startup_events(now);
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id,
    std::uint32_t client_initial_version) {
    start_server_if_needed(client_initial_destination_connection_id, QuicCoreTimePoint{},
                           client_initial_version);
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id, QuicCoreTimePoint now,
    std::uint32_t client_initial_version) {
    if (started_) {
        return;
    }

    maybe_open_qlog_session(now, config_.original_destination_connection_id.value_or(
                                     client_initial_destination_connection_id));
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    original_version_ = client_initial_version;
    if (config_.retry_source_connection_id.has_value()) {
        current_version_ = client_initial_version;
    } else {
        current_version_ =
            select_server_version(config_.supported_versions, client_initial_version);
    }
    client_initial_destination_connection_id_ = client_initial_destination_connection_id;
    const auto original_destination_connection_id =
        config_.original_destination_connection_id.value_or(
            client_initial_destination_connection_id);
    local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = original_destination_connection_id,
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .retry_source_connection_id = config_.retry_source_connection_id,
        .preferred_address = config_.transport.preferred_address,
        .version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_),
    };
    initialize_local_flow_control();

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = original_destination_connection_id,
            .expected_retry_source_connection_id = config_.retry_source_connection_id,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_server_transport_parameters",
                          serialized_transport_parameters.error());
        mark_failed();
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
        .accept_zero_rtt = config_.zero_rtt.allow,
        .zero_rtt_context = config_.zero_rtt.application_context,
        .tls_keylog_path = config_.tls_keylog_path,
    });
    const auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        mark_failed();
        return;
    }
    static_cast<void>(sync_tls_state().value());
    emit_local_qlog_startup_events(now);

    if (!config_.retry_source_connection_id.has_value()) {
        anti_amplification_received_bytes_ +=
            static_cast<std::uint64_t>(anti_amplification_received_bytes_ == 0) *
            kMinimumInitialDatagramSize;
    }
    if (config_.retry_source_connection_id.has_value()) {
        mark_peer_address_validated();
    }
}

CodecResult<ConnectionId> QuicConnection::peek_client_initial_destination_connection_id(
    std::span<const std::byte> bytes) const {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<ConnectionId>::failure(first_byte.error().code,
                                                  first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if ((header_byte & 0x40u) == 0) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<ConnectionId>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if (!is_initial_long_header_type(version_value,
                                     static_cast<std::uint8_t>((header_byte >> 4) & 0x03u))) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<ConnectionId>::failure(destination_connection_id_length.error().code,
                                                  destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<ConnectionId>::failure(destination_connection_id.error().code,
                                                  destination_connection_id.error().offset);
    }

    return CodecResult<ConnectionId>::success(ConnectionId(
        destination_connection_id.value().begin(), destination_connection_id.value().end()));
}

CodecResult<std::size_t>
QuicConnection::peek_next_packet_length(std::span<const std::byte> bytes) const {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<std::size_t>::failure(first_byte.error().code,
                                                 first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        if ((header_byte & 0x40u) == 0) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
        }
        return CodecResult<std::size_t>::success(bytes.size());
    }
    if ((header_byte & 0x40u) == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<std::size_t>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id_length.error().code,
                                                 destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id.error().code,
                                                 destination_connection_id.error().offset);
    }

    const auto source_connection_id_length = reader.read_byte();
    if (!source_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id_length.error().code,
                                                 source_connection_id_length.error().offset);
    }
    const auto source_connection_id_length_value =
        std::to_integer<std::uint8_t>(source_connection_id_length.value());
    if (source_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto source_connection_id = reader.read_exact(source_connection_id_length_value);
    if (!source_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id.error().code,
                                                 source_connection_id.error().offset);
    }

    const auto packet_type = static_cast<std::uint8_t>((header_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version_value, packet_type)) {
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<std::size_t>::failure(token_length.error().code,
                                                     token_length.error().offset);
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     reader.offset());
        }
        static_cast<void>(reader.read_exact(static_cast<std::size_t>(token_length.value().value)));
    } else if (!is_zero_rtt_long_header_type(version_value, packet_type) &&
               !is_handshake_long_header_type(version_value, packet_type)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto payload_length = decode_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<std::size_t>::failure(payload_length.error().code,
                                                 payload_length.error().offset);
    }
    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                 reader.offset());
    }

    return CodecResult<std::size_t>::success(
        reader.offset() + static_cast<std::size_t>(payload_length.value().value));
}

CodecResult<bool> QuicConnection::process_inbound_packet(const ProtectedPacket &packet,
                                                         QuicCoreTimePoint now,
                                                         QuicEcnCodepoint ecn) {
    return std::visit(
        [&](const auto &protected_packet) -> CodecResult<bool> {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (initial_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool duplicate_initial_packet =
                    initial_space_.received_packets.contains(protected_packet.packet_number);
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                active_peer_connection_id_sequence_ = 0;
                initial_space_.largest_authenticated_packet_number = protected_packet.packet_number;
                const auto processed =
                    process_inbound_crypto(EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(protected_packet.packet_number,
                                                                    ack_eliciting, now, ecn);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        last_peer_activity_time_ = now;
                    }
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                        initial_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                    if (duplicate_initial_packet & ack_eliciting) {
                        queue_server_handshake_recovery_probes();
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                active_peer_connection_id_sequence_ = 0;
                handshake_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_crypto(EncryptionLevel::handshake,
                                                              protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server) {
                        mark_peer_address_validated();
                    }
                    if (config_.role == EndpointRole::server) {
                        discard_initial_packet_space();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        last_peer_activity_time_ = now;
                    }
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                        handshake_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_application(protected_packet.frames, now,
                                                                   true, last_inbound_path_id_);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn);
                    last_peer_activity_time_ = now;
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
                        application_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const bool has_crypto_frame =
                    std::ranges::any_of(protected_packet.frames, [](const Frame &frame) {
                        return std::holds_alternative<CryptoFrame>(frame);
                    });
                const auto processed = process_inbound_application(
                    protected_packet.frames, now, has_crypto_frame, last_inbound_path_id_);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server &&
                        status_ != HandshakeStatus::connected) {
                        mark_peer_address_validated();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn);
                    last_peer_activity_time_ = now;
                    if (ack_eliciting) {
                        schedule_application_ack_deadline(application_space_, now,
                                                          local_transport_parameters_.max_ack_delay,
                                                          ecn);
                    }
                    if (zero_rtt_space_.read_secret.has_value() ||
                        zero_rtt_space_.write_secret.has_value()) {
                        if (config_.role == EndpointRole::server &&
                            zero_rtt_space_.read_secret.has_value()) {
                            arm_server_zero_rtt_discard_deadline(now);
                        } else {
                            discard_packet_space_state(zero_rtt_space_);
                        }
                    }
                }
                return processed;
            }
        },
        packet);
}

CodecResult<bool> QuicConnection::process_inbound_crypto(EncryptionLevel level,
                                                         std::span<const Frame> frames,
                                                         QuicCoreTimePoint now) {
    auto &packet_space = packet_space_for_level(level, initial_space_, handshake_space_,
                                                zero_rtt_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            static_cast<void>(process_inbound_ack(
                packet_space, *ack_frame, now, /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
                config_.role == EndpointRole::client && level == EncryptionLevel::initial));
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            continue;
        }

        if (std::holds_alternative<TransportConnectionCloseFrame>(frame)) {
            pending_terminal_state_ = QuicConnectionTerminalState::closed;
            mark_failed();
            continue;
        }

        const bool application_handshake_done = (level == EncryptionLevel::application) &
                                                std::holds_alternative<HandshakeDoneFrame>(frame);
        if (application_handshake_done) {
            confirm_handshake();
            continue;
        }

        const auto *crypto_frame = std::get_if<CryptoFrame>(&frame);
        if (crypto_frame == nullptr) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type, 0);
        }
        const auto contiguous_bytes =
            packet_space.receive_crypto.push(crypto_frame->offset, crypto_frame->crypto_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                              contiguous_bytes.error().offset);
        }
        if (contiguous_bytes.value().empty()) {
            continue;
        }

        if (!tls_.has_value()) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }

        const auto provided = tls_->provide(level, contiguous_bytes.value());
        if (!provided.has_value()) {
            return provided;
        }

        install_available_secrets();
        collect_pending_tls_bytes();
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_ack(PacketSpaceState &packet_space,
                                                      const AckFrame &ack, QuicCoreTimePoint now,
                                                      std::uint64_t ack_delay_exponent,
                                                      std::uint64_t max_ack_delay_ms,
                                                      bool suppress_pto_reset) {
    std::vector<SentPacketRecord> late_acked_packets;
    std::vector<std::uint64_t> late_acked_packet_numbers;
    for (const auto &[packet_number, packet] : packet_space.declared_lost_packets) {
        if (!ack_frame_acks_packet(ack, packet_number)) {
            continue;
        }

        late_acked_packets.push_back(packet);
        late_acked_packet_numbers.push_back(packet_number);
    }
    for (const auto packet_number : late_acked_packet_numbers) {
        packet_space.declared_lost_packets.erase(packet_number);
    }

    packet_space.recovery.rtt_state() = shared_recovery_rtt_state();
    auto ack_result = packet_space.recovery.on_ack_received(ack, now);
    std::vector<SentPacketRecord> acked_packets;
    acked_packets.reserve(ack_result.acked_packets.size());
    for (const auto &packet_metadata : ack_result.acked_packets) {
        if (packet_metadata.declared_lost) {
            continue;
        }

        const auto packet_it = packet_space.sent_packets.find(packet_metadata.packet_number);
        if (packet_it == packet_space.sent_packets.end()) {
            continue;
        }
        acked_packets.push_back(packet_it->second);
    }
    std::vector<SentPacketRecord> newly_lost_packets;
    newly_lost_packets.reserve(ack_result.lost_packets.size());
    for (const auto &packet_metadata : ack_result.lost_packets) {
        const auto packet_it = packet_space.sent_packets.find(packet_metadata.packet_number);
        if (packet_it == packet_space.sent_packets.end()) {
            continue;
        }
        newly_lost_packets.push_back(packet_it->second);
    }
    for (const auto &packet : acked_packets) {
        retire_acked_packet(packet_space, packet);
    }
    for (const auto &packet : late_acked_packets) {
        retire_acked_packet(packet_space, packet);
    }
    for (const auto &packet : newly_lost_packets) {
        const auto trigger =
            is_packet_threshold_lost(packet.packet_number, ack.largest_acknowledged)
                ? "reordering_threshold"
                : "time_threshold";
        emit_qlog_packet_lost(packet, trigger, now);
        mark_lost_packet(packet_space, packet, /*already_marked_in_recovery=*/true);
    }

    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    if (ack_result.largest_acknowledged_was_newly_acked) {
        struct PathEcnAckSummary {
            std::uint64_t newly_acked_ect0 = 0;
            std::uint64_t newly_acked_ect1 = 0;
            std::optional<QuicCoreTimePoint> latest_marked_sent_time;
        };

        std::map<QuicPathId, PathEcnAckSummary> acked_ecn_by_path;
        const auto note_acked_ecn_packet = [&](const SentPacketRecord &packet) {
            if (!is_ect_codepoint(packet.ecn)) {
                return;
            }

            auto &summary = acked_ecn_by_path[packet.path_id];
            if (packet.ecn == QuicEcnCodepoint::ect0) {
                ++summary.newly_acked_ect0;
            } else {
                ++summary.newly_acked_ect1;
            }
            summary.latest_marked_sent_time =
                summary.latest_marked_sent_time.has_value()
                    ? std::max(*summary.latest_marked_sent_time, packet.sent_time)
                    : packet.sent_time;
        };
        for (const auto &packet : acked_packets) {
            note_acked_ecn_packet(packet);
        }
        for (const auto &packet : late_acked_packets) {
            note_acked_ecn_packet(packet);
        }

        if (!acked_ecn_by_path.empty()) {
            const std::array packet_spaces = {
                &initial_space_,
                &handshake_space_,
                &application_space_,
            };
            const auto packet_space_index = ecn_packet_space_index(packet_space, packet_spaces);
            for (const auto &[path_id, summary] : acked_ecn_by_path) {
                auto &path = ensure_path_state(path_id);
                if (path.ecn.state == QuicPathEcnState::failed) {
                    continue;
                }

                if (!ack.ecn_counts.has_value()) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                const auto previous_counts = path.ecn.has_last_peer_counts[packet_space_index]
                                                 ? path.ecn.last_peer_counts[packet_space_index]
                                                 : AckEcnCounts{};
                const auto &current_counts = *ack.ecn_counts;
                const bool counts_decreased = current_counts.ect0 < previous_counts.ect0 ||
                                              current_counts.ect1 < previous_counts.ect1 ||
                                              current_counts.ecn_ce < previous_counts.ecn_ce;
                if (counts_decreased) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                const auto delta_ect0 = current_counts.ect0 - previous_counts.ect0;
                const auto delta_ect1 = current_counts.ect1 - previous_counts.ect1;
                const auto delta_ce = current_counts.ecn_ce - previous_counts.ecn_ce;
                const bool missing_ect0_feedback = delta_ect0 + delta_ce < summary.newly_acked_ect0;
                const bool missing_ect1_feedback = delta_ect1 + delta_ce < summary.newly_acked_ect1;
                const bool impossible_ect0_count = current_counts.ect0 > path.ecn.total_sent_ect0;
                const bool impossible_ect1_count = current_counts.ect1 > path.ecn.total_sent_ect1;
                if (missing_ect0_feedback || missing_ect1_feedback || impossible_ect0_count ||
                    impossible_ect1_count) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                path.ecn.last_peer_counts[packet_space_index] = current_counts;
                path.ecn.has_last_peer_counts[packet_space_index] = true;
                if (path.ecn.state == QuicPathEcnState::probing) {
                    path.ecn.probing_packets_acked +=
                        summary.newly_acked_ect0 + summary.newly_acked_ect1;
                    path.ecn.state = QuicPathEcnState::capable;
                }

                if (packet_space_is_application(packet_space, application_space_) &&
                    delta_ce != 0) {
                    const auto latest_marked_sent_time = *summary.latest_marked_sent_time;
                    latest_ecn_ce_sent_time =
                        std::max(latest_ecn_ce_sent_time.value_or(latest_marked_sent_time),
                                 latest_marked_sent_time);
                }
            }
        }
    }

    if (ack_result.largest_acknowledged_was_newly_acked &&
        ack_result.has_newly_acked_ack_eliciting &&
        ack_result.largest_newly_acked_packet.has_value()) {
        update_rtt(packet_space.recovery.rtt_state(), now,
                   SentPacketRecord{.sent_time = ack_result.largest_newly_acked_packet->sent_time},
                   decode_ack_delay(ack, ack_delay_exponent),
                   std::chrono::milliseconds(max_ack_delay_ms));
        recovery_rtt_state_ = packet_space.recovery.rtt_state();
        synchronize_recovery_rtt_state();
    }
    const bool has_any_acked_packets = !acked_packets.empty() || !late_acked_packets.empty();
    if (&packet_space == &application_space_ && has_any_acked_packets) {
        confirm_handshake();
    }
    if (packet_space_is_application(packet_space, application_space_)) {
        const auto &shared_rtt_state = shared_recovery_rtt_state();
        const auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(newly_lost_packets);
        if (!ack_eliciting_lost_packets.empty()) {
            congestion_controller_.on_loss_event(
                now, latest_packet_sent_time(ack_eliciting_lost_packets));
            if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                                  std::chrono::milliseconds(max_ack_delay_ms))) {
                congestion_controller_.on_persistent_congestion();
            }
        }
        if (latest_ecn_ce_sent_time.has_value()) {
            congestion_controller_.on_loss_event(now, *latest_ecn_ce_sent_time);
        }
        congestion_controller_.on_packets_acked(acked_packets, !has_pending_application_send());
    }
    if (has_any_acked_packets && !suppress_pto_reset) {
        const bool keepalive_probe_packet_space =
            (&packet_space == &initial_space_) | (&packet_space == &handshake_space_);
        const bool client_handshake_keepalive_ack_only =
            (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::in_progress) &
                !handshake_confirmed_ & keepalive_probe_packet_space &
                std::ranges::all_of(acked_packets,
                                    [&](const SentPacketRecord &packet) {
                                        return packet.has_ping &
                                               (retransmittable_probe_frame_count(packet) == 0);
                                    }) &&
            std::ranges::all_of(late_acked_packets, [&](const SentPacketRecord &packet) {
                return packet.has_ping & (retransmittable_probe_frame_count(packet) == 0);
            });
        if (!client_handshake_keepalive_ack_only) {
            pto_count_ = 0;
        }
    }

    if (packet_space_is_application(packet_space, application_space_) &&
        packet_trace_matches_connection(config_.source_connection_id)) {
        std::cerr << "quic-packet-trace ack scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " path=" << last_inbound_path_id_ << " ranges=" << format_ack_ranges(ack)
                  << " acked={" << summarize_packets(acked_packets) << "}"
                  << " late={" << summarize_packets(late_acked_packets) << "}"
                  << " lost={" << summarize_packets(newly_lost_packets) << "}"
                  << " pending_send=" << static_cast<int>(has_pending_application_send())
                  << " probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight()
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "}\n";
    }
    maybe_emit_qlog_recovery_metrics(now);
    return CodecResult<bool>::success(true);
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space,
                                       const SentPacketRecord &packet) {
    packet_space.sent_packets[packet.packet_number] = packet;
    packet_space.recovery.on_packet_sent(packet);
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (packet.ecn == QuicEcnCodepoint::ect0) {
            ++path.ecn.total_sent_ect0;
        } else {
            ++path.ecn.total_sent_ect1;
        }
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_sent;
        }
    }
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    }
    maybe_emit_qlog_recovery_metrics(packet.sent_time);
}

void QuicConnection::retire_acked_packet(PacketSpaceState &packet_space,
                                         const SentPacketRecord &packet) {
    std::vector<std::uint64_t> retirement_candidates;
    const auto note_retirement_candidate = [&](std::uint64_t stream_id) {
        if (std::find(retirement_candidates.begin(), retirement_candidates.end(), stream_id) ==
            retirement_candidates.end()) {
            retirement_candidates.push_back(stream_id);
        }
    };
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.acknowledge(range.offset, range.bytes.size());
    }
    if (packet.max_data_frame.has_value()) {
        connection_flow_control_.acknowledge_max_data_frame(*packet.max_data_frame);
    }
    if (packet.data_blocked_frame.has_value()) {
        connection_flow_control_.acknowledge_data_blocked_frame(*packet.data_blocked_frame);
    }
    for (const auto &frame : packet.max_stream_data_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_max_stream_data_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stream_data_blocked_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_send_fragment(fragment);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(fragment.stream_id);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_reset_frame(frame);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stop_sending_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.acknowledge_max_streams_frame(frame);
    }
    if (packet.has_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::acknowledged;
    }

    packet_space.recovery.retire_packet(packet.packet_number);
    packet_space.sent_packets.erase(packet.packet_number);
    packet_space.declared_lost_packets.erase(packet.packet_number);
    for (const auto stream_id : retirement_candidates) {
        maybe_retire_stream(stream_id);
    }
}

void QuicConnection::mark_lost_packet(PacketSpaceState &packet_space,
                                      const SentPacketRecord &packet,
                                      bool already_marked_in_recovery) {
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packets_lost(std::span<const SentPacketRecord>(&packet, 1));
        if (current_send_path_id_.has_value()) {
            auto &path = ensure_path_state(*current_send_path_id_);
            if (!path.validated & path.outstanding_challenge.has_value()) {
                path.challenge_pending = true;
            }
        }
    }
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_lost;
            const bool all_probes_lost =
                path.ecn.probing_packets_sent != 0 && path.ecn.probing_packets_acked == 0 &&
                path.ecn.probing_packets_lost >= path.ecn.probing_packets_sent;
            if (all_probes_lost) {
                disable_ecn_on_path(packet.path_id);
            }
        }
    }
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.mark_lost(range.offset, range.bytes.size());
    }
    if (packet.max_data_frame.has_value()) {
        connection_flow_control_.mark_max_data_frame_lost(*packet.max_data_frame);
    }
    if (packet.data_blocked_frame.has_value()) {
        connection_flow_control_.mark_data_blocked_frame_lost(*packet.data_blocked_frame);
    }
    for (const auto &frame : packet.max_stream_data_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_max_stream_data_frame_lost(frame);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_stream_data_blocked_frame_lost(frame);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_send_fragment_lost(fragment);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_reset_frame_lost(frame);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_stop_sending_frame_lost(frame);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.mark_max_streams_frame_lost(frame);
    }
    const bool lost_handshake_done =
        packet.has_handshake_done &
        (handshake_done_state_ != StreamControlFrameState::acknowledged);
    if (lost_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::pending;
    }

    if (!already_marked_in_recovery) {
        packet_space.recovery.on_packet_declared_lost(packet.packet_number);
    }
    packet_space.sent_packets.erase(packet.packet_number);
    auto declared_lost = packet;
    declared_lost.declared_lost = true;
    declared_lost.in_flight = false;
    declared_lost.bytes_in_flight = 0;
    packet_space.declared_lost_packets[packet.packet_number] = std::move(declared_lost);
}

void QuicConnection::rebuild_recovery(PacketSpaceState &packet_space) {
    const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
    const auto rtt_state = packet_space.recovery.rtt_state();

    packet_space.recovery = PacketSpaceRecovery{};
    packet_space.recovery.rtt_state() = rtt_state;
    if (largest_acked.has_value()) {
        static_cast<void>(packet_space.recovery.on_ack_received(
            AckFrame{
                .largest_acknowledged = *largest_acked,
                .first_ack_range = 0,
            },
            QuicCoreTimePoint{}));
    }

    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        packet_space.recovery.on_packet_sent(packet);
    }
}

CodecResult<bool> QuicConnection::process_inbound_application(std::span<const Frame> frames,
                                                              QuicCoreTimePoint now,
                                                              bool allow_preconnected_frames,
                                                              QuicPathId path_id) {
    static_assert(std::variant_size_v<Frame> == 21,
                  "Update process_inbound_application when Frame gains new variants");
    const bool require_connected = !allow_preconnected_frames;
    const bool traces_this_packet = packet_trace_matches_connection(config_.source_connection_id);
    const bool has_ack_frame = std::ranges::any_of(
        frames, [](const Frame &frame) { return std::holds_alternative<AckFrame>(frame); });
    const bool has_path_challenge_frame = std::ranges::any_of(frames, [](const Frame &frame) {
        return std::holds_alternative<PathChallengeFrame>(frame);
    });
    const bool has_path_response_frame = std::ranges::any_of(frames, [](const Frame &frame) {
        return std::holds_alternative<PathResponseFrame>(frame);
    });
    if (traces_this_packet & (has_ack_frame | has_path_challenge_frame | has_path_response_frame)) {
        std::cerr << "quic-packet-trace recv-app scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path_id
                  << " frames_ack=" << static_cast<int>(has_ack_frame)
                  << " frames_path_challenge=" << static_cast<int>(has_path_challenge_frame)
                  << " frames_path_response=" << static_cast<int>(has_path_response_frame)
                  << " probing_only=" << static_cast<int>(is_probing_only(frames))
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, path_id))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "} probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
    }
    const auto keep_current_validating_path = [&] {
        if (!current_send_path_id_.has_value() || path_id == *current_send_path_id_) {
            return false;
        }
        const auto current = paths_.find(*current_send_path_id_);
        const auto inbound = paths_.find(path_id);
        const bool has_current = current != paths_.end();
        const bool has_inbound = inbound != paths_.end();
        const bool current_validating = has_current ? !current->second.validated : false;
        const bool inbound_validated = has_inbound ? inbound->second.validated : false;
        return static_cast<bool>(has_current & has_inbound & current_validating &
                                 inbound_validated);
    }();
    if (path_id != current_send_path_id_.value_or(path_id) && !is_probing_only(frames) &&
        !keep_current_validating_path) {
        maybe_switch_to_path(path_id, /*initiated_locally=*/false);
    }
    if (!paths_.empty() | (path_id != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(path_id);
    }
    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            const auto ack_delay_exponent = peer_transport_parameters_.has_value()
                                                ? peer_transport_parameters_->ack_delay_exponent
                                                : TransportParameters{}.ack_delay_exponent;
            const auto max_ack_delay_ms = peer_transport_parameters_.has_value()
                                              ? peer_transport_parameters_->max_ack_delay
                                              : TransportParameters{}.max_ack_delay;
            static_cast<void>(process_inbound_ack(application_space_, *ack_frame, now,
                                                  ack_delay_exponent, max_ack_delay_ms,
                                                  /*suppress_pto_reset=*/false));
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            const bool allow_preconnected_ping_frame = application_space_.read_secret.has_value() &&
                                                       status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_ping_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            continue;
        }

        if (const auto *crypto_frame = std::get_if<CryptoFrame>(&frame)) {
            const auto contiguous_bytes = application_space_.receive_crypto.push(
                crypto_frame->offset, crypto_frame->crypto_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }
            if (contiguous_bytes.value().empty()) {
                continue;
            }
            if (status_ == HandshakeStatus::connected && !tls_.has_value()) {
                continue;
            }

            if (!tls_.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                  0);
            }

            const auto provided =
                tls_->provide(EncryptionLevel::application, contiguous_bytes.value());
            if (!provided.has_value()) {
                return provided;
            }

            install_available_secrets();
            collect_pending_tls_bytes();
            continue;
        }

        const auto *stream_frame = std::get_if<StreamFrame>(&frame);
        if (stream_frame != nullptr) {
            const bool allow_preconnected_stream_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_stream_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            if (stream_frame->has_offset && !stream_frame->offset.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            const auto stream_offset = stream_frame->offset.value_or(0);

            auto stream = get_or_open_receive_stream(stream_frame->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            auto *stream_state = stream.value();
            if (stream_state->peer_reset_received) {
                continue;
            }

            const auto previous_highest_offset = stream_state->highest_received_offset;
            const auto validated = stream_state->validate_receive_range(
                stream_offset, stream_frame->stream_data.size(), stream_frame->fin);
            if (!validated.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            const auto received_delta =
                stream_state->highest_received_offset - previous_highest_offset;
            if (connection_flow_control_.received_committed >
                    connection_flow_control_.advertised_max_data ||
                received_delta > connection_flow_control_.advertised_max_data -
                                     connection_flow_control_.received_committed) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            connection_flow_control_.received_committed += received_delta;

            const auto contiguous_bytes =
                stream_state->receive_buffer.push(stream_offset, stream_frame->stream_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }
            if (stream_frame->stream_id == 0 &&
                packet_trace_matches_connection(config_.source_connection_id)) {
                std::cerr << "quic-packet-trace stream scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " offset=" << stream_offset
                          << " len=" << stream_frame->stream_data.size()
                          << " fin=" << stream_frame->fin
                          << " contiguous=" << contiguous_bytes.value().size()
                          << " highest=" << stream_state->highest_received_offset << '\n';
            }

            stream_state->receive_flow_control_consumed +=
                static_cast<std::uint64_t>(contiguous_bytes.value().size());
            const auto fin_ready =
                stream_state->peer_final_size.has_value() &&
                stream_state->receive_flow_control_consumed == *stream_state->peer_final_size &&
                !stream_state->peer_fin_delivered;
            if (!contiguous_bytes.value().empty() || fin_ready) {
                pending_stream_receive_effects_.push_back(QuicCoreReceiveStreamData{
                    .stream_id = stream_frame->stream_id,
                    .bytes = contiguous_bytes.value(),
                    .fin = fin_ready,
                });
                stream_state->flow_control.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_bytes.value().size());
                connection_flow_control_.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_bytes.value().size());
                if (fin_ready) {
                    stream_state->peer_fin_delivered = true;
                }
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/false);
                maybe_refresh_connection_receive_credit(/*force=*/false);
                maybe_refresh_peer_stream_limit(*stream_state);
                maybe_retire_stream(stream_frame->stream_id);
            }
            continue;
        }

        if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_receive_stream(reset_stream->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            auto *stream_state = stream.value();
            const auto noted = stream_state->note_peer_reset(*reset_stream);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
                .stream_id = reset_stream->stream_id,
                .application_error_code = reset_stream->application_protocol_error_code,
                .final_size = reset_stream->final_size,
            });
            maybe_refresh_peer_stream_limit(*stream_state);
            maybe_retire_stream(reset_stream->stream_id);
            continue;
        }

        if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_send_stream_for_peer_stop(stop_sending->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            auto *stream_state = stream.value();
            static_cast<void>(stream_state->note_peer_stop_sending(
                stop_sending->application_protocol_error_code));

            pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
                .stream_id = stop_sending->stream_id,
                .application_error_code = stop_sending->application_protocol_error_code,
            });
            continue;
        }

        if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            connection_flow_control_.note_peer_max_data(max_data->maximum_data);
            if (total_queued_stream_bytes() <= connection_flow_control_.peer_max_data) {
                connection_flow_control_.pending_data_blocked_frame = std::nullopt;
                connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
            }
            continue;
        }

        if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_send_stream(max_stream_data->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            stream.value()->note_peer_max_stream_data(max_stream_data->maximum_stream_data);
            continue;
        }

        if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            stream_open_limits_.note_peer_max_streams(max_streams->stream_type,
                                                      max_streams->maximum_streams);
            continue;
        }

        if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            if (data_blocked->maximum_data >= connection_flow_control_.advertised_max_data) {
                maybe_refresh_connection_receive_credit(/*force=*/true);
            }
            continue;
        }

        if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_receive_stream(stream_data_blocked->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto *stream_state = stream.value();
            if (stream_data_blocked->maximum_stream_data >=
                stream_state->flow_control.advertised_max_stream_data) {
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/true);
            }
            continue;
        }

        if (std::holds_alternative<StreamsBlockedFrame>(frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            continue;
        }

        if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
            const auto stored = process_new_connection_id_frame(*new_connection_id);
            if (!stored.has_value()) {
                return CodecResult<bool>::failure(stored.error().code, stored.error().offset);
            }
            continue;
        }

        if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            queue_path_response(path_id, path_challenge->data);
            continue;
        }

        if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto matching_path = std::find_if(paths_.begin(), paths_.end(), [&](const auto &entry) {
                return entry.second.outstanding_challenge.has_value() &&
                       entry.second.outstanding_challenge.value() == path_response->data;
            });
            auto *path = matching_path != paths_.end() ? &matching_path->second
                                                       : &ensure_path_state(path_id);
            const auto validated_path_id =
                matching_path != paths_.end() ? matching_path->first : path_id;
            const bool had_outstanding_challenge = path->outstanding_challenge.has_value();
            const bool matched_outstanding_challenge =
                had_outstanding_challenge &&
                path->outstanding_challenge.value() == path_response->data;
            if (matched_outstanding_challenge) {
                path->validated = true;
                path->challenge_pending = false;
                path->validation_initiated_locally = false;
                path->outstanding_challenge.reset();
                path->validation_deadline.reset();
                last_validated_path_id_ = validated_path_id;
                if (current_send_path_id_ != validated_path_id) {
                    maybe_switch_to_path(validated_path_id, /*initiated_locally=*/false);
                }
            }
            if (traces_this_packet) {
                std::cerr << "quic-packet-trace path-response scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " path=" << path_id << " validated_path=" << validated_path_id
                          << " had_outstanding=" << static_cast<int>(had_outstanding_challenge)
                          << " matched=" << static_cast<int>(matched_outstanding_challenge)
                          << " current=" << format_optional_path_id(current_send_path_id_)
                          << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                          << " path_state={" << format_path_state_summary(path) << "}\n";
            }
            continue;
        }

        if (std::holds_alternative<NewTokenFrame>(frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type,
                                                  0);
            }
            continue;
        }

        const bool has_transport_close =
            std::holds_alternative<TransportConnectionCloseFrame>(frame);
        const bool has_application_close =
            std::holds_alternative<ApplicationConnectionCloseFrame>(frame);
        if (has_transport_close | has_application_close) {
            pending_terminal_state_ = QuicConnectionTerminalState::closed;
            mark_failed();
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            confirm_handshake();
            continue;
        }

        const auto &retire_connection_id = std::get<RetireConnectionIdFrame>(frame);
        const auto retired = process_retire_connection_id_frame(retire_connection_id);
        if (!retired.has_value()) {
            return CodecResult<bool>::failure(retired.error().code, retired.error().offset);
        }
        continue;
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::install_available_secrets() {
    if (!tls_.has_value()) {
        return;
    }

    bool installed_client_application_keys = false;
    for (auto &available_secret : tls_->take_available_secrets()) {
        available_secret.secret.quic_version = current_version_;
        auto &packet_space =
            packet_space_for_level(available_secret.level, initial_space_, handshake_space_,
                                   zero_rtt_space_, application_space_);
        if (available_secret.sender == config_.role) {
            packet_space.write_secret = std::move(available_secret.secret);
        } else {
            packet_space.read_secret = std::move(available_secret.secret);
        }
        installed_client_application_keys |= config_.role == EndpointRole::client &&
                                             available_secret.level == EncryptionLevel::application;
    }

    if (installed_client_application_keys && zero_rtt_space_.write_secret.has_value()) {
        discard_packet_space_state(zero_rtt_space_);
    }
}

void QuicConnection::collect_pending_tls_bytes() {
    if (!tls_.has_value()) {
        return;
    }

    initial_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::initial));
    handshake_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::handshake));
    zero_rtt_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::zero_rtt));
    application_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::application));
}

void QuicConnection::replay_deferred_protected_packets(QuicCoreTimePoint now) {
    auto deferred_packets = std::move(deferred_protected_packets_);
    deferred_protected_packets_.clear();
    for (const auto &deferred_packet : deferred_packets) {
        process_inbound_datagram(deferred_packet.bytes, now, deferred_packet.path_id,
                                 deferred_packet.ecn, deferred_packet.datagram_id,
                                 /*replay_trigger=*/true,
                                 /*count_inbound_bytes=*/false);
        if (status_ == HandshakeStatus::failed) {
            return;
        }
    }
}

CodecResult<bool> QuicConnection::sync_tls_state() {
    if (tls_.has_value()) {
        tls_->poll();
    }

    install_available_secrets();
    collect_pending_tls_bytes();

    const auto validated = validate_peer_transport_parameters_if_ready();
    if (!validated.has_value()) {
        return validated;
    }

    if (!peer_preferred_address_emitted_ && peer_transport_parameters_validated_ &&
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->preferred_address.has_value()) {
        pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
            .preferred_address = *peer_transport_parameters_->preferred_address,
        };
        peer_preferred_address_emitted_ = true;
    }

    update_handshake_status();
    maybe_emit_qlog_alpn_information(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    auto *tls = tls_.has_value() ? &*tls_ : nullptr;
    const bool tls_handshake_complete = tls != nullptr ? tls->handshake_complete() : false;
    if (resumption_state_emitted_) {
        return CodecResult<bool>::success(true);
    }
    if (tls == nullptr) {
        return CodecResult<bool>::success(true);
    }
    if (!tls_handshake_complete) {
        return CodecResult<bool>::success(true);
    }
    if (!peer_transport_parameters_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (const auto ticket = tls->take_resumption_state(); ticket.has_value()) {
        auto encoded = encode_resumption_state(
            *ticket, current_version_, config_.application_protocol, *peer_transport_parameters_,
            config_.zero_rtt.application_context);
        pending_resumption_state_effect_ = QuicCoreResumptionStateAvailable{
            .state =
                QuicResumptionState{
                    .serialized = std::move(encoded),
                },
        };
        resumption_state_emitted_ = true;
    }
    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::validate_peer_transport_parameters_if_ready() {
    if (peer_transport_parameters_validated_ || !tls_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (config_.role == EndpointRole::client && decoded_resumption_state_.has_value() &&
        peer_transport_parameters_.has_value() && !tls_->handshake_complete()) {
        return CodecResult<bool>::success(true);
    }

    const auto &peer_transport_parameters_bytes = tls_->peer_transport_parameters();
    const bool received_peer_transport_parameters = peer_transport_parameters_bytes.has_value();
    if (received_peer_transport_parameters) {
        const auto parameters =
            deserialize_transport_parameters(peer_transport_parameters_bytes.value());
        if (!parameters.has_value()) {
            log_codec_failure("deserialize_transport_parameters", parameters.error());
            return CodecResult<bool>::failure(parameters.error().code, parameters.error().offset);
        }

        peer_transport_parameters_ = parameters.value();
    }
    if (!received_peer_transport_parameters && !peer_transport_parameters_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto validation_context = peer_transport_parameters_validation_context();
    if (!validation_context.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto peer_transport_parameters =
        peer_transport_parameters_.value_or(TransportParameters{});
    const auto validation = validate_peer_transport_parameters(
        opposite_role(config_.role), peer_transport_parameters, validation_context.value());
    if (!validation.has_value()) {
        log_codec_failure("validate_peer_transport_parameters", validation.error());
        return CodecResult<bool>::failure(validation.error().code, validation.error().offset);
    }

    peer_transport_parameters_validated_ = true;
    initialize_peer_flow_control_from_transport_parameters();
    const auto peer_preferred_address = peer_transport_parameters.preferred_address;
    const auto emitted_preferred_address = peer_preferred_address.value_or(PreferredAddress{});
    if (!peer_preferred_address_emitted_ & peer_preferred_address.has_value()) {
        pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
            .preferred_address = emitted_preferred_address,
        };
        peer_preferred_address_emitted_ = true;
    }
    maybe_emit_remote_qlog_parameters(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    return CodecResult<bool>::success(true);
}

void QuicConnection::update_handshake_status() {
    if (status_ == HandshakeStatus::failed || !started_) {
        return;
    }
    if (!tls_.has_value()) {
        return;
    }

    const bool handshake_ready = tls_->handshake_complete() & peer_transport_parameters_validated_ &
                                 application_space_.read_secret.has_value() &
                                 application_space_.write_secret.has_value();
    if (handshake_ready) {
        if (status_ != HandshakeStatus::connected) {
            status_ = HandshakeStatus::connected;
            if (config_.role == EndpointRole::client) {
                mark_peer_address_validated();
            }
            queue_state_change(QuicCoreStateChange::handshake_ready);
        }
        if (config_.role == EndpointRole::server) {
            if (handshake_done_state_ == StreamControlFrameState::none) {
                handshake_done_state_ = StreamControlFrameState::pending;
            }
        }
    } else {
        status_ = HandshakeStatus::in_progress;
    }
}

void QuicConnection::confirm_handshake() {
    if (handshake_confirmed_) {
        return;
    }

    handshake_confirmed_ = true;
    queue_state_change(QuicCoreStateChange::handshake_confirmed);
    issue_spare_connection_ids();
    discard_handshake_packet_space();
}

PathState &QuicConnection::ensure_path_state(QuicPathId path_id) {
    auto [it, inserted] = paths_.try_emplace(
        path_id, PathState{
                     .id = path_id,
                     .peer_connection_id_sequence = active_peer_connection_id_sequence_,
                 });
    if (inserted) {
        it->second.validated =
            last_validated_path_id_.has_value() && last_validated_path_id_ == path_id;
    }
    return it->second;
}

void QuicConnection::start_path_validation(QuicPathId path_id, bool initiated_locally) {
    if (current_send_path_id_.has_value() && current_send_path_id_ != path_id) {
        previous_path_id_ = current_send_path_id_;
        if (const auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
            current->second.is_current_send_path = false;
        }
    }

    const auto peer_connection_id_sequence = [&] {
        if (initiated_locally) {
            return select_peer_connection_id_sequence_for_path(path_id);
        }
        if (const auto existing = paths_.find(path_id);
            existing != paths_.end() &&
            peer_connection_ids_.contains(existing->second.peer_connection_id_sequence)) {
            return existing->second.peer_connection_id_sequence;
        }
        if (current_send_path_id_.has_value()) {
            if (const auto current = paths_.find(*current_send_path_id_);
                current != paths_.end() &&
                peer_connection_ids_.contains(current->second.peer_connection_id_sequence)) {
                return current->second.peer_connection_id_sequence;
            }
        }
        return active_peer_connection_id_sequence_;
    }();
    auto &path = ensure_path_state(path_id);
    path.validated = false;
    path.is_current_send_path = true;
    path.peer_connection_id_sequence = peer_connection_id_sequence;
    path.challenge_pending = true;
    path.validation_initiated_locally = initiated_locally;
    path.outstanding_challenge = next_path_challenge_data(path_id);
    path.validation_deadline.reset();
    current_send_path_id_ = path_id;
}

std::array<std::byte, 8> QuicConnection::next_path_challenge_data(QuicPathId path_id) {
    return make_path_challenge_data(config_.source_connection_id, path_id,
                                    next_path_challenge_sequence_++);
}

void QuicConnection::queue_path_response(QuicPathId path_id, const std::array<std::byte, 8> &data) {
    auto &path = ensure_path_state(path_id);
    path.pending_response = data;
}

bool QuicConnection::path_validation_timed_out(QuicPathId path_id, QuicCoreTimePoint now) const {
    const auto path = paths_.find(path_id);
    if (path == paths_.end()) {
        return false;
    }

    const auto &validation_deadline = path->second.validation_deadline;
    return validation_deadline.has_value() && now >= validation_deadline.value();
}

CodecResult<bool>
QuicConnection::process_new_connection_id_frame(const NewConnectionIdFrame &frame) {
    if (!peer_connection_ids_.contains(0) && peer_source_connection_id_.has_value()) {
        peer_connection_ids_.emplace(0, PeerConnectionIdRecord{
                                            .sequence_number = 0,
                                            .connection_id = peer_source_connection_id_.value(),
                                        });
    }
    if (frame.retire_prior_to > frame.sequence_number) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto duplicate_sequence = peer_connection_ids_.find(frame.sequence_number);
    if (duplicate_sequence != peer_connection_ids_.end()) {
        const bool mismatched_duplicate =
            duplicate_sequence->second.connection_id != frame.connection_id |
            duplicate_sequence->second.stateless_reset_token != frame.stateless_reset_token;
        if (mismatched_duplicate) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        }
    }

    const auto conflicting_connection_id = std::find_if(
        peer_connection_ids_.begin(), peer_connection_ids_.end(), [&](const auto &entry) {
            return entry.first != frame.sequence_number &&
                   entry.second.connection_id == frame.connection_id;
        });
    if (conflicting_connection_id != peer_connection_ids_.end()) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
    }

    for (const auto &[sequence_number, record] : peer_connection_ids_) {
        static_cast<void>(record);
        if (sequence_number >= frame.retire_prior_to) {
            continue;
        }

        pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = sequence_number,
        });
    }
    std::erase_if(peer_connection_ids_,
                  [&](const auto &entry) { return entry.first < frame.retire_prior_to; });
    peer_connection_ids_[frame.sequence_number] = PeerConnectionIdRecord{
        .sequence_number = frame.sequence_number,
        .connection_id = frame.connection_id,
        .stateless_reset_token = frame.stateless_reset_token,
    };

    if (!peer_connection_ids_.contains(active_peer_connection_id_sequence_) |
        (active_peer_connection_id_sequence_ < frame.retire_prior_to)) {
        active_peer_connection_id_sequence_ = frame.sequence_number;
    }

    if (peer_connection_ids_.size() > local_transport_parameters_.active_connection_id_limit) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool>
QuicConnection::process_retire_connection_id_frame(const RetireConnectionIdFrame &frame) {
    issue_spare_connection_ids();
    const auto record = local_connection_ids_.find(frame.sequence_number);
    if (record == local_connection_ids_.end()) {
        if (!handshake_confirmed_) {
            return CodecResult<bool>::success(true);
        }
        return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (record->second.retired) {
        return CodecResult<bool>::success(true);
    }

    record->second.retired = true;
    if (frame.sequence_number == active_local_connection_id_sequence_) {
        const auto next_active =
            std::find_if(local_connection_ids_.begin(), local_connection_ids_.end(),
                         [](const auto &entry) { return !entry.second.retired; });
        if (next_active != local_connection_ids_.end()) {
            active_local_connection_id_sequence_ = next_active->first;
        }
    }
    issue_spare_connection_ids();
    return CodecResult<bool>::success(true);
}

void QuicConnection::issue_spare_connection_ids() {
    if (!handshake_confirmed_ || !peer_transport_parameters_.has_value() ||
        config_.source_connection_id.empty()) {
        return;
    }
    if (config_.role == EndpointRole::client &&
        local_transport_parameters_.disable_active_migration) {
        return;
    }

    const auto peer_limit =
        static_cast<std::size_t>(peer_transport_parameters_->active_connection_id_limit);
    if (peer_limit == 0) {
        return;
    }

    while (count_active_connection_ids(local_connection_ids_) < peer_limit) {
        const auto sequence_number = next_local_connection_id_sequence_++;
        const auto connection_id =
            make_issued_connection_id(config_.source_connection_id, sequence_number);
        const auto stateless_reset_token =
            make_stateless_reset_token(connection_id, sequence_number);
        local_connection_ids_[sequence_number] = LocalConnectionIdRecord{
            .sequence_number = sequence_number,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        };
        pending_new_connection_id_frames_.push_back(NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = 0,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
    }
}

std::uint64_t
QuicConnection::select_peer_connection_id_sequence_for_path(QuicPathId path_id) const {
    if (const auto path = paths_.find(path_id);
        path != paths_.end() &&
        peer_connection_ids_.contains(path->second.peer_connection_id_sequence)) {
        return path->second.peer_connection_id_sequence;
    }

    const auto sequence_assigned_to_other_path = [&](std::uint64_t sequence_number) {
        return std::ranges::any_of(paths_, [&](const auto &entry) {
            return (entry.first != path_id) &
                   (entry.second.peer_connection_id_sequence == sequence_number);
        });
    };

    for (const auto &[sequence_number, connection_id] : peer_connection_ids_) {
        static_cast<void>(connection_id);
        if ((sequence_number == active_peer_connection_id_sequence_) |
            sequence_assigned_to_other_path(sequence_number)) {
            continue;
        }

        return sequence_number;
    }

    return active_peer_connection_id_sequence_;
}

ConnectionId QuicConnection::active_peer_destination_connection_id() const {
    if (const auto active = peer_connection_ids_.find(active_peer_connection_id_sequence_);
        active != peer_connection_ids_.end()) {
        return active->second.connection_id;
    }
    if (peer_source_connection_id_.has_value()) {
        return peer_source_connection_id_.value();
    }
    return config_.initial_destination_connection_id;
}

std::optional<NewConnectionIdFrame> QuicConnection::take_pending_new_connection_id_frame() {
    if (pending_new_connection_id_frames_.empty()) {
        return std::nullopt;
    }

    auto frame = pending_new_connection_id_frames_.front();
    pending_new_connection_id_frames_.erase(pending_new_connection_id_frames_.begin());
    return frame;
}

bool QuicConnection::should_reset_client_handshake_peer_state(
    const ConnectionId &source_connection_id) const {
    return config_.role == EndpointRole::client && status_ == HandshakeStatus::in_progress &&
           !handshake_confirmed_ && peer_source_connection_id_.has_value() &&
           peer_source_connection_id_.value() != source_connection_id;
}

void QuicConnection::reset_client_handshake_peer_state_for_new_source_connection_id() {
    reset_packet_space_receive_state(initial_space_);
    reset_packet_space_receive_state(handshake_space_);
    reset_packet_space_receive_state(zero_rtt_space_);
    deferred_protected_packets_.clear();
    peer_transport_parameters_.reset();
    peer_connection_ids_.clear();
    active_peer_connection_id_sequence_ = 0;
    peer_transport_parameters_validated_ = false;
}

bool QuicConnection::packet_targets_discarded_long_header_space(
    std::span<const std::byte> packet_bytes) const {
    if (packet_bytes.size() < 5) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(packet_bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return false;
    }

    const auto version = read_u32_be(packet_bytes.subspan(1, 4));
    const auto packet_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version, packet_type)) {
        return initial_packet_space_discarded_;
    }
    if (is_handshake_long_header_type(version, packet_type)) {
        return handshake_packet_space_discarded_;
    }

    return false;
}

void QuicConnection::discard_initial_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    initial_packet_space_discarded_ = true;
    discard_packet_space_state(initial_space_);
    pto_count_ = 0;
}

void QuicConnection::discard_handshake_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    handshake_packet_space_discarded_ = true;
    discard_packet_space_state(handshake_space_);
    pto_count_ = 0;
}

void QuicConnection::mark_failed() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (!pending_terminal_state_.has_value()) {
        pending_terminal_state_ = QuicConnectionTerminalState::failed;
    }
    status_ = HandshakeStatus::failed;
    streams_.clear();
    deferred_protected_packets_.clear();
    pending_stream_receive_effects_.clear();
    pending_peer_reset_effects_.clear();
    pending_peer_stop_effects_.clear();
    pending_state_changes_.clear();
    pending_resumption_state_effect_.reset();
    pending_zero_rtt_status_event_.reset();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::queue_state_change(QuicCoreStateChange change) {
    if (change == QuicCoreStateChange::handshake_ready) {
        if (handshake_ready_emitted_) {
            return;
        }
        handshake_ready_emitted_ = true;
    } else if (change == QuicCoreStateChange::handshake_confirmed) {
        if (handshake_confirmed_emitted_) {
            return;
        }
        handshake_confirmed_emitted_ = true;
    } else {
        if (failed_emitted_) {
            return;
        }
        failed_emitted_ = true;
    }

    pending_state_changes_.push_back(change);
}

std::optional<TransportParametersValidationContext>
QuicConnection::peer_transport_parameters_validation_context() const {
    if (!peer_source_connection_id_.has_value()) {
        return std::nullopt;
    }

    if (config_.role == EndpointRole::client) {
        const auto expected_version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_);
        return TransportParametersValidationContext{
            .expected_initial_source_connection_id = peer_source_connection_id_.value(),
            .expected_original_destination_connection_id =
                config_.original_destination_connection_id.value_or(
                    config_.initial_destination_connection_id),
            .expected_retry_source_connection_id = config_.retry_source_connection_id,
            .expected_version_information = expected_version_information,
            .reacted_to_version_negotiation = config_.reacted_to_version_negotiation,
        };
    }

    const auto expected_version_information = version_information_for_handshake(
        config_.supported_versions, original_version_, config_.retry_source_connection_id,
        original_version_, current_version_);
    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = peer_source_connection_id_.value(),
        .expected_original_destination_connection_id = std::nullopt,
        .expected_retry_source_connection_id = std::nullopt,
        .expected_version_information = expected_version_information,
    };
}

void QuicConnection::initialize_local_flow_control() {
    connection_flow_control_ = ConnectionFlowControlState{
        .local_receive_window = local_transport_parameters_.initial_max_data,
        .advertised_max_data = local_transport_parameters_.initial_max_data,
    };
    local_stream_limit_state_.initialize(PeerStreamOpenLimits{
        .bidirectional = local_transport_parameters_.initial_max_streams_bidi,
        .unidirectional = local_transport_parameters_.initial_max_streams_uni,
    });
}

void QuicConnection::initialize_peer_flow_control_from_transport_parameters() {
    if (!peer_transport_parameters_.has_value()) {
        return;
    }

    connection_flow_control_.note_peer_max_data(peer_transport_parameters_->initial_max_data);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::bidirectional,
                                              peer_transport_parameters_->initial_max_streams_bidi);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::unidirectional,
                                              peer_transport_parameters_->initial_max_streams_uni);

    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
        stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
        if ((stream.receive_flow_control_limit == 0) &
            (stream.flow_control.local_receive_window == 0) &
            (stream.flow_control.advertised_max_stream_data ==
             std::numeric_limits<std::uint64_t>::max())) {
            stream.flow_control.local_receive_window =
                initial_stream_receive_window(stream.stream_id);
            stream.flow_control.advertised_max_stream_data =
                stream.flow_control.local_receive_window;
            stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
        }
    }
}

std::uint64_t QuicConnection::initial_stream_send_limit(std::uint64_t stream_id) const {
    if (!peer_transport_parameters_.has_value()) {
        return 0;
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return peer_transport_parameters_->initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return peer_transport_parameters_->initial_max_stream_data_bidi_remote;
    }

    return peer_transport_parameters_->initial_max_stream_data_bidi_local;
}

std::uint64_t QuicConnection::initial_stream_receive_window(std::uint64_t stream_id) const {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return local_transport_parameters_.initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return local_transport_parameters_.initial_max_stream_data_bidi_local;
    }

    return local_transport_parameters_.initial_max_stream_data_bidi_remote;
}

void QuicConnection::initialize_stream_flow_control(StreamState &stream) const {
    stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
    stream.flow_control.local_receive_window = initial_stream_receive_window(stream.stream_id);
    stream.flow_control.advertised_max_stream_data = stream.flow_control.local_receive_window;
    stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
    stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
}

StreamState *QuicConnection::find_stream_state(std::uint64_t stream_id) {
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
        return &it->second;
    }
    if (auto it = retired_streams_.find(stream_id); it != retired_streams_.end()) {
        return &it->second;
    }
    return nullptr;
}

const StreamState *QuicConnection::find_stream_state(std::uint64_t stream_id) const {
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
        return &it->second;
    }
    if (auto it = retired_streams_.find(stream_id); it != retired_streams_.end()) {
        return &it->second;
    }
    return nullptr;
}

void QuicConnection::maybe_retire_stream(std::uint64_t stream_id) {
    const auto stream = streams_.find(stream_id);
    if (stream == streams_.end()) {
        return;
    }
    if (!stream_receive_terminal(stream->second) || !stream_send_terminal(stream->second) ||
        stream->second.has_pending_send() || stream->second.has_outstanding_send()) {
        return;
    }
    const bool has_pending_receive_effect = std::ranges::any_of(
        pending_stream_receive_effects_,
        [&](const QuicCoreReceiveStreamData &effect) { return effect.stream_id == stream_id; });
    if (has_pending_receive_effect) {
        return;
    }
    if (last_application_send_stream_id_ == stream_id) {
        last_application_send_stream_id_.reset();
    }

    retired_streams_.insert_or_assign(stream_id, std::move(stream->second));
    streams_.erase(stream);
}

StreamStateResult<StreamState *> QuicConnection::get_or_open_local_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return StreamStateResult<StreamState *>::success(existing);
    }

    if (!is_local_implicit_stream_open_allowed(stream_id, config_.role)) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        const auto code = !id_info.local_can_send ? StreamStateErrorCode::invalid_stream_direction
                                                  : StreamStateErrorCode::invalid_stream_id;
        return StreamStateResult<StreamState *>::failure(code, stream_id);
    }
    if (!stream_open_limits_.can_open_local_stream(stream_id, config_.role)) {
        return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                         stream_id);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return StreamStateResult<StreamState *>::success(&it->second);
}

StreamStateResult<StreamState *>
QuicConnection::get_existing_receive_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return StreamStateResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return StreamStateResult<StreamState *>::failure(
            StreamStateErrorCode::invalid_stream_direction, stream_id);
    }

    return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                     stream_id);
}

CodecResult<StreamState *> QuicConnection::get_or_open_receive_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (stream_id == kCompatibilityStreamId && id_info.initiator == StreamInitiator::local) {
        auto [it, inserted] =
            streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
        static_cast<void>(inserted);
        initialize_stream_flow_control(it->second);
        return CodecResult<StreamState *>::success(&it->second);
    }
    if (id_info.initiator != StreamInitiator::peer ||
        !is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return CodecResult<StreamState *>::success(&it->second);
}

CodecResult<StreamState *> QuicConnection::get_or_open_send_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }

    if (id_info.initiator == StreamInitiator::local) {
        const auto local_stream = get_or_open_local_stream(stream_id);
        if (!local_stream.has_value()) {
            return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
        }
        return CodecResult<StreamState *>::success(local_stream.value());
    }

    if (!is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return CodecResult<StreamState *>::success(&it->second);
}

CodecResult<StreamState *>
QuicConnection::get_or_open_send_stream_for_peer_stop(std::uint64_t stream_id) {
    return get_or_open_send_stream(stream_id);
}

PeerStreamOpenLimits QuicConnection::peer_stream_open_limits() const {
    return PeerStreamOpenLimits{
        .bidirectional = local_stream_limit_state_.advertised_max_streams_bidi == 0
                             ? (local_transport_parameters_.initial_max_streams_bidi == 0
                                    ? config_.transport.initial_max_streams_bidi
                                    : local_transport_parameters_.initial_max_streams_bidi)
                             : local_stream_limit_state_.advertised_max_streams_bidi,
        .unidirectional = local_stream_limit_state_.advertised_max_streams_uni == 0
                              ? (local_transport_parameters_.initial_max_streams_uni == 0
                                     ? config_.transport.initial_max_streams_uni
                                     : local_transport_parameters_.initial_max_streams_uni)
                              : local_stream_limit_state_.advertised_max_streams_uni,
    };
}

bool QuicConnection::has_pending_application_send() const {
    for (const auto &[path_id, path] : paths_) {
        static_cast<void>(path_id);
        if (path.pending_response.has_value() || path.challenge_pending) {
            return true;
        }
    }

    if (pending_application_close_.has_value()) {
        return true;
    }

    if (handshake_done_state_ == StreamControlFrameState::pending) {
        return true;
    }

    if (connection_flow_control_.max_data_state == StreamControlFrameState::pending ||
        connection_flow_control_.data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }
    if (local_stream_limit_state_.max_streams_bidi_state == StreamControlFrameState::pending ||
        local_stream_limit_state_.max_streams_uni_state == StreamControlFrameState::pending) {
        return true;
    }

    const auto connection_send_credit =
        connection_flow_control_.peer_max_data > connection_flow_control_.highest_sent
            ? connection_flow_control_.peer_max_data - connection_flow_control_.highest_sent
            : 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        const bool has_pending_control_frame =
            (stream.reset_state == StreamControlFrameState::pending) |
            (stream.stop_sending_state == StreamControlFrameState::pending) |
            (stream.flow_control.max_stream_data_state == StreamControlFrameState::pending) |
            (stream.flow_control.stream_data_blocked_state == StreamControlFrameState::pending);
        if (has_pending_control_frame) {
            return true;
        }
        if (stream.reset_state != StreamControlFrameState::none) {
            continue;
        }

        const auto fin_sendable = stream_fin_sendable(stream);
        if (stream.send_buffer.has_lost_data() || fin_sendable) {
            return true;
        }
        if (connection_send_credit != 0 && stream.sendable_bytes() != 0) {
            return true;
        }
    }

    return false;
}

bool QuicConnection::has_pending_fresh_application_stream_send() const {
    const auto connection_send_credit = saturating_subtract(connection_flow_control_.peer_max_data,
                                                            connection_flow_control_.highest_sent);
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        if (stream.reset_state != StreamControlFrameState::none) {
            continue;
        }

        if (stream_fin_sendable(stream)) {
            return true;
        }
        if ((connection_send_credit != 0) & (stream.sendable_bytes() != 0)) {
            return true;
        }
    }

    return false;
}

std::uint64_t QuicConnection::total_queued_stream_bytes() const {
    std::uint64_t total = 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        total += stream.send_flow_control_committed;
    }

    return total;
}

void QuicConnection::maybe_queue_connection_blocked_frame() {
    const auto queued_bytes = total_queued_stream_bytes();
    const bool should_skip_queue =
        !connection_flow_control_.should_send_data_blocked(queued_bytes) |
        (connection_flow_control_.sendable_bytes(queued_bytes) != 0);
    if (should_skip_queue) {
        return;
    }

    connection_flow_control_.queue_data_blocked(connection_flow_control_.peer_max_data);
}

void QuicConnection::maybe_queue_stream_blocked_frame(StreamState &stream) {
    if (stream.sendable_bytes() != 0) {
        return;
    }

    stream.queue_stream_data_blocked();
}

void QuicConnection::maybe_refresh_connection_receive_credit(bool force) {
    if (!should_refresh_receive_window(connection_flow_control_.delivered_bytes,
                                       connection_flow_control_.advertised_max_data,
                                       connection_flow_control_.local_receive_window, force)) {
        return;
    }

    connection_flow_control_.queue_max_data(connection_flow_control_.delivered_bytes +
                                            connection_flow_control_.local_receive_window);
}

void QuicConnection::maybe_refresh_stream_receive_credit(StreamState &stream, bool force) {
    if (!should_refresh_receive_window(stream.flow_control.delivered_bytes,
                                       stream.flow_control.advertised_max_stream_data,
                                       stream.flow_control.local_receive_window, force)) {
        return;
    }

    stream.queue_max_stream_data(stream.flow_control.delivered_bytes +
                                 stream.flow_control.local_receive_window);
}

void QuicConnection::maybe_refresh_peer_stream_limit(StreamState &stream) {
    if (stream.peer_stream_limit_released || stream.id_info.initiator != StreamInitiator::peer ||
        !stream_receive_terminal(stream) || !stream_send_terminal(stream)) {
        return;
    }

    stream.peer_stream_limit_released = true;
    if (stream.id_info.direction == StreamDirection::bidirectional) {
        local_stream_limit_state_.queue_max_streams(StreamLimitType::bidirectional,
                                                    peer_stream_open_limits().bidirectional + 1);
        return;
    }

    local_stream_limit_state_.queue_max_streams(StreamLimitType::unidirectional,
                                                peer_stream_open_limits().unidirectional + 1);
}

bool QuicConnection::is_probing_only(std::span<const Frame> frames) const {
    return std::ranges::all_of(frames, [](const Frame &frame) {
        return is_padding_frame(frame) | std::holds_alternative<PathChallengeFrame>(frame) |
               std::holds_alternative<PathResponseFrame>(frame) |
               std::holds_alternative<NewConnectionIdFrame>(frame);
    });
}

void QuicConnection::maybe_switch_to_path(QuicPathId path_id, bool initiated_locally) {
    if (current_send_path_id_.has_value() && current_send_path_id_ == path_id) {
        return;
    }

    const auto existing_path = paths_.find(path_id);
    if (existing_path != paths_.end() && existing_path->second.validated) {
        if (current_send_path_id_.has_value()) {
            previous_path_id_ = current_send_path_id_;
            if (const auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
                current->second.is_current_send_path = false;
            }
        }
        auto &path = existing_path->second;
        path.is_current_send_path = true;
        current_send_path_id_ = path_id;
        return;
    }

    start_path_validation(path_id, initiated_locally);
}

bool QuicConnection::anti_amplification_applies() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        return anti_amplification_applies(pending_response_path->first);
    }
    if (current_send_path_id_.has_value() && anti_amplification_applies(*current_send_path_id_)) {
        return true;
    }
    return config_.role == EndpointRole::server && status_ == HandshakeStatus::in_progress &&
           !peer_address_validated_;
}

bool QuicConnection::anti_amplification_applies(QuicPathId path_id) const {
    if ((config_.role != EndpointRole::server) | !paths_.contains(path_id)) {
        return false;
    }

    const auto &path = paths_.at(path_id);
    return !path.validated & ((path.anti_amplification_received_bytes != 0) |
                              (path.anti_amplification_sent_bytes != 0));
}

std::uint64_t QuicConnection::anti_amplification_send_budget() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        return anti_amplification_send_budget(pending_response_path->first);
    }
    if (current_send_path_id_.has_value() && anti_amplification_applies(*current_send_path_id_)) {
        return anti_amplification_send_budget(*current_send_path_id_);
    }

    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    if (anti_amplification_received_bytes_ > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    return anti_amplification_received_bytes_ * 3u;
}

std::uint64_t QuicConnection::anti_amplification_send_budget(QuicPathId path_id) const {
    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    const auto &path = paths_.at(path_id);
    if (path.anti_amplification_received_bytes > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    return path.anti_amplification_received_bytes * 3u;
}

std::size_t QuicConnection::outbound_datagram_size_limit() const {
    auto max_datagram_size = config_.max_outbound_datagram_size;
    if (peer_transport_parameters_.has_value()) {
        max_datagram_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(static_cast<std::uint64_t>(max_datagram_size),
                                    peer_transport_parameters_->max_udp_payload_size));
    }

    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end() &&
        anti_amplification_applies(pending_response_path->first)) {
        const auto remaining_budget =
            saturating_subtract(anti_amplification_send_budget(pending_response_path->first),
                                pending_response_path->second.anti_amplification_sent_bytes);
        return static_cast<std::size_t>(std::min<std::uint64_t>(
            remaining_budget, static_cast<std::uint64_t>(max_datagram_size)));
    }
    if (current_send_path_id_.has_value() && anti_amplification_applies(*current_send_path_id_)) {
        const auto &path = paths_.at(*current_send_path_id_);
        const auto remaining_budget =
            saturating_subtract(anti_amplification_send_budget(*current_send_path_id_),
                                path.anti_amplification_sent_bytes);
        return static_cast<std::size_t>(std::min<std::uint64_t>(
            remaining_budget, static_cast<std::uint64_t>(max_datagram_size)));
    }
    if (!anti_amplification_applies()) {
        return max_datagram_size;
    }

    const auto remaining_budget =
        saturating_subtract(anti_amplification_send_budget(), anti_amplification_sent_bytes_);
    return static_cast<std::size_t>(
        std::min<std::uint64_t>(remaining_budget, static_cast<std::uint64_t>(max_datagram_size)));
}

void QuicConnection::note_inbound_datagram_bytes(std::size_t bytes) {
    if (bytes == 0) {
        return;
    }

    if (status_ == HandshakeStatus::connected) {
        auto &path = ensure_path_state(last_inbound_path_id_);
        const auto received = path.anti_amplification_received_bytes;
        const auto increment = static_cast<std::uint64_t>(bytes);
        path.anti_amplification_received_bytes =
            received > std::numeric_limits<std::uint64_t>::max() - increment
                ? std::numeric_limits<std::uint64_t>::max()
                : received + increment;
        return;
    }
    if (!anti_amplification_applies()) {
        return;
    }

    const auto received = anti_amplification_received_bytes_;
    const auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_received_bytes_ =
        received > std::numeric_limits<std::uint64_t>::max() - increment
            ? std::numeric_limits<std::uint64_t>::max()
            : received + increment;
}

void QuicConnection::note_outbound_datagram_bytes(std::size_t bytes,
                                                  std::optional<QuicPathId> path_id) {
    if (bytes == 0) {
        return;
    }

    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (effective_path_id.has_value() && anti_amplification_applies(*effective_path_id)) {
        auto &path = ensure_path_state(*effective_path_id);
        const auto sent = path.anti_amplification_sent_bytes;
        const auto increment = static_cast<std::uint64_t>(bytes);
        path.anti_amplification_sent_bytes =
            sent > std::numeric_limits<std::uint64_t>::max() - increment
                ? std::numeric_limits<std::uint64_t>::max()
                : sent + increment;
        return;
    }
    if (!anti_amplification_applies()) {
        return;
    }

    const auto sent = anti_amplification_sent_bytes_;
    const auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_sent_bytes_ = sent > std::numeric_limits<std::uint64_t>::max() - increment
                                         ? std::numeric_limits<std::uint64_t>::max()
                                         : sent + increment;
}

void QuicConnection::mark_peer_address_validated() {
    peer_address_validated_ = true;
    if (current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        path.validated = true;
        path.challenge_pending = false;
        path.validation_initiated_locally = false;
        path.outstanding_challenge.reset();
        path.validation_deadline.reset();
        last_validated_path_id_ = current_send_path_id_;
    }
}

void QuicConnection::disable_ecn_on_path(QuicPathId path_id) {
    auto &path = ensure_path_state(path_id);
    path.ecn.state = QuicPathEcnState::failed;
    path.ecn.has_last_peer_counts.fill(false);
    path.ecn.last_peer_counts = {};
    path.ecn.probing_packets_sent = 0;
    path.ecn.probing_packets_acked = 0;
    path.ecn.probing_packets_lost = 0;
}

QuicEcnCodepoint
QuicConnection::outbound_ecn_codepoint_for_path(std::optional<QuicPathId> path_id) const {
    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (!effective_path_id.has_value()) {
        return QuicEcnCodepoint::not_ect;
    }

    const auto path = paths_.find(*effective_path_id);
    if (path == paths_.end() || path->second.ecn.state == QuicPathEcnState::failed ||
        !is_ect_codepoint(path->second.ecn.transmit_mark)) {
        return QuicEcnCodepoint::not_ect;
    }

    return path->second.ecn.transmit_mark;
}

ConnectionId
QuicConnection::outbound_destination_connection_id(std::optional<QuicPathId> path_id) const {
    if (path_id.has_value()) {
        if (const auto path = paths_.find(*path_id); path != paths_.end()) {
            const auto &destination_connection_id_override =
                path->second.destination_connection_id_override;
            if (destination_connection_id_override.has_value()) {
                return destination_connection_id_override.value();
            }
            if (const auto peer_connection_id =
                    peer_connection_ids_.find(path->second.peer_connection_id_sequence);
                peer_connection_id != peer_connection_ids_.end()) {
                return peer_connection_id->second.connection_id;
            }
        }
    }

    return active_peer_destination_connection_id();
}

ConnectionId QuicConnection::client_initial_destination_connection_id() const {
    if (client_initial_destination_connection_id_.has_value()) {
        return client_initial_destination_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

std::vector<std::byte> QuicConnection::flush_outbound_datagram(QuicCoreTimePoint now) {
    const auto max_outbound_datagram_size = outbound_datagram_size_limit();
    const bool traces_this_connection =
        packet_trace_matches_connection(config_.source_connection_id);
    if (max_outbound_datagram_size == 0) {
        if (traces_this_connection) {
            std::cerr << "quic-packet-trace send-blocked scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " reason=amp-budget-zero"
                      << " current=" << format_optional_path_id(current_send_path_id_)
                      << " previous=" << format_optional_path_id(previous_path_id_)
                      << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                      << " current_path={"
                      << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                      << "} inbound_path={"
                      << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                      << "} pending_send=" << static_cast<int>(has_pending_application_send())
                      << " probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << '\n';
        }
        return {};
    }

    if (config_.role == EndpointRole::client && application_space_.write_secret.has_value() &&
        zero_rtt_space_.write_secret.has_value()) {
        discard_packet_space_state(zero_rtt_space_);
    }

    auto packets = std::vector<ProtectedPacket>{};
    auto selected_send_path_id = current_send_path_id_;
    const auto destination_connection_id = outbound_destination_connection_id();
    const auto application_destination_connection_id = [&]() {
        return outbound_destination_connection_id(selected_send_path_id);
    };
    const auto initial_destination_connection_id = config_.role == EndpointRole::client
                                                       ? client_initial_destination_connection_id()
                                                       : destination_connection_id;
    const bool duplicate_first_compatible_server_initial_crypto =
        (config_.role == EndpointRole::server) & (original_version_ != current_version_) &
        (initial_space_.next_send_packet_number == 0) &
        (handshake_space_.next_send_packet_number == 0);
    const bool initial_probe_pending = initial_space_.pending_probe_packet.has_value();
    const bool handshake_probe_pending = handshake_space_.pending_probe_packet.has_value();
    const bool application_probe_pending = application_space_.pending_probe_packet.has_value();
    const auto pto_probe_burst_active =
        (remaining_pto_probe_datagrams_ > 0) &
        (initial_probe_pending | handshake_probe_pending | application_probe_pending);
    const auto preserve_pto_probe_packets =
        pto_probe_burst_active && remaining_pto_probe_datagrams_ > 1;
    const bool track_client_handshake_keepalive_probes = (config_.role == EndpointRole::client) &
                                                         (status_ == HandshakeStatus::in_progress) &
                                                         !handshake_confirmed_;
    const auto clear_probe_packet_after_send =
        [&](std::optional<SentPacketRecord> &pending_probe_packet) {
            if (pending_probe_packet.has_value() && !preserve_pto_probe_packets) {
                pending_probe_packet = std::nullopt;
            }
        };
    const auto note_client_handshake_keepalive_probe = [&](const SentPacketRecord &sent_packet) {
        if (!sent_packet.has_ping || retransmittable_probe_frame_count(sent_packet) != 0) {
            return;
        }

        last_client_handshake_keepalive_probe_time_ = now;
    };
    const bool defer_server_compatible_negotiation_crypto =
        (config_.role == EndpointRole::server) && (original_version_ != current_version_) &&
        !peer_transport_parameters_validated_;
    const auto initial_packet_version =
        defer_server_compatible_negotiation_crypto ? original_version_ : current_version_;
    static const std::vector<std::byte> kEmptyInitialToken;
    const std::vector<std::byte> &initial_token =
        config_.role == EndpointRole::client ? config_.retry_token : kEmptyInitialToken;
    const auto make_serialize_context = [&]() -> CodecResult<SerializeProtectionContext> {
        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.write_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(handshake_ready.error().code,
                                                                    handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.write_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(zero_rtt_ready.error().code,
                                                                    zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_space_.write_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                    one_rtt_ready.error().offset);
        }

        return CodecResult<SerializeProtectionContext>::success(SerializeProtectionContext{
            .local_role = config_.role,
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.write_secret,
            .zero_rtt_secret = zero_rtt_space_.write_secret,
            .one_rtt_secret = application_space_.write_secret,
            .one_rtt_key_phase = application_write_key_phase_,
        });
    };

    const auto serialize_candidate_datagram_with_metadata =
        [&](const std::vector<ProtectedPacket> &candidate_packets,
            const ProtectedPacket *appended_packet = nullptr,
            const ProtectedOneRttPacketView *appended_one_rtt_packet = nullptr,
            const ProtectedOneRttPacketFragmentView *appended_one_rtt_fragment_packet =
                nullptr) -> CodecResult<SerializedProtectedDatagram> {
        auto datagram_packets = candidate_packets;
        const auto context = make_serialize_context();
        if (!context.has_value()) {
            return CodecResult<SerializedProtectedDatagram>::failure(context.error().code,
                                                                     context.error().offset);
        }

        const auto serialize_datagram = [&](const SerializeProtectionContext &serialize_context)
            -> CodecResult<SerializedProtectedDatagram> {
            if (appended_one_rtt_packet != nullptr) {
                auto encoded =
                    serialize_protected_datagram_with_metadata(datagram_packets, serialize_context);
                if (!encoded.has_value()) {
                    return encoded;
                }
                const auto offset = encoded.value().bytes.size();
                const auto appended = append_protected_one_rtt_packet_to_datagram(
                    encoded.value().bytes, *appended_one_rtt_packet, serialize_context);
                if (!appended.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        appended.error().code, appended.error().offset);
                }
                encoded.value().packet_metadata.push_back(SerializedProtectedPacketMetadata{
                    .offset = offset,
                    .length = appended.value(),
                });
                return encoded;
            }
            if (appended_one_rtt_fragment_packet != nullptr) {
                auto encoded =
                    serialize_protected_datagram_with_metadata(datagram_packets, serialize_context);
                if (!encoded.has_value()) {
                    return encoded;
                }
                const auto offset = encoded.value().bytes.size();
                const auto appended = append_protected_one_rtt_packet_to_datagram(
                    encoded.value().bytes, *appended_one_rtt_fragment_packet, serialize_context);
                if (!appended.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        appended.error().code, appended.error().offset);
                }
                encoded.value().packet_metadata.push_back(SerializedProtectedPacketMetadata{
                    .offset = offset,
                    .length = appended.value(),
                });
                return encoded;
            }
            if (appended_packet == nullptr) {
                return serialize_protected_datagram_with_metadata(datagram_packets,
                                                                  serialize_context);
            }
            return serialize_protected_datagram_with_metadata(datagram_packets, *appended_packet,
                                                              serialize_context);
        };

        auto datagram = serialize_datagram(context.value());
        if (!datagram.has_value()) {
            return datagram;
        }

        if (datagram.value().bytes.size() >= kMinimumInitialDatagramSize) {
            return datagram;
        }

        for (auto &packet : datagram_packets) {
            auto *initial = std::get_if<ProtectedInitialPacket>(&packet);
            if (initial == nullptr) {
                continue;
            }

            const auto frames_without_padding = initial->frames;
            const auto padding_deficit =
                kMinimumInitialDatagramSize - datagram.value().bytes.size();
            const auto serialize_padded_initial =
                [&](std::size_t padding_length) -> CodecResult<SerializedProtectedDatagram> {
                initial->frames = frames_without_padding;
                initial->frames.insert(initial->frames.end(),
                                       static_cast<std::size_t>(padding_length != 0),
                                       Frame{PaddingFrame{
                                           .length = padding_length,
                                       }});

                const auto padded_context = make_serialize_context();
                if (!padded_context.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        padded_context.error().code, padded_context.error().offset);
                }

                return serialize_datagram(padded_context.value());
            };

            auto padded_datagram = serialize_padded_initial(padding_deficit);
            if (!padded_datagram.has_value()) {
                return padded_datagram;
            }

            if (padded_datagram.value().bytes.size() == kMinimumInitialDatagramSize) {
                return CodecResult<SerializedProtectedDatagram>::success(
                    std::move(padded_datagram.value()));
            }

            // Padding here only adjusts a single Initial packet. The only reachable size jump in
            // this path is the one-byte growth of the long-header length varint, so retrying with
            // one less byte covers the alternate exact-1200 serialization.
            auto alternate_padded_datagram = serialize_padded_initial(padding_deficit - 1);
            if (!alternate_padded_datagram.has_value()) {
                return alternate_padded_datagram;
            }
            return CodecResult<SerializedProtectedDatagram>::success(
                std::move(alternate_padded_datagram.value()));
        }

        return datagram;
    };
    const auto serialize_candidate_datagram =
        [&](const std::vector<ProtectedPacket> &candidate_packets)
        -> CodecResult<std::vector<std::byte>> {
        auto datagram = serialize_candidate_datagram_with_metadata(candidate_packets);
        if (!datagram.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(datagram.error().code,
                                                                datagram.error().offset);
        }

        return CodecResult<std::vector<std::byte>>::success(std::move(datagram.value().bytes));
    };
    const auto commit_serialized_datagram =
        [&](const std::vector<ProtectedPacket> &datagram_packets,
            SerializedProtectedDatagram datagram) {
            if (pto_probe_burst_active) {
                --remaining_pto_probe_datagrams_;
                if (remaining_pto_probe_datagrams_ == 0) {
                    initial_space_.pending_probe_packet = std::nullopt;
                    handshake_space_.pending_probe_packet = std::nullopt;
                    application_space_.pending_probe_packet = std::nullopt;
                }
            }

            if (config_.role == EndpointRole::client) {
                for (const auto &packet : datagram_packets) {
                    if (std::holds_alternative<ProtectedHandshakePacket>(packet)) {
                        discard_initial_packet_space();
                        break;
                    }
                }
            }

            if (qlog_session_ != nullptr) {
                const auto outbound_datagram_id =
                    std::optional<std::uint32_t>(qlog_session_->next_outbound_datagram_id());
                for (std::size_t index = 0; index < datagram_packets.size(); ++index) {
                    const auto packet_number = std::visit(
                        [](const auto &packet_value) { return packet_value.packet_number; },
                        datagram_packets[index]);
                    auto snapshot = make_qlog_packet_snapshot(
                        datagram_packets[index],
                        qlog::PacketSnapshotContext{
                            .raw_length = datagram.packet_metadata[index].length,
                            .datagram_id = *outbound_datagram_id,
                            .trigger = pto_probe_burst_active
                                           ? std::optional<std::string>("pto_probe")
                                           : std::nullopt,
                        });
                    static_cast<void>(qlog_session_->write_event(
                        now, "quic:packet_sent", qlog::serialize_packet_snapshot(snapshot)));
                    auto snapshot_ptr = std::make_shared<qlog::PacketSnapshot>(snapshot);

                    for (auto *packet_space :
                         {&initial_space_, &handshake_space_, &application_space_}) {
                        const auto sent = packet_space->sent_packets.find(packet_number);
                        if (sent == packet_space->sent_packets.end()) {
                            continue;
                        }

                        sent->second.qlog_packet_snapshot = snapshot_ptr;
                        sent->second.qlog_pto_probe = pto_probe_burst_active;
                    }
                }
            }

            note_outbound_datagram_bytes(datagram.bytes.size(), selected_send_path_id);
            last_drained_path_id_ = selected_send_path_id;
            last_drained_ecn_codepoint_ = outbound_ecn_codepoint_for_path(selected_send_path_id);
            return std::move(datagram.bytes);
        };
    const auto finalize_datagram = [&](const std::vector<ProtectedPacket> &datagram_packets) {
        auto datagram = serialize_candidate_datagram_with_metadata(datagram_packets);
        if (!datagram.has_value()) {
            mark_failed();
            return std::vector<std::byte>{};
        }

        return commit_serialized_datagram(datagram_packets, std::move(datagram.value()));
    };
    const auto trim_crypto_ranges_to_fit =
        [&](auto &&serialize_with_crypto_ranges, auto &&restore_trimmed_crypto,
            std::vector<ByteRange> &crypto_ranges) -> CodecResult<std::vector<std::byte>> {
        auto datagram = serialize_with_crypto_ranges(crypto_ranges);
        if (!datagram.has_value()) {
            return datagram;
        }

        while (datagram.value().size() > max_outbound_datagram_size && !crypto_ranges.empty()) {
            auto &last_range = crypto_ranges.back();
            const auto overshoot = datagram.value().size() - max_outbound_datagram_size;
            const auto trim_bytes = std::min<std::size_t>(overshoot, last_range.bytes.size());
            if (trim_bytes == last_range.bytes.size()) {
                restore_trimmed_crypto(last_range.offset, last_range.bytes.size());
                crypto_ranges.pop_back();
            } else {
                const auto retained_bytes = last_range.bytes.size() - trim_bytes;
                restore_trimmed_crypto(last_range.offset + retained_bytes, trim_bytes);
                last_range.bytes.resize(retained_bytes);
            }

            datagram = serialize_with_crypto_ranges(crypto_ranges);
            if (!datagram.has_value()) {
                return datagram;
            }
        }

        return datagram;
    };

    const auto initial_ack_frame =
        (initial_space_.pending_probe_packet.has_value() &&
         initial_space_.pending_probe_packet->force_ack)
            ? initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now,
                                                              /*allow_non_pending=*/true)
            : initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now);
    auto initial_crypto_ranges = std::vector<ByteRange>{};
    if (!defer_server_compatible_negotiation_crypto) {
        initial_crypto_ranges =
            initial_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    const auto build_initial_frames = [&](std::span<const ByteRange> crypto_ranges) {
        std::vector<Frame> frames;
        frames.reserve(crypto_ranges.size() + (initial_ack_frame.has_value() ? 1u : 0u) +
                       (initial_space_.pending_probe_packet.has_value()
                            ? initial_space_.pending_probe_packet->crypto_ranges.size() + 1u
                            : 0u));
        for (const auto &range : crypto_ranges) {
            frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (initial_ack_frame.has_value() && crypto_ranges.empty()) {
            frames.emplace_back(*initial_ack_frame);
        }
        if (!defer_server_compatible_negotiation_crypto &&
            initial_space_.pending_probe_packet.has_value() && !has_ack_eliciting_frame(frames)) {
            for (const auto &range : initial_space_.pending_probe_packet->crypto_ranges) {
                frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(frames)) {
                frames.emplace_back(PingFrame{});
            }
        }

        return frames;
    };
    auto initial_frames = build_initial_frames(initial_crypto_ranges);
    if (!initial_frames.empty()) {
        const bool duplicate_compatible_negotiation_initial_crypto =
            duplicate_first_compatible_server_initial_crypto && !initial_crypto_ranges.empty();
        auto sent_initial_crypto_ranges = initial_crypto_ranges;
        const auto serialize_initial_candidate =
            [&](std::span<const ByteRange> crypto_ranges) -> CodecResult<std::vector<std::byte>> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .token = initial_token,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = initial_space_.next_send_packet_number,
                .frames = build_initial_frames(crypto_ranges),
            });
            return serialize_candidate_datagram(candidate_packets);
        };
        auto initial_candidate_datagram = trim_crypto_ranges_to_fit(
            serialize_initial_candidate,
            [&](std::uint64_t offset, std::size_t length) {
                initial_space_.send_crypto.mark_unsent(offset, length);
            },
            sent_initial_crypto_ranges);
        if (!initial_candidate_datagram.has_value()) {
            mark_failed();
            return {};
        }
        auto sent_initial_frames = build_initial_frames(sent_initial_crypto_ranges);
        const bool initial_ack_eliciting = has_ack_eliciting_frame(sent_initial_frames);
        if (initial_candidate_datagram.value().size() > max_outbound_datagram_size) {
            const bool blocked_first_server_initial =
                (initial_space_.next_send_packet_number == 0) & initial_ack_eliciting;
            if (blocked_first_server_initial) {
                return {};
            }
        } else {
            const auto packet_number = initial_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .token = initial_token,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = packet_number,
                .frames = sent_initial_frames,
            });
        }

        if (initial_candidate_datagram.value().size() <= max_outbound_datagram_size) {
            SentPacketRecord sent_packet{
                .packet_number = initial_space_.next_send_packet_number - 1,
                .sent_time = now,
                .ack_eliciting = initial_ack_eliciting,
                .in_flight = initial_ack_eliciting,
                .declared_lost = false,
                .crypto_ranges = sent_initial_crypto_ranges,
            };
            sent_packet.path_id = selected_send_path_id.value_or(0);
            sent_packet.ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
            if (!defer_server_compatible_negotiation_crypto &&
                initial_space_.pending_probe_packet.has_value() &&
                sent_packet.crypto_ranges.empty()) {
                sent_packet.crypto_ranges = initial_space_.pending_probe_packet->crypto_ranges;
                sent_packet.has_ping = initial_space_.pending_probe_packet->has_ping;
            }
            track_sent_packet(initial_space_, sent_packet);
            if (track_client_handshake_keepalive_probes) {
                note_client_handshake_keepalive_probe(sent_packet);
            }
            if (initial_space_.received_packets.has_ack_to_send()) {
                initial_space_.received_packets.on_ack_sent();
                initial_space_.pending_ack_deadline = std::nullopt;
                initial_space_.force_ack_send = false;
            }
            if (!defer_server_compatible_negotiation_crypto) {
                clear_probe_packet_after_send(initial_space_.pending_probe_packet);
            }

            if (duplicate_compatible_negotiation_initial_crypto) {
                const auto duplicate_packet_number = initial_space_.next_send_packet_number;
                auto duplicate_candidate_packets = packets;
                duplicate_candidate_packets.emplace_back(ProtectedInitialPacket{
                    .version = initial_packet_version,
                    .destination_connection_id = initial_destination_connection_id,
                    .source_connection_id = config_.source_connection_id,
                    .token = initial_token,
                    .packet_number_length = kDefaultInitialPacketNumberLength,
                    .packet_number = duplicate_packet_number,
                    .frames = sent_initial_frames,
                });
                auto duplicate_candidate_datagram =
                    serialize_candidate_datagram(duplicate_candidate_packets);
                if (!duplicate_candidate_datagram.has_value()) {
                    mark_failed();
                    return {};
                }
                if (duplicate_candidate_datagram.value().size() <= max_outbound_datagram_size) {
                    packets = std::move(duplicate_candidate_packets);
                    ++initial_space_.next_send_packet_number;
                    track_sent_packet(
                        initial_space_,
                        SentPacketRecord{
                            .packet_number = duplicate_packet_number,
                            .sent_time = now,
                            .ack_eliciting = initial_ack_eliciting,
                            .in_flight = initial_ack_eliciting,
                            .declared_lost = false,
                            .crypto_ranges = sent_initial_crypto_ranges,
                            .path_id = selected_send_path_id.value_or(0),
                            .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                        });
                }
            }
        }

        if (config_.role == EndpointRole::client &&
            initial_destination_connection_id != destination_connection_id) {
            return finalize_datagram(packets);
        }
    }

    const auto max_handshake_crypto_bytes =
        std::numeric_limits<std::size_t>::max() *
        static_cast<std::size_t>(!defer_server_compatible_negotiation_crypto);
    auto handshake_crypto_ranges =
        handshake_space_.send_crypto.take_ranges(max_handshake_crypto_bytes);
    const auto build_handshake_frames = [&](std::span<const ByteRange> crypto_ranges,
                                            bool override_probe_crypto_ranges = false,
                                            std::span<const ByteRange> probe_crypto_ranges = {}) {
        const auto handshake_ack_frame =
            (handshake_space_.pending_probe_packet.has_value() &&
             handshake_space_.pending_probe_packet->force_ack)
                ? handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now,
                                                                    /*allow_non_pending=*/true)
                : handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now);
        std::vector<Frame> frames;
        frames.reserve(crypto_ranges.size() + (handshake_ack_frame.has_value() ? 1u : 0u) +
                       (handshake_space_.pending_probe_packet.has_value()
                            ? handshake_space_.pending_probe_packet->crypto_ranges.size() + 1u
                            : 0u));
        if (handshake_ack_frame.has_value()) {
            frames.emplace_back(*handshake_ack_frame);
        }
        for (const auto &range : crypto_ranges) {
            frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (handshake_space_.pending_probe_packet.has_value() && !has_ack_eliciting_frame(frames)) {
            const auto active_probe_crypto_ranges =
                override_probe_crypto_ranges
                    ? probe_crypto_ranges
                    : std::span<const ByteRange>(
                          handshake_space_.pending_probe_packet->crypto_ranges);
            for (const auto &range : active_probe_crypto_ranges) {
                frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(frames)) {
                frames.emplace_back(PingFrame{});
            }
        }

        return frames;
    };
    auto handshake_frames = build_handshake_frames(handshake_crypto_ranges);
    if (!handshake_frames.empty()) {
        if (!handshake_space_.write_secret.has_value()) {
            mark_failed();
            return {};
        }

        auto sent_handshake_crypto_ranges = handshake_crypto_ranges;
        auto sent_handshake_probe_crypto_ranges =
            handshake_space_.pending_probe_packet.has_value()
                ? handshake_space_.pending_probe_packet->crypto_ranges
                : std::vector<ByteRange>{};
        const auto serialize_handshake_candidate =
            [&](std::span<const ByteRange> crypto_ranges) -> CodecResult<std::vector<std::byte>> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedHandshakePacket{
                .version = current_version_,
                .destination_connection_id = destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = handshake_space_.next_send_packet_number,
                .frames = build_handshake_frames(crypto_ranges),
            });
            return serialize_candidate_datagram(candidate_packets);
        };
        const auto serialize_handshake_probe_candidate =
            [&](std::span<const ByteRange> probe_crypto_ranges)
            -> CodecResult<std::vector<std::byte>> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedHandshakePacket{
                .version = current_version_,
                .destination_connection_id = destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = handshake_space_.next_send_packet_number,
                .frames = build_handshake_frames(sent_handshake_crypto_ranges,
                                                 /*override_probe_crypto_ranges=*/true,
                                                 probe_crypto_ranges),
            });
            return serialize_candidate_datagram(candidate_packets);
        };
        auto handshake_candidate_datagram =
            sent_handshake_crypto_ranges.empty() &&
                    handshake_space_.pending_probe_packet.has_value()
                ? trim_crypto_ranges_to_fit(
                      serialize_handshake_probe_candidate, [](std::uint64_t, std::size_t) {},
                      sent_handshake_probe_crypto_ranges)
                : trim_crypto_ranges_to_fit(
                      serialize_handshake_candidate,
                      [&](std::uint64_t offset, std::size_t length) {
                          handshake_space_.send_crypto.mark_unsent(offset, length);
                      },
                      sent_handshake_crypto_ranges);
        if (!handshake_candidate_datagram.has_value()) {
            mark_failed();
            return {};
        }
        auto sent_handshake_frames =
            build_handshake_frames(sent_handshake_crypto_ranges,
                                   sent_handshake_crypto_ranges.empty() &&
                                       handshake_space_.pending_probe_packet.has_value(),
                                   sent_handshake_probe_crypto_ranges);
        if (handshake_candidate_datagram.value().size() > max_outbound_datagram_size) {
            if (!packets.empty()) {
                return finalize_datagram(packets);
            }
            return {};
        }

        const auto packet_number = handshake_space_.next_send_packet_number++;

        packets.emplace_back(ProtectedHandshakePacket{
            .version = current_version_,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = packet_number,
            .frames = sent_handshake_frames,
        });

        SentPacketRecord sent_packet{
            .packet_number = packet_number,
            .sent_time = now,
            .ack_eliciting = has_ack_eliciting_frame(sent_handshake_frames),
            .in_flight = has_ack_eliciting_frame(sent_handshake_frames),
            .declared_lost = false,
            .crypto_ranges = sent_handshake_crypto_ranges,
        };
        sent_packet.path_id = selected_send_path_id.value_or(0);
        sent_packet.ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
        if (handshake_space_.pending_probe_packet.has_value() &&
            sent_packet.crypto_ranges.empty()) {
            sent_packet.crypto_ranges = sent_handshake_probe_crypto_ranges;
            sent_packet.has_ping = handshake_space_.pending_probe_packet->has_ping;
        }
        track_sent_packet(handshake_space_, sent_packet);
        if (track_client_handshake_keepalive_probes) {
            note_client_handshake_keepalive_probe(sent_packet);
        }
        if (handshake_space_.received_packets.has_ack_to_send()) {
            handshake_space_.received_packets.on_ack_sent();
            handshake_space_.pending_ack_deadline = std::nullopt;
            handshake_space_.force_ack_send = false;
        }
        clear_probe_packet_after_send(handshake_space_.pending_probe_packet);
    }

    auto application_crypto_ranges = std::vector<ByteRange>{};
    auto application_crypto_frames = std::vector<Frame>{};
    if (application_space_.write_secret.has_value()) {
        application_crypto_ranges =
            application_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    if (!application_crypto_ranges.empty()) {
        application_crypto_frames.reserve(application_crypto_ranges.size());
        for (const auto &range : application_crypto_ranges) {
            application_crypto_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
    }

    const bool use_zero_rtt_packet_protection = config_.role == EndpointRole::client &&
                                                status_ != HandshakeStatus::connected &&
                                                zero_rtt_space_.write_secret.has_value();
    const bool can_send_one_rtt_packets = application_space_.write_secret.has_value();
    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        maybe_queue_stream_blocked_frame(stream);
    }
    maybe_queue_connection_blocked_frame();
    const bool application_ack_due_now =
        application_space_.received_packets.has_ack_to_send() &&
        (application_space_.force_ack_send ||
         application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
    const bool has_pending_application_payload =
        application_ack_due_now | has_pending_application_send() |
        application_space_.pending_probe_packet.has_value() |
        !pending_new_connection_id_frames_.empty() | !pending_retire_connection_id_frames_.empty() |
        !application_crypto_frames.empty();
    if ((can_send_one_rtt_packets || use_zero_rtt_packet_protection) &&
        has_pending_application_payload) {
        const auto base_ack_frame = use_zero_rtt_packet_protection
                                        ? std::optional<AckFrame>{}
                                        : application_space_.received_packets.build_ack_frame(
                                              local_transport_parameters_.ack_delay_exponent, now);
        const auto maybe_queue_client_ack_only_receive_keepalive_challenge = [&]() {
            const bool has_receive_interest = std::ranges::any_of(
                streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
            const bool has_pending_path_validation =
                std::ranges::any_of(paths_, [](const auto &entry) {
                    return entry.second.pending_response.has_value() ||
                           entry.second.challenge_pending;
                });
            const bool eligible =
                (config_.role == EndpointRole::client) & handshake_confirmed_ &
                base_ack_frame.has_value() & last_peer_activity_time_.has_value() &
                has_receive_interest & !has_pending_application_send() &
                !application_space_.pending_probe_packet.has_value() &
                pending_new_connection_id_frames_.empty() &
                pending_retire_connection_id_frames_.empty() & application_crypto_frames.empty() &
                !has_pending_path_validation & !has_in_flight_ack_eliciting_packet(initial_space_) &
                !has_in_flight_ack_eliciting_packet(handshake_space_) &
                !has_in_flight_ack_eliciting_packet(application_space_) &
                current_send_path_id_.has_value();
            if (!eligible) {
                return;
            }

            auto &path = ensure_path_state(*current_send_path_id_);
            if (!path.validated) {
                return;
            }

            if (!path.outstanding_challenge.has_value()) {
                path.outstanding_challenge = next_path_challenge_data(*current_send_path_id_);
            }
            path.challenge_pending = true;
        };
        maybe_queue_client_ack_only_receive_keepalive_challenge();
        const auto reserve_application_packet_number =
            [&](bool using_one_rtt_packet_protection) -> std::optional<std::uint64_t> {
            const auto packet_number = application_space_.next_send_packet_number;
            if (using_one_rtt_packet_protection) {
                const auto largest_acked =
                    application_space_.recovery.largest_acked_packet_number();
                const bool can_initiate_local_key_update =
                    local_key_update_requested_ && handshake_confirmed_ &&
                    application_space_.read_secret.has_value() && !local_key_update_initiated_ &&
                    current_write_phase_first_packet_number_.has_value() &&
                    largest_acked.has_value() &&
                    *largest_acked >= *current_write_phase_first_packet_number_;
                if (can_initiate_local_key_update) {
                    const auto next_read_secret =
                        derive_next_traffic_secret(*application_space_.read_secret);
                    if (!next_read_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_read_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }

                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }

                    previous_application_read_secret_ = application_space_.read_secret;
                    previous_application_read_key_phase_ = application_read_key_phase_;
                    application_space_.read_secret = next_read_secret.value();
                    application_space_.write_secret = next_write_secret.value();
                    application_read_key_phase_ = !application_read_key_phase_;
                    application_write_key_phase_ = !application_write_key_phase_;
                    local_key_update_requested_ = false;
                    local_key_update_initiated_ = true;
                    current_write_phase_first_packet_number_ = packet_number;
                }
                if (!current_write_phase_first_packet_number_.has_value()) {
                    current_write_phase_first_packet_number_ = packet_number;
                }
            }

            ++application_space_.next_send_packet_number;
            return packet_number;
        };
        const auto take_reset_stream_frames = [](auto &streams) -> std::vector<ResetStreamFrame> {
            std::vector<ResetStreamFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_reset_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_stop_sending_frames = [](auto &streams) -> std::vector<StopSendingFrame> {
            std::vector<StopSendingFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_stop_sending_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_max_stream_data_frames =
            [](auto &streams) -> std::vector<MaxStreamDataFrame> {
            std::vector<MaxStreamDataFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_max_stream_data_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_max_streams_frames =
            [&](bool force_ack_only) -> std::vector<MaxStreamsFrame> {
            if (force_ack_only) {
                return {};
            }

            return local_stream_limit_state_.take_max_streams_frames();
        };
        const auto take_new_connection_id_frames =
            [&](bool force_ack_only) -> std::vector<NewConnectionIdFrame> {
            if (force_ack_only) {
                return {};
            }

            std::vector<NewConnectionIdFrame> frames;
            while (const auto frame = take_pending_new_connection_id_frame()) {
                frames.push_back(*frame);
            }
            return frames;
        };
        const auto take_retire_connection_id_frames =
            [&](bool force_ack_only) -> std::vector<RetireConnectionIdFrame> {
            if (force_ack_only) {
                return {};
            }

            auto frames = std::move(pending_retire_connection_id_frames_);
            pending_retire_connection_id_frames_.clear();
            return frames;
        };
        struct PendingPathValidationFrames {
            QuicPathId path_id = 0;
            std::optional<PathResponseFrame> response;
            std::optional<PathChallengeFrame> challenge;
        };
        const auto mark_path_challenge_sent = [](auto &path) { path.challenge_pending = false; };
        const auto take_path_validation_frames =
            [&](bool force_ack_only) -> PendingPathValidationFrames {
            static_cast<void>(force_ack_only);

            const auto response_path =
                std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                    return entry.second.pending_response.has_value();
                });
            if (response_path != paths_.end()) {
                PendingPathValidationFrames frames{
                    .path_id = response_path->first,
                    .response =
                        PathResponseFrame{
                            .data = *response_path->second.pending_response,
                        },
                };
                response_path->second.pending_response.reset();
                if (response_path->second.challenge_pending &
                    response_path->second.outstanding_challenge.has_value()) {
                    frames.challenge = PathChallengeFrame{
                        .data = *response_path->second.outstanding_challenge,
                    };
                    mark_path_challenge_sent(response_path->second);
                } else if (!response_path->second.validated &
                           !response_path->second.outstanding_challenge.has_value()) {
                    response_path->second.outstanding_challenge =
                        next_path_challenge_data(response_path->first);
                    frames.challenge = PathChallengeFrame{
                        .data = *response_path->second.outstanding_challenge,
                    };
                    mark_path_challenge_sent(response_path->second);
                }
                if (!response_path->second.validated &
                    current_send_path_id_ != response_path->first) {
                    if (current_send_path_id_.has_value()) {
                        previous_path_id_ = current_send_path_id_;
                        if (const auto current = paths_.find(*current_send_path_id_);
                            current != paths_.end()) {
                            current->second.is_current_send_path = false;
                        }
                    }
                    response_path->second.is_current_send_path = true;
                    current_send_path_id_ = response_path->first;
                }
                return frames;
            }

            if (!current_send_path_id_.has_value()) {
                return {};
            }
            const auto path = paths_.find(*current_send_path_id_);
            if (path == paths_.end()) {
                return {};
            }

            PendingPathValidationFrames frames{
                .path_id = *current_send_path_id_,
            };
            if (path->second.challenge_pending & path->second.outstanding_challenge.has_value()) {
                frames.challenge = PathChallengeFrame{
                    .data = *path->second.outstanding_challenge,
                };
                mark_path_challenge_sent(path->second);
            }
            return frames;
        };
        const auto take_stream_data_blocked_frames =
            [](auto &streams) -> std::vector<StreamDataBlockedFrame> {
            std::vector<StreamDataBlockedFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_stream_data_blocked_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_stream_fragments =
            [](auto &connection_flow, auto &streams, std::size_t max_bytes, auto &last_stream_id,
               bool prefer_fresh_data = false) -> std::vector<StreamFrameSendFragment> {
            std::vector<StreamFrameSendFragment> fragments;
            auto remaining_bytes = max_bytes;
            auto remaining_connection_credit =
                connection_flow.peer_max_data > connection_flow.highest_sent
                    ? connection_flow.peer_max_data - connection_flow.highest_sent
                    : 0;
            auto loss_phase = !prefer_fresh_data;
            auto switched_phase = false;
            auto allow_zero_byte_round = true;
            using StreamIterator = decltype(streams.begin());
            std::vector<StreamIterator> active_streams;
            active_streams.reserve(streams.size());
            const auto visit_round_robin = [&](auto &&visit) {
                const auto visit_range = [&](auto begin, auto end) -> bool {
                    for (auto it = begin; it != end; ++it) {
                        if (!visit(it)) {
                            return false;
                        }
                    }
                    return true;
                };

                if (streams.empty()) {
                    return;
                }
                if (!last_stream_id.has_value()) {
                    static_cast<void>(visit_range(streams.begin(), streams.end()));
                    return;
                }

                const auto start = streams.upper_bound(*last_stream_id);
                if (!visit_range(start, streams.end())) {
                    return;
                }
                static_cast<void>(visit_range(streams.begin(), start));
            };

            for (;;) {
                const bool should_continue_round = (remaining_bytes > 0) | allow_zero_byte_round;
                if (!should_continue_round) {
                    break;
                }
                const auto zero_byte_round = remaining_bytes == 0;
                allow_zero_byte_round = false;
                active_streams.clear();
                visit_round_robin([&](const auto it) {
                    auto &stream = it->second;
                    if (stream.reset_state != StreamControlFrameState::none) {
                        return true;
                    }

                    const auto fin_sendable = stream_fin_sendable(stream);
                    const auto active = loss_phase
                                            ? stream.send_buffer.has_lost_data() || fin_sendable
                                            : (stream.sendable_bytes() != 0) || fin_sendable;
                    if (active) {
                        active_streams.push_back(it);
                    }
                    return true;
                });

                if (active_streams.empty()) {
                    if (!switched_phase) {
                        loss_phase = !loss_phase;
                        switched_phase = true;
                        continue;
                    }

                    break;
                }

                std::size_t bytes_sent_this_round = 0;
                bool emitted_fragment = false;
                const auto active_stream_count = active_streams.size();
                for (const auto it : active_streams) {
                    const auto stream_id = it->first;
                    auto &stream = it->second;

                    const auto highest_sent_before = stream.flow_control.highest_sent;
                    const auto packet_share =
                        std::max<std::size_t>(static_cast<std::size_t>(!zero_byte_round),
                                              remaining_bytes / active_stream_count);
                    const auto new_byte_share =
                        loss_phase || remaining_connection_credit == 0
                            ? 0
                            : std::max<std::uint64_t>(1, remaining_connection_credit /
                                                             active_stream_count);
                    auto stream_fragments = stream.take_send_fragments(StreamSendBudget{
                        .packet_bytes = std::min(remaining_bytes, packet_share),
                        .new_bytes = new_byte_share,
                        .prefer_fresh_data = !loss_phase,
                    });
                    const auto new_bytes_sent =
                        stream.flow_control.highest_sent - highest_sent_before;
                    connection_flow.highest_sent += new_bytes_sent;
                    remaining_connection_credit -= new_bytes_sent;
                    const auto fragment_bytes = stream_fragment_bytes(stream_fragments);
                    remaining_bytes -= fragment_bytes;
                    if (!stream_fragments.empty()) {
                        emitted_fragment = true;
                        last_stream_id = stream_id;
                    }
                    bytes_sent_this_round += fragment_bytes;
                    fragments.insert(fragments.end(),
                                     std::make_move_iterator(stream_fragments.begin()),
                                     std::make_move_iterator(stream_fragments.end()));
                    const bool finished_round = (remaining_bytes == 0) & !zero_byte_round;
                    if (finished_round) {
                        break;
                    }
                }

                if (!emitted_fragment || bytes_sent_this_round == 0) {
                    break;
                }
            }

            return fragments;
        };
        const auto append_application_crypto_frames = [](std::vector<Frame> &frames,
                                                         std::span<const ByteRange> crypto_ranges) {
            for (const auto &range : crypto_ranges) {
                frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
        };
        const auto build_application_candidate_frames =
            [&](std::span<const Frame> crypto_frames, bool include_handshake_done,
                const std::optional<AckFrame> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping) -> std::vector<Frame> {
            std::vector<Frame> candidate_frames;
            candidate_frames.reserve(
                crypto_frames.size() + (ack_frame.has_value() ? 1u : 0u) +
                (include_handshake_done ? 1u : 0u) + (max_data_frame.has_value() ? 1u : 0u) +
                new_connection_id_frames.size() + retire_connection_id_frames.size() +
                static_cast<std::size_t>(path_validation_frames.response.has_value()) +
                static_cast<std::size_t>(path_validation_frames.challenge.has_value()) +
                max_stream_data_frames.size() + max_streams_frames.size() +
                reset_stream_frames.size() + stop_sending_frames.size() +
                (data_blocked_frame.has_value() ? 1u : 0u) + stream_data_blocked_frames.size() +
                (application_close_frame.has_value() ? 1u : 0u) + (include_ping ? 1u : 0u));
            candidate_frames.insert(candidate_frames.end(), crypto_frames.begin(),
                                    crypto_frames.end());
            if (ack_frame.has_value()) {
                candidate_frames.emplace_back(*ack_frame);
            }
            if (include_handshake_done) {
                candidate_frames.emplace_back(HandshakeDoneFrame{});
            }
            if (max_data_frame.has_value()) {
                candidate_frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : new_connection_id_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : retire_connection_id_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (path_validation_frames.response.has_value()) {
                candidate_frames.emplace_back(*path_validation_frames.response);
            }
            if (path_validation_frames.challenge.has_value()) {
                candidate_frames.emplace_back(*path_validation_frames.challenge);
            }
            for (const auto &frame : max_stream_data_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : max_streams_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : reset_stream_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : stop_sending_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (data_blocked_frame.has_value()) {
                candidate_frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (application_close_frame.has_value()) {
                candidate_frames.emplace_back(*application_close_frame);
            }
            if (include_ping) {
                candidate_frames.emplace_back(PingFrame{});
            }
            return candidate_frames;
        };
        const auto serialize_application_candidate_from_frames =
            [&](std::span<const Frame> candidate_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool has_application_close, std::uint64_t packet_number, bool write_key_phase,
                std::optional<ProtectedPacket> *serialized_packet)
            -> CodecResult<SerializedProtectedDatagram> {
            if (serialized_packet != nullptr) {
                serialized_packet->reset();
            }

            const bool use_zero_rtt = use_zero_rtt_packet_protection & !has_application_close;
            if (!use_zero_rtt && serialized_packet == nullptr) {
                const auto candidate_destination_connection_id =
                    application_destination_connection_id();
                const auto candidate_packet = ProtectedOneRttPacketFragmentView{
                    .key_phase = write_key_phase,
                    .destination_connection_id = candidate_destination_connection_id,
                    .packet_number_length = kDefaultInitialPacketNumberLength,
                    .packet_number = packet_number,
                    .frames = candidate_frames,
                    .stream_fragments = stream_fragments,
                };
                return serialize_candidate_datagram_with_metadata(packets, nullptr, nullptr,
                                                                  &candidate_packet);
            }

            auto candidate_packet = make_application_protected_packet(
                use_zero_rtt, current_version_, application_destination_connection_id(),
                config_.source_connection_id, write_key_phase, kDefaultInitialPacketNumberLength,
                packet_number, std::vector<Frame>(candidate_frames.begin(), candidate_frames.end()),
                stream_fragments);
            auto candidate_datagram =
                serialize_candidate_datagram_with_metadata(packets, &candidate_packet);
            if (!candidate_datagram.has_value()) {
                return candidate_datagram;
            }
            if (serialized_packet != nullptr) {
                *serialized_packet = std::move(candidate_packet);
            }

            return candidate_datagram;
        };
        const auto serialize_application_candidate =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<AckFrame> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping, std::optional<ProtectedPacket> *serialized_packet)
            -> CodecResult<SerializedProtectedDatagram> {
            std::vector<Frame> crypto_frames;
            crypto_frames.reserve(crypto_ranges.size());
            append_application_crypto_frames(crypto_frames, crypto_ranges);
            auto candidate_frames = build_application_candidate_frames(
                crypto_frames, include_handshake_done, ack_frame, max_data_frame,
                new_connection_id_frames, retire_connection_id_frames, path_validation_frames,
                max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                application_close_frame, include_ping);
            return serialize_application_candidate_from_frames(
                candidate_frames, stream_fragments, application_close_frame.has_value(),
                application_space_.next_send_packet_number, application_write_key_phase_,
                serialized_packet);
        };
        const auto restore_application_fragment = [&](const StreamFrameSendFragment &fragment) {
            const bool releases_flow_control =
                fragment.consumes_flow_control & !fragment.bytes.empty();
            if (releases_flow_control) {
                connection_flow_control_.highest_sent -=
                    static_cast<std::uint64_t>(fragment.bytes.size());
            }
            streams_.at(fragment.stream_id).restore_send_fragment(fragment);
        };
        const auto restore_unsent_application_candidate =
            [&](const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments) {
                for (const auto &range : application_crypto_ranges) {
                    application_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
                if (max_data_frame.has_value()) {
                    connection_flow_control_.mark_max_data_frame_lost(*max_data_frame);
                }
                if (data_blocked_frame.has_value()) {
                    connection_flow_control_.mark_data_blocked_frame_lost(*data_blocked_frame);
                }
                pending_new_connection_id_frames_.insert(pending_new_connection_id_frames_.begin(),
                                                         new_connection_id_frames.begin(),
                                                         new_connection_id_frames.end());
                pending_retire_connection_id_frames_.insert(
                    pending_retire_connection_id_frames_.begin(),
                    retire_connection_id_frames.begin(), retire_connection_id_frames.end());
                if (path_validation_frames.response.has_value()) {
                    auto &path = ensure_path_state(path_validation_frames.path_id);
                    path.pending_response = path_validation_frames.response->data;
                }
                if (path_validation_frames.challenge.has_value()) {
                    auto &path = ensure_path_state(path_validation_frames.path_id);
                    path.challenge_pending = true;
                }
                for (const auto &frame : max_stream_data_frames) {
                    streams_.at(frame.stream_id).mark_max_stream_data_frame_lost(frame);
                }
                for (const auto &frame : max_streams_frames) {
                    local_stream_limit_state_.mark_max_streams_frame_lost(frame);
                }
                for (const auto &frame : stream_data_blocked_frames) {
                    streams_.at(frame.stream_id).mark_stream_data_blocked_frame_lost(frame);
                }
                for (const auto &frame : reset_stream_frames) {
                    streams_.at(frame.stream_id).mark_reset_frame_lost(frame);
                }
                for (const auto &frame : stop_sending_frames) {
                    streams_.at(frame.stream_id).mark_stop_sending_frame_lost(frame);
                }
                for (const auto &fragment : stream_fragments) {
                    restore_application_fragment(fragment);
                }
            };
        const auto trim_application_ack_frame =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<AckFrame> &candidate_ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool include_ping) -> std::optional<AckFrame> {
            if (!candidate_ack_frame.has_value()) {
                return std::nullopt;
            }

            auto candidate_datagram = serialize_application_candidate(
                crypto_ranges, include_handshake_done, candidate_ack_frame, max_data_frame,
                new_connection_id_frames, retire_connection_id_frames, path_validation_frames,
                max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                stream_fragments, std::nullopt, include_ping, nullptr);
            if (!candidate_datagram.has_value()) {
                mark_failed();
                return std::nullopt;
            }
            if (candidate_ack_frame->additional_ranges.empty() ||
                candidate_datagram.value().bytes.size() <= max_outbound_datagram_size) {
                return candidate_ack_frame;
            }

            std::size_t retained_ranges_low = 0;
            std::size_t retained_ranges_high = candidate_ack_frame->additional_ranges.size();
            std::optional<AckFrame> best_trimmed_ack_frame;

            while (retained_ranges_low <= retained_ranges_high) {
                const auto retained_ranges =
                    retained_ranges_low + (retained_ranges_high - retained_ranges_low) / 2;
                auto trimmed_ack_frame = candidate_ack_frame;
                trimmed_ack_frame->additional_ranges.resize(retained_ranges);

                candidate_datagram = serialize_application_candidate(
                    crypto_ranges, include_handshake_done, trimmed_ack_frame, max_data_frame,
                    new_connection_id_frames, retire_connection_id_frames, path_validation_frames,
                    max_stream_data_frames, max_streams_frames, reset_stream_frames,
                    stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                    stream_fragments, std::nullopt, include_ping, nullptr);

                if (candidate_datagram.value().bytes.size() <= max_outbound_datagram_size) {
                    best_trimmed_ack_frame = std::move(trimmed_ack_frame);
                    retained_ranges_low = retained_ranges + 1;
                    continue;
                }

                if (retained_ranges == 0) {
                    break;
                }
                retained_ranges_high = retained_ranges - 1;
            }

            return best_trimmed_ack_frame;
        };

        const auto *pending_application_probe = application_space_.pending_probe_packet.has_value()
                                                    ? &*application_space_.pending_probe_packet
                                                    : nullptr;
        const auto has_pending_application_stream_send = [&]() {
            const auto connection_send_credit = saturating_subtract(
                connection_flow_control_.peer_max_data, connection_flow_control_.highest_sent);
            for (const auto &[stream_id, stream] : streams_) {
                static_cast<void>(stream_id);
                if (stream.reset_state != StreamControlFrameState::none) {
                    continue;
                }

                if (stream.send_buffer.has_lost_data() | stream_fin_sendable(stream)) {
                    return true;
                }
                if ((connection_send_credit != 0) & (stream.sendable_bytes() != 0)) {
                    return true;
                }
            }

            return false;
        };
        const bool prefer_fresh_application_stream_data =
            (pending_application_probe != nullptr) & (remaining_pto_probe_datagrams_ == 1) &
            has_pending_fresh_application_stream_send();
        const auto should_send_application_probe_first = [&]() {
            const auto validation_only_path_id = [&]() -> std::optional<QuicPathId> {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return response_path->first;
                }
                return current_send_path_id_;
            }();
            if (validation_only_path_id.has_value()) {
                const auto validation_path = paths_.find(*validation_only_path_id);
                if (validation_path != paths_.end() && !validation_path->second.validated &&
                    !validation_path->second.validation_initiated_locally) {
                    return false;
                }
            }
            if (pending_application_probe == nullptr) {
                return false;
            }

            const auto probe_has_path_validation = [&]() {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return true;
                }

                if (!current_send_path_id_.has_value()) {
                    return false;
                }

                const auto current_path = paths_.find(*current_send_path_id_);
                const bool has_current_path = current_path != paths_.end();
                const bool challenge_pending =
                    has_current_path ? current_path->second.challenge_pending : false;
                const bool has_outstanding_challenge =
                    has_current_path ? current_path->second.outstanding_challenge.has_value()
                                     : false;
                return static_cast<bool>(has_current_path & challenge_pending &
                                         has_outstanding_challenge);
            }();

            if (has_pending_application_stream_send()) {
                // If there is queued stream response data, don't let a control-only PTO probe
                // starve it; use the PTO opportunity to send the response.
                if (pending_application_probe->stream_fragments.empty()) {
                    return false;
                }

                // On the last datagram of a PTO burst, spend the remaining probe credit on
                // fresh queued stream data instead of retransmitting the same stream fragment
                // again.
                if (prefer_fresh_application_stream_data) {
                    return false;
                }
            }

            const bool probe_is_retransmittable =
                (retransmittable_probe_frame_count(*pending_application_probe) != 0) |
                probe_has_path_validation;
            return static_cast<bool>(probe_is_retransmittable | !has_pending_application_send());
        };

        if (should_send_application_probe_first()) {
            const auto &probe_packet = *pending_application_probe;
            auto probe_max_data_frame = probe_packet.max_data_frame;
            std::optional<MaxDataFrame> fresh_probe_max_data_frame;
            auto probe_max_stream_data_frames = probe_packet.max_stream_data_frames;
            std::vector<MaxStreamDataFrame> fresh_probe_max_stream_data_frames;
            if (probe_packet.force_ack) {
                maybe_refresh_connection_receive_credit(/*force=*/true);
                if (!probe_max_data_frame.has_value() &
                    (connection_flow_control_.max_data_state == StreamControlFrameState::pending) &
                    connection_flow_control_.pending_max_data_frame.has_value()) {
                    fresh_probe_max_data_frame = connection_flow_control_.pending_max_data_frame;
                    probe_max_data_frame = fresh_probe_max_data_frame;
                }

                for (auto &[stream_id, stream] : streams_) {
                    static_cast<void>(stream_id);
                    maybe_refresh_stream_receive_credit(stream, /*force=*/true);
                    if ((stream.flow_control.max_stream_data_state !=
                         StreamControlFrameState::pending) |
                        !stream.flow_control.pending_max_stream_data_frame.has_value()) {
                        continue;
                    }

                    const auto frame = stream.flow_control.pending_max_stream_data_frame.value_or(
                        MaxStreamDataFrame{});
                    const bool already_selected = std::ranges::any_of(
                        probe_max_stream_data_frames, [&](const MaxStreamDataFrame &selected) {
                            return (selected.stream_id == frame.stream_id) &
                                   (selected.maximum_stream_data == frame.maximum_stream_data);
                        });
                    if (already_selected) {
                        continue;
                    }

                    fresh_probe_max_stream_data_frames.push_back(frame);
                    probe_max_stream_data_frames.push_back(frame);
                }
            }
            const auto probe_base_ack_frame =
                probe_packet.force_ack ? application_space_.received_packets.build_ack_frame(
                                             local_transport_parameters_.ack_delay_exponent, now,
                                             /*allow_non_pending=*/true)
                                       : base_ack_frame;
            const auto &probe_crypto_ranges = application_crypto_ranges.empty()
                                                  ? probe_packet.crypto_ranges
                                                  : application_crypto_ranges;
            const auto include_ping = retransmittable_probe_frame_count(probe_packet) == 0;
            const auto restore_unsent_path_validation_frames =
                [&](const PendingPathValidationFrames &path_validation_frames) {
                    if (path_validation_frames.response.has_value()) {
                        auto &path = ensure_path_state(path_validation_frames.path_id);
                        path.pending_response = path_validation_frames.response->data;
                    }
                    if (path_validation_frames.challenge.has_value()) {
                        auto &path = ensure_path_state(path_validation_frames.path_id);
                        path.challenge_pending = true;
                    }
                };
            const auto make_probe_stream_fragments = [&]() {
                auto fragments = probe_packet.stream_fragments;
                for (auto &fragment : fragments) {
                    fragment.consumes_flow_control = false;
                }
                return fragments;
            };
            const auto restore_probe_fragment = [&](const StreamFrameSendFragment &fragment) {
                const auto stream = streams_.find(fragment.stream_id);
                if (stream == streams_.end()) {
                    return;
                }

                stream->second.mark_send_fragment_lost(fragment);
            };
            const auto mark_probe_fragments_sent =
                [&](std::span<const StreamFrameSendFragment> fragments) {
                    for (const auto &fragment : fragments) {
                        const auto stream = streams_.find(fragment.stream_id);
                        if (stream == streams_.end()) {
                            continue;
                        }

                        stream->second.mark_send_fragment_sent(fragment);
                    }
                };
            const auto restore_unsent_application_probe_candidate = [&]() {
                for (const auto &range : application_crypto_ranges) {
                    application_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
            };
            auto path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
            selected_send_path_id = path_validation_frames.response.has_value()
                                        ? std::optional<QuicPathId>{path_validation_frames.path_id}
                                        : current_send_path_id_;
            auto probe_stream_fragments = make_probe_stream_fragments();
            mark_probe_fragments_sent(probe_stream_fragments);
            auto ack_frame = trim_application_ack_frame(
                probe_crypto_ranges, probe_packet.has_handshake_done, probe_base_ack_frame,
                probe_max_data_frame, {}, {}, path_validation_frames, probe_max_stream_data_frames,
                probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                probe_packet.stream_data_blocked_frames, probe_stream_fragments, include_ping);
            if (has_failed()) {
                return {};
            }

            auto datagram = serialize_application_candidate(
                probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                probe_max_data_frame, {}, {}, path_validation_frames, probe_max_stream_data_frames,
                probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                probe_packet.stream_data_blocked_frames, probe_stream_fragments, std::nullopt,
                include_ping, nullptr);
            if (!datagram.has_value()) {
                mark_failed();
                return {};
            }
            if (ack_frame.has_value() &&
                datagram.value().bytes.size() > max_outbound_datagram_size) {
                auto no_ack_datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, std::nullopt,
                    probe_max_data_frame, {}, {}, path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    probe_stream_fragments, std::nullopt, include_ping, nullptr);
                if (!no_ack_datagram.has_value()) {
                    mark_failed();
                    return {};
                }
                if (no_ack_datagram.value().bytes.size() <= max_outbound_datagram_size) {
                    ack_frame = std::nullopt;
                    datagram = std::move(no_ack_datagram);
                }
            }
            const auto trim_probe_candidate_to_fit =
                [&](const std::optional<AckFrame> &candidate_ack_frame,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().bytes.size() > max_outbound_datagram_size &&
                       !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_probe_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot =
                            datagram.value().bytes.size() - max_outbound_datagram_size;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_probe_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = false,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            restore_probe_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, candidate_ack_frame,
                        probe_max_data_frame, {}, {}, path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                        probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                        fragments, std::nullopt, include_ping, nullptr);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().bytes.size() <= max_outbound_datagram_size;
            };
            if (!trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments)) {
                if (has_failed()) {
                    return {};
                }

                if (ack_frame.has_value()) {
                    ack_frame = std::nullopt;
                    probe_stream_fragments = make_probe_stream_fragments();
                    mark_probe_fragments_sent(probe_stream_fragments);
                    datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                        probe_max_data_frame, {}, {}, path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                        probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                        probe_stream_fragments, std::nullopt, include_ping, nullptr);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return {};
                    }
                    static_cast<void>(
                        trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments));
                }
            }
            const auto retry_probe_candidate_without_fresh_receive_credit = [&]() -> bool {
                if (!fresh_probe_max_data_frame.has_value() &&
                    fresh_probe_max_stream_data_frames.empty()) {
                    return true;
                }

                probe_max_data_frame = probe_packet.max_data_frame;
                probe_max_stream_data_frames = probe_packet.max_stream_data_frames;
                fresh_probe_max_data_frame = std::nullopt;
                fresh_probe_max_stream_data_frames.clear();
                probe_stream_fragments = make_probe_stream_fragments();
                mark_probe_fragments_sent(probe_stream_fragments);
                datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                    probe_max_data_frame, {}, {}, path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    probe_stream_fragments, std::nullopt, include_ping, nullptr);
                if (!datagram.has_value()) {
                    mark_failed();
                    return false;
                }
                if (ack_frame.has_value() &&
                    datagram.value().bytes.size() > max_outbound_datagram_size) {
                    auto no_ack_datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, std::nullopt,
                        probe_max_data_frame, {}, {}, path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                        probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                        probe_stream_fragments, std::nullopt, include_ping, nullptr);
                    if (!no_ack_datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                    if (no_ack_datagram.value().bytes.size() <= max_outbound_datagram_size) {
                        ack_frame = std::nullopt;
                        datagram = std::move(no_ack_datagram);
                    }
                }
                if (!trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments)) {
                    if (has_failed()) {
                        return false;
                    }

                    if (ack_frame.has_value()) {
                        ack_frame = std::nullopt;
                        probe_stream_fragments = make_probe_stream_fragments();
                        mark_probe_fragments_sent(probe_stream_fragments);
                        datagram = serialize_application_candidate(
                            probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                            probe_max_data_frame, {}, {}, path_validation_frames,
                            probe_max_stream_data_frames, probe_packet.max_streams_frames,
                            probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                            probe_packet.data_blocked_frame,
                            probe_packet.stream_data_blocked_frames, probe_stream_fragments,
                            std::nullopt, include_ping, nullptr);
                        if (!datagram.has_value()) {
                            mark_failed();
                            return false;
                        }
                        static_cast<void>(
                            trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments));
                    }
                }

                return !has_failed();
            };
            auto probe_datagram_size = datagram_size_or_zero(datagram);
            if (probe_datagram_size > max_outbound_datagram_size) {
                if (!retry_probe_candidate_without_fresh_receive_credit()) {
                    return {};
                }
                probe_datagram_size = datagram_size_or_zero(datagram);
            }
            if (probe_datagram_size > max_outbound_datagram_size) {
                restore_unsent_application_probe_candidate();
                restore_unsent_path_validation_frames(path_validation_frames);
                if (!packets.empty()) {
                    return finalize_datagram(packets);
                }
                if (max_outbound_datagram_size == kMaximumDatagramSize) {
                    mark_failed();
                    return {};
                }
                return {};
            }

            std::vector<Frame> frames;
            frames.reserve(
                probe_crypto_ranges.size() + (ack_frame.has_value() ? 1u : 0u) +
                (probe_packet.has_handshake_done ? 1u : 0u) +
                (probe_max_data_frame.has_value() ? 1u : 0u) +
                static_cast<std::size_t>(path_validation_frames.response.has_value()) +
                static_cast<std::size_t>(path_validation_frames.challenge.has_value()) +
                probe_max_stream_data_frames.size() + probe_packet.max_streams_frames.size() +
                probe_packet.reset_stream_frames.size() + probe_packet.stop_sending_frames.size() +
                (probe_packet.data_blocked_frame.has_value() ? 1u : 0u) +
                probe_packet.stream_data_blocked_frames.size() + (include_ping ? 1u : 0u));
            append_application_crypto_frames(frames, probe_crypto_ranges);
            if (ack_frame.has_value()) {
                frames.emplace_back(*ack_frame);
            }
            if (probe_packet.has_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            if (probe_max_data_frame.has_value()) {
                frames.emplace_back(*probe_max_data_frame);
            }
            if (path_validation_frames.response.has_value()) {
                frames.emplace_back(*path_validation_frames.response);
            }
            if (path_validation_frames.challenge.has_value()) {
                frames.emplace_back(*path_validation_frames.challenge);
            }
            for (const auto &frame : probe_max_stream_data_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.max_streams_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.reset_stream_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.stop_sending_frames) {
                frames.emplace_back(frame);
            }
            if (probe_packet.data_blocked_frame.has_value()) {
                frames.emplace_back(*probe_packet.data_blocked_frame);
            }
            for (const auto &frame : probe_packet.stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }
            if (include_ping) {
                frames.emplace_back(PingFrame{});
            }

            const auto packet_number =
                reserve_application_packet_number(!use_zero_rtt_packet_protection);
            if (!packet_number.has_value()) {
                return {};
            }
            packets.emplace_back(make_application_protected_packet(
                use_zero_rtt_packet_protection, current_version_,
                application_destination_connection_id(), config_.source_connection_id,
                application_write_key_phase_, kDefaultInitialPacketNumberLength, *packet_number,
                std::move(frames), probe_stream_fragments));
            if (fresh_probe_max_data_frame.has_value()) {
                static_cast<void>(connection_flow_control_.take_max_data_frame());
            }
            for (const auto &frame : fresh_probe_max_stream_data_frames) {
                static_cast<void>(streams_.at(frame.stream_id).take_max_stream_data_frame());
            }

            track_sent_packet(
                application_space_,
                SentPacketRecord{
                    .packet_number = *packet_number,
                    .sent_time = now,
                    .ack_eliciting = true,
                    .in_flight = true,
                    .declared_lost = false,
                    .has_handshake_done = probe_packet.has_handshake_done,
                    .crypto_ranges = probe_crypto_ranges,
                    .reset_stream_frames = probe_packet.reset_stream_frames,
                    .stop_sending_frames = probe_packet.stop_sending_frames,
                    .max_data_frame = probe_max_data_frame,
                    .max_stream_data_frames = probe_max_stream_data_frames,
                    .max_streams_frames = probe_packet.max_streams_frames,
                    .data_blocked_frame = probe_packet.data_blocked_frame,
                    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
                    .stream_fragments = probe_stream_fragments,
                    .has_ping = include_ping,
                    .bytes_in_flight = datagram.value().bytes.size(),
                    .path_id = selected_send_path_id.value_or(0),
                    .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                });
            if (probe_packet.has_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            if (preserve_pto_probe_packets) {
                restore_unsent_path_validation_frames(path_validation_frames);
            }
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        } else {
            const auto include_handshake_done =
                !use_zero_rtt_packet_protection && config_.role == EndpointRole::server &&
                handshake_done_state_ == StreamControlFrameState::pending;
            const auto validation_only_path_id = [&]() -> std::optional<QuicPathId> {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return response_path->first;
                }
                return current_send_path_id_;
            }();
            const bool validation_only_send = [&]() {
                if (!validation_only_path_id.has_value()) {
                    return false;
                }
                const auto validation_path = paths_.find(*validation_only_path_id);
                const bool has_validation_path = validation_path != paths_.end();
                const bool path_unvalidated =
                    has_validation_path ? !validation_path->second.validated : false;
                const bool remotely_initiated =
                    has_validation_path ? !validation_path->second.validation_initiated_locally
                                        : false;
                return static_cast<bool>(has_validation_path & path_unvalidated &
                                         remotely_initiated);
            }();
            const auto application_close_frame = pending_application_close_;
            const bool send_application_close_only = application_close_frame.has_value();
            if (application_close_frame.has_value() && !can_send_one_rtt_packets) {
                return {};
            }
            const auto application_candidate_crypto_ranges =
                send_application_close_only ? std::span<const ByteRange>{}
                                            : std::span<const ByteRange>(application_crypto_ranges);
            const auto application_candidate_crypto_frames =
                send_application_close_only ? std::span<const Frame>{}
                                            : std::span<const Frame>(application_crypto_frames);
            const auto send_application_ack_only =
                [&](const AckFrame &ack_frame) -> std::vector<std::byte> {
                const auto restore_unsent_path_validation_frames =
                    [&](const PendingPathValidationFrames &path_validation_frames) {
                        if (path_validation_frames.response.has_value()) {
                            auto &path = ensure_path_state(path_validation_frames.path_id);
                            path.pending_response = path_validation_frames.response->data;
                        }
                        if (path_validation_frames.challenge.has_value()) {
                            auto &path = ensure_path_state(path_validation_frames.path_id);
                            path.challenge_pending = true;
                        }
                    };
                auto path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
                selected_send_path_id =
                    path_validation_frames.response.has_value()
                        ? std::optional<QuicPathId>{path_validation_frames.path_id}
                        : current_send_path_id_;
                std::vector<Frame> ack_only_frames;
                ack_only_frames.emplace_back(ack_frame);
                if (path_validation_frames.response.has_value()) {
                    ack_only_frames.emplace_back(*path_validation_frames.response);
                }
                if (path_validation_frames.challenge.has_value()) {
                    ack_only_frames.emplace_back(*path_validation_frames.challenge);
                }
                const auto packet_number =
                    reserve_application_packet_number(!use_zero_rtt_packet_protection);
                if (!packet_number.has_value()) {
                    restore_unsent_path_validation_frames(path_validation_frames);
                    return {};
                }
                packets.emplace_back(make_application_protected_packet(
                    use_zero_rtt_packet_protection, current_version_,
                    application_destination_connection_id(), config_.source_connection_id,
                    application_write_key_phase_, kDefaultInitialPacketNumberLength, *packet_number,
                    std::move(ack_only_frames), {}));
                auto ack_only_datagram = serialize_candidate_datagram_with_metadata(packets);
                if (!ack_only_datagram.has_value()) {
                    restore_unsent_path_validation_frames(path_validation_frames);
                    mark_failed();
                    return {};
                }
                if (path_validation_frames.response.has_value() |
                    path_validation_frames.challenge.has_value()) {
                    track_sent_packet(
                        application_space_,
                        SentPacketRecord{
                            .packet_number = *packet_number,
                            .sent_time = now,
                            .ack_eliciting = true,
                            .in_flight = true,
                            .bytes_in_flight = ack_only_datagram.value().bytes.size(),
                            .path_id = selected_send_path_id.value_or(0),
                            .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                        });
                }
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
                return commit_serialized_datagram(packets, std::move(ack_only_datagram.value()));
            };
            std::vector<Frame> frames;
            const auto force_ack_only =
                ((application_space_.force_ack_send & base_ack_frame.has_value()) |
                 validation_only_send) &
                !send_application_close_only;
            auto max_data_frame = (force_ack_only || send_application_close_only)
                                      ? std::optional<MaxDataFrame>{}
                                      : connection_flow_control_.take_max_data_frame();
            auto data_blocked_frame = (force_ack_only || send_application_close_only)
                                          ? std::optional<DataBlockedFrame>{}
                                          : connection_flow_control_.take_data_blocked_frame();
            auto max_stream_data_frames = (force_ack_only || send_application_close_only)
                                              ? std::vector<MaxStreamDataFrame>{}
                                              : take_max_stream_data_frames(streams_);
            auto max_streams_frames = send_application_close_only
                                          ? std::vector<MaxStreamsFrame>{}
                                          : take_max_streams_frames(force_ack_only);
            auto new_connection_id_frames = take_new_connection_id_frames(force_ack_only);
            auto retire_connection_id_frames = take_retire_connection_id_frames(force_ack_only);
            auto path_validation_frames = take_path_validation_frames(force_ack_only);
            selected_send_path_id = path_validation_frames.response.has_value()
                                        ? std::optional<QuicPathId>{path_validation_frames.path_id}
                                        : current_send_path_id_;
            auto reset_stream_frames = (force_ack_only || send_application_close_only)
                                           ? std::vector<ResetStreamFrame>{}
                                           : take_reset_stream_frames(streams_);
            auto stop_sending_frames = (force_ack_only || send_application_close_only)
                                           ? std::vector<StopSendingFrame>{}
                                           : take_stop_sending_frames(streams_);
            auto stream_data_blocked_frames = (force_ack_only || send_application_close_only)
                                                  ? std::vector<StreamDataBlockedFrame>{}
                                                  : take_stream_data_blocked_frames(streams_);
            auto candidate_last_stream_id = last_application_send_stream_id_;
            auto stream_fragments =
                (force_ack_only || send_application_close_only)
                    ? std::vector<StreamFrameSendFragment>{}
                    : take_stream_fragments(connection_flow_control_, streams_,
                                            max_outbound_datagram_size, candidate_last_stream_id,
                                            prefer_fresh_application_stream_data);
            auto selected_ack_frame =
                send_application_close_only
                    ? std::optional<AckFrame>{}
                    : trim_application_ack_frame(
                          application_candidate_crypto_ranges, include_handshake_done,
                          base_ack_frame, max_data_frame, new_connection_id_frames,
                          retire_connection_id_frames, path_validation_frames,
                          max_stream_data_frames, max_streams_frames, reset_stream_frames,
                          stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                          stream_fragments, /*include_ping=*/false);
            if (has_failed()) {
                return {};
            }

            const auto candidate_application_write_key_phase = application_write_key_phase_;
            auto candidate_datagram = serialize_application_candidate(
                application_candidate_crypto_ranges, include_handshake_done, selected_ack_frame,
                max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                path_validation_frames, max_stream_data_frames, max_streams_frames,
                reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, application_close_frame,
                /*include_ping=*/false, nullptr);
            const auto finalize_existing_packets_or_empty = [&]() -> std::vector<std::byte> {
                if (packets.empty()) {
                    return {};
                }
                selected_send_path_id = current_send_path_id_;
                return finalize_datagram(packets);
            };
            if (!candidate_datagram.has_value()) {
                if (is_empty_packet_payload_error(candidate_datagram)) {
                    if (packet_trace_matches_connection(config_.source_connection_id)) {
                        std::cerr << "quic-packet-trace app-empty scid="
                                  << format_connection_id_hex(config_.source_connection_id)
                                  << " packets=" << packets.size()
                                  << " stream_fragments=" << stream_fragments.size()
                                  << " stream_bytes=" << stream_fragment_bytes(stream_fragments)
                                  << " ack=" << static_cast<int>(selected_ack_frame.has_value())
                                  << " hsdone=" << static_cast<int>(include_handshake_done) << "\n";
                    }
                    return finalize_existing_packets_or_empty();
                }
                mark_failed();
                return {};
            }
            if (selected_ack_frame.has_value() &&
                candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
                auto no_ack_candidate = serialize_application_candidate(
                    application_candidate_crypto_ranges, include_handshake_done, std::nullopt,
                    max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames, max_stream_data_frames, max_streams_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments, application_close_frame,
                    /*include_ping=*/false, nullptr);
                if (!no_ack_candidate.has_value()) {
                    mark_failed();
                    return {};
                }
                if (no_ack_candidate.value().bytes.size() <= max_outbound_datagram_size) {
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = std::move(no_ack_candidate);
                }
            }

            const auto trim_candidate_to_fit =
                [&](const std::optional<AckFrame> &ack_frame,
                    CodecResult<SerializedProtectedDatagram> &datagram,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().bytes.size() > max_outbound_datagram_size &&
                       !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_application_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot =
                            datagram.value().bytes.size() - max_outbound_datagram_size;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_application_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = last_fragment.consumes_flow_control,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            restore_application_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        application_candidate_crypto_ranges, include_handshake_done, ack_frame,
                        max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                        path_validation_frames, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, fragments, application_close_frame,
                        /*include_ping=*/false, nullptr);
                    if (!datagram.has_value()) {
                        if (is_empty_packet_payload_error(datagram)) {
                            return false;
                        }
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().bytes.size() <= max_outbound_datagram_size;
            };
            const auto fallback_to_existing_packets_or_ack_only = [&]() -> std::vector<std::byte> {
                if (!packets.empty()) {
                    return finalize_existing_packets_or_empty();
                }
                if (selected_ack_frame.has_value()) {
                    return send_application_ack_only(*selected_ack_frame);
                }
                return {};
            };

            if (!trim_candidate_to_fit(selected_ack_frame, candidate_datagram, stream_fragments)) {
                if (has_failed()) {
                    return {};
                }
                if (selected_ack_frame.has_value()) {
                    restore_unsent_application_candidate(
                        max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                        path_validation_frames, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments);

                    max_data_frame = connection_flow_control_.take_max_data_frame();
                    data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                    max_stream_data_frames = take_max_stream_data_frames(streams_);
                    max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                    new_connection_id_frames =
                        take_new_connection_id_frames(/*force_ack_only=*/false);
                    retire_connection_id_frames =
                        take_retire_connection_id_frames(/*force_ack_only=*/false);
                    path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
                    reset_stream_frames = take_reset_stream_frames(streams_);
                    stop_sending_frames = take_stop_sending_frames(streams_);
                    stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                    candidate_last_stream_id = last_application_send_stream_id_;
                    stream_fragments = take_stream_fragments(
                        connection_flow_control_, streams_, max_outbound_datagram_size,
                        candidate_last_stream_id, prefer_fresh_application_stream_data);
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = serialize_application_candidate(
                        application_candidate_crypto_ranges, include_handshake_done,
                        selected_ack_frame, max_data_frame, new_connection_id_frames,
                        retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                        max_streams_frames, reset_stream_frames, stop_sending_frames,
                        data_blocked_frame, stream_data_blocked_frames, stream_fragments,
                        application_close_frame,
                        /*include_ping=*/false, nullptr);
                    if (!candidate_datagram.has_value() &
                        !is_empty_packet_payload_error(candidate_datagram)) {
                        mark_failed();
                        return {};
                    }
                    static_cast<void>(trim_candidate_to_fit(selected_ack_frame, candidate_datagram,
                                                            stream_fragments));
                }
                if (!candidate_datagram.has_value()) {
                    return fallback_to_existing_packets_or_ack_only();
                }
            }
            const auto retry_candidate_without_receive_credit = [&]() -> bool {
                if (!max_data_frame.has_value() && max_stream_data_frames.empty()) {
                    return true;
                }

                restore_unsent_application_candidate(
                    max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames, max_stream_data_frames, max_streams_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments);
                max_data_frame = std::nullopt;
                data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                max_stream_data_frames.clear();
                max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                new_connection_id_frames = take_new_connection_id_frames(/*force_ack_only=*/false);
                retire_connection_id_frames =
                    take_retire_connection_id_frames(/*force_ack_only=*/false);
                path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
                reset_stream_frames = take_reset_stream_frames(streams_);
                stop_sending_frames = take_stop_sending_frames(streams_);
                stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                candidate_last_stream_id = last_application_send_stream_id_;
                stream_fragments = take_stream_fragments(
                    connection_flow_control_, streams_, max_outbound_datagram_size,
                    candidate_last_stream_id, prefer_fresh_application_stream_data);
                candidate_datagram = serialize_application_candidate(
                    application_candidate_crypto_ranges, include_handshake_done, selected_ack_frame,
                    max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames, max_stream_data_frames, max_streams_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments, application_close_frame,
                    /*include_ping=*/false, nullptr);
                if (!candidate_datagram.has_value() &
                    !is_empty_packet_payload_error(candidate_datagram)) {
                    mark_failed();
                    return false;
                }
                if (!candidate_datagram.has_value()) {
                    return true;
                }
                if (selected_ack_frame.has_value() &&
                    candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
                    auto no_ack_candidate = serialize_application_candidate(
                        application_candidate_crypto_ranges, include_handshake_done, std::nullopt,
                        max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                        path_validation_frames, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments, application_close_frame,
                        /*include_ping=*/false, nullptr);
                    if (!no_ack_candidate.has_value() &
                        !is_empty_packet_payload_error(no_ack_candidate)) {
                        mark_failed();
                        return false;
                    }
                    if (!no_ack_candidate.has_value()) {
                        candidate_datagram = std::move(no_ack_candidate);
                        return true;
                    }
                    if (no_ack_candidate.value().bytes.size() <= max_outbound_datagram_size) {
                        selected_ack_frame = std::nullopt;
                        candidate_datagram = std::move(no_ack_candidate);
                    }
                }
                if (!trim_candidate_to_fit(selected_ack_frame, candidate_datagram,
                                           stream_fragments)) {
                    if (has_failed()) {
                        return false;
                    }
                    if (selected_ack_frame.has_value()) {
                        restore_unsent_application_candidate(
                            max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                            path_validation_frames, max_stream_data_frames, max_streams_frames,
                            reset_stream_frames, stop_sending_frames, data_blocked_frame,
                            stream_data_blocked_frames, stream_fragments);
                        data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                        max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                        new_connection_id_frames =
                            take_new_connection_id_frames(/*force_ack_only=*/false);
                        retire_connection_id_frames =
                            take_retire_connection_id_frames(/*force_ack_only=*/false);
                        path_validation_frames =
                            take_path_validation_frames(/*force_ack_only=*/false);
                        reset_stream_frames = take_reset_stream_frames(streams_);
                        stop_sending_frames = take_stop_sending_frames(streams_);
                        stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                        candidate_last_stream_id = last_application_send_stream_id_;
                        stream_fragments = take_stream_fragments(
                            connection_flow_control_, streams_, max_outbound_datagram_size,
                            candidate_last_stream_id, prefer_fresh_application_stream_data);
                        selected_ack_frame = std::nullopt;
                        candidate_datagram = serialize_application_candidate(
                            application_candidate_crypto_ranges, include_handshake_done,
                            selected_ack_frame, max_data_frame, new_connection_id_frames,
                            retire_connection_id_frames, path_validation_frames,
                            max_stream_data_frames, max_streams_frames, reset_stream_frames,
                            stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                            stream_fragments, application_close_frame,
                            /*include_ping=*/false, nullptr);
                        if (!candidate_datagram.has_value() &
                            !is_empty_packet_payload_error(candidate_datagram)) {
                            mark_failed();
                            return false;
                        }
                        static_cast<void>(trim_candidate_to_fit(
                            selected_ack_frame, candidate_datagram, stream_fragments));
                    }
                }

                return !has_failed();
            };
            auto candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            if (candidate_datagram_size > max_outbound_datagram_size) {
                if (!retry_candidate_without_receive_credit()) {
                    return {};
                }
                if (!candidate_datagram.has_value()) {
                    return fallback_to_existing_packets_or_ack_only();
                }
                candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            }
            if (candidate_datagram_size > max_outbound_datagram_size) {
                restore_unsent_application_candidate(
                    max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames, max_stream_data_frames, max_streams_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments);
                if (!packets.empty()) {
                    selected_send_path_id = current_send_path_id_;
                    return finalize_datagram(packets);
                }
                if (max_outbound_datagram_size == kMaximumDatagramSize) {
                    mark_failed();
                    return {};
                }
                return fallback_to_existing_packets_or_ack_only();
            }

            frames.reserve(application_candidate_crypto_frames.size() +
                           (selected_ack_frame.has_value() ? 1u : 0u) +
                           (include_handshake_done ? 1u : 0u) + reset_stream_frames.size() +
                           stop_sending_frames.size() + (max_data_frame.has_value() ? 1u : 0u) +
                           new_connection_id_frames.size() + retire_connection_id_frames.size() +
                           static_cast<std::size_t>(path_validation_frames.response.has_value()) +
                           static_cast<std::size_t>(path_validation_frames.challenge.has_value()) +
                           max_stream_data_frames.size() + max_streams_frames.size() +
                           (data_blocked_frame.has_value() ? 1u : 0u) +
                           stream_data_blocked_frames.size() +
                           (application_close_frame.has_value() ? 1u : 0u));
            for (const auto &frame : application_candidate_crypto_frames) {
                frames.emplace_back(frame);
            }
            if (selected_ack_frame.has_value()) {
                frames.emplace_back(*selected_ack_frame);
            }
            if (include_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            const auto ack_eliciting =
                !application_candidate_crypto_frames.empty() ||
                application_ack_eliciting_frame_count(
                    include_handshake_done, max_data_frame, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames.response.has_value(),
                    path_validation_frames.challenge.has_value(), max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments) != 0;
            const auto bypass_congestion_window =
                application_space_.pending_probe_packet.has_value() ||
                (path_validation_frames.challenge.has_value() && stream_fragments.empty());
            if (ack_eliciting && !bypass_congestion_window &&
                !congestion_controller_.can_send_ack_eliciting(
                    candidate_datagram.value().bytes.size())) {
                if (traces_this_connection) {
                    std::cerr
                        << "quic-packet-trace send-blocked scid="
                        << format_connection_id_hex(config_.source_connection_id)
                        << " reason=congestion"
                        << " size=" << candidate_datagram.value().bytes.size()
                        << " current=" << format_optional_path_id(current_send_path_id_)
                        << " previous=" << format_optional_path_id(previous_path_id_)
                        << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                        << " current_path={"
                        << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                        << "} cwnd=" << congestion_controller_.congestion_window()
                        << " bif=" << congestion_controller_.bytes_in_flight()
                        << " pending_send=" << static_cast<int>(has_pending_application_send())
                        << " probe="
                        << static_cast<int>(application_space_.pending_probe_packet.has_value())
                        << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                        << '\n';
                }
                restore_unsent_application_candidate(
                    max_data_frame, new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames, max_stream_data_frames, max_streams_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments);
                return fallback_to_existing_packets_or_ack_only();
            }
            last_application_send_stream_id_ = candidate_last_stream_id;

            for (const auto &frame : reset_stream_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : stop_sending_frames) {
                frames.emplace_back(frame);
            }
            if (max_data_frame.has_value()) {
                frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : new_connection_id_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : retire_connection_id_frames) {
                frames.emplace_back(frame);
            }
            if (path_validation_frames.response.has_value()) {
                frames.emplace_back(*path_validation_frames.response);
            }
            if (path_validation_frames.challenge.has_value()) {
                frames.emplace_back(*path_validation_frames.challenge);
            }
            for (const auto &frame : max_stream_data_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : max_streams_frames) {
                frames.emplace_back(frame);
            }
            if (data_blocked_frame.has_value()) {
                frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }
            if (application_close_frame.has_value()) {
                frames.emplace_back(*application_close_frame);
            }

            const bool has_application_close = application_close_frame.has_value();
            const auto packet_number = reserve_application_packet_number(
                (!use_zero_rtt_packet_protection) | has_application_close);
            if (!packet_number.has_value()) {
                return {};
            }
            if (application_write_key_phase_ != candidate_application_write_key_phase) {
                auto final_candidate_datagram = serialize_application_candidate_from_frames(
                    frames, stream_fragments, has_application_close, *packet_number,
                    application_write_key_phase_, nullptr);
                if (!final_candidate_datagram.has_value()) {
                    mark_failed();
                    return {};
                }
                candidate_datagram = std::move(final_candidate_datagram);
            }
            const auto stream_bytes = stream_fragment_bytes(stream_fragments);
            if (packet_trace_matches_connection(config_.source_connection_id)) {
                const auto ack_trace_value = static_cast<int>(selected_ack_frame.has_value());
                const auto handshake_done_trace_value = static_cast<int>(include_handshake_done);
                std::cerr << "quic-packet-trace send scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " pn=" << *packet_number << " ack=" << ack_trace_value
                          << " hsdone=" << handshake_done_trace_value << " stream=" << stream_bytes
                          << " bytes=" << candidate_datagram.value().bytes.size() << '\n';
            }
            packets.emplace_back(make_application_protected_packet(
                use_zero_rtt_packet_protection & !has_application_close, current_version_,
                application_destination_connection_id(), config_.source_connection_id,
                application_write_key_phase_, kDefaultInitialPacketNumberLength, *packet_number,
                std::move(frames), stream_fragments));

            if (ack_eliciting) {
                track_sent_packet(application_space_,
                                  SentPacketRecord{
                                      .packet_number = *packet_number,
                                      .sent_time = now,
                                      .ack_eliciting = ack_eliciting,
                                      .in_flight = ack_eliciting,
                                      .declared_lost = false,
                                      .has_handshake_done = include_handshake_done,
                                      .crypto_ranges = std::vector<ByteRange>(
                                          application_candidate_crypto_ranges.begin(),
                                          application_candidate_crypto_ranges.end()),
                                      .reset_stream_frames = reset_stream_frames,
                                      .stop_sending_frames = stop_sending_frames,
                                      .max_data_frame = max_data_frame,
                                      .max_stream_data_frames = max_stream_data_frames,
                                      .max_streams_frames = max_streams_frames,
                                      .data_blocked_frame = data_blocked_frame,
                                      .stream_data_blocked_frames = stream_data_blocked_frames,
                                      .stream_fragments = stream_fragments,
                                      .bytes_in_flight = candidate_datagram.value().bytes.size(),
                                      .path_id = selected_send_path_id.value_or(0),
                                      .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                                  });
            }
            if (include_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (selected_ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            if (!validation_only_send) {
                clear_probe_packet_after_send(application_space_.pending_probe_packet);
            }
            if (application_close_frame.has_value()) {
                pending_application_close_.reset();
                local_application_close_sent_ = true;
                pending_terminal_state_ = QuicConnectionTerminalState::closed;
                mark_failed();
            }
            return commit_serialized_datagram(packets, std::move(candidate_datagram.value()));
        }
    }

    if (packets.empty()) {
        if (traces_this_connection & (has_pending_application_send() |
                                      application_space_.pending_probe_packet.has_value())) {
            std::cerr << "quic-packet-trace send-empty scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " max=" << max_outbound_datagram_size
                      << " current=" << format_optional_path_id(current_send_path_id_)
                      << " previous=" << format_optional_path_id(previous_path_id_)
                      << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                      << " current_path={"
                      << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                      << "} inbound_path={"
                      << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                      << "} pending_send=" << static_cast<int>(has_pending_application_send())
                      << " probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << " pto_count=" << pto_count_
                      << " cwnd=" << congestion_controller_.congestion_window()
                      << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
        }
        return {};
    }

    return finalize_datagram(packets);
}

} // namespace coquic::quic

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::quic::test {

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

} // namespace

bool connection_helper_edge_cases_for_tests() {
    constexpr std::array supported_versions = {kQuicVersion2, kQuicVersion1};
    const auto retry_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x00}};
    const bool retry_same_version_omits_version_information =
        !version_information_for_handshake(supported_versions, kQuicVersion1,
                                           retry_source_connection_id, kQuicVersion1, kQuicVersion1)
             .has_value();
    const bool retry_version_change_keeps_version_information =
        version_information_for_handshake(supported_versions, kQuicVersion2,
                                          retry_source_connection_id, kQuicVersion1, kQuicVersion2)
            .has_value();

    const auto failed_datagram =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    const auto empty_packet_payload_datagram =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload, 0);
    const bool failed_datagram_reports_zero_size = datagram_size_or_zero(failed_datagram) == 0;
    const bool empty_packet_payload_error_reported =
        is_empty_packet_payload_error(empty_packet_payload_datagram);
    const bool non_empty_packet_payload_error_not_reported =
        !is_empty_packet_payload_error(failed_datagram);

    TransportParameters invalid_transport_parameters;
    invalid_transport_parameters.max_udp_payload_size = std::numeric_limits<std::uint64_t>::max();
    const bool encode_failure_returns_empty =
        encode_resumption_state({}, kQuicVersion1, "h3", invalid_transport_parameters, {}).empty();

    constexpr std::array wrong_magic_bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                              std::byte{0x00}, std::byte{0x00}};
    const bool wrong_magic_rejected = !decode_resumption_state(wrong_magic_bytes).has_value();

    std::vector<std::byte> truncated_tls_state = {std::byte{0x01}};
    append_u32_be(truncated_tls_state, kQuicVersion1);
    const bool truncated_tls_state_rejected =
        !decode_resumption_state(truncated_tls_state).has_value();

    const TransportParameters resumption_transport_parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };
    const auto transport_parameters =
        serialize_transport_parameters(resumption_transport_parameters).value();

    std::vector<std::byte> missing_application_context = {std::byte{0x01}};
    append_u32_be(missing_application_context, kQuicVersion1);
    append_length_prefixed_bytes(missing_application_context, {});
    append_length_prefixed_text(missing_application_context, "h3");
    append_length_prefixed_bytes(missing_application_context, transport_parameters);
    const bool missing_application_context_rejected =
        !decode_resumption_state(missing_application_context).has_value();

    std::vector<std::byte> missing_application_protocol = {std::byte{0x01}};
    append_u32_be(missing_application_protocol, kQuicVersion1);
    append_length_prefixed_bytes(missing_application_protocol, {});
    const bool missing_application_protocol_rejected =
        !decode_resumption_state(missing_application_protocol).has_value();

    std::vector<std::byte> missing_transport_parameters = {std::byte{0x01}};
    append_u32_be(missing_transport_parameters, kQuicVersion1);
    append_length_prefixed_bytes(missing_transport_parameters, {});
    append_length_prefixed_text(missing_transport_parameters, "h3");
    const bool missing_transport_parameters_rejected =
        !decode_resumption_state(missing_transport_parameters).has_value();

    auto trailing_resumption_state =
        encode_resumption_state({}, kQuicVersion1, "h3", resumption_transport_parameters, {});
    trailing_resumption_state.push_back(std::byte{0xff});
    const bool trailing_bytes_rejected =
        !decode_resumption_state(trailing_resumption_state).has_value();

    auto stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    stream.send_final_size = 1;
    stream.send_fin_state = StreamSendFinState::pending;
    stream.flow_control.peer_max_stream_data = 1;
    const std::array pending_data = {std::byte{0x78}};
    stream.send_buffer.append(pending_data);
    const bool pending_data_blocks_fin = !stream_fin_sendable(stream);

    LocalStreamLimitState stream_limits;
    stream_limits.max_streams_bidi_state = StreamControlFrameState::pending;
    stream_limits.max_streams_uni_state = StreamControlFrameState::pending;
    const auto max_streams_frames = stream_limits.take_max_streams_frames();
    const bool missing_pending_frames_preserve_state =
        max_streams_frames.empty() &
        (stream_limits.max_streams_bidi_state == StreamControlFrameState::pending) &
        (stream_limits.max_streams_uni_state == StreamControlFrameState::pending);

    constexpr std::array short_header_packet = {std::byte{0x40}};
    const bool short_header_is_bufferable = packet_is_bufferable(short_header_packet);
    constexpr std::array truncated_long_header = {std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}};
    const bool truncated_long_header_is_not_bufferable =
        !packet_is_bufferable(truncated_long_header);
    constexpr std::array handshake_long_header = {std::byte{0xe0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}, std::byte{0x01}};
    const bool handshake_long_header_is_bufferable = packet_is_bufferable(handshake_long_header);

    const ProtectedOneRttPacket connected_state_frame{
        .frames =
            {
                ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
    };
    const bool protected_one_rtt_packet_deferred =
        should_defer_protected_one_rtt_packet(connected_state_frame, HandshakeStatus::in_progress);
    const bool connected_protected_one_rtt_packet_not_deferred =
        !should_defer_protected_one_rtt_packet(connected_state_frame, HandshakeStatus::connected);
    const bool corrupted_long_header_discarded =
        should_discard_corrupted_long_header_packet(false, CodecErrorCode::invalid_fixed_bit) &
        should_discard_corrupted_long_header_packet(false, CodecErrorCode::unsupported_packet_type);
    const bool short_header_not_discarded_as_corrupted_long_header =
        !should_discard_corrupted_long_header_packet(true, CodecErrorCode::invalid_fixed_bit);

    const auto bytes_from_ints = [](std::initializer_list<std::uint8_t> values) {
        std::vector<std::byte> bytes;
        bytes.reserve(values.size());
        for (const auto value : values) {
            bytes.push_back(static_cast<std::byte>(value));
        }
        return bytes;
    };

    const std::string empty_connection_id_hex = format_connection_id_hex({});
    const std::string retry_source_connection_id_hex =
        format_connection_id_hex(retry_source_connection_id);
    const bool empty_connection_id_formats_empty = empty_connection_id_hex.empty();
    const bool connection_id_formats_lower_hex = retry_source_connection_id_hex == "5300";
    const bool empty_issued_connection_id_remains_empty =
        make_issued_connection_id({}, /*sequence_number=*/7).empty();
    const DeferredProtectedDatagram deferred_packet(bytes_from_ints({0x01, 0x02, 0x03}),
                                                    /*id=*/9);
    const bool vector_equals_deferred_packet =
        bytes_from_ints({0x01, 0x02, 0x03}) == deferred_packet;

    PathState traced_path{
        .id = 7,
        .validated = true,
        .is_current_send_path = true,
        .challenge_pending = true,
        .anti_amplification_received_bytes = 11,
        .anti_amplification_sent_bytes = 7,
        .outstanding_challenge =
            std::array{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                       std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}},
        .pending_response =
            std::array{std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
                       std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18}},
    };
    std::map<QuicPathId, PathState> traced_paths{
        {traced_path.id, traced_path},
    };
    const bool optional_path_none_formats_dash = format_optional_path_id(std::nullopt) == "-";
    const bool optional_path_value_formats_decimal = format_optional_path_id(traced_path.id) == "7";
    const bool missing_optional_path_returns_null =
        find_path_state(traced_paths, std::nullopt) == nullptr;
    const bool unknown_path_returns_null = find_path_state(traced_paths, 99) == nullptr;
    const bool existing_path_is_found = find_path_state(traced_paths, traced_path.id) != nullptr;
    const bool null_path_summary_formats_dash = format_path_state_summary(nullptr) == "-";
    const std::string traced_path_summary = format_path_state_summary(&traced_path);
    const bool traced_path_summary_mentions_path_state =
        (traced_path_summary.find("id=7") != std::string::npos) &
        (traced_path_summary.find("val=1") != std::string::npos) &
        (traced_path_summary.find("cur=1") != std::string::npos) &
        (traced_path_summary.find("chal=1") != std::string::npos) &
        (traced_path_summary.find("out=1") != std::string::npos) &
        (traced_path_summary.find("resp=1") != std::string::npos) &
        (traced_path_summary.find("recv=11") != std::string::npos) &
        (traced_path_summary.find("sent=7") != std::string::npos);
    const bool invalid_ack_first_range_formats_invalid = format_ack_ranges(AckFrame{
                                                             .largest_acknowledged = 1,
                                                             .first_ack_range = 2,
                                                         }) == "[invalid]";
    const bool invalid_ack_gap_formats_invalid = format_ack_ranges(AckFrame{
                                                     .largest_acknowledged = 10,
                                                     .first_ack_range = 0,
                                                     .additional_ranges =
                                                         {
                                                             AckRange{.gap = 9, .range_length = 0},
                                                         },
                                                 }) == "[10-10,invalid]";
    const bool invalid_ack_range_length_formats_invalid =
        format_ack_ranges(AckFrame{
            .largest_acknowledged = 10,
            .first_ack_range = 2,
            .additional_ranges =
                {
                    AckRange{.gap = 0, .range_length = 7},
                },
        }) == "[8-10,invalid]";
    const bool valid_ack_ranges_format_expected = format_ack_ranges(AckFrame{
                                                      .largest_acknowledged = 10,
                                                      .first_ack_range = 1,
                                                      .additional_ranges =
                                                          {
                                                              AckRange{.gap = 0, .range_length = 1},
                                                          },
                                                  }) == "[9-10,6-7]";
    const bool empty_packet_summary_reports_zero = summarize_packets({}) == "count=0";
    const std::array sent_packets = {
        SentPacketRecord{
            .packet_number = 5,
            .stream_fragments =
                {
                    StreamFrameSendFragment{
                        .stream_id = 0,
                        .offset = 4,
                        .bytes = SharedBytes(bytes_from_ints({0xaa, 0xbb})),
                        .fin = false,
                        .consumes_flow_control = true,
                    },
                },
        },
        SentPacketRecord{
            .packet_number = 9,
        },
    };
    const std::string packet_summary = summarize_packets(sent_packets);
    const bool packet_summary_mentions_counts =
        (packet_summary.find("count=2") != std::string::npos) &
        (packet_summary.find("pn=5-9") != std::string::npos) &
        (packet_summary.find("stream_fragments=1") != std::string::npos) &
        (packet_summary.find("first_stream_offset=4") != std::string::npos);
    const std::array no_stream_packets = {
        SentPacketRecord{
            .packet_number = 6,
        },
        SentPacketRecord{
            .packet_number = 8,
        },
    };
    const std::string no_stream_packet_summary = summarize_packets(no_stream_packets);
    const bool packet_summary_without_stream_offset_omits_offset =
        (no_stream_packet_summary.find("count=2") != std::string::npos) &
        (no_stream_packet_summary.find("pn=6-8") != std::string::npos) &
        (no_stream_packet_summary.find("stream_fragments=0") != std::string::npos) &
        (no_stream_packet_summary.find("first_stream_offset=") == std::string::npos);

    bool trace_unset_disabled = false;
    bool trace_empty_disabled = false;
    bool trace_zero_disabled = false;
    bool trace_matches_without_filter = false;
    bool trace_matches_with_empty_filter = false;
    bool trace_matches_with_exact_filter = false;
    bool trace_rejects_mismatched_filter = false;
    {
        ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
        ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", std::nullopt);
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
            trace_unset_disabled = !packet_trace_enabled() &
                                   !packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "");
            trace_empty_disabled = !packet_trace_enabled();
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "0");
            trace_zero_disabled = !packet_trace_enabled();
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
            trace_matches_without_filter = packet_trace_enabled() & packet_trace_matches_connection(
                                                                        retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
            trace_matches_with_empty_filter =
                packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", retry_source_connection_id_hex);
            trace_matches_with_exact_filter =
                packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "deadbeef");
            trace_rejects_mismatched_filter =
                !packet_trace_matches_connection(retry_source_connection_id);
        }
    }

    const bool empty_long_header_rejected =
        !peek_discardable_long_header_packet_length({}).has_value();
    const bool short_header_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0x40})).has_value();
    const bool truncated_version_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00}))
             .has_value();
    const bool unsupported_version_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00}))
             .has_value();
    const bool missing_destination_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}))
             .has_value();
    const bool oversized_destination_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}))
             .has_value();
    const bool truncated_destination_connection_id_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01}))
             .has_value();
    const bool missing_source_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}))
             .has_value();
    const bool oversized_source_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x15}))
             .has_value();
    const bool truncated_source_connection_id_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}))
             .has_value();
    const bool missing_initial_token_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool oversized_initial_token_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value();
    const bool unsupported_retry_packet_type_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool missing_payload_length_after_initial_token_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00}))
             .has_value();
    const bool missing_payload_length_for_handshake_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool missing_payload_length_for_zero_rtt_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool oversized_payload_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value();

    return retry_same_version_omits_version_information &
           retry_version_change_keeps_version_information & failed_datagram_reports_zero_size &
           empty_packet_payload_error_reported & non_empty_packet_payload_error_not_reported &
           encode_failure_returns_empty & wrong_magic_rejected & truncated_tls_state_rejected &
           missing_application_protocol_rejected & missing_transport_parameters_rejected &
           missing_application_context_rejected & trailing_bytes_rejected &
           pending_data_blocks_fin & missing_pending_frames_preserve_state &
           short_header_is_bufferable & truncated_long_header_is_not_bufferable &
           handshake_long_header_is_bufferable & protected_one_rtt_packet_deferred &
           connected_protected_one_rtt_packet_not_deferred & corrupted_long_header_discarded &
           short_header_not_discarded_as_corrupted_long_header & empty_connection_id_formats_empty &
           connection_id_formats_lower_hex & empty_issued_connection_id_remains_empty &
           vector_equals_deferred_packet & optional_path_none_formats_dash &
           optional_path_value_formats_decimal & missing_optional_path_returns_null &
           unknown_path_returns_null & existing_path_is_found & null_path_summary_formats_dash &
           traced_path_summary_mentions_path_state & invalid_ack_first_range_formats_invalid &
           invalid_ack_gap_formats_invalid & invalid_ack_range_length_formats_invalid &
           valid_ack_ranges_format_expected & empty_packet_summary_reports_zero &
           packet_summary_mentions_counts & packet_summary_without_stream_offset_omits_offset &
           trace_unset_disabled & trace_empty_disabled & trace_zero_disabled &
           trace_matches_without_filter & trace_matches_with_empty_filter &
           trace_matches_with_exact_filter & trace_rejects_mismatched_filter &
           empty_long_header_rejected & short_header_rejected & truncated_version_rejected &
           unsupported_version_rejected & missing_destination_connection_id_length_rejected &
           oversized_destination_connection_id_length_rejected &
           truncated_destination_connection_id_rejected &
           missing_source_connection_id_length_rejected &
           oversized_source_connection_id_length_rejected &
           truncated_source_connection_id_rejected & missing_initial_token_length_rejected &
           oversized_initial_token_length_rejected & unsupported_retry_packet_type_rejected &
           missing_payload_length_after_initial_token_rejected &
           missing_payload_length_for_handshake_rejected &
           missing_payload_length_for_zero_rtt_rejected & oversized_payload_length_rejected;
}

} // namespace coquic::quic::test

#if defined(__clang__)
#pragma clang attribute pop
#endif

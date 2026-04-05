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

bool packet_trace_matches_connection(std::span<const std::byte> local_connection_id) {
    if (!packet_trace_enabled()) {
        return false;
    }

    const char *filter = std::getenv("COQUIC_PACKET_TRACE_SCID");
    if (filter == nullptr || filter[0] == '\0') {
        return true;
    }

    return std::string_view(filter) == format_connection_id_hex(local_connection_id);
}

bool supports_version(std::span<const std::uint32_t> supported_versions, std::uint32_t version) {
    return std::find(supported_versions.begin(), supported_versions.end(), version) !=
           supported_versions.end();
}

bool supports_quic_v2(std::span<const std::uint32_t> supported_versions) {
    return supports_version(supported_versions, kQuicVersion2);
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

bool has_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (packet.ack_eliciting & packet.in_flight) {
            return true;
        }
    }

    return false;
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
    std::span<const MaxStreamDataFrame> max_stream_data_frames,
    std::span<const MaxStreamsFrame> max_streams_frames,
    std::span<const ResetStreamFrame> reset_stream_frames,
    std::span<const StopSendingFrame> stop_sending_frames,
    const std::optional<DataBlockedFrame> &data_blocked_frame,
    std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
    std::span<const StreamFrameSendFragment> stream_fragments) {
    return max_stream_data_frames.size() + max_streams_frames.size() + reset_stream_frames.size() +
           stop_sending_frames.size() + stream_data_blocked_frames.size() +
           stream_fragments.size() + static_cast<std::size_t>(include_handshake_done) +
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
      current_version_(config_.initial_version), congestion_controller_(kMaximumDatagramSize) {
    if (config_.supported_versions.empty()) {
        config_.supported_versions.push_back(current_version_);
    }
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
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
    };
    initialize_local_flow_control();
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
                                              QuicCoreTimePoint now) {
    const auto inbound_datagram_id =
        qlog_session_ != nullptr
            ? std::optional<std::uint32_t>(qlog_session_->next_inbound_datagram_id())
            : std::nullopt;
    process_inbound_datagram(bytes, now, inbound_datagram_id, /*replay_trigger=*/false,
                             /*count_inbound_bytes=*/true);
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                              QuicCoreTimePoint now,
                                              std::optional<std::uint32_t> inbound_datagram_id,
                                              bool replay_trigger, bool count_inbound_bytes) {
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        return;
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
    const auto defer_packet = [&](std::span<const std::byte> packet_bytes,
                                  std::uint32_t datagram_id) {
        auto deferred = std::vector<std::byte>(packet_bytes.begin(), packet_bytes.end());
        if (std::find_if(deferred_protected_packets_.begin(), deferred_protected_packets_.end(),
                         [&](const DeferredProtectedPacket &candidate) {
                             return candidate.bytes == deferred;
                         }) != deferred_protected_packets_.end()) {
            return;
        }
        if (deferred_protected_packets_.size() >= kMaximumDeferredProtectedPackets) {
            deferred_protected_packets_.erase(deferred_protected_packets_.begin());
        }
        deferred_protected_packets_.push_back(
            DeferredProtectedPacket(std::move(deferred), datagram_id));
    };
    std::size_t offset = 0;
    bool processed_any_packet = false;
    const auto make_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> DeserializeProtectionContext {
        return DeserializeProtectionContext{
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
        };
    };
    const auto process_packet_bytes = [&](std::span<const std::byte> packet_bytes, bool allow_defer,
                                          std::optional<std::uint32_t> datagram_id,
                                          bool packet_replay_trigger) -> bool {
        auto packets = deserialize_protected_datagram(
            packet_bytes,
            make_deserialize_context(application_space_.read_secret, application_read_key_phase_));
        const bool short_header_packet =
            (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
        bool used_previous_application_read_secret = false;
        bool processed_current_read_phase_packet = false;
        if (!packets.has_value() && short_header_packet &&
            previous_application_read_secret_.has_value()) {
            auto previous_packets = deserialize_protected_datagram(
                packet_bytes, make_deserialize_context(previous_application_read_secret_,
                                                       previous_application_read_key_phase_));
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
                auto updated_packets = deserialize_protected_datagram(
                    packet_bytes,
                    make_deserialize_context(next_read_secret, !application_read_key_phase_));
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
                defer_packet(packet_bytes, datagram_id.value_or(0));
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
                defer_packet(packet_bytes, datagram_id.value_or(0));
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
            const auto processed = process_inbound_packet(packet, now);
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
        for (const auto &packet : deferred_packets) {
            if (packet_requires_connected_state(packet.bytes) &&
                status_ != HandshakeStatus::connected) {
                defer_packet(packet.bytes, packet.datagram_id);
                continue;
            }
            if (!process_packet_bytes(packet.bytes, /*allow_defer=*/true, packet.datagram_id,
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
        if (!process_packet_bytes(packet_bytes, /*allow_defer=*/true, inbound_datagram_id,
                                  replay_trigger)) {
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

void QuicConnection::request_key_update() {
    local_key_update_requested_ = true;
}

std::vector<std::byte> QuicConnection::drain_outbound_datagram(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
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

    return flush_outbound_datagram(now);
}

void QuicConnection::on_timeout(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    maybe_discard_server_zero_rtt_packet_space(now);

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
    }
}

std::optional<QuicCoreReceiveStreamData> QuicConnection::take_received_stream_data() {
    if (status_ == HandshakeStatus::failed || pending_stream_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_stream_receive_effects_.front());
    pending_stream_receive_effects_.erase(pending_stream_receive_effects_.begin());
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

std::optional<QuicCoreTimePoint> QuicConnection::next_wakeup() const {
    if (status_ == HandshakeStatus::failed) {
        return std::nullopt;
    }

    return earliest_of(
        {loss_deadline(), pto_deadline(), ack_deadline(), zero_rtt_discard_deadline()});
}

std::optional<QuicCoreTimePoint> QuicConnection::loss_deadline() const {
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto packet_space_loss_deadline =
        [&](const PacketSpaceState &packet_space) -> std::optional<QuicCoreTimePoint> {
        const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
        if (!largest_acked.has_value()) {
            return std::nullopt;
        }

        std::optional<QuicCoreTimePoint> deadline;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            if (!packet.in_flight || packet.packet_number >= *largest_acked) {
                continue;
            }

            const auto candidate =
                compute_time_threshold_deadline(shared_rtt_state, packet.sent_time);
            if (!deadline.has_value() || candidate < *deadline) {
                deadline = candidate;
            }
        }

        return deadline;
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
    const auto packet_space_pto_deadline =
        [&](const PacketSpaceState &packet_space,
            std::chrono::milliseconds max_ack_delay) -> std::optional<QuicCoreTimePoint> {
        std::optional<QuicCoreTimePoint> last_ack_eliciting_sent_time;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            if (!packet.ack_eliciting || !packet.in_flight) {
                continue;
            }

            if (!last_ack_eliciting_sent_time.has_value() ||
                packet.sent_time > *last_ack_eliciting_sent_time) {
                last_ack_eliciting_sent_time = packet.sent_time;
            }
        }

        if (!last_ack_eliciting_sent_time.has_value()) {
            return std::nullopt;
        }

        return compute_pto_deadline(shared_rtt_state, max_ack_delay, *last_ack_eliciting_sent_time,
                                    pto_count_);
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
    if (!client_handshake_keepalive_reference_time.has_value() || initial_packet_space_discarded_) {
        return std::nullopt;
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
        congestion_controller_.on_loss_event(now);
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              application_max_ack_delay)) {
            congestion_controller_.on_persistent_congestion();
        }
    }
    rebuild_recovery(packet_space);
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
    const auto effective_pto_count = [&](const PacketSpaceState & /*packet_space*/) {
        if (config_.role != EndpointRole::client || handshake_confirmed_) {
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
        client_handshake_keepalive_reference_time.has_value() & !initial_packet_space_discarded_;
    PacketSpaceState *client_handshake_keepalive_space =
        client_handshake_keepalive_eligible ? &initial_space_ : nullptr;
    auto client_handshake_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_handshake_keepalive_reference_time.has_value() && !initial_packet_space_discarded_) {
        client_handshake_keepalive_deadline = compute_pto_deadline(
            shared_rtt_state, std::chrono::milliseconds(0),
            *client_handshake_keepalive_reference_time, std::min(pto_count_, 2u));
    }
    const bool client_handshake_keepalive_due = client_handshake_keepalive_deadline.has_value() &&
                                                now >= *client_handshake_keepalive_deadline;
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
        if (!client_handshake_keepalive_due) {
            return;
        }
        selected_packet_space = client_handshake_keepalive_space;
        selected_deadline = client_handshake_keepalive_deadline;
    }

    ++pto_count_;
    remaining_pto_probe_datagrams_ = 0;
    bool armed_pto_probe = false;
    const auto arm_packet_space_probe = [&](PacketSpaceState &packet_space) {
        const bool allow_client_handshake_keepalive_probe =
            client_handshake_keepalive_due && &packet_space == client_handshake_keepalive_space;
        if (!allow_client_handshake_keepalive_probe &&
            !has_in_flight_ack_eliciting_packet(packet_space)) {
            return;
        }

        if (&packet_space != &application_space_ && packet_space.send_crypto.has_pending_data()) {
            return;
        }

        packet_space.pending_probe_packet = select_pto_probe(packet_space);
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
        .active_connection_id_limit = 2,
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
        .active_connection_id_limit = 2,
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
                                                         QuicCoreTimePoint now) {
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
                initial_space_.largest_authenticated_packet_number = protected_packet.packet_number;
                const auto processed =
                    process_inbound_crypto(EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(protected_packet.packet_number,
                                                                    ack_eliciting, now);
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
                        protected_packet.packet_number, ack_eliciting, now);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        last_peer_activity_time_ = now;
                    }
                    if (ack_eliciting && !should_defer_client_standalone_handshake_ack()) {
                        handshake_space_.pending_ack_deadline = now;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed =
                    process_inbound_application(protected_packet.frames, now, true);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now);
                    last_peer_activity_time_ = now;
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
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
                const auto processed =
                    process_inbound_application(protected_packet.frames, now, has_crypto_frame);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server) {
                        mark_peer_address_validated();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now);
                    last_peer_activity_time_ = now;
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
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
    for (const auto &packet : ack_result.acked_packets) {
        retire_acked_packet(packet_space, packet);
    }
    for (const auto &packet : late_acked_packets) {
        retire_acked_packet(packet_space, packet);
    }
    for (const auto &packet : ack_result.lost_packets) {
        const auto trigger =
            is_packet_threshold_lost(packet.packet_number, ack.largest_acknowledged)
                ? "reordering_threshold"
                : "time_threshold";
        emit_qlog_packet_lost(packet, trigger, now);
        mark_lost_packet(packet_space, packet);
    }

    if (ack_result.largest_acknowledged_was_newly_acked &&
        ack_result.has_newly_acked_ack_eliciting) {
        update_rtt(packet_space.recovery.rtt_state(), now, ack_result.acked_packets.back(),
                   decode_ack_delay(ack, ack_delay_exponent),
                   std::chrono::milliseconds(max_ack_delay_ms));
        recovery_rtt_state_ = packet_space.recovery.rtt_state();
        synchronize_recovery_rtt_state();
    }
    if (&packet_space == &application_space_ && !ack_result.acked_packets.empty()) {
        confirm_handshake();
    }
    if (packet_space_is_application(packet_space, application_space_)) {
        const auto &shared_rtt_state = shared_recovery_rtt_state();
        const auto ack_eliciting_lost_packets =
            ack_eliciting_in_flight_losses(ack_result.lost_packets);
        if (!ack_eliciting_lost_packets.empty()) {
            congestion_controller_.on_loss_event(now);
            if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                                  std::chrono::milliseconds(max_ack_delay_ms))) {
                congestion_controller_.on_persistent_congestion();
            }
        }
        congestion_controller_.on_packets_acked(ack_result.acked_packets,
                                                !has_pending_application_send());
    }
    if (!ack_result.acked_packets.empty() && !suppress_pto_reset) {
        const bool keepalive_probe_packet_space =
            (&packet_space == &initial_space_) | (&packet_space == &handshake_space_);
        const bool client_handshake_keepalive_ack_only =
            (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::in_progress) &
            !handshake_confirmed_ & keepalive_probe_packet_space &
            std::ranges::all_of(ack_result.acked_packets, [&](const SentPacketRecord &packet) {
                return packet.has_ping & (retransmittable_probe_frame_count(packet) == 0);
            });
        if (!client_handshake_keepalive_ack_only) {
            pto_count_ = 0;
        }
    }

    maybe_emit_qlog_recovery_metrics(now);
    return CodecResult<bool>::success(true);
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space,
                                       const SentPacketRecord &packet) {
    packet_space.sent_packets[packet.packet_number] = packet;
    packet_space.recovery.on_packet_sent(packet);
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    }
    maybe_emit_qlog_recovery_metrics(packet.sent_time);
}

void QuicConnection::retire_acked_packet(PacketSpaceState &packet_space,
                                         const SentPacketRecord &packet) {
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
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stream_data_blocked_frame(frame);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_send_fragment(fragment);
        maybe_refresh_peer_stream_limit(stream->second);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_reset_frame(frame);
        maybe_refresh_peer_stream_limit(stream->second);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stop_sending_frame(frame);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.acknowledge_max_streams_frame(frame);
    }
    if (packet.has_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::acknowledged;
    }

    packet_space.sent_packets.erase(packet.packet_number);
    packet_space.declared_lost_packets.erase(packet.packet_number);
}

void QuicConnection::mark_lost_packet(PacketSpaceState &packet_space,
                                      const SentPacketRecord &packet) {
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packets_lost(std::span<const SentPacketRecord>(&packet, 1));
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
                                                              bool allow_preconnected_frames) {
    const bool require_connected = !allow_preconnected_frames;
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

        if (std::holds_alternative<NewConnectionIdFrame>(frame)) {
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
            mark_failed();
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            confirm_handshake();
            continue;
        }

        const bool allow_preconnected_retire_connection_id_frame =
            application_space_.read_secret.has_value() & (status_ == HandshakeStatus::in_progress) &
            std::holds_alternative<RetireConnectionIdFrame>(frame);
        const bool reject_preconnected_application_frame =
            require_connected & !allow_preconnected_retire_connection_id_frame &
            (status_ != HandshakeStatus::connected);
        if (reject_preconnected_application_frame) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        }
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
    for (const auto &packet : deferred_packets) {
        process_inbound_datagram(packet.bytes, now, packet.datagram_id,
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

    update_handshake_status();
    maybe_emit_qlog_alpn_information(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    auto *tls = tls_.has_value() ? &*tls_ : nullptr;
    const bool tls_handshake_complete = tls != nullptr ? tls->handshake_complete() : false;
    if (!resumption_state_emitted_ && (tls != nullptr) && tls_handshake_complete &&
        peer_transport_parameters_.has_value()) {
        if (const auto ticket = tls->take_resumption_state(); ticket.has_value()) {
            auto encoded = encode_resumption_state(
                *ticket, current_version_, config_.application_protocol,
                *peer_transport_parameters_, config_.zero_rtt.application_context);
            pending_resumption_state_effect_ = QuicCoreResumptionStateAvailable{
                .state =
                    QuicResumptionState{
                        .serialized = std::move(encoded),
                    },
            };
            resumption_state_emitted_ = true;
        }
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
    if (peer_transport_parameters_bytes.has_value()) {
        const auto parameters =
            deserialize_transport_parameters(peer_transport_parameters_bytes.value());
        if (!parameters.has_value()) {
            log_codec_failure("deserialize_transport_parameters", parameters.error());
            return CodecResult<bool>::failure(parameters.error().code, parameters.error().offset);
        }

        peer_transport_parameters_ = parameters.value();
    } else if (!peer_transport_parameters_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto validation_context = peer_transport_parameters_validation_context();
    if (!validation_context.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto validation = validate_peer_transport_parameters(opposite_role(config_.role),
                                                               peer_transport_parameters_.value(),
                                                               validation_context.value());
    if (!validation.has_value()) {
        log_codec_failure("validate_peer_transport_parameters", validation.error());
        return CodecResult<bool>::failure(validation.error().code, validation.error().offset);
    }

    peer_transport_parameters_validated_ = true;
    initialize_peer_flow_control_from_transport_parameters();
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
    discard_handshake_packet_space();
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

bool QuicConnection::should_defer_client_standalone_handshake_ack() const {
    return (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::in_progress) &
           !handshake_confirmed_ & !initial_packet_space_discarded_ &
           !handshake_space_.send_crypto.has_pending_data() &
           !handshake_space_.pending_probe_packet.has_value();
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

StreamStateResult<StreamState *> QuicConnection::get_or_open_local_stream(std::uint64_t stream_id) {
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return StreamStateResult<StreamState *>::success(&existing->second);
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
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return StreamStateResult<StreamState *>::success(&existing->second);
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
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return CodecResult<StreamState *>::success(&existing->second);
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
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return CodecResult<StreamState *>::success(&existing->second);
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

bool QuicConnection::anti_amplification_applies() const {
    return config_.role == EndpointRole::server && status_ == HandshakeStatus::in_progress &&
           !peer_address_validated_;
}

std::uint64_t QuicConnection::anti_amplification_send_budget() const {
    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    if (anti_amplification_received_bytes_ > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    return anti_amplification_received_bytes_ * 3u;
}

std::size_t QuicConnection::outbound_datagram_size_limit() const {
    if (!anti_amplification_applies()) {
        return kMaximumDatagramSize;
    }

    const auto remaining_budget =
        saturating_subtract(anti_amplification_send_budget(), anti_amplification_sent_bytes_);
    return static_cast<std::size_t>(std::min<std::uint64_t>(
        remaining_budget, static_cast<std::uint64_t>(kMaximumDatagramSize)));
}

void QuicConnection::note_inbound_datagram_bytes(std::size_t bytes) {
    if (!anti_amplification_applies() || bytes == 0) {
        return;
    }

    const auto received = anti_amplification_received_bytes_;
    const auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_received_bytes_ =
        received > std::numeric_limits<std::uint64_t>::max() - increment
            ? std::numeric_limits<std::uint64_t>::max()
            : received + increment;
}

void QuicConnection::note_outbound_datagram_bytes(std::size_t bytes) {
    if (!anti_amplification_applies() || bytes == 0) {
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
}

ConnectionId QuicConnection::outbound_destination_connection_id() const {
    if (peer_source_connection_id_.has_value()) {
        return peer_source_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

ConnectionId QuicConnection::client_initial_destination_connection_id() const {
    if (client_initial_destination_connection_id_.has_value()) {
        return client_initial_destination_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

std::vector<std::byte> QuicConnection::flush_outbound_datagram(QuicCoreTimePoint now) {
    const auto max_outbound_datagram_size = outbound_datagram_size_limit();
    if (max_outbound_datagram_size == 0) {
        return {};
    }

    if (config_.role == EndpointRole::client && application_space_.write_secret.has_value() &&
        zero_rtt_space_.write_secret.has_value()) {
        discard_packet_space_state(zero_rtt_space_);
    }

    auto packets = std::vector<ProtectedPacket>{};
    const auto destination_connection_id = outbound_destination_connection_id();
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
    const auto serialize_candidate_datagram_with_metadata =
        [&](const std::vector<ProtectedPacket> &candidate_packets)
        -> CodecResult<SerializedProtectedDatagram> {
        auto datagram_packets = candidate_packets;
        auto datagram = serialize_protected_datagram_with_metadata(
            datagram_packets, SerializeProtectionContext{
                                  .local_role = config_.role,
                                  .client_initial_destination_connection_id =
                                      client_initial_destination_connection_id(),
                                  .handshake_secret = handshake_space_.write_secret,
                                  .zero_rtt_secret = zero_rtt_space_.write_secret,
                                  .one_rtt_secret = application_space_.write_secret,
                                  .one_rtt_key_phase = application_write_key_phase_,
                              });
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

                return serialize_protected_datagram_with_metadata(
                    datagram_packets, SerializeProtectionContext{
                                          .local_role = config_.role,
                                          .client_initial_destination_connection_id =
                                              client_initial_destination_connection_id(),
                                          .handshake_secret = handshake_space_.write_secret,
                                          .zero_rtt_secret = zero_rtt_space_.write_secret,
                                          .one_rtt_secret = application_space_.write_secret,
                                          .one_rtt_key_phase = application_write_key_phase_,
                                      });
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
    const auto finalize_datagram = [&](const std::vector<ProtectedPacket> &datagram_packets) {
        auto datagram = serialize_candidate_datagram_with_metadata(datagram_packets);
        if (!datagram.has_value()) {
            mark_failed();
            return std::vector<std::byte>{};
        }

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

        const auto outbound_datagram_id =
            qlog_session_ != nullptr
                ? std::optional<std::uint32_t>(qlog_session_->next_outbound_datagram_id())
                : std::nullopt;
        for (std::size_t index = 0; index < datagram_packets.size(); ++index) {
            const auto packet_number =
                std::visit([](const auto &packet_value) { return packet_value.packet_number; },
                           datagram_packets[index]);
            const auto snapshot = make_qlog_packet_snapshot(
                datagram_packets[index],
                qlog::PacketSnapshotContext{
                    .raw_length = datagram.value().packet_metadata[index].length,
                    .datagram_id = outbound_datagram_id.value_or(0),
                    .trigger = pto_probe_burst_active ? std::optional<std::string>("pto_probe")
                                                      : std::nullopt,
                });
            if (qlog_session_ != nullptr && outbound_datagram_id.has_value()) {
                static_cast<void>(qlog_session_->write_event(
                    now, "quic:packet_sent", qlog::serialize_packet_snapshot(snapshot)));
            }

            for (auto *packet_space : {&initial_space_, &handshake_space_, &application_space_}) {
                const auto sent = packet_space->sent_packets.find(packet_number);
                if (sent == packet_space->sent_packets.end()) {
                    continue;
                }

                sent->second.qlog_packet_snapshot =
                    std::make_shared<qlog::PacketSnapshot>(snapshot);
                sent->second.qlog_pto_probe = pto_probe_burst_active;
            }
        }

        note_outbound_datagram_bytes(datagram.value().bytes.size());

        return datagram.value().bytes;
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
        initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now);
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
                    track_sent_packet(initial_space_,
                                      SentPacketRecord{
                                          .packet_number = duplicate_packet_number,
                                          .sent_time = now,
                                          .ack_eliciting = initial_ack_eliciting,
                                          .in_flight = initial_ack_eliciting,
                                          .declared_lost = false,
                                          .crypto_ranges = sent_initial_crypto_ranges,
                                      });
                }
            }
        }

        if (config_.role == EndpointRole::client &&
            initial_destination_connection_id != destination_connection_id) {
            return finalize_datagram(packets);
        }
    }

    const auto handshake_ack_frame =
        handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now);
    const bool defer_client_standalone_handshake_ack =
        should_defer_client_standalone_handshake_ack();
    const auto max_handshake_crypto_bytes =
        std::numeric_limits<std::size_t>::max() *
        static_cast<std::size_t>(!defer_server_compatible_negotiation_crypto);
    auto handshake_crypto_ranges =
        handshake_space_.send_crypto.take_ranges(max_handshake_crypto_bytes);
    const auto build_handshake_frames = [&](std::span<const ByteRange> crypto_ranges,
                                            bool override_probe_crypto_ranges = false,
                                            std::span<const ByteRange> probe_crypto_ranges = {}) {
        std::vector<Frame> frames;
        frames.reserve(crypto_ranges.size() + (handshake_ack_frame.has_value() ? 1u : 0u) +
                       (handshake_space_.pending_probe_packet.has_value()
                            ? handshake_space_.pending_probe_packet->crypto_ranges.size() + 1u
                            : 0u));
        const bool suppress_ack_only_handshake_packet = defer_client_standalone_handshake_ack;
        if (handshake_ack_frame.has_value() && !suppress_ack_only_handshake_packet) {
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
    const bool has_pending_application_payload =
        application_space_.received_packets.has_ack_to_send() | has_pending_application_send() |
        application_space_.pending_probe_packet.has_value() | !application_crypto_frames.empty();
    if ((can_send_one_rtt_packets || use_zero_rtt_packet_protection) &&
        has_pending_application_payload) {
        const auto base_ack_frame = use_zero_rtt_packet_protection
                                        ? std::optional<AckFrame>{}
                                        : application_space_.received_packets.build_ack_frame(
                                              local_transport_parameters_.ack_delay_exponent, now);
        for (auto &[stream_id, stream] : streams_) {
            static_cast<void>(stream_id);
            maybe_queue_stream_blocked_frame(stream);
        }
        maybe_queue_connection_blocked_frame();
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
            [](auto &connection_flow, auto &streams, std::size_t max_bytes,
               auto &last_stream_id) -> std::vector<StreamFrameSendFragment> {
            std::vector<StreamFrameSendFragment> fragments;
            auto remaining_bytes = max_bytes;
            auto remaining_connection_credit =
                connection_flow.peer_max_data > connection_flow.highest_sent
                    ? connection_flow.peer_max_data - connection_flow.highest_sent
                    : 0;
            auto loss_phase = true;
            auto allow_zero_byte_round = true;

            for (;;) {
                const bool should_continue_round = (remaining_bytes > 0) | allow_zero_byte_round;
                if (!should_continue_round) {
                    break;
                }
                const auto zero_byte_round = remaining_bytes == 0;
                allow_zero_byte_round = false;
                const auto order = round_robin_stream_order(streams, last_stream_id);
                std::vector<std::uint64_t> active_stream_ids;
                active_stream_ids.reserve(order.size());
                for (const auto stream_id : order) {
                    auto &stream = streams.at(stream_id);
                    if (stream.reset_state != StreamControlFrameState::none) {
                        continue;
                    }

                    const auto active = loss_phase ? stream.send_buffer.has_lost_data() ||
                                                         stream_fin_sendable(stream)
                                                   : stream.sendable_bytes() != 0;
                    if (active) {
                        active_stream_ids.push_back(stream_id);
                    }
                }

                if (active_stream_ids.empty()) {
                    if (loss_phase) {
                        loss_phase = false;
                        continue;
                    }

                    break;
                }

                std::size_t bytes_sent_this_round = 0;
                bool emitted_fragment = false;
                for (const auto stream_id : active_stream_ids) {
                    auto &stream = streams.at(stream_id);

                    const auto highest_sent_before = stream.flow_control.highest_sent;
                    const auto packet_share =
                        std::max<std::size_t>(static_cast<std::size_t>(!zero_byte_round),
                                              remaining_bytes / active_stream_ids.size());
                    const auto new_byte_share =
                        loss_phase || remaining_connection_credit == 0
                            ? 0
                            : std::max<std::uint64_t>(1, remaining_connection_credit /
                                                             active_stream_ids.size());
                    auto stream_fragments = stream.take_send_fragments(StreamSendBudget{
                        .packet_bytes = std::min(remaining_bytes, packet_share),
                        .new_bytes = new_byte_share,
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
        const auto serialize_application_candidate =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<AckFrame> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool include_ping) -> CodecResult<std::vector<std::byte>> {
            std::vector<Frame> candidate_frames;
            candidate_frames.reserve(crypto_ranges.size() + (ack_frame.has_value() ? 1u : 0u) +
                                     (include_handshake_done ? 1u : 0u) +
                                     (max_data_frame.has_value() ? 1u : 0u) +
                                     max_stream_data_frames.size() + max_streams_frames.size() +
                                     reset_stream_frames.size() + stop_sending_frames.size() +
                                     (data_blocked_frame.has_value() ? 1u : 0u) +
                                     stream_data_blocked_frames.size() + (include_ping ? 1u : 0u));
            append_application_crypto_frames(candidate_frames, crypto_ranges);
            if (ack_frame.has_value()) {
                candidate_frames.emplace_back(*ack_frame);
            }
            if (include_handshake_done) {
                candidate_frames.emplace_back(HandshakeDoneFrame{});
            }
            if (max_data_frame.has_value()) {
                candidate_frames.emplace_back(*max_data_frame);
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
            if (include_ping) {
                candidate_frames.emplace_back(PingFrame{});
            }

            auto candidate_packets = packets;
            candidate_packets.emplace_back(make_application_protected_packet(
                use_zero_rtt_packet_protection, current_version_, destination_connection_id,
                config_.source_connection_id, application_write_key_phase_,
                kDefaultInitialPacketNumberLength, application_space_.next_send_packet_number,
                std::move(candidate_frames), stream_fragments));

            return serialize_candidate_datagram(candidate_packets);
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
                max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                stream_fragments, include_ping);
            if (!candidate_datagram.has_value()) {
                mark_failed();
                return std::nullopt;
            }
            if (candidate_ack_frame->additional_ranges.empty() ||
                candidate_datagram.value().size() <= max_outbound_datagram_size) {
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

                candidate_datagram = CodecResult<std::vector<std::byte>>::success(
                    serialize_application_candidate(
                        crypto_ranges, include_handshake_done, trimmed_ack_frame, max_data_frame,
                        max_stream_data_frames, max_streams_frames, reset_stream_frames,
                        stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                        stream_fragments, include_ping)
                        .value());

                if (candidate_datagram.value().size() <= max_outbound_datagram_size) {
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
        const auto should_send_application_probe_first = [&]() {
            if (pending_application_probe == nullptr) {
                return false;
            }

            if (has_pending_application_stream_send()) {
                // If there is queued stream response data, don't let a control-only PTO probe
                // starve it; use the PTO opportunity to send the response.
                if (pending_application_probe->stream_fragments.empty()) {
                    return false;
                }

                // On the last datagram of a PTO burst, spend the remaining probe credit on
                // fresh queued stream data instead of retransmitting the same stream fragment
                // again.
                if (remaining_pto_probe_datagrams_ == 1) {
                    return false;
                }
            }

            const bool probe_is_retransmittable =
                retransmittable_probe_frame_count(*pending_application_probe) != 0;
            return static_cast<bool>(probe_is_retransmittable | !has_pending_application_send());
        };

        if (should_send_application_probe_first()) {
            const auto &probe_packet = *pending_application_probe;
            const auto &probe_crypto_ranges = application_crypto_ranges.empty()
                                                  ? probe_packet.crypto_ranges
                                                  : application_crypto_ranges;
            const auto include_ping = retransmittable_probe_frame_count(probe_packet) == 0;
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
            auto probe_stream_fragments = make_probe_stream_fragments();
            mark_probe_fragments_sent(probe_stream_fragments);
            auto ack_frame = trim_application_ack_frame(
                probe_crypto_ranges, probe_packet.has_handshake_done, base_ack_frame,
                probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                probe_packet.stream_data_blocked_frames, probe_stream_fragments, include_ping);
            if (has_failed()) {
                return {};
            }

            auto datagram = serialize_application_candidate(
                probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                probe_packet.stream_data_blocked_frames, probe_stream_fragments, include_ping);
            if (!datagram.has_value()) {
                mark_failed();
                return {};
            }
            if (ack_frame.has_value() && datagram.value().size() > max_outbound_datagram_size) {
                auto no_ack_datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, std::nullopt,
                    probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                    probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                    probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                    probe_packet.stream_data_blocked_frames, probe_stream_fragments, include_ping);
                if (!no_ack_datagram.has_value()) {
                    mark_failed();
                    return {};
                }
                if (no_ack_datagram.value().size() <= max_outbound_datagram_size) {
                    ack_frame = std::nullopt;
                    datagram = std::move(no_ack_datagram);
                }
            }
            const auto trim_probe_candidate_to_fit =
                [&](const std::optional<AckFrame> &candidate_ack_frame,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().size() > max_outbound_datagram_size && !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_probe_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot = datagram.value().size() - max_outbound_datagram_size;
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
                        probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                        probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                        probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                        probe_packet.stream_data_blocked_frames, fragments, include_ping);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().size() <= max_outbound_datagram_size;
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
                        probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                        probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                        probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                        probe_packet.stream_data_blocked_frames, probe_stream_fragments,
                        include_ping);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return {};
                    }
                    static_cast<void>(
                        trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments));
                }
            }
            const auto probe_datagram_size = datagram_size_or_zero(datagram);
            if (probe_datagram_size > max_outbound_datagram_size) {
                restore_unsent_application_probe_candidate();
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
                (probe_packet.max_data_frame.has_value() ? 1u : 0u) +
                probe_packet.max_stream_data_frames.size() +
                probe_packet.max_streams_frames.size() + probe_packet.reset_stream_frames.size() +
                probe_packet.stop_sending_frames.size() +
                (probe_packet.data_blocked_frame.has_value() ? 1u : 0u) +
                probe_packet.stream_data_blocked_frames.size() + (include_ping ? 1u : 0u));
            append_application_crypto_frames(frames, probe_crypto_ranges);
            if (ack_frame.has_value()) {
                frames.emplace_back(*ack_frame);
            }
            if (probe_packet.has_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            if (probe_packet.max_data_frame.has_value()) {
                frames.emplace_back(*probe_packet.max_data_frame);
            }
            for (const auto &frame : probe_packet.max_stream_data_frames) {
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
                use_zero_rtt_packet_protection, current_version_, destination_connection_id,
                config_.source_connection_id, application_write_key_phase_,
                kDefaultInitialPacketNumberLength, *packet_number, std::move(frames),
                probe_stream_fragments));

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
                    .max_data_frame = probe_packet.max_data_frame,
                    .max_stream_data_frames = probe_packet.max_stream_data_frames,
                    .max_streams_frames = probe_packet.max_streams_frames,
                    .data_blocked_frame = probe_packet.data_blocked_frame,
                    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
                    .stream_fragments = probe_stream_fragments,
                    .has_ping = include_ping,
                    .bytes_in_flight = datagram.value().size(),
                });
            if (probe_packet.has_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        } else {
            const auto include_handshake_done =
                !use_zero_rtt_packet_protection && config_.role == EndpointRole::server &&
                handshake_done_state_ == StreamControlFrameState::pending;
            const auto send_application_ack_only =
                [&](const AckFrame &ack_frame) -> std::vector<std::byte> {
                auto ack_only_datagram = serialize_application_candidate(
                    {}, /*include_handshake_done=*/false, ack_frame, std::nullopt, {}, {}, {}, {},
                    std::nullopt, {}, {}, /*include_ping=*/false);
                if (!ack_only_datagram.has_value()) {
                    mark_failed();
                    return {};
                }

                std::vector<Frame> ack_only_frames;
                ack_only_frames.emplace_back(ack_frame);
                const auto packet_number =
                    reserve_application_packet_number(!use_zero_rtt_packet_protection);
                if (!packet_number.has_value()) {
                    return {};
                }
                packets.emplace_back(make_application_protected_packet(
                    use_zero_rtt_packet_protection, current_version_, destination_connection_id,
                    config_.source_connection_id, application_write_key_phase_,
                    kDefaultInitialPacketNumberLength, *packet_number, std::move(ack_only_frames),
                    {}));
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
                return finalize_datagram(packets);
            };
            std::vector<Frame> frames;
            const auto force_ack_only =
                application_space_.force_ack_send & base_ack_frame.has_value();
            auto max_data_frame = force_ack_only ? std::optional<MaxDataFrame>{}
                                                 : connection_flow_control_.take_max_data_frame();
            auto data_blocked_frame = force_ack_only
                                          ? std::optional<DataBlockedFrame>{}
                                          : connection_flow_control_.take_data_blocked_frame();
            auto max_stream_data_frames = force_ack_only ? std::vector<MaxStreamDataFrame>{}
                                                         : take_max_stream_data_frames(streams_);
            auto max_streams_frames = take_max_streams_frames(force_ack_only);
            auto reset_stream_frames = force_ack_only ? std::vector<ResetStreamFrame>{}
                                                      : take_reset_stream_frames(streams_);
            auto stop_sending_frames = force_ack_only ? std::vector<StopSendingFrame>{}
                                                      : take_stop_sending_frames(streams_);
            auto stream_data_blocked_frames = force_ack_only
                                                  ? std::vector<StreamDataBlockedFrame>{}
                                                  : take_stream_data_blocked_frames(streams_);
            auto candidate_last_stream_id = last_application_send_stream_id_;
            auto stream_fragments =
                force_ack_only
                    ? std::vector<StreamFrameSendFragment>{}
                    : take_stream_fragments(connection_flow_control_, streams_,
                                            max_outbound_datagram_size, candidate_last_stream_id);
            auto selected_ack_frame = trim_application_ack_frame(
                application_crypto_ranges, include_handshake_done, base_ack_frame, max_data_frame,
                max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                stream_fragments, /*include_ping=*/false);
            if (has_failed()) {
                return {};
            }

            auto candidate_datagram = serialize_application_candidate(
                application_crypto_ranges, include_handshake_done, selected_ack_frame,
                max_data_frame, max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                stream_fragments, /*include_ping=*/false);
            if (!candidate_datagram.has_value()) {
                mark_failed();
                return {};
            }
            if (selected_ack_frame.has_value() &&
                candidate_datagram.value().size() > max_outbound_datagram_size) {
                auto no_ack_candidate = serialize_application_candidate(
                    application_crypto_ranges, include_handshake_done, std::nullopt, max_data_frame,
                    max_stream_data_frames, max_streams_frames, reset_stream_frames,
                    stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                    stream_fragments, /*include_ping=*/false);
                if (!no_ack_candidate.has_value()) {
                    mark_failed();
                    return {};
                }
                if (no_ack_candidate.value().size() <= max_outbound_datagram_size) {
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = std::move(no_ack_candidate);
                }
            }

            const auto trim_candidate_to_fit =
                [&](const std::optional<AckFrame> &ack_frame,
                    CodecResult<std::vector<std::byte>> &datagram,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().size() > max_outbound_datagram_size && !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_application_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot = datagram.value().size() - max_outbound_datagram_size;
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
                        application_crypto_ranges, include_handshake_done, ack_frame,
                        max_data_frame, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, fragments, /*include_ping=*/false);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().size() <= max_outbound_datagram_size;
            };
            const auto fallback_to_existing_packets_or_ack_only = [&]() -> std::vector<std::byte> {
                if (!packets.empty()) {
                    return finalize_datagram(packets);
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
                        max_data_frame, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments);

                    max_data_frame = connection_flow_control_.take_max_data_frame();
                    data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                    max_stream_data_frames = take_max_stream_data_frames(streams_);
                    max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                    reset_stream_frames = take_reset_stream_frames(streams_);
                    stop_sending_frames = take_stop_sending_frames(streams_);
                    stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                    candidate_last_stream_id = last_application_send_stream_id_;
                    stream_fragments =
                        take_stream_fragments(connection_flow_control_, streams_,
                                              max_outbound_datagram_size, candidate_last_stream_id);
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = serialize_application_candidate(
                        application_crypto_ranges, include_handshake_done, selected_ack_frame,
                        max_data_frame, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments, /*include_ping=*/false);
                    if (!candidate_datagram.has_value()) {
                        mark_failed();
                        return {};
                    }
                    static_cast<void>(trim_candidate_to_fit(selected_ack_frame, candidate_datagram,
                                                            stream_fragments));
                }
            }
            const auto candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            if (candidate_datagram_size > max_outbound_datagram_size) {
                restore_unsent_application_candidate(max_data_frame, max_stream_data_frames,
                                                     max_streams_frames, reset_stream_frames,
                                                     stop_sending_frames, data_blocked_frame,
                                                     stream_data_blocked_frames, stream_fragments);
                if (!packets.empty()) {
                    return finalize_datagram(packets);
                }
                if (max_outbound_datagram_size == kMaximumDatagramSize) {
                    mark_failed();
                    return {};
                }
                return fallback_to_existing_packets_or_ack_only();
            }

            frames.reserve(
                application_crypto_frames.size() + (selected_ack_frame.has_value() ? 1u : 0u) +
                (include_handshake_done ? 1u : 0u) + reset_stream_frames.size() +
                stop_sending_frames.size() + (max_data_frame.has_value() ? 1u : 0u) +
                max_stream_data_frames.size() + max_streams_frames.size() +
                (data_blocked_frame.has_value() ? 1u : 0u) + stream_data_blocked_frames.size());
            for (const auto &frame : application_crypto_frames) {
                frames.emplace_back(frame);
            }
            if (selected_ack_frame.has_value()) {
                frames.emplace_back(*selected_ack_frame);
            }
            if (include_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            const auto ack_eliciting =
                !application_crypto_frames.empty() ||
                application_ack_eliciting_frame_count(
                    include_handshake_done, max_data_frame, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments) != 0;
            const auto bypass_congestion_window =
                application_space_.pending_probe_packet.has_value();
            if (ack_eliciting && !bypass_congestion_window &&
                !congestion_controller_.can_send_ack_eliciting(candidate_datagram.value().size())) {
                restore_unsent_application_candidate(max_data_frame, max_stream_data_frames,
                                                     max_streams_frames, reset_stream_frames,
                                                     stop_sending_frames, data_blocked_frame,
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

            const auto packet_number =
                reserve_application_packet_number(!use_zero_rtt_packet_protection);
            if (!packet_number.has_value()) {
                return {};
            }
            const auto stream_bytes = stream_fragment_bytes(stream_fragments);
            if (packet_trace_matches_connection(config_.source_connection_id)) {
                const auto ack_trace_value = static_cast<int>(selected_ack_frame.has_value());
                const auto handshake_done_trace_value = static_cast<int>(include_handshake_done);
                std::cerr << "quic-packet-trace send scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " pn=" << *packet_number << " ack=" << ack_trace_value
                          << " hsdone=" << handshake_done_trace_value << " stream=" << stream_bytes
                          << " bytes=" << candidate_datagram.value().size() << '\n';
            }
            packets.emplace_back(make_application_protected_packet(
                use_zero_rtt_packet_protection, current_version_, destination_connection_id,
                config_.source_connection_id, application_write_key_phase_,
                kDefaultInitialPacketNumberLength, *packet_number, std::move(frames),
                stream_fragments));

            if (ack_eliciting) {
                track_sent_packet(application_space_,
                                  SentPacketRecord{
                                      .packet_number = *packet_number,
                                      .sent_time = now,
                                      .ack_eliciting = ack_eliciting,
                                      .in_flight = ack_eliciting,
                                      .declared_lost = false,
                                      .has_handshake_done = include_handshake_done,
                                      .crypto_ranges = application_crypto_ranges,
                                      .reset_stream_frames = reset_stream_frames,
                                      .stop_sending_frames = stop_sending_frames,
                                      .max_data_frame = max_data_frame,
                                      .max_stream_data_frames = max_stream_data_frames,
                                      .max_streams_frames = max_streams_frames,
                                      .data_blocked_frame = data_blocked_frame,
                                      .stream_data_blocked_frames = stream_data_blocked_frames,
                                      .stream_fragments = stream_fragments,
                                      .bytes_in_flight = candidate_datagram.value().size(),
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
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        }
    }

    if (packets.empty()) {
        return {};
    }

    return finalize_datagram(packets);
}

} // namespace coquic::quic

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
    const bool failed_datagram_reports_zero_size = datagram_size_or_zero(failed_datagram) == 0;

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
           encode_failure_returns_empty & wrong_magic_rejected & truncated_tls_state_rejected &
           missing_application_protocol_rejected & missing_transport_parameters_rejected &
           missing_application_context_rejected & trailing_bytes_rejected &
           pending_data_blocks_fin & missing_pending_frames_preserve_state &
           short_header_is_bufferable & truncated_long_header_is_not_bufferable &
           handshake_long_header_is_bufferable & protected_one_rtt_packet_deferred &
           connected_protected_one_rtt_packet_not_deferred & corrupted_long_header_discarded &
           short_header_not_discarded_as_corrupted_long_header & empty_connection_id_formats_empty &
           connection_id_formats_lower_hex & trace_unset_disabled & trace_empty_disabled &
           trace_zero_disabled & trace_matches_without_filter & trace_matches_with_empty_filter &
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

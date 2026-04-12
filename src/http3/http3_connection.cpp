#include "src/http3/http3_connection.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "src/quic/streams.h"
#include "src/quic/varint.h"

namespace coquic::http3 {

using quic::classify_stream_id;
using quic::CodecErrorCode;
using quic::decode_varint_bytes;
using quic::StreamDirection;
using quic::StreamInitiator;

namespace {

enum class BufferedInstructionStatus : std::uint8_t {
    complete,
    incomplete,
    invalid,
};

struct BufferedInstructionProgress {
    BufferedInstructionStatus status = BufferedInstructionStatus::incomplete;
    std::size_t bytes_consumed = 0;
};

BufferedInstructionProgress parse_prefixed_integer_progress(std::span<const std::byte> bytes,
                                                            std::uint8_t prefix_bits) {
    if (bytes.empty()) {
        return {};
    }

    const auto first = std::to_integer<std::uint8_t>(bytes.front());
    const auto max_in_prefix = (static_cast<std::uint64_t>(1) << prefix_bits) - 1u;
    std::uint64_t value = first & static_cast<std::uint8_t>(max_in_prefix);
    std::size_t bytes_consumed = 1;
    if (value < max_in_prefix) {
        return {
            .status = BufferedInstructionStatus::complete,
            .bytes_consumed = bytes_consumed,
        };
    }

    std::uint64_t shift = 0;
    while (true) {
        if (bytes_consumed >= bytes.size()) {
            return {};
        }

        const auto byte = std::to_integer<std::uint8_t>(bytes[bytes_consumed++]);
        const auto chunk = static_cast<std::uint64_t>(byte & 0x7fu);
        if (shift >= 63 || chunk > ((std::numeric_limits<std::uint64_t>::max() - value) >> shift)) {
            return {
                .status = BufferedInstructionStatus::invalid,
            };
        }

        value += chunk << shift;
        if ((byte & 0x80u) == 0u) {
            return {
                .status = BufferedInstructionStatus::complete,
                .bytes_consumed = bytes_consumed,
            };
        }

        shift += 7;
    }
}

BufferedInstructionProgress parse_string_literal_progress(std::span<const std::byte> bytes,
                                                          std::uint8_t prefix_bits) {
    const auto length = parse_prefixed_integer_progress(bytes, prefix_bits);
    if (length.status != BufferedInstructionStatus::complete) {
        return length;
    }

    if (bytes.size() < length.bytes_consumed) {
        return {};
    }

    const auto length_bytes = bytes.subspan(0, length.bytes_consumed);
    const auto max_in_prefix = (static_cast<std::uint64_t>(1) << prefix_bits) - 1u;
    std::uint64_t value = std::to_integer<std::uint8_t>(length_bytes.front()) &
                          static_cast<std::uint8_t>(max_in_prefix);
    if (value == max_in_prefix) {
        std::uint64_t shift = 0;
        for (std::size_t index = 1; index < length.bytes_consumed; ++index) {
            const auto byte = std::to_integer<std::uint8_t>(length_bytes[index]);
            value += static_cast<std::uint64_t>(byte & 0x7fu) << shift;
            shift += 7;
        }
    }

    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return {
            .status = BufferedInstructionStatus::invalid,
        };
    }

    const auto payload_size = static_cast<std::size_t>(value);
    if (bytes.size() - length.bytes_consumed < payload_size) {
        return {};
    }

    return {
        .status = BufferedInstructionStatus::complete,
        .bytes_consumed = length.bytes_consumed + payload_size,
    };
}

BufferedInstructionProgress
complete_qpack_encoder_instruction_size(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }

    const auto first = std::to_integer<std::uint8_t>(bytes.front());
    if ((first & 0xe0u) == 0x20u) {
        return parse_prefixed_integer_progress(bytes, 5);
    }

    if ((first & 0x80u) == 0x80u) {
        const auto name_reference = parse_prefixed_integer_progress(bytes, 6);
        if (name_reference.status != BufferedInstructionStatus::complete) {
            return name_reference;
        }

        if (bytes.size() <= name_reference.bytes_consumed) {
            return {};
        }

        const auto value =
            parse_string_literal_progress(bytes.subspan(name_reference.bytes_consumed), 7);
        if (value.status != BufferedInstructionStatus::complete) {
            return value;
        }

        return {
            .status = BufferedInstructionStatus::complete,
            .bytes_consumed = name_reference.bytes_consumed + value.bytes_consumed,
        };
    }

    if ((first & 0x40u) == 0x40u) {
        const auto name = parse_string_literal_progress(bytes, 5);
        if (name.status != BufferedInstructionStatus::complete) {
            return name;
        }

        if (bytes.size() <= name.bytes_consumed) {
            return {};
        }

        const auto value = parse_string_literal_progress(bytes.subspan(name.bytes_consumed), 7);
        if (value.status != BufferedInstructionStatus::complete) {
            return value;
        }

        return {
            .status = BufferedInstructionStatus::complete,
            .bytes_consumed = name.bytes_consumed + value.bytes_consumed,
        };
    }

    if ((first & 0xe0u) == 0x00u) {
        return parse_prefixed_integer_progress(bytes, 5);
    }

    return {
        .status = BufferedInstructionStatus::invalid,
    };
}

BufferedInstructionProgress
complete_qpack_decoder_instruction_size(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }

    const auto first = std::to_integer<std::uint8_t>(bytes.front());
    if ((first & 0x80u) == 0x80u) {
        return parse_prefixed_integer_progress(bytes, 7);
    }

    return parse_prefixed_integer_progress(bytes, 6);
}

quic::EndpointRole endpoint_role(Http3ConnectionRole role) {
    return role == Http3ConnectionRole::client ? quic::EndpointRole::client
                                               : quic::EndpointRole::server;
}

Http3QpackSettings qpack_settings_from_snapshot(const Http3SettingsSnapshot &settings) {
    return Http3QpackSettings{
        .max_table_capacity = settings.qpack_max_table_capacity,
        .blocked_streams = settings.qpack_blocked_streams,
    };
}

std::vector<Http3Setting> settings_from_snapshot(const Http3SettingsSnapshot &settings) {
    std::vector<Http3Setting> values = {
        Http3Setting{
            .id = kHttp3SettingsQpackMaxTableCapacity,
            .value = settings.qpack_max_table_capacity,
        },
    };
    if (settings.max_field_section_size.has_value()) {
        values.push_back(Http3Setting{
            .id = kHttp3SettingsMaxFieldSectionSize,
            .value = *settings.max_field_section_size,
        });
    }
    values.push_back(Http3Setting{
        .id = kHttp3SettingsQpackBlockedStreams,
        .value = settings.qpack_blocked_streams,
    });
    return values;
}

std::optional<std::size_t> complete_http3_frame_size(std::span<const std::byte> bytes) {
    const auto type = decode_varint_bytes(bytes);
    if (!type.has_value()) {
        if (type.error().code == CodecErrorCode::truncated_input) {
            return std::nullopt;
        }
        return 0;
    }

    const auto after_type = bytes.subspan(type.value().bytes_consumed);
    const auto length = decode_varint_bytes(after_type);
    if (!length.has_value()) {
        if (length.error().code == CodecErrorCode::truncated_input) {
            return std::nullopt;
        }
        return 0;
    }

    const auto header_size = type.value().bytes_consumed + length.value().bytes_consumed;
    if (length.value().value > bytes.size() - header_size) {
        return std::nullopt;
    }
    return header_size + static_cast<std::size_t>(length.value().value);
}

} // namespace

Http3Connection::Http3Connection(Http3ConnectionConfig config)
    : config_(config), peer_settings_(), encoder_{}, decoder_{} {
    encoder_.peer_settings = qpack_settings_from_snapshot(peer_settings_);
    decoder_.local_settings = qpack_settings_from_snapshot(config_.local_settings);
}

Http3EndpointUpdate Http3Connection::on_core_result(const quic::QuicCoreResult &result,
                                                    quic::QuicCoreTimePoint now) {
    (void)now;

    if (closed_) {
        return drain_pending_inputs(/*terminal_failure=*/true);
    }

    if (result.local_error.has_value()) {
        closed_ = true;
        return drain_pending_inputs(/*terminal_failure=*/true);
    }

    for (const auto &effect : result.effects) {
        if (const auto *state = std::get_if<quic::QuicCoreStateEvent>(&effect)) {
            if (state->change == quic::QuicCoreStateChange::handshake_ready ||
                state->change == quic::QuicCoreStateChange::handshake_confirmed) {
                transport_ready_ = true;
            } else if (state->change == quic::QuicCoreStateChange::failed) {
                closed_ = true;
            }
            continue;
        }

        if (const auto *received = std::get_if<quic::QuicCoreReceiveStreamData>(&effect)) {
            handle_receive_stream_data(*received);
            continue;
        }

        if (const auto *reset = std::get_if<quic::QuicCorePeerResetStream>(&effect)) {
            handle_peer_reset_stream(*reset);
            continue;
        }

        if (const auto *stop = std::get_if<quic::QuicCorePeerStopSending>(&effect)) {
            handle_peer_stop_sending(*stop);
            continue;
        }
    }

    if (transport_ready_) {
        queue_startup_streams();
    }
    flush_qpack_decoder_instructions();
    return drain_pending_inputs(closed_);
}

Http3EndpointUpdate Http3Connection::poll(quic::QuicCoreTimePoint now) {
    (void)now;
    if (transport_ready_) {
        queue_startup_streams();
    }
    flush_qpack_decoder_instructions();
    return drain_pending_inputs(closed_);
}

const Http3ConnectionState &Http3Connection::state() const {
    return state_;
}

const Http3SettingsSnapshot &Http3Connection::local_settings() const {
    return config_.local_settings;
}

const Http3SettingsSnapshot &Http3Connection::peer_settings() const {
    return peer_settings_;
}

bool Http3Connection::peer_settings_received() const {
    return state_.remote_settings_received;
}

bool Http3Connection::is_closed() const {
    return closed_;
}

Http3EndpointUpdate Http3Connection::drain_pending_inputs(bool terminal_failure) {
    Http3EndpointUpdate update{};
    while (!pending_core_inputs_.empty()) {
        update.core_inputs.push_back(std::move(pending_core_inputs_.front()));
        pending_core_inputs_.pop_front();
    }
    update.has_pending_work = !update.core_inputs.empty();
    update.terminal_failure = terminal_failure;
    return update;
}

void Http3Connection::queue_startup_streams() {
    if (startup_streams_queued_ || closed_) {
        return;
    }

    const auto control_stream_id = next_local_uni_stream_id();
    const auto encoder_stream_id = control_stream_id + 4u;
    const auto decoder_stream_id = encoder_stream_id + 4u;

    const auto control_stream =
        serialize_http3_control_stream(settings_from_snapshot(config_.local_settings));
    if (!control_stream.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize control stream");
        return;
    }

    const auto encoder_prefix =
        serialize_http3_uni_stream_prefix(Http3UniStreamType::qpack_encoder);
    if (!encoder_prefix.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize qpack encoder stream type");
        return;
    }

    const auto decoder_prefix =
        serialize_http3_uni_stream_prefix(Http3UniStreamType::qpack_decoder);
    if (!decoder_prefix.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize qpack decoder stream type");
        return;
    }

    state_.local_control_stream_id = control_stream_id;
    state_.local_qpack_encoder_stream_id = encoder_stream_id;
    state_.local_qpack_decoder_stream_id = decoder_stream_id;
    state_.local_settings_sent = true;

    queue_send(control_stream_id, control_stream.value());
    queue_send(encoder_stream_id, encoder_prefix.value());
    queue_send(decoder_stream_id, decoder_prefix.value());
    startup_streams_queued_ = true;
}

void Http3Connection::flush_qpack_decoder_instructions() {
    if (!state_.local_qpack_decoder_stream_id.has_value() || closed_) {
        return;
    }

    const auto instructions = take_http3_qpack_decoder_instructions(decoder_);
    if (!instructions.has_value()) {
        queue_connection_close(instructions.error().code, instructions.error().detail);
        return;
    }

    if (!instructions.value().empty()) {
        queue_send(*state_.local_qpack_decoder_stream_id, instructions.value());
    }
}

void Http3Connection::queue_connection_close(Http3ErrorCode code, std::string detail) {
    if (closed_) {
        return;
    }

    closed_ = true;
    pending_core_inputs_.push_back(quic::QuicCoreCloseConnection{
        .application_error_code = static_cast<std::uint64_t>(code),
        .reason_phrase = std::move(detail),
    });
}

void Http3Connection::handle_receive_stream_data(const quic::QuicCoreReceiveStreamData &received) {
    const auto info = classify_stream_id(received.stream_id, endpoint_role(config_.role));
    if (info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::unidirectional) {
        handle_peer_uni_stream_data(received.stream_id, received.bytes, received.fin);
        return;
    }

    if (info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::bidirectional) {
        handle_peer_bidi_stream(received.stream_id);
    }
}

void Http3Connection::handle_peer_reset_stream(const quic::QuicCorePeerResetStream &reset) {
    if (is_remote_critical_stream(reset.stream_id)) {
        queue_connection_close(Http3ErrorCode::closed_critical_stream,
                               "peer reset critical stream");
        return;
    }

    peer_uni_streams_.erase(reset.stream_id);
}

void Http3Connection::handle_peer_stop_sending(const quic::QuicCorePeerStopSending &stop) {
    if (is_local_critical_stream(stop.stream_id)) {
        queue_connection_close(Http3ErrorCode::closed_critical_stream,
                               "peer requested stop sending on critical stream");
    }
}

void Http3Connection::handle_peer_bidi_stream(std::uint64_t stream_id) {
    if (config_.role == Http3ConnectionRole::client) {
        queue_connection_close(Http3ErrorCode::stream_creation_error,
                               "server-initiated bidirectional stream is not permitted");
    }
    (void)stream_id;
}

void Http3Connection::handle_peer_uni_stream_data(std::uint64_t stream_id,
                                                  std::span<const std::byte> bytes, bool fin) {
    auto &stream = peer_uni_streams_[stream_id];
    stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());

    if (!stream.kind.has_value()) {
        const auto decoded = parse_http3_uni_stream_type(stream.buffer);
        if (!decoded.has_value()) {
            if (decoded.error().code == CodecErrorCode::truncated_input) {
                if (fin) {
                    peer_uni_streams_.erase(stream_id);
                }
                return;
            }
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "invalid unidirectional stream type");
            return;
        }

        register_peer_uni_stream(stream_id, decoded.value().value);
        if (closed_) {
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(decoded.value().bytes_consumed));
        if (stream.kind == PeerUniStreamKind::ignored) {
            stream.buffer.clear();
        }
    }

    if (stream.kind == PeerUniStreamKind::control) {
        process_control_stream(stream_id, stream);
    } else if (stream.kind == PeerUniStreamKind::qpack_encoder) {
        process_qpack_encoder_stream(stream_id, stream);
    } else if (stream.kind == PeerUniStreamKind::qpack_decoder) {
        process_qpack_decoder_stream(stream_id, stream);
    } else {
        stream.buffer.clear();
    }

    if (!fin || closed_) {
        return;
    }

    if (!stream.kind.has_value() || *stream.kind == PeerUniStreamKind::ignored) {
        peer_uni_streams_.erase(stream_id);
        return;
    }

    if (*stream.kind == PeerUniStreamKind::control && !state_.remote_settings_received) {
        queue_connection_close(Http3ErrorCode::missing_settings,
                               "peer control stream ended before settings");
        return;
    }

    queue_connection_close(Http3ErrorCode::closed_critical_stream, "peer closed critical stream");
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void Http3Connection::register_peer_uni_stream(std::uint64_t stream_id, std::uint64_t stream_type) {
    auto &stream = peer_uni_streams_.at(stream_id);

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::control)) {
        if (state_.remote_control_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer control stream");
            return;
        }
        state_.remote_control_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::control;
        return;
    }

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::qpack_encoder)) {
        if (state_.remote_qpack_encoder_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer qpack encoder stream");
            return;
        }
        state_.remote_qpack_encoder_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::qpack_encoder;
        return;
    }

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::qpack_decoder)) {
        if (state_.remote_qpack_decoder_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer qpack decoder stream");
            return;
        }
        state_.remote_qpack_decoder_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::qpack_decoder;
        return;
    }

    stream.kind = PeerUniStreamKind::ignored;
}

void Http3Connection::process_control_stream(std::uint64_t stream_id, PeerUniStreamState &stream) {
    while (!stream.buffer.empty() && !closed_) {
        const auto frame_size = complete_http3_frame_size(stream.buffer);
        if (!frame_size.has_value()) {
            return;
        }
        if (*frame_size == 0) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame encoding");
            return;
        }

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame");
            return;
        }

        handle_control_frame(stream_id, parsed.value().frame);
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(parsed.value().bytes_consumed));
    }
}

void Http3Connection::process_qpack_encoder_stream(std::uint64_t stream_id,
                                                   PeerUniStreamState &stream) {
    (void)stream_id;
    while (!stream.buffer.empty() && !closed_) {
        const auto instruction = complete_qpack_encoder_instruction_size(stream.buffer);
        if (instruction.status == BufferedInstructionStatus::incomplete) {
            return;
        }
        if (instruction.status == BufferedInstructionStatus::invalid) {
            queue_connection_close(Http3ErrorCode::qpack_encoder_stream_error,
                                   "invalid qpack encoder instruction");
            return;
        }

        const auto decoded = process_http3_qpack_encoder_instructions(
            decoder_, std::span<const std::byte>(stream.buffer.data(), instruction.bytes_consumed));
        if (!decoded.has_value()) {
            queue_connection_close(decoded.error().code, decoded.error().detail);
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(instruction.bytes_consumed));
        flush_qpack_decoder_instructions();
    }
}

void Http3Connection::process_qpack_decoder_stream(std::uint64_t stream_id,
                                                   PeerUniStreamState &stream) {
    (void)stream_id;
    while (!stream.buffer.empty() && !closed_) {
        const auto instruction = complete_qpack_decoder_instruction_size(stream.buffer);
        if (instruction.status == BufferedInstructionStatus::incomplete) {
            return;
        }
        if (instruction.status == BufferedInstructionStatus::invalid) {
            queue_connection_close(Http3ErrorCode::qpack_decoder_stream_error,
                                   "invalid qpack decoder instruction");
            return;
        }

        const auto processed = process_http3_qpack_decoder_instructions(
            encoder_, std::span<const std::byte>(stream.buffer.data(), instruction.bytes_consumed));
        if (!processed.has_value()) {
            queue_connection_close(processed.error().code, processed.error().detail);
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(instruction.bytes_consumed));
    }
}

void Http3Connection::handle_control_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (!state_.remote_settings_received) {
        const auto *settings = std::get_if<Http3SettingsFrame>(&frame);
        if (settings == nullptr) {
            queue_connection_close(Http3ErrorCode::missing_settings,
                                   "peer control stream did not start with settings");
            return;
        }

        const auto valid = validate_http3_settings_frame(*settings);
        if (!valid.has_value()) {
            queue_connection_close(valid.error().code, valid.error().detail);
            return;
        }

        apply_remote_settings(*settings);
        state_.remote_settings_received = true;
        return;
    }

    if (std::holds_alternative<Http3SettingsFrame>(frame)) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "duplicate settings frame on control stream");
        return;
    }

    if (!http3_frame_allowed_on_control_stream(config_.role, frame)) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "frame is not permitted on the control stream");
        return;
    }

    if (const auto *goaway = std::get_if<Http3GoawayFrame>(&frame)) {
        const auto valid = validate_http3_goaway_id(config_.role, goaway->id);
        if (!valid.has_value()) {
            queue_connection_close(valid.error().code, valid.error().detail);
            return;
        }
        if (state_.goaway_id.has_value() && goaway->id > *state_.goaway_id) {
            queue_connection_close(Http3ErrorCode::id_error, "peer goaway identifier increased");
            return;
        }
        state_.goaway_id = goaway->id;
    }

    (void)stream_id;
}

void Http3Connection::apply_remote_settings(const Http3SettingsFrame &frame) {
    auto updated = peer_settings_;
    for (const auto &setting : frame.settings) {
        if (setting.id == kHttp3SettingsQpackMaxTableCapacity) {
            updated.qpack_max_table_capacity = setting.value;
        } else if (setting.id == kHttp3SettingsQpackBlockedStreams) {
            updated.qpack_blocked_streams = setting.value;
        } else if (setting.id == kHttp3SettingsMaxFieldSectionSize) {
            updated.max_field_section_size = setting.value;
        }
    }

    peer_settings_ = updated;
    encoder_.peer_settings = qpack_settings_from_snapshot(peer_settings_);
}

void Http3Connection::queue_send(std::uint64_t stream_id, std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    pending_core_inputs_.push_back(quic::QuicCoreSendStreamData{
        .stream_id = stream_id,
        .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
        .fin = false,
    });
}

std::uint64_t Http3Connection::next_local_uni_stream_id() const {
    return config_.role == Http3ConnectionRole::client ? 2u : 3u;
}

bool Http3Connection::is_remote_critical_stream(std::uint64_t stream_id) const {
    return state_.remote_control_stream_id == stream_id ||
           state_.remote_qpack_encoder_stream_id == stream_id ||
           state_.remote_qpack_decoder_stream_id == stream_id;
}

bool Http3Connection::is_local_critical_stream(std::uint64_t stream_id) const {
    return state_.local_control_stream_id == stream_id ||
           state_.local_qpack_encoder_stream_id == stream_id ||
           state_.local_qpack_decoder_stream_id == stream_id;
}

} // namespace coquic::http3

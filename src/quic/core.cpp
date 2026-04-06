#include "src/quic/core.h"

#include <array>
#include <utility>

#include "src/quic/connection.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/streams.h"

namespace coquic::quic {

namespace {

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

constexpr auto kStreamStateErrorMap = std::to_array<QuicCoreLocalErrorCode>({
    QuicCoreLocalErrorCode::invalid_stream_id,
    QuicCoreLocalErrorCode::invalid_stream_direction,
    QuicCoreLocalErrorCode::send_side_closed,
    QuicCoreLocalErrorCode::receive_side_closed,
    QuicCoreLocalErrorCode::final_size_conflict,
});

static_assert(kStreamStateErrorMap.size() ==
              static_cast<std::size_t>(StreamStateErrorCode::final_size_conflict) + 1);

QuicCoreLocalError stream_state_error_to_local_error(const StreamStateError &error) {
    return QuicCoreLocalError{
        .code = kStreamStateErrorMap[static_cast<std::size_t>(error.code)],
        .stream_id = error.stream_id,
    };
}

std::uint32_t read_u32_be_at(std::span<const std::byte> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 24) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3]));
}

bool contains_version(std::span<const std::uint32_t> versions, std::uint32_t version) {
    return std::find(versions.begin(), versions.end(), version) != versions.end();
}

std::optional<VersionNegotiationPacket>
parse_version_negotiation_packet(std::span<const std::byte> bytes) {
    if (bytes.size() < 5 || read_u32_be_at(bytes, 1) != kVersionNegotiationVersion) {
        return std::nullopt;
    }

    const auto decoded = deserialize_packet(bytes, {});
    if (!decoded.has_value()) {
        return std::nullopt;
    }

    return std::get<VersionNegotiationPacket>(decoded.value().packet);
}

std::optional<RetryPacket> parse_retry_packet(std::span<const std::byte> bytes) {
    if (bytes.size() < 5 || read_u32_be_at(bytes, 1) == kVersionNegotiationVersion) {
        return std::nullopt;
    }

    const auto decoded = deserialize_packet(bytes, {});
    if (!decoded.has_value() || decoded.value().bytes_consumed != bytes.size()) {
        return std::nullopt;
    }

    if (const auto *retry = std::get_if<RetryPacket>(&decoded.value().packet)) {
        return *retry;
    }

    return std::nullopt;
}

} // namespace

QuicCore::QuicCore(QuicCoreConfig config)
    : config_(std::move(config)), connection_(std::make_unique<QuicConnection>(config_)) {
}

QuicCore::~QuicCore() = default;

QuicCore::QuicCore(QuicCore &&) noexcept = default;

QuicCore &QuicCore::operator=(QuicCore &&) noexcept = default;

QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    QuicCoreResult result;
    std::visit(
        overloaded{
            [&](const QuicCoreStart &) { connection_->start(now); },
            [&](const QuicCoreInboundDatagram &in) {
                if (config_.role == EndpointRole::client) {
                    if (!connection_->is_handshake_complete()) {
                        const auto version_negotiation = parse_version_negotiation_packet(in.bytes);
                        if (version_negotiation.has_value()) {
                            const bool valid_destination_connection_id =
                                version_negotiation->destination_connection_id ==
                                config_.source_connection_id;
                            const bool valid_source_connection_id =
                                version_negotiation->source_connection_id ==
                                config_.initial_destination_connection_id;
                            const bool echoes_original_version = contains_version(
                                version_negotiation->supported_versions, config_.original_version);
                            if (valid_destination_connection_id && valid_source_connection_id &&
                                !echoes_original_version) {
                                for (const auto supported_version : config_.supported_versions) {
                                    if (!contains_version(version_negotiation->supported_versions,
                                                          supported_version)) {
                                        continue;
                                    }
                                    config_.initial_version = supported_version;
                                    config_.reacted_to_version_negotiation = true;
                                    connection_ = std::make_unique<QuicConnection>(config_);
                                    connection_->start(now);
                                    return;
                                }
                            }
                            return;
                        }
                    }

                    const auto retry = parse_retry_packet(in.bytes);
                    if (retry.has_value()) {
                        const auto original_destination_connection_id =
                            config_.original_destination_connection_id.value_or(
                                config_.initial_destination_connection_id);
                        const auto retry_integrity_valid = validate_retry_integrity_tag(
                            *retry, original_destination_connection_id);
                        const bool can_process_retry =
                            !connection_->is_handshake_complete() &&
                            !connection_->has_processed_peer_packet() &&
                            !config_.retry_source_connection_id.has_value();
                        const bool valid_integrity =
                            retry_integrity_valid.has_value() && retry_integrity_valid.value();
                        const bool valid_destination_connection_id =
                            retry->destination_connection_id == config_.source_connection_id;
                        const bool valid_version = retry->version == config_.original_version;
                        const bool valid_retry_token = !retry->retry_token.empty();
                        if (can_process_retry && valid_integrity &&
                            valid_destination_connection_id && valid_version && valid_retry_token) {
                            const auto next_initial_send_packet_number =
                                connection_->initial_space_.next_send_packet_number;
                            config_.original_destination_connection_id =
                                original_destination_connection_id;
                            config_.retry_source_connection_id = retry->source_connection_id;
                            config_.retry_token = retry->retry_token;
                            config_.initial_destination_connection_id = retry->source_connection_id;
                            connection_ = std::make_unique<QuicConnection>(config_);
                            connection_->initial_space_.next_send_packet_number =
                                next_initial_send_packet_number;
                            connection_->start(now);
                        }
                        return;
                    }
                }
                connection_->process_inbound_datagram(in.bytes, now);
            },
            [&](const QuicCoreSendStreamData &in) {
                const auto queued = connection_->queue_stream_send(in.stream_id, in.bytes, in.fin);
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreResetStream &in) {
                const auto queued = connection_->queue_stream_reset(LocalResetCommand{
                    .stream_id = in.stream_id,
                    .application_error_code = in.application_error_code,
                });
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreStopSending &in) {
                const auto queued = connection_->queue_stop_sending(LocalStopSendingCommand{
                    .stream_id = in.stream_id,
                    .application_error_code = in.application_error_code,
                });
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreCloseConnection &in) {
                connection_->queue_application_close(LocalApplicationCloseCommand{
                    .application_error_code = in.application_error_code,
                    .reason_phrase = in.reason_phrase,
                });
            },
            [&](const QuicCoreRequestKeyUpdate &) { connection_->request_key_update(); },
            [&](const QuicCoreTimerExpired &) { connection_->on_timeout(now); },
        },
        input);

    while (true) {
        auto datagram = connection_->drain_outbound_datagram(now);
        if (datagram.empty()) {
            break;
        }
        result.effects.emplace_back(QuicCoreSendDatagram{std::move(datagram)});
    }
    while (const auto received = connection_->take_received_stream_data()) {
        result.effects.emplace_back(*received);
    }
    while (const auto reset = connection_->take_peer_reset_stream()) {
        result.effects.emplace_back(*reset);
    }
    while (const auto stop = connection_->take_peer_stop_sending()) {
        result.effects.emplace_back(*stop);
    }
    while (const auto event = connection_->take_state_change()) {
        result.effects.emplace_back(QuicCoreStateEvent{*event});
    }
    while (const auto state = connection_->take_resumption_state_available()) {
        result.effects.emplace_back(*state);
    }
    while (const auto status = connection_->take_zero_rtt_status_event()) {
        result.effects.emplace_back(*status);
    }
    result.next_wakeup = connection_->next_wakeup();
    return result;
}

bool QuicCore::is_handshake_complete() const {
    return connection_->is_handshake_complete();
}

bool QuicCore::has_failed() const {
    return connection_->has_failed();
}

} // namespace coquic::quic

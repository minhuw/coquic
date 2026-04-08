#include "src/quic/core.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <utility>

#include "src/quic/connection.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/streams.h"

namespace coquic::quic {

struct QuicCore::ConnectionEntry {
    QuicConnectionHandle handle = 0;
    std::optional<QuicRouteHandle> default_route_handle;
    std::unique_ptr<QuicConnection> connection;
};

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
        .connection = std::nullopt,
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

QuicCore::LegacyConnectionView &
QuicCore::LegacyConnectionView::operator=(std::unique_ptr<QuicConnection> connection) {
    owner->set_legacy_connection(std::move(connection));
    return *this;
}

QuicConnection *QuicCore::LegacyConnectionView::get() const {
    if (owner == nullptr) {
        return nullptr;
    }
    auto *entry = owner->legacy_entry();
    return entry == nullptr ? nullptr : entry->connection.get();
}

QuicConnection *QuicCore::LegacyConnectionView::operator->() const {
    return get();
}

QuicConnection &QuicCore::LegacyConnectionView::operator*() const {
    assert(get() != nullptr);
    return *get();
}

QuicCore::LegacyConnectionView::operator bool() const {
    return get() != nullptr;
}

bool QuicCore::LegacyConnectionView::operator==(std::nullptr_t) const {
    return get() == nullptr;
}

bool QuicCore::LegacyConnectionView::operator!=(std::nullptr_t) const {
    return get() != nullptr;
}

QuicCore::ConnectionEntry *QuicCore::legacy_entry() {
    if (!legacy_connection_handle_.has_value()) {
        return nullptr;
    }
    const auto it = connections_.find(*legacy_connection_handle_);
    if (it == connections_.end()) {
        return nullptr;
    }
    return &it->second;
}

const QuicCore::ConnectionEntry *QuicCore::legacy_entry() const {
    if (!legacy_connection_handle_.has_value()) {
        return nullptr;
    }
    const auto it = connections_.find(*legacy_connection_handle_);
    if (it == connections_.end()) {
        return nullptr;
    }
    return &it->second;
}

QuicCore::ConnectionEntry *QuicCore::ensure_legacy_entry() {
    if (auto *entry = legacy_entry()) {
        return entry;
    }
    if (!legacy_config_.has_value()) {
        return nullptr;
    }
    if (!legacy_connection_handle_.has_value()) {
        legacy_connection_handle_ = next_connection_handle_++;
    }

    auto entry = ConnectionEntry{
        .handle = *legacy_connection_handle_,
        .connection = std::make_unique<QuicConnection>(*legacy_config_),
    };
    auto [it, inserted] =
        connections_.insert_or_assign(*legacy_connection_handle_, std::move(entry));
    (void)inserted;
    return &it->second;
}

void QuicCore::set_legacy_connection(std::unique_ptr<QuicConnection> connection) {
    if (!legacy_connection_handle_.has_value()) {
        legacy_connection_handle_ = next_connection_handle_++;
    }
    if (connection == nullptr) {
        connections_.erase(*legacy_connection_handle_);
        return;
    }

    auto entry = ConnectionEntry{
        .handle = *legacy_connection_handle_,
        .connection = std::move(connection),
    };
    connections_.insert_or_assign(*legacy_connection_handle_, std::move(entry));
}

QuicCore::QuicCore(QuicCoreEndpointConfig config)
    : endpoint_config_(std::move(config)), connection_(this) {
}

QuicCore::QuicCore(QuicCoreConfig config)
    : endpoint_config_(QuicCoreEndpointConfig{
          .role = config.role,
          .supported_versions = config.supported_versions,
          .verify_peer = config.verify_peer,
          .application_protocol = config.application_protocol,
          .identity = config.identity,
          .transport = config.transport,
          .allowed_tls_cipher_suites = config.allowed_tls_cipher_suites,
          .qlog = config.qlog,
          .tls_keylog_path = config.tls_keylog_path,
      }),
      legacy_config_(std::move(config)), connection_(this) {
    static_cast<void>(ensure_legacy_entry());
}

QuicCore::~QuicCore() = default;

QuicCore::QuicCore(QuicCore &&other) noexcept
    : endpoint_config_(std::move(other.endpoint_config_)),
      legacy_config_(std::move(other.legacy_config_)), connections_(std::move(other.connections_)),
      legacy_connection_handle_(other.legacy_connection_handle_),
      next_connection_handle_(other.next_connection_handle_), connection_(this) {
    other.connection_.owner = &other;
}

QuicCore &QuicCore::operator=(QuicCore &&other) noexcept {
    if (this == &other) {
        return *this;
    }
    endpoint_config_ = std::move(other.endpoint_config_);
    legacy_config_ = std::move(other.legacy_config_);
    connections_ = std::move(other.connections_);
    legacy_connection_handle_ = other.legacy_connection_handle_;
    next_connection_handle_ = other.next_connection_handle_;
    connection_.owner = this;
    other.connection_.owner = &other;
    return *this;
}

std::optional<QuicCoreTimePoint> QuicCore::next_wakeup() const {
    std::optional<QuicCoreTimePoint> earliest;
    for (const auto &[handle, entry] : connections_) {
        (void)handle;
        const auto candidate = entry.connection->next_wakeup();
        if (!candidate.has_value()) {
            continue;
        }
        earliest = std::min(earliest.value_or(*candidate), *candidate);
    }
    return earliest;
}

std::size_t QuicCore::connection_count() const {
    return connections_.size();
}

QuicCoreResult QuicCore::advance_endpoint(QuicCoreEndpointInput input, QuicCoreTimePoint now) {
    if (const auto *open = std::get_if<QuicCoreOpenConnection>(&input)) {
        QuicCoreConfig config{
            .role = endpoint_config_.role,
            .source_connection_id = open->connection.source_connection_id,
            .initial_destination_connection_id = open->connection.initial_destination_connection_id,
            .original_destination_connection_id =
                open->connection.original_destination_connection_id,
            .retry_source_connection_id = open->connection.retry_source_connection_id,
            .retry_token = open->connection.retry_token,
            .original_version = open->connection.original_version,
            .initial_version = open->connection.initial_version,
            .supported_versions = endpoint_config_.supported_versions,
            .reacted_to_version_negotiation = open->connection.reacted_to_version_negotiation,
            .verify_peer = endpoint_config_.verify_peer,
            .server_name = open->connection.server_name,
            .application_protocol = endpoint_config_.application_protocol,
            .identity = endpoint_config_.identity,
            .transport = endpoint_config_.transport,
            .allowed_tls_cipher_suites = endpoint_config_.allowed_tls_cipher_suites,
            .resumption_state = open->connection.resumption_state,
            .zero_rtt = open->connection.zero_rtt,
            .qlog = endpoint_config_.qlog,
            .tls_keylog_path = endpoint_config_.tls_keylog_path,
        };

        auto entry = ConnectionEntry{
            .handle = next_connection_handle_++,
            .default_route_handle = open->initial_route_handle,
            .connection = std::make_unique<QuicConnection>(std::move(config)),
        };
        entry.connection->start(now);

        QuicCoreResult result;
        const auto handle = entry.handle;
        while (true) {
            auto datagram = entry.connection->drain_outbound_datagram(now);
            if (datagram.empty()) {
                break;
            }
            result.effects.emplace_back(QuicCoreSendDatagram{
                .connection = handle,
                .path_id = entry.connection->last_drained_path_id(),
                .route_handle = entry.default_route_handle,
                .bytes = std::move(datagram),
                .ecn = entry.connection->last_drained_ecn_codepoint(),
            });
        }
        result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = handle,
            .event = QuicCoreConnectionLifecycle::created,
        });
        connections_.emplace(handle, std::move(entry));
        result.next_wakeup = next_wakeup();
        return result;
    }

    (void)now;
    QuicCoreResult result;
    result.local_error = QuicCoreLocalError{
        .connection = std::nullopt,
        .code = QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = std::nullopt,
    };
    result.next_wakeup = next_wakeup();
    return result;
}

QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    QuicCoreResult result;
    auto *entry = ensure_legacy_entry();
    if (entry == nullptr || entry->connection == nullptr || !legacy_config_.has_value()) {
        return result;
    }
    auto &config = *legacy_config_;
    auto *connection = entry->connection.get();

    std::visit(
        overloaded{
            [&](const QuicCoreStart &) { connection->start(now); },
            [&](const QuicCoreInboundDatagram &in) {
                if (config.role == EndpointRole::client) {
                    if (!connection->is_handshake_complete()) {
                        const auto version_negotiation = parse_version_negotiation_packet(in.bytes);
                        if (version_negotiation.has_value()) {
                            const bool valid_destination_connection_id =
                                version_negotiation->destination_connection_id ==
                                config.source_connection_id;
                            const bool valid_source_connection_id =
                                version_negotiation->source_connection_id ==
                                config.initial_destination_connection_id;
                            const bool echoes_original_version = contains_version(
                                version_negotiation->supported_versions, config.original_version);
                            if (valid_destination_connection_id && valid_source_connection_id &&
                                !echoes_original_version) {
                                for (const auto supported_version : config.supported_versions) {
                                    if (!contains_version(version_negotiation->supported_versions,
                                                          supported_version)) {
                                        continue;
                                    }
                                    config.initial_version = supported_version;
                                    config.reacted_to_version_negotiation = true;
                                    entry->connection = std::make_unique<QuicConnection>(config);
                                    connection = entry->connection.get();
                                    connection->last_inbound_path_id_ = in.path_id;
                                    connection->current_send_path_id_ = in.path_id;
                                    connection->ensure_path_state(in.path_id).is_current_send_path =
                                        true;
                                    connection->start(now);
                                    return;
                                }
                            }
                            return;
                        }
                    }

                    const auto retry = parse_retry_packet(in.bytes);
                    if (retry.has_value()) {
                        const auto original_destination_connection_id =
                            config.original_destination_connection_id.value_or(
                                config.initial_destination_connection_id);
                        const auto retry_integrity_valid = validate_retry_integrity_tag(
                            *retry, original_destination_connection_id);
                        const bool can_process_retry =
                            !connection->is_handshake_complete() &&
                            !connection->has_processed_peer_packet() &&
                            !config.retry_source_connection_id.has_value();
                        const bool valid_integrity =
                            retry_integrity_valid.has_value() && retry_integrity_valid.value();
                        const bool valid_destination_connection_id =
                            retry->destination_connection_id == config.source_connection_id;
                        const bool valid_version = retry->version == config.original_version;
                        const bool valid_retry_token = !retry->retry_token.empty();
                        if (can_process_retry && valid_integrity &&
                            valid_destination_connection_id && valid_version && valid_retry_token) {
                            const auto next_initial_send_packet_number =
                                connection->initial_space_.next_send_packet_number;
                            config.original_destination_connection_id =
                                original_destination_connection_id;
                            config.retry_source_connection_id = retry->source_connection_id;
                            config.retry_token = retry->retry_token;
                            config.initial_destination_connection_id = retry->source_connection_id;
                            entry->connection = std::make_unique<QuicConnection>(config);
                            connection = entry->connection.get();
                            connection->initial_space_.next_send_packet_number =
                                next_initial_send_packet_number;
                            connection->last_inbound_path_id_ = in.path_id;
                            connection->current_send_path_id_ = in.path_id;
                            connection->ensure_path_state(in.path_id).is_current_send_path = true;
                            connection->start(now);
                        }
                        return;
                    }
                }
                connection->process_inbound_datagram(in.bytes, now, in.path_id, in.ecn);
            },
            [&](const QuicCoreSendStreamData &in) {
                const auto queued = connection->queue_stream_send(in.stream_id, in.bytes, in.fin);
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreResetStream &in) {
                const auto queued = connection->queue_stream_reset(LocalResetCommand{
                    .stream_id = in.stream_id,
                    .application_error_code = in.application_error_code,
                });
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreStopSending &in) {
                const auto queued = connection->queue_stop_sending(LocalStopSendingCommand{
                    .stream_id = in.stream_id,
                    .application_error_code = in.application_error_code,
                });
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreCloseConnection &in) {
                static_cast<void>(connection->queue_application_close(LocalApplicationCloseCommand{
                    .application_error_code = in.application_error_code,
                    .reason_phrase = in.reason_phrase,
                }));
            },
            [&](const QuicCoreRequestKeyUpdate &) { connection->request_key_update(); },
            [&](const QuicCoreRequestConnectionMigration &in) {
                const auto requested =
                    connection->request_connection_migration(in.path_id, in.reason);
                if (!requested.has_value()) {
                    result.local_error = QuicCoreLocalError{
                        .connection = std::nullopt,
                        .code = QuicCoreLocalErrorCode::unsupported_operation,
                        .stream_id = std::nullopt,
                    };
                }
            },
            [&](const QuicCoreTimerExpired &) { connection->on_timeout(now); },
        },
        input);

    while (true) {
        auto datagram = connection->drain_outbound_datagram(now);
        if (datagram.empty()) {
            break;
        }
        result.effects.emplace_back(QuicCoreSendDatagram{
            .path_id = connection->last_drained_path_id(),
            .bytes = std::move(datagram),
            .ecn = connection->last_drained_ecn_codepoint(),
        });
    }
    while (const auto received = connection->take_received_stream_data()) {
        result.effects.emplace_back(*received);
    }
    while (const auto reset = connection->take_peer_reset_stream()) {
        result.effects.emplace_back(*reset);
    }
    while (const auto stop = connection->take_peer_stop_sending()) {
        result.effects.emplace_back(*stop);
    }
    while (const auto event = connection->take_state_change()) {
        result.effects.emplace_back(QuicCoreStateEvent{
            .change = *event,
        });
    }
    while (const auto preferred = connection->take_peer_preferred_address_available()) {
        result.effects.emplace_back(*preferred);
    }
    while (const auto state = connection->take_resumption_state_available()) {
        result.effects.emplace_back(*state);
    }
    while (const auto status = connection->take_zero_rtt_status_event()) {
        result.effects.emplace_back(*status);
    }
    result.next_wakeup = next_wakeup();
    return result;
}

std::vector<ConnectionId> QuicCore::active_local_connection_ids() const {
    if (const auto *entry = legacy_entry()) {
        return entry->connection->active_local_connection_ids();
    }
    return {};
}

bool QuicCore::is_handshake_complete() const {
    if (const auto *entry = legacy_entry()) {
        return entry->connection->is_handshake_complete();
    }
    return false;
}

bool QuicCore::has_failed() const {
    if (const auto *entry = legacy_entry()) {
        return entry->connection->has_failed();
    }
    return false;
}

} // namespace coquic::quic

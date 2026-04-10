#include "src/quic/core.h"
#include "src/quic/core_test_hooks.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <utility>

#include "src/quic/buffer.h"
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
constexpr std::size_t kMinimumClientInitialDatagramBytes = 1200;
constexpr std::size_t kEndpointConnectionIdLength = 8;
constexpr QuicPathId kDefaultPathId = 0;

static_assert(kStreamStateErrorMap.size() ==
              static_cast<std::size_t>(StreamStateErrorCode::final_size_conflict) + 1);

QuicCoreLocalError stream_state_error_to_local_error(const StreamStateError &error) {
    return QuicCoreLocalError{
        .connection = std::nullopt,
        .code = kStreamStateErrorMap[static_cast<std::size_t>(error.code)],
        .stream_id = error.stream_id,
    };
}

QuicCoreResult drain_connection_effects(
    QuicConnectionHandle handle, const std::optional<QuicRouteHandle> &default_route_handle,
    const std::unordered_map<QuicPathId, QuicRouteHandle> &route_handle_by_path_id,
    QuicConnection &connection, QuicCoreTimePoint now) {
    QuicCoreResult result;

    while (true) {
        auto datagram = connection.drain_outbound_datagram(now);
        if (datagram.empty()) {
            break;
        }

        const auto path_id = connection.last_drained_path_id();
        const auto route_it = path_id.has_value() ? route_handle_by_path_id.find(*path_id)
                                                  : route_handle_by_path_id.end();
        result.effects.emplace_back(QuicCoreSendDatagram{
            .connection = handle,
            .route_handle = route_it != route_handle_by_path_id.end()
                                ? std::optional<QuicRouteHandle>(route_it->second)
                                : default_route_handle,
            .bytes = std::move(datagram),
            .ecn = connection.last_drained_ecn_codepoint(),
        });
    }

    while (auto received = connection.take_received_stream_data()) {
        result.effects.emplace_back(QuicCoreReceiveStreamData{
            .connection = handle,
            .stream_id = received->stream_id,
            .bytes = std::move(received->bytes),
            .fin = received->fin,
        });
    }
    while (const auto reset = connection.take_peer_reset_stream()) {
        result.effects.emplace_back(QuicCorePeerResetStream{
            .connection = handle,
            .stream_id = reset->stream_id,
            .application_error_code = reset->application_error_code,
            .final_size = reset->final_size,
        });
    }
    while (const auto stop = connection.take_peer_stop_sending()) {
        result.effects.emplace_back(QuicCorePeerStopSending{
            .connection = handle,
            .stream_id = stop->stream_id,
            .application_error_code = stop->application_error_code,
        });
    }
    while (const auto event = connection.take_state_change()) {
        result.effects.emplace_back(QuicCoreStateEvent{
            .connection = handle,
            .change = *event,
        });
    }
    while (const auto preferred = connection.take_peer_preferred_address_available()) {
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .connection = handle,
            .preferred_address = preferred->preferred_address,
        });
    }
    while (const auto state = connection.take_resumption_state_available()) {
        result.effects.emplace_back(QuicCoreResumptionStateAvailable{
            .connection = handle,
            .state = state->state,
        });
    }
    while (const auto status = connection.take_zero_rtt_status_event()) {
        result.effects.emplace_back(QuicCoreZeroRttStatusEvent{
            .connection = handle,
            .status = status->status,
        });
    }
    if (const auto terminal = connection.take_terminal_state()) {
        if (*terminal == QuicConnectionTerminalState::closed) {
            result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
                .connection = handle,
                .event = QuicCoreConnectionLifecycle::closed,
            });
        }
    }

    result.next_wakeup = connection.next_wakeup();
    return result;
}

bool has_closed_lifecycle_event(const QuicCoreResult &result) {
    return std::any_of(result.effects.begin(), result.effects.end(), [](const auto &effect) {
        const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
        return event != nullptr && event->event == QuicCoreConnectionLifecycle::closed;
    });
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

ConnectionId make_endpoint_connection_id(std::byte prefix, std::uint64_t sequence) {
    ConnectionId connection_id(kEndpointConnectionIdLength, std::byte{0x00});
    connection_id.front() = prefix;
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        const auto shift = static_cast<unsigned>((connection_id.size() - 1 - index) * 8);
        connection_id[index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return connection_id;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t type) {
    if (version == kQuicVersion2) {
        return type == 0x01u;
    }
    return type == 0x00u;
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

    const auto handle = *legacy_connection_handle_;
    auto [it, inserted] = connections_.try_emplace(handle);
    (void)inserted;
    auto &entry = it->second;
    entry.handle = handle;
    entry.connection = std::make_unique<QuicConnection>(*legacy_config_);
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

    auto &entry = connections_[*legacy_connection_handle_];
    entry = {};
    entry.handle = *legacy_connection_handle_;
    entry.connection = std::move(connection);
}

std::string QuicCore::connection_id_key(std::span<const std::byte> connection_id) {
    if (connection_id.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(connection_id.data()), connection_id.size());
}

std::optional<QuicCore::ParsedEndpointDatagram>
QuicCore::parse_endpoint_datagram(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0) {
        if ((first_byte & 0x40u) == 0 || bytes.size() < 1 + kEndpointConnectionIdLength) {
            return std::nullopt;
        }

        return ParsedEndpointDatagram{
            .kind = ParsedEndpointDatagram::Kind::short_header,
            .destination_connection_id =
                ConnectionId(bytes.begin() + 1, bytes.begin() + 1 + kEndpointConnectionIdLength),
        };
    }

    if ((first_byte & 0x40u) == 0 || bytes.size() < 7) {
        return std::nullopt;
    }

    const auto version = read_u32_be_at(bytes, 1);
    if (version == kVersionNegotiationVersion) {
        return std::nullopt;
    }

    std::size_t offset = 5;
    const auto destination_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + destination_connection_id_length + 1 > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId destination_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + destination_connection_id_length));
    offset += destination_connection_id_length;

    const auto source_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + source_connection_id_length > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId source_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + source_connection_id_length));
    offset += source_connection_id_length;

    if (!is_supported_quic_version(version)) {
        return ParsedEndpointDatagram{
            .kind = ParsedEndpointDatagram::Kind::unsupported_version_long_header,
            .destination_connection_id = std::move(destination_connection_id),
            .source_connection_id = std::move(source_connection_id),
            .version = version,
        };
    }

    const auto type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    std::vector<std::byte> token;
    if (is_initial_long_header_type(version, type)) {
        BufferReader reader(bytes.subspan(offset));
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return std::nullopt;
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return std::nullopt;
        }
        const auto token_bytes =
            reader.read_exact(static_cast<std::size_t>(token_length.value().value));
        if (!token_bytes.has_value()) {
            return std::nullopt;
        }
        token.assign(token_bytes.value().begin(), token_bytes.value().end());
    }

    return ParsedEndpointDatagram{
        .kind = is_initial_long_header_type(version, type)
                    ? ParsedEndpointDatagram::Kind::supported_initial
                    : ParsedEndpointDatagram::Kind::supported_long_header,
        .destination_connection_id = std::move(destination_connection_id),
        .source_connection_id = std::move(source_connection_id),
        .version = version,
        .token = std::move(token),
    };
}

std::vector<std::byte> QuicCore::make_endpoint_retry_token(std::uint64_t sequence) {
    std::vector<std::byte> token(16, std::byte{0x00});
    token[0] = std::byte{0x72};
    token[1] = std::byte{0x74};
    token[2] = std::byte{0x72};
    token[3] = std::byte{0x79};
    for (std::size_t index = 0; index < sizeof(sequence); ++index) {
        const auto shift = static_cast<unsigned>((sizeof(sequence) - 1 - index) * 8);
        token[8 + index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return token;
}

std::optional<QuicCore::PendingRetryToken>
QuicCore::take_retry_context(const ParsedEndpointDatagram &parsed,
                             const std::optional<QuicRouteHandle> &route_handle) {
    const auto it = retry_tokens_.find(connection_id_key(parsed.token));
    if (it == retry_tokens_.end()) {
        return std::nullopt;
    }

    const auto &pending = it->second;
    if (pending.route_handle != route_handle ||
        parsed.destination_connection_id != pending.retry_source_connection_id ||
        parsed.version != pending.original_version) {
        return std::nullopt;
    }

    auto retry_context = pending;
    retry_tokens_.erase(it);
    return retry_context;
}

std::vector<std::byte>
QuicCore::make_version_negotiation_packet_bytes(const ParsedEndpointDatagram &parsed,
                                                std::span<const std::uint32_t> supported_versions) {
    if (!parsed.source_connection_id.has_value()) {
        return {};
    }

    const auto encoded = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = *parsed.source_connection_id,
        .source_connection_id = parsed.destination_connection_id,
        .supported_versions =
            std::vector<std::uint32_t>(supported_versions.begin(), supported_versions.end()),
    });
    return encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
}

std::vector<std::byte> QuicCore::make_retry_packet_bytes(const ParsedEndpointDatagram &parsed,
                                                         const PendingRetryToken &pending) {
    if (!parsed.source_connection_id.has_value()) {
        return {};
    }

    RetryPacket packet{
        .version = parsed.version,
        .retry_unused_bits = 0,
        .destination_connection_id = *parsed.source_connection_id,
        .source_connection_id = pending.retry_source_connection_id,
        .retry_token = pending.token,
    };
    const auto integrity_tag =
        compute_retry_integrity_tag(packet, parsed.destination_connection_id);
    if (!integrity_tag.has_value()) {
        return {};
    }
    packet.retry_integrity_tag = integrity_tag.value();

    const auto encoded = serialize_packet(packet);
    return encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
}

std::optional<QuicConnectionHandle>
QuicCore::find_endpoint_connection_for_datagram(const ParsedEndpointDatagram &parsed) const {
    const auto destination_connection_id_key = connection_id_key(parsed.destination_connection_id);
    const auto connection_it = connection_id_routes_.find(destination_connection_id_key);
    if (connection_it != connection_id_routes_.end()) {
        return connection_it->second;
    }

    if (parsed.kind != ParsedEndpointDatagram::Kind::supported_initial &&
        parsed.kind != ParsedEndpointDatagram::Kind::supported_long_header) {
        return std::nullopt;
    }

    const auto initial_it = initial_destination_routes_.find(destination_connection_id_key);
    if (initial_it == initial_destination_routes_.end()) {
        return std::nullopt;
    }
    return initial_it->second;
}

void QuicCore::erase_endpoint_connection_routes(const ConnectionEntry &entry) {
    for (const auto &connection_id_key_value : entry.active_connection_id_keys) {
        const auto it = connection_id_routes_.find(connection_id_key_value);
        if (it != connection_id_routes_.end() && it->second == entry.handle) {
            connection_id_routes_.erase(it);
        }
    }
    if (entry.initial_destination_connection_id_key.has_value()) {
        const auto it =
            initial_destination_routes_.find(*entry.initial_destination_connection_id_key);
        if (it != initial_destination_routes_.end() && it->second == entry.handle) {
            initial_destination_routes_.erase(it);
        }
    }
}

void QuicCore::refresh_server_connection_routes(ConnectionEntry &entry) {
    std::vector<std::string> active_connection_id_keys;
    for (const auto &connection_id : entry.connection->active_local_connection_ids()) {
        auto key = connection_id_key(connection_id);
        if (key.empty()) {
            continue;
        }
        connection_id_routes_[key] = entry.handle;
        active_connection_id_keys.push_back(std::move(key));
    }

    for (const auto &existing_key : entry.active_connection_id_keys) {
        if (std::find(active_connection_id_keys.begin(), active_connection_id_keys.end(),
                      existing_key) != active_connection_id_keys.end()) {
            continue;
        }
        const auto route_it = connection_id_routes_.find(existing_key);
        if (route_it != connection_id_routes_.end() && route_it->second == entry.handle) {
            connection_id_routes_.erase(route_it);
        }
    }
    entry.active_connection_id_keys = std::move(active_connection_id_keys);

    const auto next_initial_destination_key =
        connection_id_key(entry.connection->client_initial_destination_connection_id());
    if (entry.initial_destination_connection_id_key.has_value() &&
        entry.initial_destination_connection_id_key != next_initial_destination_key) {
        const auto initial_it =
            initial_destination_routes_.find(*entry.initial_destination_connection_id_key);
        if (initial_it != initial_destination_routes_.end() && initial_it->second == entry.handle) {
            initial_destination_routes_.erase(initial_it);
        }
    }

    if (next_initial_destination_key.empty()) {
        entry.initial_destination_connection_id_key.reset();
        return;
    }

    initial_destination_routes_[next_initial_destination_key] = entry.handle;
    entry.initial_destination_connection_id_key = next_initial_destination_key;
}

QuicPathId QuicCore::remember_inbound_path(ConnectionEntry &entry, QuicRouteHandle route_handle) {
    if (!entry.default_route_handle.has_value()) {
        entry.default_route_handle = route_handle;
    }

    const auto existing = entry.path_id_by_route_handle.find(route_handle);
    if (existing != entry.path_id_by_route_handle.end()) {
        return existing->second;
    }

    QuicPathId path_id =
        entry.route_handle_by_path_id.empty() ? kDefaultPathId : entry.next_path_id++;
    while (entry.route_handle_by_path_id.contains(path_id)) {
        path_id = entry.next_path_id++;
    }

    entry.path_id_by_route_handle.emplace(route_handle, path_id);
    entry.route_handle_by_path_id.emplace(path_id, route_handle);
    return path_id;
}

std::optional<QuicRouteHandle>
QuicCore::route_handle_for_path(const ConnectionEntry &entry,
                                const std::optional<QuicPathId> &path_id) {
    if (path_id.has_value()) {
        const auto route_it = entry.route_handle_by_path_id.find(*path_id);
        if (route_it != entry.route_handle_by_path_id.end()) {
            return route_it->second;
        }
    }
    return entry.default_route_handle;
}

bool test::seed_legacy_route_handle_path_for_tests(QuicCore &core, QuicRouteHandle route_handle,
                                                   QuicPathId path_id) {
    auto *entry = core.ensure_legacy_entry();
    if (entry == nullptr) {
        return false;
    }

    if (!entry->default_route_handle.has_value()) {
        entry->default_route_handle = route_handle;
    }

    const auto existing_by_handle = entry->path_id_by_route_handle.find(route_handle);
    if (existing_by_handle != entry->path_id_by_route_handle.end() &&
        existing_by_handle->second == path_id) {
        return true;
    }

    if (path_id == std::numeric_limits<QuicPathId>::max()) {
        return false;
    }

    if (existing_by_handle != entry->path_id_by_route_handle.end()) {
        entry->route_handle_by_path_id.erase(existing_by_handle->second);
    }

    const auto existing_by_path = entry->route_handle_by_path_id.find(path_id);
    if (existing_by_path != entry->route_handle_by_path_id.end() &&
        existing_by_path->second != route_handle) {
        const auto displaced_route_handle = existing_by_path->second;
        entry->path_id_by_route_handle.erase(displaced_route_handle);
        if (entry->default_route_handle == displaced_route_handle) {
            entry->default_route_handle = route_handle;
        }
    }

    entry->path_id_by_route_handle[route_handle] = path_id;
    entry->route_handle_by_path_id[path_id] = route_handle;
    entry->next_path_id = std::max(entry->next_path_id, static_cast<QuicPathId>(path_id + 1));
    return true;
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
          .zero_rtt = config.zero_rtt,
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
      connection_id_routes_(std::move(other.connection_id_routes_)),
      initial_destination_routes_(std::move(other.initial_destination_routes_)),
      retry_tokens_(std::move(other.retry_tokens_)),
      legacy_connection_handle_(other.legacy_connection_handle_),
      next_connection_handle_(other.next_connection_handle_),
      next_server_connection_id_sequence_(other.next_server_connection_id_sequence_),
      connection_(this) {
    other.connection_.owner = &other;
}

QuicCore &QuicCore::operator=(QuicCore &&other) noexcept {
    if (this == &other) {
        return *this;
    }
    endpoint_config_ = std::move(other.endpoint_config_);
    legacy_config_ = std::move(other.legacy_config_);
    connections_ = std::move(other.connections_);
    connection_id_routes_ = std::move(other.connection_id_routes_);
    initial_destination_routes_ = std::move(other.initial_destination_routes_);
    retry_tokens_ = std::move(other.retry_tokens_);
    legacy_connection_handle_ = other.legacy_connection_handle_;
    next_connection_handle_ = other.next_connection_handle_;
    next_server_connection_id_sequence_ = other.next_server_connection_id_sequence_;
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
        if (endpoint_config_.role != EndpointRole::client) {
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

        const auto handle = next_connection_handle_++;
        auto [it, inserted] = connections_.try_emplace(handle);
        (void)inserted;
        auto &entry = it->second;
        entry = {};
        entry.handle = handle;
        entry.default_route_handle = open->initial_route_handle;
        entry.connection = std::make_unique<QuicConnection>(std::move(config));
        entry.path_id_by_route_handle.emplace(open->initial_route_handle, 0);
        entry.route_handle_by_path_id.emplace(0, open->initial_route_handle);
        entry.connection->start(now);

        auto result =
            drain_connection_effects(handle, entry.default_route_handle,
                                     entry.route_handle_by_path_id, *entry.connection, now);
        result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = handle,
            .event = QuicCoreConnectionLifecycle::created,
        });
        result.next_wakeup = next_wakeup();
        return result;
    }

    if (const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&input);
        inbound != nullptr && endpoint_config_.role == EndpointRole::server) {
        QuicCoreResult result;
        const auto parsed = parse_endpoint_datagram(inbound->bytes);
        if (!parsed.has_value()) {
            result.next_wakeup = next_wakeup();
            return result;
        }

        if (const auto handle = find_endpoint_connection_for_datagram(*parsed);
            handle.has_value()) {
            auto entry_it = connections_.find(*handle);
            if (entry_it != connections_.end()) {
                auto &entry = entry_it->second;
                const auto path_id =
                    inbound->route_handle.has_value()
                        ? remember_inbound_path(entry, *inbound->route_handle)
                        : (entry.default_route_handle.has_value()
                               ? remember_inbound_path(entry, *entry.default_route_handle)
                               : kDefaultPathId);
                entry.connection->process_inbound_datagram(inbound->bytes, now, path_id,
                                                           inbound->ecn);

                auto drained =
                    drain_connection_effects(entry.handle, entry.default_route_handle,
                                             entry.route_handle_by_path_id, *entry.connection, now);
                result.effects.insert(result.effects.end(),
                                      std::make_move_iterator(drained.effects.begin()),
                                      std::make_move_iterator(drained.effects.end()));
                refresh_server_connection_routes(entry);
                if (entry.connection->has_failed() || has_closed_lifecycle_event(drained)) {
                    erase_endpoint_connection_routes(entry);
                    connections_.erase(entry_it);
                }
                result.next_wakeup = next_wakeup();
                return result;
            }
        }

        const bool endpoint_supports_version =
            contains_version(endpoint_config_.supported_versions, parsed->version);
        const bool should_send_version_negotiation =
            parsed->kind == ParsedEndpointDatagram::Kind::unsupported_version_long_header ||
            ((parsed->kind == ParsedEndpointDatagram::Kind::supported_initial ||
              parsed->kind == ParsedEndpointDatagram::Kind::supported_long_header) &&
             !endpoint_supports_version);
        if (should_send_version_negotiation) {
            if (inbound->bytes.size() >= kMinimumClientInitialDatagramBytes) {
                const auto advertised_versions =
                    parsed->kind == ParsedEndpointDatagram::Kind::unsupported_version_long_header
                        ? supported_quic_versions()
                        : endpoint_config_.supported_versions;
                auto bytes = make_version_negotiation_packet_bytes(*parsed, advertised_versions);
                if (!bytes.empty()) {
                    result.effects.emplace_back(QuicCoreSendDatagram{
                        .connection = 0,
                        .route_handle = inbound->route_handle,
                        .bytes = std::move(bytes),
                    });
                }
            }
            result.next_wakeup = next_wakeup();
            return result;
        }

        if (parsed->kind != ParsedEndpointDatagram::Kind::supported_initial) {
            result.next_wakeup = next_wakeup();
            return result;
        }

        std::optional<PendingRetryToken> retry_context;
        if (endpoint_config_.retry_enabled) {
            retry_context = take_retry_context(*parsed, inbound->route_handle);
            if (!retry_context.has_value()) {
                if (!parsed->token.empty()) {
                    result.next_wakeup = next_wakeup();
                    return result;
                }

                const auto sequence = next_server_connection_id_sequence_++;
                PendingRetryToken pending{
                    .original_destination_connection_id = parsed->destination_connection_id,
                    .retry_source_connection_id =
                        make_endpoint_connection_id(std::byte{0x53}, sequence),
                    .original_version = parsed->version,
                    .token = make_endpoint_retry_token(sequence),
                    .route_handle = inbound->route_handle,
                };
                retry_tokens_.insert_or_assign(connection_id_key(pending.token), pending);

                auto bytes = make_retry_packet_bytes(*parsed, pending);
                if (!bytes.empty()) {
                    result.effects.emplace_back(QuicCoreSendDatagram{
                        .connection = 0,
                        .route_handle = inbound->route_handle,
                        .bytes = std::move(bytes),
                    });
                }
                result.next_wakeup = next_wakeup();
                return result;
            }
        }

        QuicCoreConfig config{
            .role = EndpointRole::server,
            .source_connection_id =
                retry_context.has_value()
                    ? retry_context->retry_source_connection_id
                    : make_endpoint_connection_id(std::byte{0x53},
                                                  next_server_connection_id_sequence_++),
            .original_version = parsed->version,
            .initial_version = parsed->version,
            .supported_versions = endpoint_config_.supported_versions,
            .verify_peer = endpoint_config_.verify_peer,
            .application_protocol = endpoint_config_.application_protocol,
            .identity = endpoint_config_.identity,
            .transport = endpoint_config_.transport,
            .allowed_tls_cipher_suites = endpoint_config_.allowed_tls_cipher_suites,
            .zero_rtt = endpoint_config_.zero_rtt,
            .qlog = endpoint_config_.qlog,
            .tls_keylog_path = endpoint_config_.tls_keylog_path,
        };
        if (retry_context.has_value()) {
            config.initial_destination_connection_id = retry_context->retry_source_connection_id;
            config.original_destination_connection_id =
                retry_context->original_destination_connection_id;
            config.retry_source_connection_id = retry_context->retry_source_connection_id;
            config.original_version = retry_context->original_version;
            config.initial_version = retry_context->original_version;
        }

        auto entry = ConnectionEntry{
            .handle = next_connection_handle_++,
            .default_route_handle = inbound->route_handle,
            .connection = std::make_unique<QuicConnection>(std::move(config)),
        };
        const auto path_id = inbound->route_handle.has_value()
                                 ? remember_inbound_path(entry, *inbound->route_handle)
                                 : (entry.default_route_handle.has_value()
                                        ? remember_inbound_path(entry, *entry.default_route_handle)
                                        : kDefaultPathId);
        entry.connection->process_inbound_datagram(inbound->bytes, now, path_id, inbound->ecn);

        auto drained =
            drain_connection_effects(entry.handle, entry.default_route_handle,
                                     entry.route_handle_by_path_id, *entry.connection, now);
        result.effects.insert(result.effects.end(),
                              std::make_move_iterator(drained.effects.begin()),
                              std::make_move_iterator(drained.effects.end()));
        result.effects.insert(result.effects.begin(),
                              QuicCoreConnectionLifecycleEvent{
                                  .connection = entry.handle,
                                  .event = QuicCoreConnectionLifecycle::accepted,
                              });

        if (!(entry.connection->has_failed() || has_closed_lifecycle_event(drained))) {
            const auto handle = entry.handle;
            auto [it, inserted] = connections_.emplace(handle, std::move(entry));
            (void)inserted;
            refresh_server_connection_routes(it->second);
        }
        result.next_wakeup = next_wakeup();
        return result;
    }

    if (const auto *command = std::get_if<QuicCoreConnectionCommand>(&input)) {
        auto entry_it = connections_.find(command->connection);
        if (entry_it == connections_.end()) {
            return QuicCoreResult{
                .next_wakeup = next_wakeup(),
                .local_error =
                    QuicCoreLocalError{
                        .connection = command->connection,
                        .code = QuicCoreLocalErrorCode::unsupported_operation,
                        .stream_id = std::nullopt,
                    },
            };
        }

        auto &entry = entry_it->second;
        QuicCoreResult result;
        std::visit(
            overloaded{
                [&](const QuicCoreSendStreamData &in) {
                    const auto queued =
                        entry.connection->queue_stream_send(in.stream_id, in.bytes, in.fin);
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreResetStream &in) {
                    const auto queued = entry.connection->queue_stream_reset(LocalResetCommand{
                        .stream_id = in.stream_id,
                        .application_error_code = in.application_error_code,
                    });
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreStopSending &in) {
                    const auto queued =
                        entry.connection->queue_stop_sending(LocalStopSendingCommand{
                            .stream_id = in.stream_id,
                            .application_error_code = in.application_error_code,
                        });
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreCloseConnection &in) {
                    static_cast<void>(
                        entry.connection->queue_application_close(LocalApplicationCloseCommand{
                            .application_error_code = in.application_error_code,
                            .reason_phrase = in.reason_phrase,
                        }));
                },
                [&](const QuicCoreRequestKeyUpdate &) { entry.connection->request_key_update(); },
                [&](const QuicCoreRequestConnectionMigration &in) {
                    const auto path_id = remember_inbound_path(entry, in.route_handle);
                    const auto requested =
                        entry.connection->request_connection_migration(path_id, in.reason);
                    if (!requested.has_value()) {
                        result.local_error = QuicCoreLocalError{
                            .connection = entry.handle,
                            .code = QuicCoreLocalErrorCode::unsupported_operation,
                            .stream_id = std::nullopt,
                        };
                    }
                },
                [&](const auto &) {},
            },
            command->input);

        auto drained =
            drain_connection_effects(entry.handle, entry.default_route_handle,
                                     entry.route_handle_by_path_id, *entry.connection, now);
        result.effects.insert(result.effects.end(),
                              std::make_move_iterator(drained.effects.begin()),
                              std::make_move_iterator(drained.effects.end()));
        if (endpoint_config_.role == EndpointRole::server) {
            refresh_server_connection_routes(entry);
        }
        if (entry.connection->has_failed() || has_closed_lifecycle_event(drained)) {
            if (endpoint_config_.role == EndpointRole::server) {
                erase_endpoint_connection_routes(entry);
            }
            connections_.erase(entry_it);
        }
        result.next_wakeup = next_wakeup();
        return result;
    }

    if (std::holds_alternative<QuicCoreTimerExpired>(input)) {
        QuicCoreResult result;
        std::vector<QuicConnectionHandle> erase_after;
        for (auto &[handle, entry] : connections_) {
            (void)handle;
            const auto wakeup = entry.connection->next_wakeup();
            if (!wakeup.has_value() || *wakeup > now) {
                continue;
            }

            entry.connection->on_timeout(now);
            auto drained =
                drain_connection_effects(entry.handle, entry.default_route_handle,
                                         entry.route_handle_by_path_id, *entry.connection, now);
            result.effects.insert(result.effects.end(),
                                  std::make_move_iterator(drained.effects.begin()),
                                  std::make_move_iterator(drained.effects.end()));
            if (endpoint_config_.role == EndpointRole::server) {
                refresh_server_connection_routes(entry);
            }
            if (entry.connection->has_failed() || has_closed_lifecycle_event(drained)) {
                erase_after.push_back(entry.handle);
            }
        }

        for (const auto handle : erase_after) {
            const auto entry_it = connections_.find(handle);
            if (entry_it == connections_.end()) {
                continue;
            }
            if (endpoint_config_.role == EndpointRole::server) {
                erase_endpoint_connection_routes(entry_it->second);
            }
            connections_.erase(entry_it);
        }
        result.next_wakeup = next_wakeup();
        return result;
    }

    (void)now;
    QuicCoreResult result;
    const auto connection = [&]() -> std::optional<QuicConnectionHandle> {
        if (const auto *command = std::get_if<QuicCoreConnectionCommand>(&input)) {
            return command->connection;
        }
        return std::nullopt;
    }();
    result.local_error = QuicCoreLocalError{
        .connection = connection,
        .code = QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = std::nullopt,
    };
    result.next_wakeup = next_wakeup();
    return result;
}

QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    QuicCoreResult result;
    if (!legacy_config_.has_value()) {
        result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        result.next_wakeup = next_wakeup();
        return result;
    }

    auto *entry = ensure_legacy_entry();
    if (entry == nullptr || entry->connection == nullptr) {
        return result;
    }
    auto config = legacy_config_.value_or(QuicCoreConfig{});
    auto *connection = entry->connection.get();

    std::visit(
        overloaded{
            [&](const QuicCoreStart &) { connection->start(now); },
            [&](const QuicCoreInboundDatagram &in) {
                const auto path_id =
                    in.route_handle.has_value()
                        ? remember_inbound_path(*entry, *in.route_handle)
                        : (entry->default_route_handle.has_value()
                               ? remember_inbound_path(*entry, *entry->default_route_handle)
                               : kDefaultPathId);
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
                                    connection->last_inbound_path_id_ = path_id;
                                    connection->current_send_path_id_ = path_id;
                                    connection->ensure_path_state(path_id).is_current_send_path =
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
                            connection->last_inbound_path_id_ = path_id;
                            connection->current_send_path_id_ = path_id;
                            connection->ensure_path_state(path_id).is_current_send_path = true;
                            connection->start(now);
                        }
                        return;
                    }
                }
                connection->process_inbound_datagram(in.bytes, now, path_id, in.ecn);
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
                const auto path_id = remember_inbound_path(*entry, in.route_handle);
                const auto requested = connection->request_connection_migration(path_id, in.reason);
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
        const auto route_handle = route_handle_for_path(*entry, connection->last_drained_path_id());
        result.effects.emplace_back(QuicCoreSendDatagram{
            .connection = entry->handle,
            .route_handle = route_handle,
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
    legacy_config_ = std::move(config);
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

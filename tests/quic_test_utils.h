#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#define private public
#include "src/quic/connection.h"
#undef private
#include "src/quic/buffer.h"
#include "src/quic/packet_crypto.h"

namespace coquic::quic::test {

inline std::string read_text_file(const char *path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

inline std::vector<std::byte> sample_transport_parameters() {
    return {
        std::byte{0x0f}, std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x0e}, std::byte{0x01}, std::byte{0x02},
    };
}

inline QuicCoreConfig make_client_core_config() {
    return QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .verify_peer = false,
        .server_name = "localhost",
    };
}

inline QuicCoreConfig make_server_core_config() {
    return QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .verify_peer = false,
        .server_name = "localhost",
        .identity =
            TlsIdentity{
                .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
                .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
            },
    };
}

inline QuicCoreTimePoint test_time(std::int64_t ms = 0) {
    return QuicCoreTimePoint{} + std::chrono::milliseconds(ms);
}

inline std::vector<std::vector<std::byte>> send_datagrams_from(const QuicCoreResult &result) {
    std::vector<std::vector<std::byte>> out;
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            out.push_back(send->bytes);
        }
    }

    return out;
}

inline std::vector<QuicResumptionState> resumption_states_from(const QuicCoreResult &result) {
    std::vector<QuicResumptionState> out;
    for (const auto &effect : result.effects) {
        if (const auto *available = std::get_if<QuicCoreResumptionStateAvailable>(&effect)) {
            out.push_back(available->state);
        }
    }

    return out;
}

inline std::vector<QuicZeroRttStatus> zero_rtt_statuses_from(const QuicCoreResult &result) {
    std::vector<QuicZeroRttStatus> out;
    for (const auto &effect : result.effects) {
        if (const auto *status = std::get_if<QuicCoreZeroRttStatusEvent>(&effect)) {
            out.push_back(status->status);
        }
    }

    return out;
}

inline std::vector<QuicCoreStateChange> state_changes_from(const QuicCoreResult &result) {
    std::vector<QuicCoreStateChange> out;
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect)) {
            out.push_back(event->change);
        }
    }

    return out;
}

inline std::size_t count_state_change(std::span<const QuicCoreStateChange> changes,
                                      QuicCoreStateChange change) {
    std::size_t count = 0;
    for (const auto value : changes) {
        if (value == change) {
            ++count;
        }
    }

    return count;
}

inline std::vector<std::byte> received_application_data_from(const QuicCoreResult &result) {
    std::vector<std::byte> out;
    for (const auto &effect : result.effects) {
        if (const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect)) {
            out.insert(out.end(), received->bytes.begin(), received->bytes.end());
        }
    }

    return out;
}

inline std::vector<QuicCoreReceiveStreamData>
received_stream_data_from(const QuicCoreResult &result) {
    std::vector<QuicCoreReceiveStreamData> out;
    for (const auto &effect : result.effects) {
        if (const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect)) {
            out.push_back(*received);
        }
    }

    return out;
}

struct StreamPayload {
    std::uint64_t stream_id = 0;
    std::string text;
    bool fin = false;

    bool operator==(const StreamPayload &) const = default;
};

inline std::vector<StreamPayload> stream_payloads_from(const QuicCoreResult &result) {
    std::vector<StreamPayload> payloads;
    for (const auto &received : received_stream_data_from(result)) {
        std::string text;
        text.reserve(received.bytes.size());
        for (const auto byte : received.bytes) {
            text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
        }
        payloads.push_back(StreamPayload{
            .stream_id = received.stream_id,
            .text = std::move(text),
            .fin = received.fin,
        });
    }

    return payloads;
}

inline std::vector<QuicCorePeerResetStream> peer_resets_from(const QuicCoreResult &result) {
    std::vector<QuicCorePeerResetStream> out;
    for (const auto &effect : result.effects) {
        if (const auto *reset = std::get_if<QuicCorePeerResetStream>(&effect)) {
            out.push_back(*reset);
        }
    }

    return out;
}

inline std::vector<QuicCorePeerStopSending> peer_stops_from(const QuicCoreResult &result) {
    std::vector<QuicCorePeerStopSending> out;
    for (const auto &effect : result.effects) {
        if (const auto *stop = std::get_if<QuicCorePeerStopSending>(&effect)) {
            out.push_back(*stop);
        }
    }

    return out;
}

inline QuicCoreResult relay_send_datagrams_to_peer(const QuicCoreResult &result, QuicCore &peer,
                                                   QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (auto datagram : send_datagrams_from(result)) {
        auto step = peer.advance(QuicCoreInboundDatagram{std::move(datagram)}, now);
        combined.effects.insert(combined.effects.end(),
                                std::make_move_iterator(step.effects.begin()),
                                std::make_move_iterator(step.effects.end()));
        combined.next_wakeup = step.next_wakeup;
    }

    return combined;
}

struct QuicHandshakeTranscript {
    std::vector<QuicCoreResult> client_results;
    std::vector<QuicCoreResult> server_results;
};

inline std::optional<QuicResumptionState>
last_resumption_state_from(std::span<const QuicCoreResult> results);

inline QuicCoreResult relay_datagrams_to_peer(std::span<const std::vector<std::byte>> datagrams,
                                              std::span<const std::size_t> delivery_order,
                                              QuicCore &peer, QuicCoreTimePoint now);

inline QuicCoreResult relay_send_datagrams_to_peer_except(const QuicCoreResult &result,
                                                          std::span<const std::size_t> dropped,
                                                          QuicCore &peer, QuicCoreTimePoint now) {
    const auto datagrams = send_datagrams_from(result);
    std::vector<std::size_t> delivery_order;
    delivery_order.reserve(datagrams.size());
    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        if (std::find(dropped.begin(), dropped.end(), index) != dropped.end()) {
            continue;
        }

        delivery_order.push_back(index);
    }

    return relay_datagrams_to_peer(datagrams, delivery_order, peer, now);
}

inline QuicCoreResult relay_nth_send_datagram_to_peer(const QuicCoreResult &result,
                                                      std::size_t index, QuicCore &peer,
                                                      QuicCoreTimePoint now) {
    const auto datagrams = send_datagrams_from(result);
    if (index >= datagrams.size()) {
        return {};
    }

    return relay_datagrams_to_peer(datagrams, std::array<std::size_t, 1>{index}, peer, now);
}

inline std::optional<QuicCoreTimePoint>
earliest_next_wakeup(std::initializer_list<std::optional<QuicCoreTimePoint>> wakeups) {
    std::optional<QuicCoreTimePoint> earliest;
    for (const auto &wakeup : wakeups) {
        if (!wakeup.has_value()) {
            continue;
        }

        if (!earliest.has_value() || *wakeup < *earliest) {
            earliest = wakeup;
        }
    }

    return earliest;
}

inline QuicCoreResult
drive_earliest_next_wakeup(QuicCore &core,
                           std::initializer_list<std::optional<QuicCoreTimePoint>> wakeups) {
    const auto earliest = earliest_next_wakeup(wakeups);
    if (!earliest.has_value()) {
        return {};
    }

    return core.advance(QuicCoreTimerExpired{}, *earliest);
}

inline QuicCoreResult relay_datagrams_to_peer(std::span<const std::vector<std::byte>> datagrams,
                                              std::span<const std::size_t> delivery_order,
                                              QuicCore &peer, QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (const auto index : delivery_order) {
        auto step = peer.advance(QuicCoreInboundDatagram{datagrams[index]}, now);
        combined.effects.insert(combined.effects.end(),
                                std::make_move_iterator(step.effects.begin()),
                                std::make_move_iterator(step.effects.end()));
        combined.next_wakeup = step.next_wakeup;
    }

    return combined;
}

inline QuicCoreResult advance_core_with_inputs(QuicCore &core,
                                               std::span<const QuicCoreInput> inputs,
                                               QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (const auto &input : inputs) {
        auto step = core.advance(input, now);
        combined.effects.insert(combined.effects.end(),
                                std::make_move_iterator(step.effects.begin()),
                                std::make_move_iterator(step.effects.end()));
        combined.next_wakeup = step.next_wakeup;
        if (step.local_error.has_value()) {
            combined.local_error = step.local_error;
            break;
        }
    }

    return combined;
}

class ScopedTempDir {
  public:
    ScopedTempDir() {
        std::ostringstream suffix;
        suffix << "coquic-http09-" << std::rand();
        path_ = std::filesystem::temp_directory_path() / suffix.str();
        std::filesystem::create_directories(path_);
    }

    ~ScopedTempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    ScopedTempDir(const ScopedTempDir &) = delete;
    ScopedTempDir &operator=(const ScopedTempDir &) = delete;

    const std::filesystem::path &path() const {
        return path_;
    }

    void write_file(const std::filesystem::path &relative_path, std::string_view text) const {
        const auto full_path = path_ / relative_path;
        std::filesystem::create_directories(full_path.parent_path());
        std::ofstream output(full_path, std::ios::binary);
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
    }

  private:
    std::filesystem::path path_;
};

inline void drive_quic_handshake(QuicCore &client, QuicCore &server, QuicCoreTimePoint now,
                                 std::vector<QuicCoreStateChange> *client_events = nullptr,
                                 std::vector<QuicCoreStateChange> *server_events = nullptr) {
    const auto append_state_changes = [](const QuicCoreResult &result,
                                         std::vector<QuicCoreStateChange> *events) {
        if (events == nullptr) {
            return;
        }
        auto changes = state_changes_from(result);
        events->insert(events->end(), changes.begin(), changes.end());
    };

    auto to_server = client.advance(QuicCoreStart{}, now);
    append_state_changes(to_server, client_events);
    auto to_client = QuicCoreResult{};
    auto step_now = now;

    for (int i = 0; i < 32; ++i) {
        if (!send_datagrams_from(to_server).empty()) {
            step_now += std::chrono::milliseconds(1);
            to_client = relay_send_datagrams_to_peer(to_server, server, step_now);
            append_state_changes(to_client, server_events);
            to_server.effects.clear();
            continue;
        }

        if (!send_datagrams_from(to_client).empty()) {
            step_now += std::chrono::milliseconds(1);
            to_server = relay_send_datagrams_to_peer(to_client, client, step_now);
            append_state_changes(to_server, client_events);
            to_client.effects.clear();
            continue;
        }

        const auto next = earliest_next_wakeup({to_server.next_wakeup, to_client.next_wakeup});
        if (!next.has_value()) {
            break;
        }

        if (to_server.next_wakeup.has_value() && *to_server.next_wakeup == *next) {
            to_server = client.advance(QuicCoreTimerExpired{}, *next);
            append_state_changes(to_server, client_events);
            continue;
        }

        if (to_client.next_wakeup.has_value() && *to_client.next_wakeup == *next) {
            to_client = server.advance(QuicCoreTimerExpired{}, *next);
            append_state_changes(to_client, server_events);
            continue;
        }
    }

    if (!(client.is_handshake_complete() && server.is_handshake_complete())) {
        return;
    }
}

inline QuicHandshakeTranscript drive_quic_handshake_with_results(QuicCore &client, QuicCore &server,
                                                                 QuicCoreTimePoint now) {
    QuicHandshakeTranscript transcript;
    auto to_server = client.advance(QuicCoreStart{}, now);
    transcript.client_results.push_back(to_server);
    auto to_client = QuicCoreResult{};
    auto step_now = now;

    for (int i = 0; i < 32; ++i) {
        if (!send_datagrams_from(to_server).empty()) {
            step_now += std::chrono::milliseconds(1);
            to_client = relay_send_datagrams_to_peer(to_server, server, step_now);
            transcript.server_results.push_back(to_client);
            to_server.effects.clear();
            continue;
        }

        if (!send_datagrams_from(to_client).empty()) {
            step_now += std::chrono::milliseconds(1);
            to_server = relay_send_datagrams_to_peer(to_client, client, step_now);
            transcript.client_results.push_back(to_server);
            to_client.effects.clear();
            continue;
        }

        const auto next = earliest_next_wakeup({to_server.next_wakeup, to_client.next_wakeup});
        if (!next.has_value()) {
            break;
        }

        if (to_server.next_wakeup.has_value() && *to_server.next_wakeup == *next) {
            to_server = client.advance(QuicCoreTimerExpired{}, *next);
            transcript.client_results.push_back(to_server);
            continue;
        }

        if (to_client.next_wakeup.has_value() && *to_client.next_wakeup == *next) {
            to_client = server.advance(QuicCoreTimerExpired{}, *next);
            transcript.server_results.push_back(to_client);
            continue;
        }
    }

    for (int i = 0; i < 8; ++i) {
        step_now += std::chrono::milliseconds(1);
        auto server_tick = server.advance(QuicCoreTimerExpired{}, step_now);
        transcript.server_results.push_back(server_tick);
        if (!send_datagrams_from(server_tick).empty()) {
            step_now += std::chrono::milliseconds(1);
            transcript.client_results.push_back(
                relay_send_datagrams_to_peer(server_tick, client, step_now));
        }
        if (last_resumption_state_from(transcript.client_results).has_value()) {
            break;
        }

        step_now += std::chrono::milliseconds(1);
        auto client_tick = client.advance(QuicCoreTimerExpired{}, step_now);
        transcript.client_results.push_back(client_tick);
        if (!send_datagrams_from(client_tick).empty()) {
            step_now += std::chrono::milliseconds(1);
            transcript.server_results.push_back(
                relay_send_datagrams_to_peer(client_tick, server, step_now));
        }
        if (last_resumption_state_from(transcript.client_results).has_value()) {
            break;
        }
    }

    return transcript;
}

inline void
drive_quic_handshake_from_results(QuicCore &client, QuicCore &server, QuicCoreResult to_server,
                                  QuicCoreResult to_client, QuicCoreTimePoint now,
                                  std::vector<QuicCoreStateChange> *client_events = nullptr,
                                  std::vector<QuicCoreStateChange> *server_events = nullptr) {
    const auto append_state_changes = [](const QuicCoreResult &result,
                                         std::vector<QuicCoreStateChange> *events) {
        if (events == nullptr) {
            return;
        }
        auto changes = state_changes_from(result);
        events->insert(events->end(), changes.begin(), changes.end());
    };

    auto step_to_server = std::move(to_server);
    auto step_to_client = std::move(to_client);
    auto step_now = now;

    for (int i = 0; i < 32; ++i) {
        if (!send_datagrams_from(step_to_server).empty()) {
            step_now += std::chrono::milliseconds(1);
            step_to_client = relay_send_datagrams_to_peer(step_to_server, server, step_now);
            append_state_changes(step_to_client, server_events);
            step_to_server.effects.clear();
            continue;
        }

        if (!send_datagrams_from(step_to_client).empty()) {
            step_now += std::chrono::milliseconds(1);
            step_to_server = relay_send_datagrams_to_peer(step_to_client, client, step_now);
            append_state_changes(step_to_server, client_events);
            step_to_client.effects.clear();
            continue;
        }

        const auto next =
            earliest_next_wakeup({step_to_server.next_wakeup, step_to_client.next_wakeup});
        if (!next.has_value()) {
            break;
        }

        if (step_to_server.next_wakeup.has_value() && *step_to_server.next_wakeup == *next) {
            step_to_server = client.advance(QuicCoreTimerExpired{}, *next);
            append_state_changes(step_to_server, client_events);
            continue;
        }

        if (step_to_client.next_wakeup.has_value() && *step_to_client.next_wakeup == *next) {
            step_to_client = server.advance(QuicCoreTimerExpired{}, *next);
            append_state_changes(step_to_client, server_events);
            continue;
        }
    }
}

inline QuicHandshakeTranscript
drive_quic_handshake_from_results_with_results(QuicCore &client, QuicCore &server,
                                               QuicCoreResult to_server, QuicCoreResult to_client,
                                               QuicCoreTimePoint now) {
    QuicHandshakeTranscript transcript;
    auto step_to_server = std::move(to_server);
    if (!step_to_server.effects.empty() || step_to_server.next_wakeup.has_value() ||
        step_to_server.local_error.has_value()) {
        transcript.client_results.push_back(step_to_server);
    }
    auto step_to_client = std::move(to_client);
    if (!step_to_client.effects.empty() || step_to_client.next_wakeup.has_value() ||
        step_to_client.local_error.has_value()) {
        transcript.server_results.push_back(step_to_client);
    }
    auto step_now = now;

    for (int i = 0; i < 32; ++i) {
        if (!send_datagrams_from(step_to_server).empty()) {
            step_now += std::chrono::milliseconds(1);
            step_to_client = relay_send_datagrams_to_peer(step_to_server, server, step_now);
            transcript.server_results.push_back(step_to_client);
            step_to_server.effects.clear();
            continue;
        }

        if (!send_datagrams_from(step_to_client).empty()) {
            step_now += std::chrono::milliseconds(1);
            step_to_server = relay_send_datagrams_to_peer(step_to_client, client, step_now);
            transcript.client_results.push_back(step_to_server);
            step_to_client.effects.clear();
            continue;
        }

        const auto next =
            earliest_next_wakeup({step_to_server.next_wakeup, step_to_client.next_wakeup});
        if (!next.has_value()) {
            break;
        }

        if (step_to_server.next_wakeup.has_value() && *step_to_server.next_wakeup == *next) {
            step_to_server = client.advance(QuicCoreTimerExpired{}, *next);
            transcript.client_results.push_back(step_to_server);
            continue;
        }

        if (step_to_client.next_wakeup.has_value() && *step_to_client.next_wakeup == *next) {
            step_to_client = server.advance(QuicCoreTimerExpired{}, *next);
            transcript.server_results.push_back(step_to_client);
            continue;
        }
    }

    return transcript;
}

inline std::optional<QuicResumptionState>
last_resumption_state_from(std::span<const QuicCoreResult> results) {
    std::optional<QuicResumptionState> latest;
    for (const auto &result : results) {
        const auto states = resumption_states_from(result);
        if (!states.empty()) {
            latest = states.back();
        }
    }
    return latest;
}

inline std::vector<std::byte> bytes_from_string(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const auto character : text) {
        bytes.push_back(static_cast<std::byte>(character));
    }
    return bytes;
}

inline std::string string_from_bytes(std::span<const std::byte> bytes) {
    std::string text;
    text.reserve(bytes.size());
    for (const auto byte : bytes) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return text;
}

inline CodecResult<std::vector<std::byte>> make_valid_retry_datagram(
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    std::span<const std::byte> retry_token, const ConnectionId &original_destination_connection_id,
    std::uint32_t version = kQuicVersion1, std::uint8_t retry_unused_bits = 0) {
    RetryPacket retry_packet{
        .version = version,
        .retry_unused_bits = retry_unused_bits,
        .destination_connection_id = destination_connection_id,
        .source_connection_id = source_connection_id,
        .retry_token = std::vector<std::byte>(retry_token.begin(), retry_token.end()),
    };
    const auto integrity_tag =
        compute_retry_integrity_tag(retry_packet, original_destination_connection_id);
    if (!integrity_tag.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(integrity_tag.error().code,
                                                            integrity_tag.error().offset);
    }
    retry_packet.retry_integrity_tag = integrity_tag.value();
    return serialize_packet(retry_packet);
}

inline std::optional<ConnectionId>
long_header_destination_connection_id(std::span<const std::byte> datagram) {
    BufferReader reader(datagram);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value() ||
        (std::to_integer<std::uint8_t>(first_byte.value()) & 0x80u) == 0) {
        return std::nullopt;
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return std::nullopt;
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return std::nullopt;
    }
    const auto destination_connection_id =
        reader.read_exact(std::to_integer<std::uint8_t>(destination_connection_id_length.value()));
    if (!destination_connection_id.has_value()) {
        return std::nullopt;
    }

    return ConnectionId(destination_connection_id.value().begin(),
                        destination_connection_id.value().end());
}

inline std::optional<std::vector<std::byte>>
client_initial_datagram_token(std::span<const std::byte> datagram) {
    BufferReader reader(datagram);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return std::nullopt;
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0 || (header_byte & 0x40u) == 0) {
        return std::nullopt;
    }

    const auto version_bytes = reader.read_exact(4);
    if (!version_bytes.has_value()) {
        return std::nullopt;
    }
    const auto version =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(version_bytes.value()[0]))
         << 24) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(version_bytes.value()[1]))
         << 16) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(version_bytes.value()[2])) << 8) |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(version_bytes.value()[3]));

    const auto packet_type = static_cast<std::uint8_t>((header_byte >> 4) & 0x03u);
    const bool is_initial = version == kQuicVersion2 ? packet_type == 0x01u : packet_type == 0x00u;
    if (!is_initial) {
        return std::nullopt;
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return std::nullopt;
    }
    const auto destination_connection_id =
        reader.read_exact(std::to_integer<std::uint8_t>(destination_connection_id_length.value()));
    if (!destination_connection_id.has_value()) {
        return std::nullopt;
    }

    const auto source_connection_id_length = reader.read_byte();
    if (!source_connection_id_length.has_value()) {
        return std::nullopt;
    }
    const auto source_connection_id =
        reader.read_exact(std::to_integer<std::uint8_t>(source_connection_id_length.value()));
    if (!source_connection_id.has_value()) {
        return std::nullopt;
    }

    const auto token_length = decode_varint(reader);
    if (!token_length.has_value() || token_length.value().value > reader.remaining()) {
        return std::nullopt;
    }
    const auto token = reader.read_exact(static_cast<std::size_t>(token_length.value().value));
    if (!token.has_value()) {
        return std::nullopt;
    }

    return std::vector<std::byte>(token.value().begin(), token.value().end());
}

inline StreamFrame make_inbound_application_stream_frame(std::string_view text,
                                                         std::uint64_t offset = 0,
                                                         std::uint64_t stream_id = 0,
                                                         bool fin = false, bool has_offset = true,
                                                         bool has_length = true) {
    return StreamFrame{
        .fin = fin,
        .has_offset = has_offset,
        .has_length = has_length,
        .stream_id = stream_id,
        .offset = has_offset ? std::optional<std::uint64_t>(offset) : std::nullopt,
        .stream_data = bytes_from_string(text),
    };
}

struct QuicConnectionTestPeer {
    static void set_handshake_status(QuicConnection &connection, HandshakeStatus status) {
        connection.status_ = status;
    }

    static bool inject_inbound_one_rtt_frames(QuicConnection &connection, std::vector<Frame> frames,
                                              std::uint64_t packet_number = 0) {
        const auto processed = connection.process_inbound_packet(
            ProtectedOneRttPacket{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = packet_number,
                .frames = std::move(frames),
            },
            test_time());
        if (!processed.has_value()) {
            connection.status_ = HandshakeStatus::failed;
            return false;
        }

        return true;
    }
};

} // namespace coquic::quic::test

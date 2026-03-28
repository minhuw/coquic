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

#include "src/quic/qlog/session.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include "src/quic/qlog/json.h"

namespace coquic::quic::qlog {
namespace {

std::string format_connection_id_hex(const ConnectionId &connection_id) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(connection_id.size() * 2);
    for (const auto byte : connection_id) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        hex.push_back(kDigits[value >> 4]);
        hex.push_back(kDigits[value & 0x0f]);
    }
    return hex;
}

template <typename SessionFactory>
std::unique_ptr<Session> try_open_with_sink(std::unique_ptr<QlogFileSeqSink> sink,
                                            EndpointRole role, const ConnectionId &odcid,
                                            QuicCoreTimePoint start_time,
                                            SessionFactory &&session_factory) {
    const auto suffix = role == EndpointRole::client ? "client" : "server";
    const auto odcid_hex = format_connection_id_hex(odcid);
    if (sink == nullptr || !sink->healthy()) {
        return nullptr;
    }

    const auto preamble = serialize_file_seq_preamble(FilePreamble{
        .title = "coquic qlog",
        .description = "core QUIC trace",
        .group_id = odcid_hex,
        .vantage_point_type = suffix,
        .event_schemas = {"urn:ietf:params:qlog:events:quic-12"},
    });
    if (!sink->write_record(make_json_seq_record(preamble))) {
        return nullptr;
    }

    return std::forward<SessionFactory>(session_factory)(start_time, std::move(sink));
}

} // namespace

Session::Session(QuicCoreTimePoint start_time, std::unique_ptr<QlogFileSeqSink> sink)
    : sink_(std::move(sink)), start_time_(start_time) {
}

std::unique_ptr<Session> Session::try_open(const QuicQlogConfig &config, EndpointRole role,
                                           const ConnectionId &odcid,
                                           QuicCoreTimePoint start_time) {
    const auto suffix = role == EndpointRole::client ? "client" : "server";
    const auto odcid_hex = format_connection_id_hex(odcid);
    auto sink =
        std::make_unique<QlogFileSeqSink>(config.directory / (odcid_hex + "_" + suffix + ".sqlog"));
    if (!sink->open()) {
        return nullptr;
    }
    return try_open_with_sink(
        std::move(sink), role, odcid, start_time,
        [](QuicCoreTimePoint session_start_time, std::unique_ptr<QlogFileSeqSink> session_sink) {
            return std::unique_ptr<Session>(
                new Session(session_start_time, std::move(session_sink)));
        });
}

std::unique_ptr<Session> Session::try_open_with_sink_for_test(std::unique_ptr<QlogFileSeqSink> sink,
                                                              EndpointRole role,
                                                              const ConnectionId &odcid,
                                                              QuicCoreTimePoint start_time) {
    return try_open_with_sink(
        std::move(sink), role, odcid, start_time,
        [](QuicCoreTimePoint session_start_time, std::unique_ptr<QlogFileSeqSink> session_sink) {
            return std::unique_ptr<Session>(
                new Session(session_start_time, std::move(session_sink)));
        });
}

bool Session::healthy() const {
    return sink_ != nullptr && sink_->healthy();
}

std::uint32_t Session::next_inbound_datagram_id() {
    return next_inbound_datagram_id_++;
}

std::uint32_t Session::next_outbound_datagram_id() {
    return next_outbound_datagram_id_++;
}

double Session::relative_time_ms(QuicCoreTimePoint now) const {
    return std::chrono::duration<double, std::milli>(now - start_time_).count();
}

bool Session::write_event(QuicCoreTimePoint now, std::string_view name,
                          std::string_view data_json) {
    if (!healthy()) {
        return false;
    }

    const std::string event =
        std::string("{") + "\"time\":" + std::to_string(relative_time_ms(now)) + ",\"name\":\"" +
        escape_json_string(name) + "\",\"data\":" + std::string(data_json) + "}";
    return sink_->write_record(make_json_seq_record(event));
}

bool Session::mark_local_version_information_emitted() {
    if (local_version_information_emitted_) {
        return false;
    }
    local_version_information_emitted_ = true;
    return true;
}

bool Session::mark_local_alpn_information_emitted() {
    if (local_alpn_information_emitted_) {
        return false;
    }
    local_alpn_information_emitted_ = true;
    return true;
}

bool Session::mark_local_parameters_set_emitted() {
    if (local_parameters_set_emitted_) {
        return false;
    }
    local_parameters_set_emitted_ = true;
    return true;
}

bool Session::mark_remote_parameters_set_emitted() {
    if (remote_parameters_set_emitted_) {
        return false;
    }
    remote_parameters_set_emitted_ = true;
    return true;
}

bool Session::mark_server_alpn_selection_emitted() {
    if (server_alpn_selection_emitted_) {
        return false;
    }
    server_alpn_selection_emitted_ = true;
    return true;
}

bool Session::mark_client_chosen_alpn_emitted() {
    if (client_chosen_alpn_emitted_) {
        return false;
    }
    client_chosen_alpn_emitted_ = true;
    return true;
}

bool Session::maybe_write_recovery_metrics(QuicCoreTimePoint now,
                                           const RecoveryMetricsSnapshot &metrics) {
    if (last_recovery_metrics_.has_value() && *last_recovery_metrics_ == metrics) {
        return true;
    }

    last_recovery_metrics_ = metrics;
    return write_event(now, "quic:recovery_metrics_updated", serialize_recovery_metrics(metrics));
}

} // namespace coquic::quic::qlog

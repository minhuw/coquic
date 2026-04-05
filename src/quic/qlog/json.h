#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "src/quic/transport_parameters.h"
#include "src/quic/qlog/types.h"

namespace coquic::quic::qlog {

std::string escape_json_string(std::string_view value);
std::string serialize_file_seq_preamble(const FilePreamble &preamble);
std::string make_json_seq_record(std::string_view json_object);
std::string serialize_version_information(EndpointRole role,
                                          std::span<const std::uint32_t> supported_versions,
                                          std::optional<std::uint32_t> chosen_version);
std::string
serialize_alpn_information(std::optional<std::span<const std::vector<std::byte>>> local_alpns,
                           std::optional<std::span<const std::vector<std::byte>>> peer_alpns,
                           std::optional<std::span<const std::byte>> chosen_alpn,
                           EndpointRole role);
std::string serialize_parameters_set(std::string_view initiator,
                                     const TransportParameters &parameters);
std::string serialize_packet_snapshot(const PacketSnapshot &snapshot);
std::string serialize_recovery_metrics(const RecoveryMetricsSnapshot &metrics);

} // namespace coquic::quic::qlog

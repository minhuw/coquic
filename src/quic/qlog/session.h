#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "src/quic/core.h"
#include "src/quic/qlog/sink.h"
#include "src/quic/qlog/types.h"

namespace coquic::quic::qlog {

class Session {
  public:
    static std::unique_ptr<Session> try_open(const QuicQlogConfig &config, EndpointRole role,
                                             const ConnectionId &odcid,
                                             QuicCoreTimePoint start_time);

    bool healthy() const;
    std::uint32_t next_inbound_datagram_id();
    std::uint32_t next_outbound_datagram_id();
    double relative_time_ms(QuicCoreTimePoint now) const;
    bool write_event(QuicCoreTimePoint now, std::string_view name, std::string_view data_json);
    bool mark_local_version_information_emitted();
    bool mark_local_alpn_information_emitted();
    bool mark_local_parameters_set_emitted();
    bool mark_remote_parameters_set_emitted();
    bool mark_server_alpn_selection_emitted();
    bool mark_client_chosen_alpn_emitted();
    bool maybe_write_recovery_metrics(QuicCoreTimePoint now,
                                      const RecoveryMetricsSnapshot &metrics);

  private:
    Session(QuicCoreTimePoint start_time, std::unique_ptr<QlogFileSeqSink> sink);

    std::unique_ptr<QlogFileSeqSink> sink_;
    QuicCoreTimePoint start_time_{};
    std::uint32_t next_inbound_datagram_id_ = 0;
    std::uint32_t next_outbound_datagram_id_ = 0;
    bool local_version_information_emitted_ = false;
    bool local_alpn_information_emitted_ = false;
    bool local_parameters_set_emitted_ = false;
    bool remote_parameters_set_emitted_ = false;
    bool server_alpn_selection_emitted_ = false;
    bool client_chosen_alpn_emitted_ = false;
    std::optional<RecoveryMetricsSnapshot> last_recovery_metrics_;
};

} // namespace coquic::quic::qlog

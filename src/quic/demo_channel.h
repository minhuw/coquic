#pragma once

#include <cstddef>
#include <vector>

#include "src/quic/core.h"

namespace coquic::quic {

class QuicDemoChannel {
  public:
    explicit QuicDemoChannel(QuicCoreConfig config);

    void send_message(std::vector<std::byte> bytes);
    std::vector<std::byte> on_datagram(std::vector<std::byte> bytes);
    std::vector<std::vector<std::byte>> take_messages();
    bool is_ready() const;
    bool has_failed() const;

  private:
    void process_core_result(QuicCoreResult result);
    std::vector<std::byte> take_next_outbound_datagram();

    QuicCore core_;
    std::vector<std::byte> pending_send_bytes_;
    std::vector<std::byte> pending_receive_bytes_;
    std::vector<std::vector<std::byte>> pending_outbound_datagrams_;
    std::vector<std::vector<std::byte>> complete_messages_;
    bool failed_ = false;
};

} // namespace coquic::quic

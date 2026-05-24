#pragma once

#include <optional>
#include <vector>

#include "src/io/io_backend.h"
#include "src/quic/core.h"

namespace coquic::perf {

std::optional<quic::QuicCoreEndpointInput>
make_endpoint_input_from_io_event(io::QuicIoEvent &event);

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result);

class PerfSendBuffer {
  public:
    bool append_or_flush(io::QuicIoBackend &backend, const quic::QuicCoreResult &result);
    bool flush(io::QuicIoBackend &backend);
    bool empty() const;
    std::size_t size() const;

  private:
    std::vector<io::QuicIoTxDatagram> datagrams_;
};

} // namespace coquic::perf

#pragma once

#include <optional>
#include <vector>

#include "src/io/io_backend.h"
#include "src/quic/core.h"

namespace coquic::perf {

std::optional<quic::QuicCoreEndpointInput>
make_endpoint_input_from_io_event(io::QuicIoEvent &event);

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result);

class PerfSendBuffer : public quic::QuicCoreSendDatagramSink {
  public:
    void set_backend(io::QuicIoBackend *backend);
    bool on_send_datagram(quic::QuicCoreSendDatagram datagram) override;
    bool on_send_datagram_payload(quic::QuicConnectionHandle connection,
                                  quic::QuicRouteHandle route_handle, quic::DatagramBuffer bytes,
                                  quic::QuicEcnCodepoint ecn, bool is_pmtu_probe,
                                  std::uint64_t packet_inspection_datagram_id) override;
    bool append_or_flush(io::QuicIoBackend &backend, quic::QuicCoreResult &result);
    bool flush(io::QuicIoBackend &backend);
    bool empty() const;
    std::size_t size() const;

  private:
    bool append_send_datagram(io::QuicIoBackend &backend, quic::QuicCoreSendDatagram &&datagram,
                              bool flush_when_full);
    bool append_payload_datagram(io::QuicIoBackend &backend, quic::QuicRouteHandle route_handle,
                                 quic::DatagramBuffer &&bytes, quic::QuicEcnCodepoint ecn,
                                 bool is_pmtu_probe, bool flush_when_full);

    io::QuicIoBackend *backend_ = nullptr;
    std::vector<io::QuicIoTxDatagram> datagrams_;
};

} // namespace coquic::perf

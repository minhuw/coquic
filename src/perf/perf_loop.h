#pragma once

#include <vector>

#include "src/io/io_backend.h"
#include "src/quic/core.h"

namespace coquic::perf {

std::vector<quic::QuicCoreEndpointInput>
make_endpoint_inputs_from_io_event(const io::QuicIoEvent &event);

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result);

} // namespace coquic::perf

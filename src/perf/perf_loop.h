#pragma once

#include <optional>
#include <vector>

#include "src/io/io_backend.h"
#include "src/quic/core.h"

namespace coquic::perf {

std::optional<quic::QuicCoreEndpointInput>
make_endpoint_input_from_io_event(io::QuicIoEvent &event);

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result);

} // namespace coquic::perf

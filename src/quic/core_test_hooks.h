#pragma once

#include "src/quic/core.h"

namespace coquic::quic::test {

bool seed_legacy_route_handle_path_for_tests(QuicCore &core, QuicRouteHandle route_handle,
                                             QuicPathId path_id);

} // namespace coquic::quic::test

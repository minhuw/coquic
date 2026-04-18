#pragma once

#include "src/http3/http3.h"

#include <cstddef>
#include <optional>

namespace coquic::http3 {

struct Http3DemoRouteLimits {
    std::size_t max_speed_download_bytes = static_cast<std::size_t>(4) * 1024u * 1024u;
    std::size_t max_speed_upload_bytes = static_cast<std::size_t>(4) * 1024u * 1024u;
};

std::optional<Http3Response> try_demo_route_response(const Http3Request &request,
                                                     const Http3DemoRouteLimits &limits = {});

} // namespace coquic::http3

#pragma once

#include "src/http3/http3.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace coquic::http3 {

struct Http3DemoRouteLimits {
    std::size_t max_speed_download_bytes = static_cast<std::size_t>(4) * 1024u * 1024u;
    std::size_t max_speed_upload_bytes = static_cast<std::size_t>(4) * 1024u * 1024u;
};

void append_json_escaped(std::string &out, std::string_view value);
std::vector<std::byte> inspect_json_body(const Http3Request &request);

std::optional<Http3Response> try_demo_route_response(const Http3Request &request,
                                                     const Http3DemoRouteLimits &limits = {});

} // namespace coquic::http3

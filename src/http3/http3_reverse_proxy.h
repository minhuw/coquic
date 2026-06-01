#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "src/http3/http3.h"

namespace coquic::http3 {

struct Http3ReverseProxyConfig {
    std::string host = "127.0.0.1";
    std::uint16_t port = 3000;
};

std::optional<Http3ReverseProxyConfig> parse_http_reverse_proxy_target(std::string_view target);
Http3Response fetch_http_reverse_proxy_response(const Http3ReverseProxyConfig &config,
                                                const Http3Request &request);
void stream_http_reverse_proxy_response(const Http3ReverseProxyConfig &config,
                                        const Http3Request &request,
                                        const std::function<bool(Http3ResponsePart)> &emit);

} // namespace coquic::http3

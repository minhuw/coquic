#include "coquic/h3_server.h"

#include "src/http3/http3_runtime.h"

namespace coquic::h3_server {

int run_cli(int argc, char **argv) {
    const auto config = http3::parse_http3_server_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return http3::run_http3_server(*config);
}

} // namespace coquic::h3_server

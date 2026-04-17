#include "src/http3/http3_runtime.h"

int main(int argc, char **argv) {
    const auto config = coquic::http3::parse_http3_server_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::http3::run_http3_server(*config);
}

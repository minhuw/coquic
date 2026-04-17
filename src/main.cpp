#include "src/http3/http3_interop.h"
#include "src/http3/http3_runtime.h"
#include "src/http09/http09_runtime.h"

#include <string_view>

int main(int argc, char **argv) {
    if (argc >= 2) {
        const auto subcommand = std::string_view(argv[1]);
        if (subcommand == "h3-client") {
            const auto config = coquic::http3::parse_http3_client_args(argc - 1, argv + 1);
            if (!config.has_value()) {
                return 1;
            }
            return coquic::http3::run_http3_client(*config);
        }
        if (subcommand == "h3-interop-server" || subcommand == "h3-interop-client") {
            const auto config = coquic::http3::parse_http3_interop_args(argc, argv);
            if (!config.has_value()) {
                return 1;
            }
            return coquic::http3::run_http3_interop(*config);
        }
    }

    const auto config = coquic::http09::parse_http09_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::http09::run_http09_runtime(*config);
}

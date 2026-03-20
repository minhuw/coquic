#include "src/quic/http09_runtime.h"

int main(int argc, char **argv) {
    const auto config = coquic::quic::parse_http09_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::quic::run_http09_runtime(*config);
}

#include "src/http09/http09_runtime.h"

int main(int argc, char **argv) {
    const auto config = coquic::http09::parse_http09_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::http09::run_http09_runtime(*config);
}

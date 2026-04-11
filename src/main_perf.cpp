#include "src/perf/perf_runtime.h"

int main(int argc, char **argv) {
    const auto config = coquic::perf::parse_perf_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return coquic::perf::run_perf_runtime(*config);
}

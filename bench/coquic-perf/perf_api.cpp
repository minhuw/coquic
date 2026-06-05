#include "coquic/perf.h"

#include "bench/coquic-perf/perf_runtime.h"

namespace coquic::perf {

int run_cli(int argc, char **argv) {
    const auto config = parse_perf_runtime_args(argc, argv);
    if (!config.has_value()) {
        return 1;
    }
    return run_perf_runtime(*config);
}

} // namespace coquic::perf

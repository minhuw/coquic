#pragma once

#include <optional>

#include "src/http09/http09_runtime.h"

namespace coquic::interop {

std::optional<http09::Http09RuntimeConfig> parse_http09_interop_args(int argc, char **argv);

} // namespace coquic::interop

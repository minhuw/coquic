#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "src/http09/http09_runtime.h"

namespace coquic::interop {

enum class Http09InteropTestcase : std::uint8_t {
    handshake,
    transfer,
    keyupdate,
    rebind_port,
    rebind_addr,
    connectionmigration,
    ecn,
    multiconnect,
    chacha20,
    resumption,
    zerortt,
    v2,
};

std::optional<Http09InteropTestcase> parse_http09_interop_testcase(std::string_view value);
bool apply_http09_interop_testcase(http09::Http09RuntimeConfig &config, std::string_view value);
void apply_http09_interop_profile(http09::Http09RuntimeConfig &config,
                                  Http09InteropTestcase testcase);

} // namespace coquic::interop

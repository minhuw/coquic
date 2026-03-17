#include "src/coquic.h"

#include <openssl/crypto.h>
#include <spdlog/spdlog.h>

namespace {

bool &logging_ready_flag() {
    static bool ready = false;
    return ready;
}

} // namespace

namespace coquic {

std::string_view project_name() {
    return "coquic";
}

bool openssl_available() {
    return OpenSSL_version_num() != 0;
}

void init_logging() {
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
    logging_ready_flag() = spdlog::default_logger() != nullptr;
}

bool logging_ready() {
    return logging_ready_flag();
}

} // namespace coquic

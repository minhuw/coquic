#pragma once

#include <string_view>

#include "src/quic/plaintext_codec.h"
#include "src/quic/protected_codec.h"

namespace coquic {

std::string_view project_name();
bool openssl_available();
void init_logging();
bool logging_ready();

} // namespace coquic

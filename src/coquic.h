#pragma once

#include <string_view>

namespace coquic {

std::string_view project_name();
bool openssl_available();

} // namespace coquic

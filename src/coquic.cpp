#include "src/coquic.h"

#include <openssl/crypto.h>

namespace coquic {

std::string_view project_name() {
    return "coquic";
}

bool openssl_available() {
    return OpenSSL_version_num() != 0;
}

} // namespace coquic

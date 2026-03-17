#include "src/coquic.h"

int main() {
    coquic::init_logging();

    return coquic::project_name().empty() || !coquic::openssl_available() ||
           !coquic::logging_ready();
}

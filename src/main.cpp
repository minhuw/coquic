#include "src/coquic.h"

int main() {
    return coquic::project_name().empty() || !coquic::openssl_available();
}

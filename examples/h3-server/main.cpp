#include "coquic/h3_server.h"

int main(int argc, char **argv) {
    return coquic::h3_server::run_cli(argc, argv);
}

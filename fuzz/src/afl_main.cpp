#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);

namespace {

constexpr std::size_t kMaxInputSize = 1 << 20;

std::vector<std::uint8_t> read_all(std::istream &input) {
    std::vector<std::uint8_t> bytes;
    bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return bytes;
}

int run_input(const std::vector<std::uint8_t> &bytes) {
    if (bytes.size() > kMaxInputSize) {
        return 0;
    }
    return LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
}

} // namespace

int main(int argc, char **argv) {
    if (argc <= 1) {
        auto bytes = read_all(std::cin);
        return run_input(bytes);
    }

    for (int i = 1; i < argc; ++i) {
        std::ifstream input(argv[i], std::ios::binary);
        if (!input) {
            std::cerr << "failed to open " << argv[i] << '\n';
            return EXIT_FAILURE;
        }
        auto bytes = read_all(input);
        const auto result = run_input(bytes);
        if (result != 0) {
            return result;
        }
    }

    return EXIT_SUCCESS;
}

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

#if !defined(COQUIC_FUZZ_BUILD) && !defined(COQUIC_WASM_NO_FILESYSTEM)
#include <array>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#endif

namespace coquic::quic {

inline bool fuzz_corpus_capture_enabled() {
#if !defined(COQUIC_FUZZ_BUILD) && !defined(COQUIC_WASM_NO_FILESYSTEM)
    static const bool enabled = [] {
        const char *root = std::getenv("COQUIC_FUZZ_CORPUS_CAPTURE_DIR");
        return root != nullptr && root[0] != '\0';
    }();
    return enabled;
#else
    return false;
#endif
}

inline void capture_fuzz_corpus_sample(std::string_view target, std::span<const std::byte> bytes) {
#if !defined(COQUIC_FUZZ_BUILD) && !defined(COQUIC_WASM_NO_FILESYSTEM)
    if (bytes.empty()) {
        return;
    }

    struct State {
        std::once_flag init_once;
        bool enabled = false;
        std::filesystem::path root;
        std::size_t max_samples_per_target = 5000;
        std::mutex mutex;
        std::unordered_map<std::string, std::size_t> counts;
        std::unordered_map<std::string, std::unordered_set<std::string>> seen;
    };

    static State state;
    std::call_once(state.init_once, [&] {
        const char *root = std::getenv("COQUIC_FUZZ_CORPUS_CAPTURE_DIR");
        if (root == nullptr || root[0] == '\0') {
            return;
        }

        state.enabled = true;
        state.root = root;
        if (const char *limit = std::getenv("COQUIC_FUZZ_CORPUS_CAPTURE_LIMIT");
            limit != nullptr && limit[0] != '\0') {
            char *end = nullptr;
            const auto parsed = std::strtoull(limit, &end, 10);
            if (end != limit && *end == '\0') {
                state.max_samples_per_target = static_cast<std::size_t>(parsed);
            }
        }
    });

    if (!fuzz_corpus_capture_enabled() || !state.enabled) {
        return;
    }

    auto hash = std::uint64_t{1469598103934665603ull};
    for (const auto byte : bytes) {
        hash ^= std::to_integer<std::uint8_t>(byte);
        hash *= std::uint64_t{1099511628211ull};
    }

    constexpr std::array<char, 16> hex_digits{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    std::string digest(16, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        const auto shift = static_cast<unsigned>((digest.size() - index - 1) * 4);
        digest[index] = hex_digits[(hash >> shift) & 0x0fu];
    }

    const auto target_name = std::string(target);
    {
        std::lock_guard lock(state.mutex);
        auto &count = state.counts[target_name];
        if (count >= state.max_samples_per_target) {
            return;
        }
        auto &seen = state.seen[target_name];
        if (!seen.insert(digest).second) {
            return;
        }
        ++count;
    }

    std::error_code error;
    const auto target_dir = state.root / target_name;
    std::filesystem::create_directories(target_dir, error);
    if (error) {
        return;
    }

    const auto output_path = target_dir / (digest + ".raw");
    if (std::filesystem::exists(output_path, error)) {
        return;
    }

    std::ofstream output(output_path, std::ios::binary);
    if (!output.is_open()) {
        return;
    }
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
#else
    static_cast<void>(target);
    static_cast<void>(bytes);
#endif
}

} // namespace coquic::quic

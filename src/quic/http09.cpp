#include "src/quic/http09.h"

#include <algorithm>
#include <string_view>
#include <utility>

namespace coquic::quic {

namespace {

constexpr CodecErrorCode kHttp09ParseError = CodecErrorCode::http09_parse_error;

CodecResult<QuicHttp09Request> parse_absolute_https_request(std::string_view token) {
    constexpr std::string_view scheme = "https://";
    if (!token.starts_with(scheme)) {
        return CodecResult<QuicHttp09Request>::failure(kHttp09ParseError, 0);
    }

    const std::string_view remainder = token.substr(scheme.size());
    if (remainder.empty()) {
        return CodecResult<QuicHttp09Request>::failure(kHttp09ParseError, 0);
    }

    const std::size_t slash = remainder.find('/');
    const std::string_view authority =
        slash == std::string_view::npos ? remainder : remainder.substr(0, slash);
    if (authority.empty()) {
        return CodecResult<QuicHttp09Request>::failure(kHttp09ParseError, 0);
    }

    std::string_view request_target =
        slash == std::string_view::npos ? std::string_view{"/"} : remainder.substr(slash);

    const auto resolved_target =
        resolve_http09_path_under_root(std::filesystem::path("/"), request_target);
    if (!resolved_target.has_value()) {
        return CodecResult<QuicHttp09Request>::failure(kHttp09ParseError, 0);
    }

    return CodecResult<QuicHttp09Request>::success(QuicHttp09Request{
        .url = std::string(token),
        .authority = std::string(authority),
        .request_target = std::string(request_target),
        .relative_output_path = resolved_target.value().lexically_relative("/"),
    });
}

bool path_has_prefix(const std::filesystem::path &path, const std::filesystem::path &prefix) {
    auto path_it = path.begin();
    auto prefix_it = prefix.begin();
    for (; prefix_it != prefix.end(); ++prefix_it, ++path_it) {
        if (*path_it != *prefix_it) {
            return false;
        }
    }

    return true;
}

bool has_raw_dot_segment(const std::filesystem::path &path) {
    return std::any_of(path.begin(), path.end(), [](const std::filesystem::path &part) {
        return part == "." || part == "..";
    });
}

bool is_invalid_http09_target_char(char ch) {
    const auto value = static_cast<unsigned char>(ch);
    return value <= 0x20u || value == 0x7fu;
}

QuicTransportConfig http09_transport_for_testcase(QuicHttp09Testcase testcase) {
    auto config = QuicTransportConfig{};
    if (testcase == QuicHttp09Testcase::multiconnect) {
        config.max_idle_timeout = 180000;
    }
    return config;
}

} // namespace

CodecResult<std::vector<QuicHttp09Request>>
parse_http09_requests_env(std::string_view requests_env) {
    std::vector<QuicHttp09Request> requests;
    std::string authority;

    std::size_t offset = 0;
    while (offset < requests_env.size()) {
        while (offset < requests_env.size() && requests_env[offset] == ' ') {
            ++offset;
        }
        if (offset >= requests_env.size()) {
            break;
        }

        std::size_t end = offset;
        while (end < requests_env.size() && requests_env[end] != ' ') {
            ++end;
        }

        const auto parsed = parse_absolute_https_request(requests_env.substr(offset, end - offset));
        if (!parsed.has_value()) {
            return CodecResult<std::vector<QuicHttp09Request>>::failure(kHttp09ParseError, offset);
        }

        if (authority.empty()) {
            authority = parsed.value().authority;
        } else if (authority != parsed.value().authority) {
            return CodecResult<std::vector<QuicHttp09Request>>::failure(kHttp09ParseError, offset);
        }

        requests.push_back(parsed.value());
        offset = end;
    }

    if (requests.empty()) {
        return CodecResult<std::vector<QuicHttp09Request>>::failure(kHttp09ParseError, 0);
    }

    return CodecResult<std::vector<QuicHttp09Request>>::success(std::move(requests));
}

CodecResult<std::string> parse_http09_request_target(std::span<const std::byte> bytes) {
    std::string request_bytes;
    request_bytes.reserve(bytes.size());
    for (const auto byte : bytes) {
        request_bytes.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }

    constexpr std::string_view method = "GET ";
    const std::size_t line_end = request_bytes.find('\n');
    if (line_end == std::string::npos) {
        return CodecResult<std::string>::failure(CodecErrorCode::truncated_input, bytes.size());
    }

    std::string_view request_line(request_bytes.data(), line_end);
    if (!request_line.empty() && request_line.back() == '\r') {
        request_line.remove_suffix(1);
    }

    if (!request_line.starts_with(method)) {
        return CodecResult<std::string>::failure(kHttp09ParseError, 0);
    }

    const std::string_view target = request_line.substr(method.size());
    if (target.empty()) {
        return CodecResult<std::string>::failure(kHttp09ParseError, 0);
    }

    if (target.front() != '/' || std::any_of(target.begin(), target.end(), [](char ch) {
            return is_invalid_http09_target_char(ch);
        })) {
        return CodecResult<std::string>::failure(kHttp09ParseError, 0);
    }

    return CodecResult<std::string>::success(std::string(target));
}

CodecResult<std::filesystem::path> resolve_http09_path_under_root(const std::filesystem::path &root,
                                                                  std::string_view request_target) {
    if (request_target.empty() || request_target.front() != '/') {
        return CodecResult<std::filesystem::path>::failure(kHttp09ParseError, 0);
    }
    if (request_target.find('?') != std::string_view::npos ||
        request_target.find('#') != std::string_view::npos) {
        return CodecResult<std::filesystem::path>::failure(kHttp09ParseError, 0);
    }

    const std::filesystem::path normalized_root = root.lexically_normal();
    const std::filesystem::path raw_relative(request_target.substr(1));
    if (raw_relative.is_absolute()) {
        return CodecResult<std::filesystem::path>::failure(kHttp09ParseError, 0);
    }

    if (has_raw_dot_segment(raw_relative)) {
        return CodecResult<std::filesystem::path>::failure(kHttp09ParseError, 0);
    }

    const std::filesystem::path relative = raw_relative.lexically_normal();

    // This is a lexical containment check; it does not resolve symlinks.
    const std::filesystem::path candidate = (normalized_root / relative).lexically_normal();
    if (!path_has_prefix(candidate, normalized_root)) {
        return CodecResult<std::filesystem::path>::failure(kHttp09ParseError, 0);
    }

    return CodecResult<std::filesystem::path>::success(candidate);
}

std::vector<std::byte>
http09_zero_rtt_application_context(std::span<const QuicHttp09Request> requests) {
    if (requests.empty()) {
        return {};
    }

    constexpr std::string_view marker = "http09-get";
    std::vector<std::byte> context;
    context.reserve(marker.size() + 1u + requests.front().authority.size());
    for (const char ch : marker) {
        context.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    context.push_back(std::byte{0x00});
    for (const char ch : requests.front().authority) {
        context.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return context;
}

QuicTransportConfig http09_client_transport_for_testcase(QuicHttp09Testcase testcase) {
    auto config = http09_transport_for_testcase(testcase);
    if (testcase == QuicHttp09Testcase::transfer) {
        config.initial_max_data = 32ull * 1024ull * 1024ull;
        config.initial_max_stream_data_bidi_local = 16ull * 1024ull * 1024ull;
    }
    return config;
}

QuicTransportConfig http09_server_transport_for_testcase(QuicHttp09Testcase testcase) {
    auto config = http09_transport_for_testcase(testcase);
    if (testcase == QuicHttp09Testcase::resumption || testcase == QuicHttp09Testcase::zerortt) {
        // Official resumed interop cases fan out enough request streams that the
        // default limit of 16 forces extra 1-RTT churn after warmup.
        config.initial_max_streams_bidi = 64;
    }
    return config;
}

std::vector<CipherSuite> http09_tls_cipher_suites_for_testcase(QuicHttp09Testcase testcase) {
    if (testcase == QuicHttp09Testcase::chacha20) {
        return {
            CipherSuite::tls_chacha20_poly1305_sha256,
        };
    }

    return {};
}

} // namespace coquic::quic

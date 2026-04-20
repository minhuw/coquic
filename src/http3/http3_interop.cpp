#include "src/http3/http3_interop.h"

#include "src/http3/http3_runtime.h"

#include <charconv>
#include <cctype>
#include <cstdlib>
#include <span>
#include <string_view>
#include <system_error>

namespace coquic::http3 {
namespace {

std::optional<std::string> getenv_string(const char *name) {
    const char *value = std::getenv(name);
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
}

std::optional<std::uint16_t> parse_port(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }

    std::uint32_t parsed = 0;
    const char *begin = value.data();
    const char *end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed == 0 || parsed > 65535u) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

std::vector<std::string> parse_requests(std::string_view requests_env) {
    std::vector<std::string> requests;
    std::size_t index = 0;
    while (index < requests_env.size()) {
        while (index < requests_env.size() &&
               std::isspace(static_cast<unsigned char>(requests_env[index])) != 0) {
            ++index;
        }
        if (index >= requests_env.size()) {
            break;
        }
        std::size_t end = index;
        while (end < requests_env.size() &&
               std::isspace(static_cast<unsigned char>(requests_env[end])) == 0) {
            ++end;
        }
        requests.emplace_back(requests_env.substr(index, end - index));
        index = end;
    }
    return requests;
}

std::optional<std::filesystem::path>
output_path_for_request(const std::filesystem::path &download_root, std::string_view request_url) {
    constexpr std::string_view scheme = "https://";
    if (!request_url.starts_with(scheme)) {
        return std::nullopt;
    }

    const auto path_start = request_url.find('/', scheme.size());
    std::string_view path =
        path_start == std::string_view::npos ? "/" : request_url.substr(path_start);
    const auto query = path.find('?');
    if (query != std::string_view::npos) {
        path = path.substr(0, query);
    }
    const auto fragment = path.find('#');
    if (fragment != std::string_view::npos) {
        path = path.substr(0, fragment);
    }

    const auto filename = std::filesystem::path(path).filename();
    if (filename.empty()) {
        return std::nullopt;
    }
    return download_root / filename;
}

} // namespace

std::optional<Http3InteropConfig> parse_http3_interop_args(int argc, char **argv) {
    if (argc < 2) {
        return std::nullopt;
    }

    Http3InteropConfig config;
    const std::string_view subcommand = argv[1];
    if (subcommand == "h3-interop-server") {
        config.mode = Http3InteropMode::server;
    } else if (subcommand == "h3-interop-client") {
        config.mode = Http3InteropMode::client;
    } else {
        return std::nullopt;
    }

    bool testcase_present = false;
    bool host_present = false;
    bool port_present = false;
    bool document_root_present = false;
    bool certificate_chain_present = false;
    bool private_key_present = false;
    bool requests_present = false;

    if (const auto testcase = getenv_string("TESTCASE"); testcase.has_value()) {
        config.testcase = *testcase;
        testcase_present = true;
    }
    if (const auto host = getenv_string("HOST"); host.has_value()) {
        config.host = *host;
        host_present = true;
    }
    if (const auto port = getenv_string("PORT"); port.has_value()) {
        const auto parsed_port = parse_port(*port);
        if (!parsed_port.has_value()) {
            return std::nullopt;
        }
        config.port = *parsed_port;
        port_present = true;
    }
    if (const auto path = getenv_string("DOCUMENT_ROOT"); path.has_value()) {
        config.document_root = *path;
        document_root_present = true;
    }
    if (const auto path = getenv_string("DOWNLOAD_ROOT"); path.has_value()) {
        config.download_root = *path;
    }
    if (const auto path = getenv_string("CERTIFICATE_CHAIN_PATH"); path.has_value()) {
        config.certificate_chain_path = *path;
        certificate_chain_present = true;
    }
    if (const auto path = getenv_string("PRIVATE_KEY_PATH"); path.has_value()) {
        config.private_key_path = *path;
        private_key_present = true;
    }
    if (const auto server_name = getenv_string("SERVER_NAME"); server_name.has_value()) {
        config.server_name = *server_name;
    }
    if (const auto requests_env = getenv_string("REQUESTS"); requests_env.has_value()) {
        config.requests = parse_requests(*requests_env);
        requests_present = true;
    }

    if (config.mode == Http3InteropMode::server) {
        if (!testcase_present || !host_present || !port_present || !document_root_present ||
            !certificate_chain_present || !private_key_present || config.testcase.empty() ||
            config.host.empty() || config.document_root.empty() ||
            config.certificate_chain_path.empty() || config.private_key_path.empty()) {
            return std::nullopt;
        }
    } else if (!requests_present || config.requests.empty()) {
        return std::nullopt;
    }

    return config;
}

int run_http3_interop(const Http3InteropConfig &config) {
    if (config.testcase != "http3") {
        return 127;
    }

    if (config.mode == Http3InteropMode::server) {
        return run_http3_runtime(Http3RuntimeConfig{
            .mode = Http3RuntimeMode::server,
            .host = config.host,
            .port = config.port,
            .document_root = config.document_root,
            .enable_bootstrap = false,
            .certificate_chain_path = config.certificate_chain_path,
            .private_key_path = config.private_key_path,
        });
    }

    std::vector<Http3RuntimeTransferJob> jobs;
    jobs.reserve(config.requests.size());
    for (const auto &request : config.requests) {
        const auto output_path = output_path_for_request(config.download_root, request);
        if (!output_path.has_value()) {
            return 1;
        }
        jobs.push_back(Http3RuntimeTransferJob{
            .url = request,
            .output_path = *output_path,
        });
    }
    if (jobs.empty()) {
        return 1;
    }

    return run_http3_client_transfers(
        Http3RuntimeConfig{
            .mode = Http3RuntimeMode::client,
            .io_backend = io::QuicIoBackendKind::socket,
            .host = config.host,
            .port = config.port,
            .server_name = config.server_name,
            .verify_peer = false,
        },
        std::span<const Http3RuntimeTransferJob>(jobs));
}

} // namespace coquic::http3

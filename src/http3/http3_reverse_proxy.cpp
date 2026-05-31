#include "src/http3/http3_reverse_proxy.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

namespace coquic::http3 {
namespace {

constexpr std::size_t kProxyResponseLimitBytes = std::size_t{64} * 1024u * 1024u;

struct ScopedFd {
    explicit ScopedFd(int fd) : fd_(fd) {
    }

    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    int get() const {
        return fd_;
    }

    int release() {
        return std::exchange(fd_, -1);
    }

  private:
    int fd_ = -1;
};

struct ParsedHttpResponse {
    std::uint16_t status = 502;
    Http3Headers headers;
    std::vector<std::byte> body;
};

enum class HttpResponseReadState : std::uint8_t {
    incomplete,
    complete,
    invalid,
};

struct HttpResponseFraming {
    bool chunked = false;
    std::optional<std::size_t> content_length;
};

std::string lowercase_ascii(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return out;
}

std::string_view trim_ascii(std::string_view value) {
    std::size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }
    std::size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::optional<std::size_t> parse_size(std::string_view value, int base = 10) {
    std::size_t parsed = 0;
    const auto *begin = value.data();
    const auto *end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed, base);
    if (result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

bool is_hop_by_hop_header(std::string_view name) {
    const auto lower = lowercase_ascii(name);
    return lower == "connection" || lower == "keep-alive" || lower == "proxy-authenticate" ||
           lower == "proxy-authorization" || lower == "te" || lower == "trailer" ||
           lower == "transfer-encoding" || lower == "upgrade";
}

bool is_filtered_request_header(std::string_view name) {
    const auto lower = lowercase_ascii(name);
    return is_hop_by_hop_header(lower) || lower == "host" || lower == "content-length" ||
           lower == "accept-encoding";
}

bool is_filtered_response_header(std::string_view name) {
    const auto lower = lowercase_ascii(name);
    return is_hop_by_hop_header(lower) || lower == "content-length";
}

std::string byte_span_to_string(std::span<const std::byte> bytes) {
    return std::string(reinterpret_cast<const char *>(bytes.data()),
                       reinterpret_cast<const char *>(bytes.data()) + bytes.size());
}

std::vector<std::byte> string_to_bytes(std::string_view text) {
    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(text.data()),
                                  reinterpret_cast<const std::byte *>(text.data()) + text.size());
}

std::string host_header_value(const Http3ReverseProxyConfig &config) {
    return config.host + ":" + std::to_string(config.port);
}

std::string upstream_authority(const Http3ReverseProxyConfig &config,
                               const Http3RequestHead &head) {
    return head.authority.empty() ? host_header_value(config) : head.authority;
}

std::string serialize_proxy_request(const Http3ReverseProxyConfig &config,
                                    const Http3Request &request) {
    std::string out;
    const auto path = request.head.path.empty() ? std::string("/") : request.head.path;
    out += request.head.method.empty() ? "GET" : request.head.method;
    out.push_back(' ');
    out += path;
    out += " HTTP/1.1\r\nHost: ";
    out += upstream_authority(config, request.head);
    out += "\r\nConnection: close\r\nAccept-Encoding: identity\r\nX-Forwarded-Proto: https\r\n";
    out += "X-Forwarded-Host: ";
    out += upstream_authority(config, request.head);
    out += "\r\n";

    for (const auto &header : request.head.headers) {
        if (header.name.empty() || header.name.front() == ':' ||
            is_filtered_request_header(header.name)) {
            continue;
        }
        out += lowercase_ascii(header.name);
        out += ": ";
        out += header.value;
        out += "\r\n";
    }

    if (!request.body.empty() || request.head.content_length.has_value()) {
        out += "Content-Length: ";
        out += std::to_string(request.body.size());
        out += "\r\n";
    }
    out += "\r\n";
    out += byte_span_to_string(request.body);
    return out;
}

std::optional<int> connect_to_upstream(const Http3ReverseProxyConfig &config) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *raw_results = nullptr;
    const auto port = std::to_string(config.port);
    const int lookup = ::getaddrinfo(config.host.c_str(), port.c_str(), &hints, &raw_results);
    if (lookup != 0) {
        return std::nullopt;
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> results(raw_results, &freeaddrinfo);

    for (auto *candidate = results.get(); candidate != nullptr; candidate = candidate->ai_next) {
        const int fd =
            ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (fd < 0) {
            continue;
        }
        ScopedFd guard(fd);
        if (::connect(fd, candidate->ai_addr, candidate->ai_addrlen) != 0) {
            continue;
        }
        return guard.release();
    }
    return std::nullopt;
}

bool write_all(int fd, std::string_view bytes) {
    std::size_t written = 0;
    while (written < bytes.size()) {
        const auto remaining = bytes.size() - written;
        const auto chunk_size = std::min<std::size_t>(
            remaining, static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const auto result = ::send(fd, bytes.data() + written, chunk_size, MSG_NOSIGNAL);
        if (result <= 0) {
            if (result < 0 && errno == EINTR) {
                continue;
            }
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

std::optional<std::string> read_all(int fd) {
    std::string out;
    std::array<char, 8192> buffer{};
    while (out.size() <= kProxyResponseLimitBytes) {
        const auto result = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (result == 0) {
            return out;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::nullopt;
        }
        out.append(buffer.data(), static_cast<std::size_t>(result));
    }
    return std::nullopt;
}

std::optional<std::vector<std::byte>> decode_chunked_body(std::string_view encoded) {
    std::vector<std::byte> out;
    std::size_t offset = 0;
    while (true) {
        const auto line_end = encoded.find("\r\n", offset);
        if (line_end == std::string_view::npos) {
            return std::nullopt;
        }
        auto size_text = encoded.substr(offset, line_end - offset);
        const auto extension = size_text.find(';');
        if (extension != std::string_view::npos) {
            size_text = size_text.substr(0, extension);
        }
        size_text = trim_ascii(size_text);
        const auto chunk_size = parse_size(size_text, 16);
        if (!chunk_size.has_value()) {
            return std::nullopt;
        }
        offset = line_end + 2;
        if (*chunk_size == 0) {
            return out;
        }
        if (*chunk_size > encoded.size() - offset) {
            return std::nullopt;
        }
        const auto chunk = encoded.substr(offset, *chunk_size);
        out.insert(out.end(), reinterpret_cast<const std::byte *>(chunk.data()),
                   reinterpret_cast<const std::byte *>(chunk.data()) + chunk.size());
        offset += *chunk_size;
        if (encoded.substr(offset, 2) != "\r\n") {
            return std::nullopt;
        }
        offset += 2;
    }
}

HttpResponseReadState chunked_body_read_state(std::string_view encoded) {
    std::size_t offset = 0;
    while (true) {
        const auto line_end = encoded.find("\r\n", offset);
        if (line_end == std::string_view::npos) {
            return HttpResponseReadState::incomplete;
        }
        auto size_text = encoded.substr(offset, line_end - offset);
        const auto extension = size_text.find(';');
        if (extension != std::string_view::npos) {
            size_text = size_text.substr(0, extension);
        }
        size_text = trim_ascii(size_text);
        const auto chunk_size = parse_size(size_text, 16);
        if (!chunk_size.has_value()) {
            return HttpResponseReadState::invalid;
        }

        offset = line_end + 2;
        if (*chunk_size == 0) {
            if (encoded.size() < offset + 2) {
                return HttpResponseReadState::incomplete;
            }
            if (encoded.substr(offset, 2) == "\r\n") {
                return HttpResponseReadState::complete;
            }
            return encoded.find("\r\n\r\n", offset) == std::string_view::npos
                       ? HttpResponseReadState::incomplete
                       : HttpResponseReadState::complete;
        }

        if (*chunk_size > encoded.size() - offset) {
            return HttpResponseReadState::incomplete;
        }
        offset += *chunk_size;
        if (encoded.size() < offset + 2) {
            return HttpResponseReadState::incomplete;
        }
        if (encoded.substr(offset, 2) != "\r\n") {
            return HttpResponseReadState::invalid;
        }
        offset += 2;
    }
}

std::optional<HttpResponseFraming> response_framing(std::string_view headers_text) {
    HttpResponseFraming framing;
    const auto status_line_end = headers_text.find("\r\n");
    std::size_t line_begin =
        status_line_end == std::string_view::npos ? headers_text.size() : status_line_end + 2;
    while (line_begin < headers_text.size()) {
        const auto line_end = headers_text.find("\r\n", line_begin);
        const auto line = line_end == std::string_view::npos
                              ? headers_text.substr(line_begin)
                              : headers_text.substr(line_begin, line_end - line_begin);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos && colon != 0) {
            const auto name = lowercase_ascii(trim_ascii(line.substr(0, colon)));
            const auto value = trim_ascii(line.substr(colon + 1));
            if (name == "transfer-encoding" &&
                lowercase_ascii(value).find("chunked") != std::string::npos) {
                framing.chunked = true;
            } else if (name == "content-length") {
                const auto length = parse_size(value);
                if (!length.has_value()) {
                    return std::nullopt;
                }
                framing.content_length = length;
            }
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        line_begin = line_end + 2;
    }
    return framing;
}

HttpResponseReadState response_read_state(std::string_view response_text) {
    const auto header_end = response_text.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return HttpResponseReadState::incomplete;
    }

    const auto headers_text = response_text.substr(0, header_end);
    const auto body_text = response_text.substr(header_end + 4);
    const auto framing = response_framing(headers_text);
    if (!framing.has_value()) {
        return HttpResponseReadState::invalid;
    }
    if (framing->chunked) {
        return chunked_body_read_state(body_text);
    }
    if (framing->content_length.has_value()) {
        return body_text.size() >= *framing->content_length ? HttpResponseReadState::complete
                                                            : HttpResponseReadState::incomplete;
    }
    return HttpResponseReadState::incomplete;
}

std::optional<ParsedHttpResponse> parse_http_response(std::string_view response_text) {
    const auto header_end = response_text.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return std::nullopt;
    }

    const auto headers_text = response_text.substr(0, header_end);
    const auto body_text = response_text.substr(header_end + 4);
    const auto status_line_end = headers_text.find("\r\n");
    const auto status_line = status_line_end == std::string_view::npos
                                 ? headers_text
                                 : headers_text.substr(0, status_line_end);
    if (!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 ")) {
        return std::nullopt;
    }
    if (status_line.size() < 12) {
        return std::nullopt;
    }
    const auto status = parse_size(status_line.substr(9, 3));
    if (!status.has_value() || *status > std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }

    ParsedHttpResponse parsed{
        .status = static_cast<std::uint16_t>(*status),
    };
    bool chunked = false;
    std::optional<std::size_t> content_length;

    std::size_t line_begin =
        status_line_end == std::string_view::npos ? headers_text.size() : status_line_end + 2;
    while (line_begin < headers_text.size()) {
        const auto line_end = headers_text.find("\r\n", line_begin);
        const auto line = line_end == std::string_view::npos
                              ? headers_text.substr(line_begin)
                              : headers_text.substr(line_begin, line_end - line_begin);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos && colon != 0) {
            const auto name = lowercase_ascii(trim_ascii(line.substr(0, colon)));
            const auto value = trim_ascii(line.substr(colon + 1));
            if (name == "transfer-encoding" &&
                lowercase_ascii(value).find("chunked") != std::string::npos) {
                chunked = true;
            } else if (name == "content-length") {
                content_length = parse_size(value);
                if (!content_length.has_value()) {
                    return std::nullopt;
                }
            }
            if (!is_filtered_response_header(name)) {
                parsed.headers.push_back(Http3Field{
                    .name = name,
                    .value = std::string(value),
                });
            }
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        line_begin = line_end + 2;
    }

    if (chunked) {
        auto decoded = decode_chunked_body(body_text);
        if (!decoded.has_value()) {
            return std::nullopt;
        }
        parsed.body = std::move(*decoded);
    } else if (content_length.has_value()) {
        if (body_text.size() < *content_length) {
            return std::nullopt;
        }
        parsed.body = string_to_bytes(body_text.substr(0, *content_length));
    } else {
        parsed.body = string_to_bytes(body_text);
    }
    return parsed;
}

Http3Response bad_gateway_response() {
    return Http3Response{
        .head =
            {
                .status = 502,
                .content_length = 0,
                .headers = {{"cache-control", "no-store"}},
            },
    };
}

} // namespace

std::optional<Http3ReverseProxyConfig> parse_http_reverse_proxy_target(std::string_view target) {
    constexpr std::string_view scheme = "http://";
    if (!target.starts_with(scheme)) {
        return std::nullopt;
    }
    target.remove_prefix(scheme.size());
    if (target.empty() || target.find('/') != std::string_view::npos) {
        return std::nullopt;
    }

    const auto colon = target.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == target.size()) {
        return std::nullopt;
    }
    auto port = parse_size(target.substr(colon + 1));
    if (!port.has_value() || *port == 0 || *port > 65535u) {
        return std::nullopt;
    }

    return Http3ReverseProxyConfig{
        .host = std::string(target.substr(0, colon)),
        .port = static_cast<std::uint16_t>(*port),
    };
}

Http3Response fetch_http_reverse_proxy_response(const Http3ReverseProxyConfig &config,
                                                const Http3Request &request) {
    const auto fd = connect_to_upstream(config);
    if (!fd.has_value()) {
        return bad_gateway_response();
    }
    ScopedFd upstream(*fd);

    const auto proxy_request = serialize_proxy_request(config, request);
    if (!write_all(upstream.get(), proxy_request)) {
        return bad_gateway_response();
    }
    std::string response_text;
    std::array<char, 8192> buffer{};
    while (response_text.size() <= kProxyResponseLimitBytes) {
        const auto state = response_read_state(response_text);
        if (state == HttpResponseReadState::complete) {
            break;
        }
        if (state == HttpResponseReadState::invalid) {
            return bad_gateway_response();
        }

        const auto result = ::recv(upstream.get(), buffer.data(), buffer.size(), 0);
        if (result == 0) {
            break;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return bad_gateway_response();
        }
        response_text.append(buffer.data(), static_cast<std::size_t>(result));
    }
    if (response_text.size() > kProxyResponseLimitBytes) {
        return bad_gateway_response();
    }
    auto parsed = parse_http_response(response_text);
    if (!parsed.has_value()) {
        return bad_gateway_response();
    }

    return Http3Response{
        .head =
            {
                .status = parsed->status,
                .content_length = parsed->body.size(),
                .headers = std::move(parsed->headers),
            },
        .body = std::move(parsed->body),
    };
}

} // namespace coquic::http3

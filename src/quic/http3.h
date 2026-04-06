#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/core.h"

namespace coquic::quic {

inline constexpr const char *kHttp3ApplicationProtocol = "h3";

enum class Http3ErrorCode : std::uint64_t {
    no_error = 0x100,
    general_protocol_error = 0x101,
    internal_error = 0x102,
    stream_creation_error = 0x103,
    closed_critical_stream = 0x104,
    frame_unexpected = 0x105,
    frame_error = 0x106,
    excessive_load = 0x107,
    id_error = 0x108,
    settings_error = 0x109,
    missing_settings = 0x10a,
    request_rejected = 0x10b,
    request_cancelled = 0x10c,
    request_incomplete = 0x10d,
    message_error = 0x10e,
    connect_error = 0x10f,
    version_fallback = 0x110,
    qpack_decompression_failed = 0x200,
    qpack_encoder_stream_error = 0x201,
    qpack_decoder_stream_error = 0x202,
};

struct Http3Error {
    Http3ErrorCode code = Http3ErrorCode::internal_error;
    std::string reason;
};

template <typename T> struct Http3Result {
    std::variant<T, Http3Error> storage;

    bool has_value() const {
        return std::holds_alternative<T>(storage);
    }

    T &value() {
        return std::get<T>(storage);
    }

    const T &value() const {
        return std::get<T>(storage);
    }

    Http3Error &error() {
        return std::get<Http3Error>(storage);
    }

    const Http3Error &error() const {
        return std::get<Http3Error>(storage);
    }

    static Http3Result success(T value) {
        return Http3Result{
            .storage = std::move(value),
        };
    }

    static Http3Result failure(Http3ErrorCode code, std::string reason) {
        return Http3Result{
            .storage =
                Http3Error{
                    .code = code,
                    .reason = std::move(reason),
                },
        };
    }
};

struct Http3Field {
    std::string name;
    std::string value;

    bool operator==(const Http3Field &) const = default;
};

using Http3Headers = std::vector<Http3Field>;

struct Http3RequestHead {
    std::string method;
    std::string scheme;
    std::string authority;
    std::string path;
    Http3Headers headers;
};

struct Http3ResponseHead {
    std::uint16_t status = 0;
    Http3Headers headers;
};

struct Http3EndpointUpdate {
    std::vector<QuicCoreInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
};

} // namespace coquic::quic

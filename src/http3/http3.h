#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/core.h"

namespace coquic::http3 {

inline constexpr std::string_view kHttp3ApplicationProtocol = "h3";

enum class Http3ErrorCode : std::uint16_t {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    version_fallback = 0x0110,
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
};

struct Http3Error {
    Http3ErrorCode code = Http3ErrorCode::general_protocol_error;
    std::string detail;
    std::optional<std::uint64_t> stream_id;
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

    static Http3Result failure(const Http3Error &error) {
        return Http3Result{
            .storage = error,
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
    std::uint16_t status = 200;
    Http3Headers headers;
};

struct Http3EndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
};

} // namespace coquic::http3

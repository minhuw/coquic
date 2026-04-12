#pragma once

#include <cstddef>
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

enum class Http3ConnectionRole : std::uint8_t {
    client,
    server,
};

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
    std::optional<std::uint64_t> content_length;
    Http3Headers headers;
};

struct Http3ResponseHead {
    std::uint16_t status = 200;
    std::optional<std::uint64_t> content_length;
    Http3Headers headers;
};

struct Http3Request {
    Http3RequestHead head;
    std::vector<std::byte> body;
    Http3Headers trailers;
};

struct Http3Response {
    std::vector<Http3ResponseHead> interim_heads;
    Http3ResponseHead head;
    std::vector<std::byte> body;
    Http3Headers trailers;
};

struct Http3PeerRequestHeadEvent {
    std::uint64_t stream_id = 0;
    Http3RequestHead head;
};

struct Http3PeerRequestBodyEvent {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> body;
};

struct Http3PeerRequestTrailersEvent {
    std::uint64_t stream_id = 0;
    Http3Headers trailers;
};

struct Http3PeerRequestCompleteEvent {
    std::uint64_t stream_id = 0;
};

using Http3EndpointEvent =
    std::variant<Http3PeerRequestHeadEvent, Http3PeerRequestBodyEvent,
                 Http3PeerRequestTrailersEvent, Http3PeerRequestCompleteEvent>;

struct Http3SettingsSnapshot {
    std::uint64_t qpack_max_table_capacity = 4096;
    std::uint64_t qpack_blocked_streams = 16;
    std::optional<std::uint64_t> max_field_section_size = 64 * 1024;
};

struct Http3EndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3EndpointEvent> events;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
};

} // namespace coquic::http3

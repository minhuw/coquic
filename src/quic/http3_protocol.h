#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/http3.h"
#include "src/quic/varint.h"

namespace coquic::quic {

enum class Http3UniStreamType : std::uint64_t {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
};

inline constexpr std::uint64_t kHttp3FrameData = 0x00;
inline constexpr std::uint64_t kHttp3FrameHeaders = 0x01;
inline constexpr std::uint64_t kHttp3FrameSettings = 0x04;
inline constexpr std::uint64_t kHttp3FrameGoaway = 0x07;

inline constexpr std::uint64_t kHttp3SettingQpackMaxTableCapacity = 0x01;
inline constexpr std::uint64_t kHttp3SettingMaxFieldSectionSize = 0x06;
inline constexpr std::uint64_t kHttp3SettingQpackBlockedStreams = 0x07;

struct Http3Setting {
    std::uint64_t id = 0;
    std::uint64_t value = 0;

    bool operator==(const Http3Setting &) const = default;
};

struct Http3DataFrame {
    std::vector<std::byte> payload;

    bool operator==(const Http3DataFrame &) const = default;
};

struct Http3HeadersFrame {
    std::vector<std::byte> payload;

    bool operator==(const Http3HeadersFrame &) const = default;
};

struct Http3SettingsFrame {
    std::vector<Http3Setting> settings;

    bool operator==(const Http3SettingsFrame &) const = default;
};

struct Http3GoawayFrame {
    std::uint64_t id = 0;

    bool operator==(const Http3GoawayFrame &) const = default;
};

using Http3Frame =
    std::variant<Http3DataFrame, Http3HeadersFrame, Http3SettingsFrame, Http3GoawayFrame>;

struct Http3DecodedFrame {
    Http3Frame frame;
    std::size_t bytes_consumed = 0;
};

struct Http3ConnectionState {
    bool local_settings_sent = false;
    bool peer_settings_received = false;
    bool local_goaway_sent = false;
    bool peer_goaway_received = false;
};

Http3Result<std::vector<std::byte>> serialize_http3_frame(const Http3Frame &frame);

Http3Result<Http3DecodedFrame> parse_http3_frame(std::span<const std::byte> bytes);

Http3Result<Http3UniStreamType> parse_http3_uni_stream_type(std::span<const std::byte> bytes,
                                                            std::size_t &bytes_consumed);

Http3Result<std::vector<std::byte>> serialize_http3_uni_stream_prefix(Http3UniStreamType type);

Http3Result<std::vector<std::byte>>
serialize_http3_control_stream(const Http3SettingsFrame &settings,
                               const std::optional<Http3GoawayFrame> &goaway = std::nullopt);

Http3Result<Http3SettingsFrame> validate_http3_settings_frame(const Http3SettingsFrame &settings);

Http3Result<Http3RequestHead> validate_http3_request_headers(const Http3Headers &headers);
Http3Result<Http3ResponseHead> validate_http3_response_headers(const Http3Headers &headers);
Http3Result<Http3Headers> validate_http3_trailers(const Http3Headers &headers);

bool http3_frame_allowed_on_control_stream(const Http3Frame &frame);
bool http3_frame_allowed_on_request_stream(const Http3Frame &frame);

} // namespace coquic::quic

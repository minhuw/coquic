#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "src/http3/http3.h"
#include "src/quic/varint.h"

namespace coquic::http3 {

enum class Http3UniStreamType : std::uint8_t {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
};

inline constexpr std::uint64_t kHttp3FrameTypeData = 0x00;
inline constexpr std::uint64_t kHttp3FrameTypeHeaders = 0x01;
inline constexpr std::uint64_t kHttp3FrameTypeCancelPush = 0x03;
inline constexpr std::uint64_t kHttp3FrameTypeSettings = 0x04;
inline constexpr std::uint64_t kHttp3FrameTypeGoaway = 0x07;
inline constexpr std::uint64_t kHttp3FrameTypeMaxPushId = 0x0d;

inline constexpr std::uint64_t kHttp3SettingsQpackMaxTableCapacity = 0x01;
inline constexpr std::uint64_t kHttp3SettingsMaxFieldSectionSize = 0x06;
inline constexpr std::uint64_t kHttp3SettingsQpackBlockedStreams = 0x07;

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
    std::vector<std::byte> field_section;

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

struct Http3MaxPushIdFrame {
    std::uint64_t push_id = 0;

    bool operator==(const Http3MaxPushIdFrame &) const = default;
};

using Http3Frame = std::variant<Http3DataFrame, Http3HeadersFrame, Http3SettingsFrame,
                                Http3GoawayFrame, Http3MaxPushIdFrame>;

struct Http3DecodedFrame {
    Http3Frame frame;
    std::size_t bytes_consumed = 0;
};

struct Http3ConnectionState {
    std::optional<std::uint64_t> local_control_stream_id;
    std::optional<std::uint64_t> local_qpack_encoder_stream_id;
    std::optional<std::uint64_t> local_qpack_decoder_stream_id;
    std::optional<std::uint64_t> remote_control_stream_id;
    std::optional<std::uint64_t> remote_qpack_encoder_stream_id;
    std::optional<std::uint64_t> remote_qpack_decoder_stream_id;
    bool local_settings_sent = false;
    bool remote_settings_received = false;
    std::optional<std::uint64_t> goaway_id;
};

quic::CodecResult<std::vector<std::byte>> serialize_http3_frame(const Http3Frame &frame);
quic::CodecResult<Http3DecodedFrame> parse_http3_frame(std::span<const std::byte> bytes);
quic::CodecResult<quic::VarIntDecoded>
parse_http3_uni_stream_type(std::span<const std::byte> bytes);
quic::CodecResult<std::vector<std::byte>>
serialize_http3_uni_stream_prefix(Http3UniStreamType type);
quic::CodecResult<std::vector<std::byte>>
serialize_http3_control_stream(std::span<const Http3Setting> settings);

Http3Result<bool> validate_http3_settings_frame(const Http3SettingsFrame &frame);
Http3Result<bool> validate_http3_goaway_id(Http3ConnectionRole role, std::uint64_t id);
Http3Result<Http3RequestHead> validate_http3_request_headers(std::span<const Http3Field> fields);
Http3Result<Http3ResponseHead> validate_http3_response_headers(std::span<const Http3Field> fields);
Http3Result<Http3Headers> validate_http3_trailers(std::span<const Http3Field> fields);

bool http3_frame_allowed_on_control_stream(const Http3Frame &frame);
bool http3_frame_allowed_on_request_stream(const Http3Frame &frame);

} // namespace coquic::http3

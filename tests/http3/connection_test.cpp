#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "src/http3/http3_connection.h"

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

void append_ascii_bytes(std::vector<std::byte> &bytes, std::string_view text) {
    bytes.insert(bytes.end(), reinterpret_cast<const std::byte *>(text.data()),
                 reinterpret_cast<const std::byte *>(text.data()) + text.size());
}

std::vector<std::byte> bytes_from_text(std::string_view text) {
    std::vector<std::byte> bytes;
    append_ascii_bytes(bytes, text);
    return bytes;
}

coquic::quic::QuicCoreResult handshake_ready_result() {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreStateEvent{
            .change = coquic::quic::QuicCoreStateChange::handshake_ready,
        },
    });
    return result;
}

coquic::quic::QuicCoreResult receive_result(std::uint64_t stream_id,
                                            std::span<const std::byte> bytes, bool fin = false) {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreReceiveStreamData{
            .stream_id = stream_id,
            .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
            .fin = fin,
        },
    });
    return result;
}

coquic::quic::QuicCoreResult reset_result(std::uint64_t stream_id, std::uint64_t error_code = 0) {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCorePeerResetStream{
            .stream_id = stream_id,
            .application_error_code = error_code,
        },
    });
    return result;
}

std::vector<coquic::quic::QuicCoreSendStreamData>
send_stream_inputs_from(const coquic::http3::Http3EndpointUpdate &update) {
    std::vector<coquic::quic::QuicCoreSendStreamData> sends;
    for (const auto &input : update.core_inputs) {
        if (const auto *send = std::get_if<coquic::quic::QuicCoreSendStreamData>(&input)) {
            sends.push_back(*send);
        }
    }
    return sends;
}

std::optional<coquic::quic::QuicCoreCloseConnection>
close_input_from(const coquic::http3::Http3EndpointUpdate &update) {
    for (const auto &input : update.core_inputs) {
        if (const auto *close = std::get_if<coquic::quic::QuicCoreCloseConnection>(&input)) {
            return *close;
        }
    }
    return std::nullopt;
}

std::uint64_t
close_application_error_code(const std::optional<coquic::quic::QuicCoreCloseConnection> &close) {
    EXPECT_TRUE(close.has_value());
    return close.has_value() ? close->application_error_code : 0u;
}

std::vector<coquic::quic::QuicCoreResetStream>
reset_stream_inputs_from(const coquic::http3::Http3EndpointUpdate &update) {
    std::vector<coquic::quic::QuicCoreResetStream> resets;
    for (const auto &input : update.core_inputs) {
        if (const auto *reset = std::get_if<coquic::quic::QuicCoreResetStream>(&input)) {
            resets.push_back(*reset);
        }
    }
    return resets;
}

std::vector<coquic::quic::QuicCoreStopSending>
stop_sending_inputs_from(const coquic::http3::Http3EndpointUpdate &update) {
    std::vector<coquic::quic::QuicCoreStopSending> stops;
    for (const auto &input : update.core_inputs) {
        if (const auto *stop = std::get_if<coquic::quic::QuicCoreStopSending>(&input)) {
            stops.push_back(*stop);
        }
    }
    return stops;
}

std::vector<coquic::http3::Http3Setting>
settings_from_snapshot(const coquic::http3::Http3SettingsSnapshot &settings) {
    std::vector<coquic::http3::Http3Setting> values = {
        {
            .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
            .value = settings.qpack_max_table_capacity,
        },
    };
    if (settings.max_field_section_size.has_value()) {
        values.push_back(coquic::http3::Http3Setting{
            .id = coquic::http3::kHttp3SettingsMaxFieldSectionSize,
            .value = *settings.max_field_section_size,
        });
    }
    values.push_back(coquic::http3::Http3Setting{
        .id = coquic::http3::kHttp3SettingsQpackBlockedStreams,
        .value = settings.qpack_blocked_streams,
    });
    return values;
}

std::vector<std::byte> control_stream_bytes(const coquic::http3::Http3SettingsSnapshot &settings) {
    const auto bytes =
        coquic::http3::serialize_http3_control_stream(settings_from_snapshot(settings));
    EXPECT_TRUE(bytes.has_value());
    return bytes.has_value() ? bytes.value() : std::vector<std::byte>{};
}

std::vector<std::byte> settings_stream_bytes(const coquic::http3::Http3SettingsSnapshot &settings) {
    auto bytes = bytes_from_ints({0x00});
    const auto settings_frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3SettingsFrame{
            .settings = settings_from_snapshot(settings),
        },
    });
    EXPECT_TRUE(settings_frame.has_value());
    if (settings_frame.has_value()) {
        bytes.insert(bytes.end(), settings_frame.value().begin(), settings_frame.value().end());
    }
    return bytes;
}

std::vector<std::byte>
settings_frame_bytes(std::initializer_list<coquic::http3::Http3Setting> settings) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3SettingsFrame{
            .settings = std::vector<coquic::http3::Http3Setting>(settings),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte>
settings_stream_bytes(std::initializer_list<coquic::http3::Http3Setting> settings) {
    auto bytes = bytes_from_ints({0x00});
    const auto frame = settings_frame_bytes(settings);
    bytes.insert(bytes.end(), frame.begin(), frame.end());
    return bytes;
}

std::vector<std::byte> goaway_stream_bytes(std::uint64_t id) {
    auto bytes = bytes_from_ints({0x00});
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3GoawayFrame{
            .id = id,
        },
    });
    EXPECT_TRUE(frame.has_value());
    if (frame.has_value()) {
        bytes.insert(bytes.end(), frame.value().begin(), frame.value().end());
    }
    return bytes;
}

std::vector<std::byte> goaway_frame_bytes(std::uint64_t id) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3GoawayFrame{
            .id = id,
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte> encoder_stream_bytes(std::initializer_list<std::uint8_t> values) {
    auto bytes = bytes_from_ints({0x02});
    const auto payload = bytes_from_ints(values);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::byte> encoder_stream_bytes(std::span<const std::byte> payload) {
    auto bytes = bytes_from_ints({0x02});
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::byte> decoder_stream_bytes(std::initializer_list<std::uint8_t> values) {
    auto bytes = bytes_from_ints({0x03});
    const auto payload = bytes_from_ints(values);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::byte> headers_frame_bytes(coquic::http3::Http3QpackEncoderContext &encoder,
                                           std::uint64_t stream_id,
                                           std::span<const coquic::http3::Http3Field> fields,
                                           std::vector<std::byte> *encoder_instructions = nullptr) {
    const auto encoded = coquic::http3::encode_http3_field_section(encoder, stream_id, fields);
    EXPECT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return {};
    }

    if (encoder_instructions != nullptr) {
        *encoder_instructions = encoded.value().encoder_instructions;
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte> headers_frame_bytes(std::uint64_t stream_id,
                                           std::span<const coquic::http3::Http3Field> fields) {
    coquic::http3::Http3QpackEncoderContext encoder;
    return headers_frame_bytes(encoder, stream_id, fields);
}

std::vector<std::byte> data_frame_bytes(std::string_view payload_text) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3DataFrame{
            .payload = bytes_from_text(payload_text),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<coquic::http3::Http3Field>
response_fields(std::uint16_t status, std::span<const coquic::http3::Http3Field> headers,
                std::optional<std::uint64_t> content_length = std::nullopt) {
    std::vector<coquic::http3::Http3Field> fields;
    fields.reserve(headers.size() + 2u);
    fields.push_back(coquic::http3::Http3Field{
        .name = ":status",
        .value = std::to_string(status),
    });
    if (content_length.has_value()) {
        fields.push_back(coquic::http3::Http3Field{
            .name = "content-length",
            .value = std::to_string(*content_length),
        });
    }
    fields.insert(fields.end(), headers.begin(), headers.end());
    return fields;
}

void prime_server_transport(coquic::http3::Http3Connection &connection) {
    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(startup).has_value());
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);
}

void prime_client_transport(coquic::http3::Http3Connection &connection) {
    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(startup).has_value());
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);
}

void receive_completed_get_request(coquic::http3::Http3Connection &connection,
                                   std::uint64_t stream_id) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };

    const auto update = connection.on_core_result(
        receive_result(stream_id, headers_frame_bytes(stream_id, request_fields), true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[1]),
              nullptr);
}

void receive_peer_settings(coquic::http3::Http3Connection &connection,
                           const coquic::http3::Http3SettingsSnapshot &settings) {
    const auto update = connection.on_core_result(
        receive_result(2, settings_stream_bytes(settings)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
}

} // namespace

namespace coquic::http3 {

struct Http3ConnectionPeerUniStreamAccess {
    static std::size_t size(const Http3Connection &connection) {
        return connection.peer_uni_streams_.size();
    }
};

struct Http3ConnectionPeerRequestStreamAccess {
    static std::size_t size(const Http3Connection &connection) {
        return connection.peer_request_streams_.size();
    }
};

} // namespace coquic::http3

namespace {

TEST(QuicHttp3ConnectionTest, HandshakeReadyCreatesMandatoryStreamsForClientRole) {
    const coquic::http3::Http3SettingsSnapshot settings{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 3,
        .max_field_section_size = 1024,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = settings,
    });

    const auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[0].bytes, control_stream_bytes(settings));
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 6u);
    EXPECT_EQ(sends[1].bytes, bytes_from_ints({0x02}));
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].stream_id, 10u);
    EXPECT_EQ(sends[2].bytes, bytes_from_ints({0x03}));
    EXPECT_FALSE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, HandshakeReadyCreatesMandatoryStreamsForServerRole) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 3u);
    EXPECT_EQ(sends[1].stream_id, 7u);
    EXPECT_EQ(sends[2].stream_id, 11u);
}

TEST(QuicHttp3ConnectionTest, RejectsPeerControlStreamWithoutInitialSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(3, goaway_stream_bytes(0)),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
}

TEST(QuicHttp3ConnectionTest, UnknownFirstPeerControlFrameMapsToMissingSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(
        receive_result(3, bytes_from_ints({0x00, 0x21, 0x00})), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
}

TEST(QuicHttp3ConnectionTest, PeerControlStreamFinBeforeSettingsMapsToMissingSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(3, bytes_from_ints({0x00}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
}

TEST(QuicHttp3ConnectionTest, RejectsSecondPeerControlStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(receive_result(15, bytes_from_ints({0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, ReservedPeerControlFrameMapsToFrameUnexpected) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto update = connection.on_core_result(receive_result(3, bytes_from_ints({0x02, 0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownPeerControlFramesAfterSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto update = connection.on_core_result(receive_result(3, bytes_from_ints({0x21, 0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, RejectsSecondPeerQpackEncoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(receive_result(7, bytes_from_ints({0x02})),
                                                 coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(receive_result(15, bytes_from_ints({0x02})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, RejectsSecondPeerQpackDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(receive_result(11, bytes_from_ints({0x03})),
                                                 coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(receive_result(15, bytes_from_ints({0x03})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, RejectsCriticalStreamClosure) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update =
        connection.on_core_result(reset_result(3), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, RejectsQpackCriticalStreamClosure) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(receive_result(7, bytes_from_ints({0x02})),
                                                      coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update =
        connection.on_core_result(reset_result(7), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerQpackCriticalStreamFinClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(7, bytes_from_ints({0x02}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownPeerUnidirectionalStreamTypes) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update =
        connection.on_core_result(receive_result(15, bytes_from_ints({0x21, 0x01, 0x02}), true),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, CleansUpIgnoredPeerUnidirectionalStreamStateOnFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update =
        connection.on_core_result(receive_result(15, bytes_from_ints({0x21, 0x01, 0x02}), true),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerUniStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, CleansUpPartialPeerUnidirectionalStreamTypeStateOnFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(15, bytes_from_ints({0x40}), true),
                                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerUniStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, RejectsDuplicateSettingsFrameOnPeerControlStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(
        receive_result(3, settings_frame_bytes({
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 0,
                              },
                          })),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, InvalidPeerSettingsMapToSettingsError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(3, settings_stream_bytes({
                                                                        coquic::http3::Http3Setting{
                                                                            .id = 0x02,
                                                                            .value = 0,
                                                                        },
                                                                    })),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::settings_error));
}

TEST(QuicHttp3ConnectionTest, AppliesPeerSettingsAndEmitsQpackDecoderFeedback) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 4096,
    };
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 512,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });

    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(peer_settings)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());
    EXPECT_TRUE(connection.peer_settings_received());
    EXPECT_EQ(connection.peer_settings().qpack_max_table_capacity,
              peer_settings.qpack_max_table_capacity);
    EXPECT_EQ(connection.peer_settings().qpack_blocked_streams,
              peer_settings.qpack_blocked_streams);
    EXPECT_EQ(connection.peer_settings().max_field_section_size,
              peer_settings.max_field_section_size);

    const auto qpack_update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes({
                              0x3f, 0xbd, 0x01, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f,
                              0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73,
                              0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
                          })),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(qpack_update).has_value());

    const auto sends = send_stream_inputs_from(qpack_update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 10u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x01}));
    EXPECT_FALSE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, RejectsIncreasingPeerGoawayIdentifier) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto first_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(8)),
                                                        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_goaway).has_value());

    const auto second_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(12)),
                                                         coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second_goaway);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
}

TEST(QuicHttp3ConnectionTest, BuffersFragmentedPeerQpackEncoderInstructions) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 4096,
    };
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 512,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });

    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(peer_settings)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto encoder_bytes = encoder_stream_bytes({
        0x3f, 0xbd, 0x01, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
    });
    const auto first_fragment = connection.on_core_result(
        receive_result(7, std::span<const std::byte>(encoder_bytes).first(8)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_TRUE(send_stream_inputs_from(first_fragment).empty());

    const auto second_fragment = connection.on_core_result(
        receive_result(7, std::span<const std::byte>(encoder_bytes).subspan(8)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_fragment).has_value());

    const auto sends = send_stream_inputs_from(second_fragment);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 10u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x01}));
    EXPECT_FALSE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, DecoderStreamInstructionsWireIntoEncoderContext) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(11, decoder_stream_bytes({0x01})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decoder_stream_error));
}

TEST(QuicHttp3ConnectionTest, BuffersFragmentedPeerQpackDecoderInstructions) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto decoder_bytes = decoder_stream_bytes({0x7f, 0x01});
    const auto first_fragment = connection.on_core_result(
        receive_result(11, std::span<const std::byte>(decoder_bytes).first(2)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_TRUE(first_fragment.core_inputs.empty());

    const auto second_fragment = connection.on_core_result(
        receive_result(11, std::span<const std::byte>(decoder_bytes).subspan(2)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_fragment).has_value());
    EXPECT_TRUE(second_fragment.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestHeadersEmitPeerRequestHeadEvent) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/hello"},
        coquic::http3::Http3Field{"content-length", "0"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 1u);
    const auto *head = std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(head->stream_id, 0u);
    EXPECT_EQ(head->head.method, "GET");
    EXPECT_EQ(head->head.scheme, "https");
    EXPECT_EQ(head->head.authority, "example.test");
    EXPECT_EQ(head->head.path, "/hello");
    EXPECT_EQ(head->head.content_length, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, DataBeforeHeadersClosesConnectionWithFrameUnexpected) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = connection.on_core_result(receive_result(0, data_frame_bytes("body")),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, RequestTrailersEmitEventsAndCompleteOnFin) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto data = data_frame_bytes("ping");
    bytes.insert(bytes.end(), data.begin(), data.end());
    const auto trailers = headers_frame_bytes(0, trailer_fields);
    bytes.insert(bytes.end(), trailers.begin(), trailers.end());

    const auto update = connection.on_core_result(receive_result(0, bytes, true),
                                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 4u);

    const auto *head = std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(head->head.method, "POST");
    EXPECT_EQ(head->head.path, "/upload");
    EXPECT_EQ(head->head.content_length, std::optional<std::uint64_t>(4u));

    const auto *body = std::get_if<coquic::http3::Http3PeerRequestBodyEvent>(&update.events[1]);
    ASSERT_NE(body, nullptr);
    EXPECT_EQ(body->stream_id, 0u);
    EXPECT_EQ(body->body, bytes_from_text("ping"));

    const auto *trailers_event =
        std::get_if<coquic::http3::Http3PeerRequestTrailersEvent>(&update.events[2]);
    ASSERT_NE(trailers_event, nullptr);
    EXPECT_EQ(trailers_event->stream_id, 0u);
    EXPECT_EQ(trailers_event->trailers, (coquic::http3::Http3Headers{{"etag", "done"}}));

    const auto *complete =
        std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[3]);
    ASSERT_NE(complete, nullptr);
    EXPECT_EQ(complete->stream_id, 0u);
}

TEST(QuicHttp3ConnectionTest, DataAfterTrailingHeadersClosesConnectionWithFrameUnexpected) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto trailers = headers_frame_bytes(0, trailer_fields);
    bytes.insert(bytes.end(), trailers.begin(), trailers.end());
    const auto late_data = data_frame_bytes("late");
    bytes.insert(bytes.end(), late_data.begin(), late_data.end());

    const auto update =
        connection.on_core_result(receive_result(0, bytes), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, MalformedRequestHeadersResetRequestStreamWithMessageError) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "abc"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    const auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    const auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ContentLengthMismatchResetsRequestStreamWithMessageError) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(headers_update).has_value());
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    const auto body_update = connection.on_core_result(
        receive_result(0, data_frame_bytes("abc"), true), coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(body_update).has_value());
    ASSERT_EQ(body_update.events.size(), 1u);
    const auto *body =
        std::get_if<coquic::http3::Http3PeerRequestBodyEvent>(&body_update.events[0]);
    ASSERT_NE(body, nullptr);
    EXPECT_EQ(body->body, bytes_from_text("abc"));

    const auto resets = reset_stream_inputs_from(body_update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    const auto stops = stop_sending_inputs_from(body_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, BlockedRequestHeadersEmitEventOnlyAfterQpackUnblocks) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "www.example.com"},
        coquic::http3::Http3Field{":path", "/sample/path"},
    };
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
        .local_settings = local_settings,
    });
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = 220,
                .blocked_streams = 1,
            },
    };

    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_fields, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 1u);
    const auto *head =
        std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&unblocked_update.events[0]);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(head->stream_id, 0u);
    EXPECT_EQ(head->head.authority, "www.example.com");
    EXPECT_EQ(head->head.path, "/sample/path");
}

TEST(QuicHttp3ConnectionTest, CompletedRequestStreamsAreCleanedUp) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[1]),
              nullptr);
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerRequestStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, ServerQueuesHeadersOnlyFinalResponseWithFin) {
    const std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 204,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    const auto finish = connection.finish_response(0);
    ASSERT_TRUE(finish.has_value());
    EXPECT_TRUE(finish.value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto expected = headers_frame_bytes(0, response_fields(204, response_headers));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, ServerQueuesFinalHeadersThenBodyWithFin) {
    const std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    const auto body = connection.submit_response_body(0, bytes_from_text("pong"), true);
    ASSERT_TRUE(body.has_value());
    EXPECT_TRUE(body.value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto expected_headers = headers_frame_bytes(0, response_fields(200, response_headers));
    const auto expected_body = data_frame_bytes("pong");

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ServerQueuesTrailersWithFinAfterResponseBody) {
    const std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    const auto body = connection.submit_response_body(0, bytes_from_text("pong"));
    ASSERT_TRUE(body.has_value());
    EXPECT_TRUE(body.value());

    const auto trailers = connection.submit_response_trailers(0, trailer_fields, true);
    ASSERT_TRUE(trailers.has_value());
    EXPECT_TRUE(trailers.value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder;
    const auto expected_headers =
        headers_frame_bytes(encoder, 0, response_fields(200, response_headers));
    const auto expected_body = data_frame_bytes("pong");
    const auto expected_trailers = headers_frame_bytes(encoder, 0, trailer_fields);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].stream_id, 0u);
    EXPECT_EQ(sends[2].bytes, expected_trailers);
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, ServerAllowsInterimResponseBeforeFinalResponse) {
    const std::array interim_headers{
        coquic::http3::Http3Field{"link", "</style.css>; rel=preload"},
    };
    const std::array final_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto interim = connection.submit_response_head(
        0,
        coquic::http3::Http3ResponseHead{
            .status = 103,
            .headers = coquic::http3::Http3Headers(interim_headers.begin(), interim_headers.end()),
        });
    ASSERT_TRUE(interim.has_value());
    EXPECT_TRUE(interim.value());

    const auto final = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers = coquic::http3::Http3Headers(final_headers.begin(), final_headers.end()),
           });
    ASSERT_TRUE(final.has_value());
    EXPECT_TRUE(final.value());

    const auto finish = connection.finish_response(0);
    ASSERT_TRUE(finish.has_value());
    EXPECT_TRUE(finish.value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder;
    const auto expected_interim =
        headers_frame_bytes(encoder, 0, response_fields(103, interim_headers));
    const auto expected_final =
        headers_frame_bytes(encoder, 0, response_fields(200, final_headers));

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_interim);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_final);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, SendingResponseBodyBeforeFinalHeadersFailsLocally) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto body = connection.submit_response_body(0, bytes_from_text("pong"), true);
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, SendingResponseTrailersBeforeFinalHeadersFailsLocally) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto trailers = connection.submit_response_trailers(0, trailer_fields, true);
    ASSERT_FALSE(trailers.has_value());
    EXPECT_EQ(trailers.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(trailers.error().stream_id, std::optional<std::uint64_t>(0u));

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, SendingSecondFinalResponseFailsLocally) {
    const std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto first = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(first.value());
    ASSERT_TRUE(connection.finish_response(0).has_value());

    const auto second = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 204,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(second.error().stream_id, std::optional<std::uint64_t>(0u));

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto expected_headers = headers_frame_bytes(0, response_fields(200, response_headers));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, SendingResponseBodyPastDeclaredContentLengthFailsLocally) {
    const std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .content_length = 0,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    const auto body = connection.submit_response_body(0, bytes_from_text("x"));
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, DynamicTableResponseHeadersQueueEncoderInstructionsBeforeHeaders) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array response_headers{
        coquic::http3::Http3Field{"x-coquic-token", "bravo"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);

    const auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());
    ASSERT_TRUE(connection.finish_response(0).has_value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = peer_settings.qpack_max_table_capacity,
                .blocked_streams = peer_settings.qpack_blocked_streams,
            },
    };
    std::vector<std::byte> encoder_instructions;
    const auto expected_headers = headers_frame_bytes(
        encoder, 0, response_fields(200, response_headers), &encoder_instructions);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_FALSE(encoder_instructions.empty());
    EXPECT_EQ(sends[0].stream_id, 7u);
    EXPECT_EQ(sends[0].bytes, encoder_instructions);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_headers);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleQueuesRequestHeadersBodyAndTrailersWithFin) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, peer_settings);

    const auto head = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                            .method = "POST",
                                                            .scheme = "https",
                                                            .authority = "example.test",
                                                            .path = "/upload",
                                                            .content_length = 4,
                                                        });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    const auto body = connection.submit_request_body(0, bytes_from_text("ping"));
    ASSERT_TRUE(body.has_value());
    EXPECT_TRUE(body.value());

    const auto trailers = connection.submit_request_trailers(0, request_trailers);
    ASSERT_TRUE(trailers.has_value());
    EXPECT_TRUE(trailers.value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_FALSE(sends[0].bytes.empty());
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_FALSE(sends[1].bytes.empty());
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].stream_id, 0u);
    EXPECT_FALSE(sends[2].bytes.empty());
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleEmitsInterimFinalBodyTrailersAndCompleteResponseEvents) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const std::array interim_headers{
        coquic::http3::Http3Field{":status", "103"},
        coquic::http3::Http3Field{"link", "</style.css>; rel=preload"},
    };
    const std::array final_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    const std::array trailer_headers{
        coquic::http3::Http3Field{"etag", "done"},
    };

    auto response_bytes = headers_frame_bytes(0, interim_headers);
    const auto final_frame = headers_frame_bytes(0, final_headers);
    response_bytes.insert(response_bytes.end(), final_frame.begin(), final_frame.end());
    const auto body_frame = data_frame_bytes("pong");
    response_bytes.insert(response_bytes.end(), body_frame.begin(), body_frame.end());
    const auto trailers_frame = headers_frame_bytes(0, trailer_headers);
    response_bytes.insert(response_bytes.end(), trailers_frame.begin(), trailers_frame.end());

    const auto update = connection.on_core_result(receive_result(0, response_bytes, true),
                                                  coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(update.events.size(), 5u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerInformationalResponseEvent>(&update.events[0]),
              nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&update.events[1]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseBodyEvent>(&update.events[2]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseTrailersEvent>(&update.events[3]),
              nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&update.events[4]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataBeforeHeaders) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const auto update = connection.on_core_result(
        receive_result(0, data_frame_bytes("oops"), false), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

} // namespace

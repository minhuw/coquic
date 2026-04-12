#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
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

std::vector<std::byte> decoder_stream_bytes(std::initializer_list<std::uint8_t> values) {
    auto bytes = bytes_from_ints({0x03});
    const auto payload = bytes_from_ints(values);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

} // namespace

namespace coquic::http3 {

struct Http3ConnectionPeerUniStreamAccess {
    static std::size_t size(const Http3Connection &connection) {
        return connection.peer_uni_streams_.size();
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

} // namespace

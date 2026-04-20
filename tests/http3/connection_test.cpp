#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
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

coquic::quic::QuicCoreResult handshake_confirmed_result() {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreStateEvent{
            .change = coquic::quic::QuicCoreStateChange::handshake_confirmed,
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

coquic::quic::QuicCoreResult stop_sending_result(std::uint64_t stream_id,
                                                 std::uint64_t error_code = 0) {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCorePeerStopSending{
            .stream_id = stream_id,
            .application_error_code = error_code,
        },
    });
    return result;
}

coquic::quic::QuicCoreResult local_error_result() {
    coquic::quic::QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
    };
    return result;
}

coquic::quic::QuicCoreResult failed_result() {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreStateEvent{
            .change = coquic::quic::QuicCoreStateChange::failed,
        },
    });
    return result;
}

coquic::quic::QuicCoreStateChange invalid_state_change() {
    constexpr std::uint8_t raw = 0xff;
    coquic::quic::QuicCoreStateChange change{};
    std::memcpy(&change, &raw, sizeof(change));
    return change;
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

std::vector<std::byte> raw_headers_frame_bytes(std::span<const std::byte> field_section) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3HeadersFrame{
            .field_section = std::vector<std::byte>(field_section.begin(), field_section.end()),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte> overflowing_qpack_field_section_prefix_bytes() {
    return bytes_from_ints({
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0x00,
    });
}

std::vector<std::byte> unknown_frame_bytes(std::uint64_t type) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3UnknownFrame{
            .type = type,
            .payload = {},
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

void receive_client_peer_settings(coquic::http3::Http3Connection &connection,
                                  const coquic::http3::Http3SettingsSnapshot &settings) {
    const auto update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(settings)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
}

void submit_completed_client_get_request(coquic::http3::Http3Connection &connection,
                                         std::uint64_t stream_id) {
    ASSERT_TRUE(connection
                    .submit_request_head(stream_id,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(stream_id).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());
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

struct Http3ConnectionTestAccess {
    static auto &local_request_stream(Http3Connection &connection, std::uint64_t stream_id) {
        return connection.local_request_streams_[stream_id];
    }

    static auto &local_response_stream(Http3Connection &connection, std::uint64_t stream_id) {
        return connection.local_response_streams_[stream_id];
    }

    static auto &peer_request_stream(Http3Connection &connection, std::uint64_t stream_id) {
        return connection.peer_request_streams_[stream_id];
    }

    static auto &decoder(Http3Connection &connection) {
        return connection.decoder_;
    }

    static void set_closed(Http3Connection &connection, bool closed) {
        connection.closed_ = closed;
    }

    static void clear_local_qpack_encoder_stream(Http3Connection &connection) {
        connection.state_.local_qpack_encoder_stream_id.reset();
    }

    static void queue_startup_streams(Http3Connection &connection) {
        connection.queue_startup_streams();
    }

    static void set_peer_uni_stream_kind_control(Http3Connection &connection,
                                                 std::uint64_t stream_id) {
        connection.peer_uni_streams_[stream_id].kind = Http3Connection::PeerUniStreamKind::control;
    }

    static void set_peer_uni_stream_kind_encoder(Http3Connection &connection,
                                                 std::uint64_t stream_id) {
        connection.peer_uni_streams_[stream_id].kind =
            Http3Connection::PeerUniStreamKind::qpack_encoder;
    }

    static void set_peer_uni_stream_kind_decoder(Http3Connection &connection,
                                                 std::uint64_t stream_id) {
        connection.peer_uni_streams_[stream_id].kind =
            Http3Connection::PeerUniStreamKind::qpack_decoder;
    }

    static void handle_peer_uni_stream_data(Http3Connection &connection, std::uint64_t stream_id,
                                            std::span<const std::byte> bytes, bool fin) {
        connection.handle_peer_uni_stream_data(stream_id, bytes, fin);
    }

    static void process_request_stream(Http3Connection &connection, std::uint64_t stream_id) {
        connection.process_request_stream(stream_id);
    }

    static void process_response_stream(Http3Connection &connection, std::uint64_t stream_id) {
        connection.process_response_stream(stream_id);
    }

    static void handle_request_headers_frame(Http3Connection &connection, std::uint64_t stream_id,
                                             const Http3HeadersFrame &frame) {
        connection.handle_request_headers_frame(stream_id, frame);
    }

    static void handle_request_data_frame(Http3Connection &connection, std::uint64_t stream_id,
                                          const Http3DataFrame &frame) {
        connection.handle_request_data_frame(stream_id, frame);
    }

    static void handle_response_headers_frame(Http3Connection &connection, std::uint64_t stream_id,
                                              const Http3HeadersFrame &frame) {
        connection.handle_response_headers_frame(stream_id, frame);
    }

    static void handle_response_data_frame(Http3Connection &connection, std::uint64_t stream_id,
                                           const Http3DataFrame &frame) {
        connection.handle_response_data_frame(stream_id, frame);
    }

    static void apply_initial_request_headers(Http3Connection &connection, std::uint64_t stream_id,
                                              Http3Headers headers) {
        connection.apply_request_field_section(
            stream_id, Http3Connection::RequestFieldSectionKind::initial_headers,
            std::move(headers));
    }

    static void apply_request_trailers(Http3Connection &connection, std::uint64_t stream_id,
                                       Http3Headers headers) {
        connection.apply_request_field_section(
            stream_id, Http3Connection::RequestFieldSectionKind::trailers, std::move(headers));
    }

    static void apply_response_headers(Http3Connection &connection, std::uint64_t stream_id,
                                       Http3Headers headers) {
        connection.apply_response_field_section(
            stream_id, Http3Connection::ResponseFieldSectionKind::informational_or_final_headers,
            std::move(headers));
    }

    static void apply_response_trailers(Http3Connection &connection, std::uint64_t stream_id,
                                        Http3Headers headers) {
        connection.apply_response_field_section(
            stream_id, Http3Connection::ResponseFieldSectionKind::trailers, std::move(headers));
    }

    static void handle_unblocked_request_field_section(Http3Connection &connection,
                                                       const Http3DecodedFieldSection &decoded) {
        connection.handle_unblocked_request_field_section(decoded);
    }

    static void handle_unblocked_response_field_section(Http3Connection &connection,
                                                        const Http3DecodedFieldSection &decoded) {
        connection.handle_unblocked_response_field_section(decoded);
    }

    static void finalize_request_stream(Http3Connection &connection, std::uint64_t stream_id) {
        connection.finalize_request_stream(stream_id);
    }

    static void finalize_response_stream(Http3Connection &connection, std::uint64_t stream_id) {
        connection.finalize_response_stream(stream_id);
    }

    static void queue_connection_close(Http3Connection &connection, Http3ErrorCode code,
                                       std::string detail) {
        connection.queue_connection_close(code, std::move(detail));
    }

    static void queue_stream_error(Http3Connection &connection, std::uint64_t stream_id,
                                   Http3ErrorCode code) {
        connection.queue_stream_error(stream_id, code);
    }

    static void set_peer_request_blocked_initial_headers(Http3Connection &connection,
                                                         std::uint64_t stream_id) {
        connection.peer_request_streams_[stream_id].blocked_field_section =
            Http3Connection::RequestFieldSectionKind::initial_headers;
    }

    static void set_local_request_blocked_response_headers(Http3Connection &connection,
                                                           std::uint64_t stream_id) {
        connection.local_request_streams_[stream_id].blocked_field_section =
            Http3Connection::ResponseFieldSectionKind::informational_or_final_headers;
    }

    static void queue_send(Http3Connection &connection, std::uint64_t stream_id,
                           std::span<const std::byte> bytes, bool fin = false) {
        connection.queue_send(stream_id, bytes, fin);
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

TEST(QuicHttp3ConnectionTest, HandshakeConfirmedAlsoCreatesMandatoryStreams) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update =
        connection.on_core_result(handshake_confirmed_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[1].stream_id, 6u);
    EXPECT_EQ(sends[2].stream_id, 10u);
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownStateEventsBeforeTransportReady) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::quic::QuicCoreResult unknown_state;
    unknown_state.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreStateEvent{
            .change = invalid_state_change(),
        },
    });

    const auto ignored =
        connection.on_core_result(unknown_state, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(ignored.core_inputs.empty());
    EXPECT_TRUE(ignored.events.empty());
    EXPECT_FALSE(ignored.has_pending_work);
    EXPECT_FALSE(ignored.terminal_failure);
    EXPECT_FALSE(ignored.terminal_success);

    const auto ready =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(ready);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[1].stream_id, 6u);
    EXPECT_EQ(sends[2].stream_id, 10u);
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

TEST(QuicHttp3ConnectionTest, PeerControlStreamFinAfterSettingsClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update = connection.on_core_result(
        receive_result(3, std::span<const std::byte>{}, true), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerQpackDecoderCriticalStreamFinClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(11, bytes_from_ints({0x03}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerResetOnRemoteQpackDecoderStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(receive_result(11, bytes_from_ints({0x03})),
                                                      coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update =
        connection.on_core_result(reset_result(11), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerStopSendingOnLocalControlStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(2), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerStopSendingOnLocalQpackEncoderStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(6), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerStopSendingOnLocalQpackDecoderStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(10), coquic::quic::QuicCoreTimePoint{});
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

TEST(QuicHttp3ConnectionTest, FragmentedPeerUniStreamTypeLaterResolvesToControlStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first_fragment = connection.on_core_result(
        receive_result(15, bytes_from_ints({0x40})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_FALSE(connection.peer_settings_received());

    auto second_fragment = bytes_from_ints({0x00});
    const auto control_stream = settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{});
    second_fragment.insert(second_fragment.end(), control_stream.begin() + 1, control_stream.end());

    const auto update = connection.on_core_result(receive_result(15, second_fragment),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(connection.peer_settings_received());
}

TEST(QuicHttp3ConnectionTest, FragmentedPeerUniStreamTypeLaterResolvesToQpackDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first_fragment = connection.on_core_result(
        receive_result(15, bytes_from_ints({0x40})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());

    const auto update = connection.on_core_result(receive_result(15, bytes_from_ints({0x03})),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
    EXPECT_TRUE(update.core_inputs.empty());
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

TEST(QuicHttp3ConnectionTest, IgnoresUnknownPeerSettingsIdentifier) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(
        receive_result(3, settings_stream_bytes({
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 128,
                              },
                              coquic::http3::Http3Setting{
                                  .id = 0x2a,
                                  .value = 99,
                              },
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackBlockedStreams,
                                  .value = 4,
                              },
                          })),
        coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(connection.peer_settings_received());
    EXPECT_EQ(connection.peer_settings().qpack_max_table_capacity, 128u);
    EXPECT_EQ(connection.peer_settings().qpack_blocked_streams, 4u);
    EXPECT_EQ(connection.peer_settings().max_field_section_size, std::nullopt);
}

TEST(QuicHttp3ConnectionTest, DuplicateSettingsIdentifiersInSingleFrameMapToSettingsError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(
        receive_result(3, settings_stream_bytes({
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 16,
                              },
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 32,
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

TEST(QuicHttp3ConnectionTest, AcceptsNonIncreasingPeerGoawayIdentifier) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto first_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(12)),
                                                        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_goaway).has_value());

    const auto second_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(8)),
                                                         coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_goaway).has_value());
    EXPECT_FALSE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, InvalidPeerGoawayIdentifierMapsToIdError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(receive_result(3, goaway_frame_bytes(1)),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, BuffersIncompletePeerControlFrameUntilCompletion) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto first_fragment = connection.on_core_result(
        receive_result(3, bytes_from_ints({0x07, 0x01})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_TRUE(first_fragment.core_inputs.empty());
    EXPECT_FALSE(connection.is_closed());

    const auto second_fragment = connection.on_core_result(
        receive_result(3, bytes_from_ints({0x00})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_fragment).has_value());
    EXPECT_TRUE(second_fragment.core_inputs.empty());
    EXPECT_FALSE(connection.is_closed());
    EXPECT_EQ(connection.state().goaway_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, MalformedGoawayPayloadOnControlStreamMapsToFrameError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update = connection.on_core_result(
        receive_result(
            3, bytes_from_ints(
                   {static_cast<std::uint8_t>(coquic::http3::kHttp3FrameTypeGoaway), 0x01, 0x40})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, MalformedMaxPushIdPayloadOnControlStreamMapsToFrameError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update = connection.on_core_result(
        receive_result(
            3, bytes_from_ints({static_cast<std::uint8_t>(coquic::http3::kHttp3FrameTypeMaxPushId),
                                0x01, 0x40})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
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

TEST(QuicHttp3ConnectionTest, OverflowingPeerQpackEncoderInstructionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes(
                              {0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_encoder_stream_error));
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderCapacityUpdateAboveSettingClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings =
            coquic::http3::Http3SettingsSnapshot{
                .qpack_max_table_capacity = 32,
            },
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes({0x3f, 0x21})), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_encoder_stream_error));
    EXPECT_TRUE(connection.is_closed());
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

TEST(QuicHttp3ConnectionTest, OverflowingPeerQpackDecoderInstructionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(
        receive_result(11, decoder_stream_bytes(
                               {0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decoder_stream_error));
    EXPECT_TRUE(connection.is_closed());
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

TEST(QuicHttp3ConnectionTest, ServerResponseApiRejectsWrongRoleTransportAndClosedStates) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unready(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    ASSERT_FALSE(unready.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                     .has_value());
    ASSERT_FALSE(unready.submit_response_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(unready.submit_response_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(unready.finish_response(0).has_value());

    coquic::http3::Http3Connection wrong_role(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    ASSERT_FALSE(wrong_role.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                     .has_value());
    ASSERT_FALSE(wrong_role.submit_response_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(wrong_role.submit_response_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(wrong_role.finish_response(0).has_value());

    coquic::http3::Http3Connection closed(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(closed);
    EXPECT_TRUE(close_input_from(closed.on_core_result(stop_sending_result(3),
                                                       coquic::quic::QuicCoreTimePoint{}))
                    .has_value());
    ASSERT_TRUE(closed.is_closed());
    ASSERT_FALSE(closed.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                     .has_value());
    ASSERT_FALSE(closed.submit_response_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(closed.submit_response_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(closed.finish_response(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerResponseHeadValidationBranches) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(
        unknown_stream.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
            .has_value());

    coquic::http3::Http3Connection duplicate_final(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(duplicate_final);
    receive_completed_get_request(duplicate_final, 0);
    ASSERT_TRUE(
        duplicate_final.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
            .has_value());
    ASSERT_FALSE(
        duplicate_final.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
            .has_value());

    coquic::http3::Http3Connection after_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(after_trailers);
    receive_completed_get_request(after_trailers, 0);
    ASSERT_TRUE(after_trailers
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_TRUE(after_trailers.submit_response_trailers(0, trailer_fields, false).has_value());
    ASSERT_FALSE(
        after_trailers.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
            .has_value());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsInvalidResponseHeadFields) {
    const std::array invalid_headers{
        coquic::http3::Http3Field{"Connection", "close"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto result =
        connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                               .status = 200,
                                               .headers = std::vector<coquic::http3::Http3Field>(
                                                   invalid_headers.begin(), invalid_headers.end()),
                                           });
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(result.error().stream_id, std::nullopt);
}

TEST(QuicHttp3ConnectionTest, ServerResponseBodyValidationBranches) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.submit_response_body(0, bytes_from_text("x")).has_value());

    coquic::http3::Http3Connection finished(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(finished);
    receive_completed_get_request(finished, 0);
    ASSERT_TRUE(finished
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 1,
                                          })
                    .has_value());
    ASSERT_TRUE(finished.submit_response_body(0, bytes_from_text("x"), true).has_value());
    ASSERT_FALSE(finished.submit_response_body(0, bytes_from_text("y")).has_value());

    coquic::http3::Http3Connection after_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(after_trailers);
    receive_completed_get_request(after_trailers, 0);
    ASSERT_TRUE(after_trailers
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_TRUE(after_trailers.submit_response_trailers(0, trailer_fields, false).has_value());
    ASSERT_FALSE(after_trailers.submit_response_body(0, bytes_from_text("late")).has_value());

    coquic::http3::Http3Connection fin_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(fin_mismatch);
    receive_completed_get_request(fin_mismatch, 0);
    ASSERT_TRUE(fin_mismatch
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 2,
                                          })
                    .has_value());
    ASSERT_FALSE(fin_mismatch.submit_response_body(0, bytes_from_text("x"), true).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerResponseTrailersValidationBranches) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    const std::array invalid_trailers{
        coquic::http3::Http3Field{":status", "200"},
    };

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.submit_response_trailers(0, trailer_fields).has_value());

    coquic::http3::Http3Connection finished(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(finished);
    receive_completed_get_request(finished, 0);
    ASSERT_TRUE(finished.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
                    .has_value());
    ASSERT_TRUE(finished.finish_response(0).has_value());
    ASSERT_FALSE(finished.submit_response_trailers(0, trailer_fields).has_value());

    coquic::http3::Http3Connection duplicate_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(duplicate_trailers);
    receive_completed_get_request(duplicate_trailers, 0);
    ASSERT_TRUE(duplicate_trailers
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_TRUE(duplicate_trailers.submit_response_trailers(0, trailer_fields, false).has_value());
    ASSERT_FALSE(duplicate_trailers.submit_response_trailers(0, trailer_fields, false).has_value());

    coquic::http3::Http3Connection body_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(body_mismatch);
    receive_completed_get_request(body_mismatch, 0);
    ASSERT_TRUE(body_mismatch
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 1,
                                          })
                    .has_value());
    ASSERT_FALSE(body_mismatch.submit_response_trailers(0, trailer_fields).has_value());

    coquic::http3::Http3Connection invalid_trailer_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(invalid_trailer_connection);
    receive_completed_get_request(invalid_trailer_connection, 0);
    ASSERT_TRUE(invalid_trailer_connection
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_FALSE(
        invalid_trailer_connection.submit_response_trailers(0, invalid_trailers).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerFinishResponseValidationBranches) {
    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.finish_response(0).has_value());

    coquic::http3::Http3Connection missing_final(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(missing_final);
    receive_completed_get_request(missing_final, 0);
    ASSERT_FALSE(missing_final.finish_response(0).has_value());

    coquic::http3::Http3Connection duplicate_finish(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(duplicate_finish);
    receive_completed_get_request(duplicate_finish, 0);
    ASSERT_TRUE(
        duplicate_finish.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
            .has_value());
    ASSERT_TRUE(duplicate_finish.finish_response(0).has_value());
    ASSERT_FALSE(duplicate_finish.finish_response(0).has_value());

    coquic::http3::Http3Connection body_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(body_mismatch);
    receive_completed_get_request(body_mismatch, 0);
    ASSERT_TRUE(body_mismatch
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 1,
                                          })
                    .has_value());
    ASSERT_FALSE(body_mismatch.finish_response(0).has_value());
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

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsRequestLifecycleAfterInvalidInitialHeaders) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    const auto invalid_head = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                                    .method = "",
                                                                    .scheme = "https",
                                                                    .authority = "example.test",
                                                                    .path = "/resource",
                                                                });
    ASSERT_FALSE(invalid_head.has_value());

    const auto body = connection.submit_request_body(0, bytes_from_text("x"));
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));

    const auto trailers = connection.submit_request_trailers(0, trailer_fields);
    ASSERT_FALSE(trailers.has_value());
    EXPECT_EQ(trailers.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(trailers.error().stream_id, std::optional<std::uint64_t>(0u));

    const auto finish = connection.finish_request(0);
    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(finish.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsRequestBodyThatExceedsDeclaredContentLength) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 1,
                                         })
                    .has_value());

    const auto body = connection.submit_request_body(0, bytes_from_text("xy"));
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsFinishingRequestWithContentLengthMismatch) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 2,
                                         })
                    .has_value());
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("x")).has_value());

    const auto finish = connection.finish_request(0);
    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(finish.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsDuplicateFinishedRequest) {
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

    const auto second_finish = connection.finish_request(0);
    ASSERT_FALSE(second_finish.has_value());
    EXPECT_EQ(second_finish.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(second_finish.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRequestApiRejectsWrongRoleTransportAndClosedStates) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unready(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    ASSERT_FALSE(unready
                     .submit_request_head(0,
                                          coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          })
                     .has_value());
    ASSERT_FALSE(unready.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(unready.submit_request_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(unready.finish_request(0).has_value());

    coquic::http3::Http3Connection wrong_role(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    ASSERT_FALSE(wrong_role
                     .submit_request_head(0,
                                          coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          })
                     .has_value());
    ASSERT_FALSE(wrong_role.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(wrong_role.submit_request_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(wrong_role.finish_request(0).has_value());

    coquic::http3::Http3Connection closed(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(closed);
    EXPECT_TRUE(close_input_from(closed.on_core_result(stop_sending_result(2),
                                                       coquic::quic::QuicCoreTimePoint{}))
                    .has_value());
    ASSERT_TRUE(closed.is_closed());
    ASSERT_FALSE(closed
                     .submit_request_head(0,
                                          coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          })
                     .has_value());
    ASSERT_FALSE(closed.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(closed.submit_request_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(closed.finish_request(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestHeadRejectsNonRequestStreamAndDuplicateHeaders) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    const auto peer_initiated_stream =
        connection.submit_request_head(1, coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          });
    ASSERT_FALSE(peer_initiated_stream.has_value());
    EXPECT_EQ(peer_initiated_stream.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(peer_initiated_stream.error().stream_id, std::optional<std::uint64_t>(1u));

    const auto invalid_stream = connection.submit_request_head(2, coquic::http3::Http3RequestHead{
                                                                      .method = "GET",
                                                                      .scheme = "https",
                                                                      .authority = "example.test",
                                                                      .path = "/resource",
                                                                  });
    ASSERT_FALSE(invalid_stream.has_value());
    EXPECT_EQ(invalid_stream.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(invalid_stream.error().stream_id, std::optional<std::uint64_t>(2u));

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());

    const auto duplicate = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                                 .method = "GET",
                                                                 .scheme = "https",
                                                                 .authority = "example.test",
                                                                 .path = "/other",
                                                             });
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(duplicate.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleAllowsUndeclaredLengthRequestBodyFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                         })
                    .has_value());

    const auto body = connection.submit_request_body(0, bytes_from_text("ping"), true);

    ASSERT_TRUE(body.has_value());
    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, data_frame_bytes("ping"));
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleAllowsUndeclaredLengthRequestTrailersAndFinish) {
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("ping")).has_value());
    ASSERT_TRUE(connection.submit_request_trailers(0, trailer_fields, false).has_value());

    const auto finish = connection.finish_request(0);

    ASSERT_TRUE(finish.has_value());
    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[2].stream_id, 0u);
    EXPECT_FALSE(sends[2].bytes.empty());
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRequestBodyAndTrailersValidationBranches) {
    const std::array invalid_trailers{
        coquic::http3::Http3Field{":status", "200"},
    };
    const std::array valid_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection final_chunk_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(final_chunk_mismatch);
    receive_peer_settings(final_chunk_mismatch, {});
    ASSERT_TRUE(final_chunk_mismatch
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 2,
                                         })
                    .has_value());
    ASSERT_FALSE(
        final_chunk_mismatch.submit_request_body(0, bytes_from_text("x"), true).has_value());

    coquic::http3::Http3Connection body_after_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(body_after_trailers);
    receive_peer_settings(body_after_trailers, {});
    ASSERT_TRUE(body_after_trailers
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    ASSERT_TRUE(body_after_trailers.submit_request_trailers(0, valid_trailers, false).has_value());
    ASSERT_FALSE(body_after_trailers.submit_request_body(0, bytes_from_text("late")).has_value());

    coquic::http3::Http3Connection trailers_before_body_complete(
        coquic::http3::Http3ConnectionConfig{
            .role = coquic::http3::Http3ConnectionRole::client,
        });
    prime_client_transport(trailers_before_body_complete);
    receive_peer_settings(trailers_before_body_complete, {});
    ASSERT_TRUE(trailers_before_body_complete
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 1,
                                         })
                    .has_value());
    ASSERT_FALSE(
        trailers_before_body_complete.submit_request_trailers(0, valid_trailers).has_value());

    coquic::http3::Http3Connection invalid_trailer_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(invalid_trailer_connection);
    receive_peer_settings(invalid_trailer_connection, {});
    ASSERT_TRUE(invalid_trailer_connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    ASSERT_FALSE(
        invalid_trailer_connection.submit_request_trailers(0, invalid_trailers).has_value());

    coquic::http3::Http3Connection trailers_after_finished(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(trailers_after_finished);
    receive_peer_settings(trailers_after_finished, {});
    ASSERT_TRUE(trailers_after_finished
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(trailers_after_finished.finish_request(0).has_value());
    ASSERT_FALSE(trailers_after_finished.submit_request_trailers(0, valid_trailers).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsRequestOperationsForMissingAndFinishedStreams) {
    const std::array valid_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection missing_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(missing_stream);
    receive_peer_settings(missing_stream, {});

    ASSERT_FALSE(missing_stream.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(missing_stream.submit_request_trailers(0, valid_trailers).has_value());
    ASSERT_FALSE(missing_stream.finish_request(0).has_value());

    coquic::http3::Http3Connection duplicate_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(duplicate_trailers);
    receive_peer_settings(duplicate_trailers, {});
    ASSERT_TRUE(duplicate_trailers
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    ASSERT_TRUE(duplicate_trailers.submit_request_trailers(0, valid_trailers, false).has_value());
    ASSERT_FALSE(duplicate_trailers.submit_request_trailers(0, valid_trailers).has_value());

    coquic::http3::Http3Connection finished_request(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(finished_request);
    receive_peer_settings(finished_request, {});
    ASSERT_TRUE(finished_request
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(finished_request.finish_request(0).has_value());
    ASSERT_FALSE(finished_request.submit_request_body(0, bytes_from_text("late")).has_value());
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

TEST(QuicHttp3ConnectionTest, ClientRoleEmitsResponseBodyWithoutDeclaredContentLength) {
    const auto final_headers = response_fields(200, {});
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    const auto body_update = connection.on_core_result(
        receive_result(0, data_frame_bytes("pong"), true), coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(body_update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseBodyEvent>(&body_update.events[0]),
              nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&body_update.events[1]),
              nullptr);
    EXPECT_FALSE(close_input_from(body_update).has_value());
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

TEST(QuicHttp3ConnectionTest, ClientRolePeerResponseFinWithoutFinalHeadersResetsStream) {
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
        receive_result(0, std::span<const std::byte>{}, true), coquic::quic::QuicCoreTimePoint{});
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

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataForHeadRequest) {
    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "HEAD",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto response_bytes = headers_frame_bytes(0, response_headers);
    const auto body = data_frame_bytes("oops");
    response_bytes.insert(response_bytes.end(), body.begin(), body.end());

    const auto update = connection.on_core_result(receive_result(0, response_bytes),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataAfterTrailers) {
    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
    };
    const std::array trailer_headers{
        coquic::http3::Http3Field{"etag", "done"},
    };
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

    auto response_bytes = headers_frame_bytes(0, response_headers);
    const auto trailers = headers_frame_bytes(0, trailer_headers);
    response_bytes.insert(response_bytes.end(), trailers.begin(), trailers.end());
    const auto late_data = data_frame_bytes("late");
    response_bytes.insert(response_bytes.end(), late_data.begin(), late_data.end());

    const auto update = connection.on_core_result(receive_result(0, response_bytes),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleResponseBodyBeyondDeclaredContentLengthResetsStream) {
    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "1"},
    };
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

    auto response_bytes = headers_frame_bytes(0, response_headers);
    const auto body = data_frame_bytes("xy");
    response_bytes.insert(response_bytes.end(), body.begin(), body.end());

    const auto update = connection.on_core_result(receive_result(0, response_bytes),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&update.events[0]), nullptr);

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

TEST(QuicHttp3ConnectionTest, ClientRoleBlockedFinalResponseHeadersCompleteAfterQpackUnblocks) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array response_headers{
        coquic::http3::Http3Field{":status", "204"},
        coquic::http3::Http3Field{"x-coquic-token", "bravo"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = 220,
                .blocked_streams = 1,
            },
    };

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

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, response_headers, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto unblocked_update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&unblocked_update.events[0]),
              nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRolePeerResetEmitsResponseResetEvent) {
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
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected)),
        coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(update.events.size(), 1u);
    const auto *reset = std::get_if<coquic::http3::Http3PeerResponseResetEvent>(&update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerResetEmitsRequestResetEvent) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(reset_update.events.size(), 1u);
    const auto *reset =
        std::get_if<coquic::http3::Http3PeerRequestResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsSettingsFrameOnRequestStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = connection.on_core_result(receive_result(0, settings_frame_bytes({})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerRequestFinWithoutHeadersResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = connection.on_core_result(
        receive_result(0, std::span<const std::byte>{}, true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    const auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));

    const auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerRequestFinWithTruncatedFrameResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = connection.on_core_result(receive_result(0, bytes_from_ints({0x01}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    const auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));

    const auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBuffersIncompleteRequestFrameUntilCompletion) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto partial_update = connection.on_core_result(
        receive_result(0, bytes_from_ints({0x00})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(partial_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(partial_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(partial_update).empty());
    EXPECT_TRUE(partial_update.events.empty());

    const auto final_update = connection.on_core_result(
        receive_result(0, bytes_from_ints({0x00}), true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(final_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(final_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(final_update).empty());
    ASSERT_EQ(final_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&final_update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleMalformedCompleteRequestFrameClosesConnection) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto update = connection.on_core_result(receive_result(0, bytes_from_ints({
                                                                        0x07,
                                                                        0x01,
                                                                        0x40,
                                                                    })),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsHeadersAfterRequestTrailers) {
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
    const auto late_headers = headers_frame_bytes(0, trailer_fields);
    bytes.insert(bytes.end(), late_headers.begin(), late_headers.end());

    const auto update =
        connection.on_core_result(receive_result(0, bytes), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestBodyBeyondDeclaredContentLengthResetsStream) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "1"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto body_update = connection.on_core_result(receive_result(0, data_frame_bytes("xy")),
                                                       coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(body_update).has_value());
    EXPECT_TRUE(body_update.events.empty());

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

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestHeadersCompleteAfterQpackUnblocks) {
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_fields, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&unblocked_update.events[0]),
              nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/too-large"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    const auto abort_update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto stops = stop_sending_inputs_from(abort_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));

    const auto late_update = connection.on_core_result(
        receive_result(0, data_frame_bytes("ignored"), true), coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(late_update).has_value());
    EXPECT_TRUE(late_update.events.empty());
    EXPECT_TRUE(reset_stream_inputs_from(late_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(late_update).empty());
}

TEST(QuicHttp3ConnectionTest, ServerRoleAbortRequestValidationBranches) {
    coquic::http3::Http3Connection unready(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    ASSERT_FALSE(unready.abort_request_body(0).has_value());

    coquic::http3::Http3Connection wrong_role(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    ASSERT_FALSE(wrong_role.abort_request_body(0).has_value());

    coquic::http3::Http3Connection closed(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(closed);
    EXPECT_TRUE(close_input_from(closed.on_core_result(stop_sending_result(3),
                                                       coquic::quic::QuicCoreTimePoint{}))
                    .has_value());
    ASSERT_TRUE(closed.is_closed());
    ASSERT_FALSE(closed.abort_request_body(0).has_value());

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.abort_request_body(0).has_value());

    coquic::http3::Http3Connection terminated(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(terminated);
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
    };
    const auto request_update =
        terminated.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(request_update.events.size(), 1u);
    ASSERT_TRUE(terminated.abort_request_body(0).has_value());
    ASSERT_TRUE(terminated.abort_request_body(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerRoleAbortBlockedRequestBodyFlushesQpackCancellation) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_headers{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_headers, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 11u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

    const auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerStopSendingResetsLocalResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/hello"},
    };

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_TRUE(connection
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                          })
                    .has_value());

    const auto stop_update = connection.on_core_result(
        stop_sending_result(
            0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    const auto resets = reset_stream_inputs_from(stop_update);

    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
    EXPECT_FALSE(
        connection.submit_response_body(0, bytes_from_text("late body"), true).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsServerInitiatedBidirectionalStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(1, std::span<const std::byte>{}),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleIgnoresPeerStopSendingForUnknownResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(1), coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, ClientRoleBlockedResponseResetFlushesQpackCancellation) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array response_headers{
        coquic::http3::Http3Field{":status", "204"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = 220,
                .blocked_streams = 1,
            },
    };

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, response_headers, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(reset_update).has_value());

    const auto sends = send_stream_inputs_from(reset_update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 10u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

    ASSERT_EQ(reset_update.events.size(), 1u);
    const auto *reset =
        std::get_if<coquic::http3::Http3PeerResponseResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestResetFlushesQpackCancellation) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_headers{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_headers, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(reset_update).has_value());

    const auto sends = send_stream_inputs_from(reset_update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 11u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

    ASSERT_EQ(reset_update.events.size(), 1u);
    const auto *reset =
        std::get_if<coquic::http3::Http3PeerRequestResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestUnblockProcessesBufferedForbiddenFrame) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_headers{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    auto bytes = headers_frame_bytes(encoder, 0, request_headers, &encoder_instructions);
    const auto settings = settings_frame_bytes({});
    bytes.insert(bytes.end(), settings.begin(), settings.end());

    const auto blocked_update =
        connection.on_core_result(receive_result(0, bytes), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(unblocked_update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ServerRoleInvalidRequestHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = connection.on_core_result(receive_result(0, raw_headers_frame_bytes({})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest,
     ServerRoleOverflowingRequestHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = connection.on_core_result(
        receive_result(0, raw_headers_frame_bytes(overflowing_qpack_field_section_prefix_bytes())),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ServerRoleMalformedRequestHeadersFieldSectionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update =
        connection.on_core_result(receive_result(0, raw_headers_frame_bytes(bytes_from_ints({
                                                        0x00,
                                                        0x00,
                                                        0x01,
                                                    }))),
                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ServerRoleInvalidRequestTrailersResetStream) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    const std::array invalid_trailers{
        coquic::http3::Http3Field{":path", "/forbidden"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto trailers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, invalid_trailers), true),
                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(trailers_update).has_value());

    const auto resets = reset_stream_inputs_from(trailers_update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    const auto stops = stop_sending_inputs_from(trailers_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestTrailersCompleteAfterQpackUnblocks) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
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

    prime_server_transport(connection);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerRequestTrailersEvent>(&unblocked_update.events[0]),
        nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleEmptyRequestDataFrameCompletesWithoutBodyEvent) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    const auto update = connection.on_core_result(receive_result(0, data_frame_bytes(""), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleIgnoresUnknownRequestFrameTypeAfterHeaders) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto update = connection.on_core_result(
        receive_result(0, unknown_frame_bytes(0x21), true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleResponseFinWithTruncatedFrameResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(receive_result(0, bytes_from_ints({0x01}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

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

TEST(QuicHttp3ConnectionTest, ClientRoleBuffersIncompleteResponseFrameUntilCompletion) {
    const auto final_response_headers = response_fields(200, {}, 0);
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto partial_update = connection.on_core_result(
        receive_result(0, bytes_from_ints({0x00})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(partial_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(partial_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(partial_update).empty());
    EXPECT_TRUE(partial_update.events.empty());

    const auto final_update = connection.on_core_result(
        receive_result(0, bytes_from_ints({0x00}), true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(final_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(final_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(final_update).empty());
    ASSERT_EQ(final_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&final_update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleMalformedCompleteResponseFrameClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(receive_result(0, bytes_from_ints({
                                                                        0x07,
                                                                        0x01,
                                                                        0x40,
                                                                    })),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsForbiddenFrameTypeOnResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(receive_result(0, settings_frame_bytes({})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleInvalidResponseHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(receive_result(0, raw_headers_frame_bytes({})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest,
     ClientRoleOverflowingResponseHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(
        receive_result(0, raw_headers_frame_bytes(overflowing_qpack_field_section_prefix_bytes())),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ClientRoleMalformedResponseHeadersFieldSectionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update =
        connection.on_core_result(receive_result(0, raw_headers_frame_bytes(bytes_from_ints({
                                                        0x00,
                                                        0x00,
                                                        0x01,
                                                    }))),
                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ClientRoleInvalidResponseHeadersResetStream) {
    const std::array invalid_response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(0, invalid_response_headers), true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

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

TEST(QuicHttp3ConnectionTest, ClientRoleInvalidResponseTrailersResetStream) {
    const auto final_response_headers = response_fields(200, {});
    const std::array invalid_trailers{
        coquic::http3::Http3Field{":status", "204"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    const auto trailers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, invalid_trailers), true),
                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(trailers_update).has_value());

    const auto resets = reset_stream_inputs_from(trailers_update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    const auto stops = stop_sending_inputs_from(trailers_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsHeadersAfterResponseTrailers) {
    const auto final_response_headers = response_fields(200, {});
    const std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto head_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(head_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&head_update.events[0]),
              nullptr);

    const auto trailers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, trailer_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(trailers_update.events.size(), 1u);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseTrailersEvent>(&trailers_update.events[0]),
        nullptr);

    const auto late_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, trailer_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(late_update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleBlockedResponseTrailersCompleteAfterQpackUnblocks) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const auto final_response_headers = response_fields(200, {});
    const std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = 220,
                .blocked_streams = 1,
            },
    };

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    std::vector<std::byte> encoder_instructions;
    const auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    const auto unblocked_update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseTrailersEvent>(&unblocked_update.events[0]),
        nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleEmptyResponseDataFrameCompletesWithoutBodyEvent) {
    const auto final_response_headers = response_fields(200, {}, 0);
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    const auto update = connection.on_core_result(receive_result(0, data_frame_bytes(""), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleIgnoresUnknownResponseFrameTypeAfterHeaders) {
    const auto final_response_headers = response_fields(200, {});
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto update = connection.on_core_result(
        receive_result(0, unknown_frame_bytes(0x21), true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleResponseFinWithContentLengthMismatchResetsStream) {
    const auto final_response_headers = response_fields(200, {}, 2);
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto bytes = headers_frame_bytes(0, final_response_headers);
    const auto body = data_frame_bytes("x");
    bytes.insert(bytes.end(), body.begin(), body.end());

    const auto update = connection.on_core_result(receive_result(0, bytes, true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

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

TEST(QuicHttp3ConnectionTest, ClientRoleFinishedLocalRequestRejectsRequestHead) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 0).request_finished =
        true;

    const auto result = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                              .method = "GET",
                                                              .scheme = "https",
                                                              .authority = "example.test",
                                                              .path = "/resource",
                                                          });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestHeadersRequireLocalQpackEncoderStream) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, peer_settings);
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    const auto result = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                              .method = "GET",
                                                              .scheme = "https",
                                                              .authority = "example.test",
                                                              .path = "/resource",
                                                              .headers =
                                                                  {
                                                                      {
                                                                          .name = "x-coquic-token",
                                                                          .value = "bravo",
                                                                      },
                                                                  },
                                                          });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestTrailersRequireLocalQpackEncoderStream) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, peer_settings);
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    const auto result = connection.submit_request_trailers(0, trailer_fields);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ClientRoleDynamicRequestTrailersQueueEncoderInstructions) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "0"},
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, peer_settings);
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    ASSERT_TRUE(connection.submit_request_trailers(0, trailer_fields).has_value());

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = peer_settings.qpack_max_table_capacity,
                .blocked_streams = peer_settings.qpack_blocked_streams,
            },
    };
    headers_frame_bytes(encoder, 0, request_fields);
    std::vector<std::byte> encoder_instructions;
    const auto expected_trailers =
        headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_FALSE(encoder_instructions.empty());
    EXPECT_EQ(sends[0].stream_id, 6u);
    EXPECT_EQ(sends[0].bytes, encoder_instructions);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_trailers);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestBodyRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                         })
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 0)
        .request_body_bytes_sent = std::numeric_limits<std::uint64_t>::max();

    const auto result = connection.submit_request_body(0, bytes_from_text("x"));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ConnectionTest, ServerRoleResponseHeadersRequireLocalQpackEncoderStream) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    const auto result = connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                                               .status = 200,
                                                               .headers =
                                                                   {
                                                                       {
                                                                           .name = "x-coquic-token",
                                                                           .value = "bravo",
                                                                       },
                                                                   },
                                                           });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ServerRoleResponseTrailersRequireLocalQpackEncoderStream) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    const auto result = connection.submit_response_trailers(0, trailer_fields);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ServerRoleDynamicResponseTrailersQueueEncoderInstructions) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    const std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                    .has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    ASSERT_TRUE(connection.submit_response_trailers(0, trailer_fields).has_value());

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
    const auto expected_trailers =
        headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_FALSE(encoder_instructions.empty());
    EXPECT_EQ(sends[0].stream_id, 7u);
    EXPECT_EQ(sends[0].bytes, encoder_instructions);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_trailers);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ServerRoleResponseBodyRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});
    receive_completed_get_request(connection, 0);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::local_response_stream(connection, 0).body_bytes_sent =
        std::numeric_limits<std::uint64_t>::max();

    const auto result = connection.submit_response_body(0, bytes_from_text("x"));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ConnectionTest, RequestSidePrivateNoopGuardsDoNotMutateConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    coquic::http3::Http3ConnectionTestAccess::process_request_stream(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::handle_request_headers_frame(
        connection, 0, coquic::http3::Http3HeadersFrame{.field_section = {}});
    coquic::http3::Http3ConnectionTestAccess::handle_request_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = {}});
    coquic::http3::Http3ConnectionTestAccess::apply_initial_request_headers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::apply_request_trailers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_request_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 0,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::peer_request_stream(connection, 1);
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_request_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 1,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::finalize_request_stream(connection, 0);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(connection.is_closed());
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ResponseSidePrivateNoopGuardsDoNotMutateConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::http3::Http3ConnectionTestAccess::process_response_stream(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::handle_response_headers_frame(
        connection, 0, coquic::http3::Http3HeadersFrame{.field_section = {}});
    coquic::http3::Http3ConnectionTestAccess::handle_response_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = {}});
    coquic::http3::Http3ConnectionTestAccess::apply_response_headers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::apply_response_trailers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_response_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 0,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 1);
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_response_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 1,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::finalize_response_stream(connection, 0);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(connection.is_closed());
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestDataRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto &request = coquic::http3::Http3ConnectionTestAccess::peer_request_stream(connection, 0);
    request.initial_headers_received = true;
    request.body_bytes_received = std::numeric_limits<std::uint64_t>::max();

    coquic::http3::Http3ConnectionTestAccess::handle_request_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = bytes_from_text("x")});

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
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

TEST(QuicHttp3ConnectionTest, ClientRoleResponseDataRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto &request = coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 0);
    request.final_response_received = true;
    request.response_body_bytes_received = std::numeric_limits<std::uint64_t>::max();

    coquic::http3::Http3ConnectionTestAccess::handle_response_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = bytes_from_text("x")});

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
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

TEST(QuicHttp3ConnectionTest, ServerRoleMalformedFinishingRequestFrameDoesNotEmitCompleteEvent) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto update = connection.on_core_result(receive_result(0,
                                                                 bytes_from_ints({
                                                                     0x07,
                                                                     0x01,
                                                                     0x40,
                                                                 }),
                                                                 true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ClientRoleMalformedFinishingResponseFrameDoesNotEmitCompleteEvent) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    const auto update = connection.on_core_result(receive_result(0,
                                                                 bytes_from_ints({
                                                                     0x07,
                                                                     0x01,
                                                                     0x40,
                                                                 }),
                                                                 true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ConnectionSettingsGettersExposeLocalAndPeerSnapshots) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 3,
        .max_field_section_size = 1024,
    };
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 64,
        .qpack_blocked_streams = 2,
        .max_field_section_size = 4096,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });

    const auto actual_local_settings = connection.local_settings();
    EXPECT_EQ(actual_local_settings.qpack_max_table_capacity,
              local_settings.qpack_max_table_capacity);
    EXPECT_EQ(actual_local_settings.qpack_blocked_streams, local_settings.qpack_blocked_streams);
    EXPECT_EQ(actual_local_settings.max_field_section_size, local_settings.max_field_section_size);
    EXPECT_FALSE(connection.peer_settings_received());

    receive_client_peer_settings(connection, peer_settings);

    EXPECT_TRUE(connection.peer_settings_received());
    const auto actual_peer_settings = connection.peer_settings();
    EXPECT_EQ(actual_peer_settings.qpack_max_table_capacity,
              peer_settings.qpack_max_table_capacity);
    EXPECT_EQ(actual_peer_settings.qpack_blocked_streams, peer_settings.qpack_blocked_streams);
    EXPECT_EQ(actual_peer_settings.max_field_section_size, peer_settings.max_field_section_size);
}

TEST(QuicHttp3ConnectionTest, StartupFailsWhenLocalSettingsCannotBeSerialized) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings =
            {
                .qpack_max_table_capacity = std::numeric_limits<std::uint64_t>::max(),
            },
    });

    const auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::internal_error));
}

TEST(QuicHttp3ConnectionTest, TerminalCoreResultsDrainPendingInputsAndMarkFailure) {
    coquic::http3::Http3Connection closed_connection(coquic::http3::Http3ConnectionConfig{});
    coquic::http3::Http3ConnectionTestAccess::queue_send(closed_connection, 0,
                                                         bytes_from_text("x"));
    coquic::http3::Http3ConnectionTestAccess::set_closed(closed_connection, true);
    const auto closed_update = closed_connection.on_core_result(handshake_ready_result(),
                                                                coquic::quic::QuicCoreTimePoint{});
    ASSERT_TRUE(closed_update.terminal_failure);
    ASSERT_EQ(send_stream_inputs_from(closed_update).size(), 1u);

    coquic::http3::Http3Connection local_error_connection(coquic::http3::Http3ConnectionConfig{});
    coquic::http3::Http3ConnectionTestAccess::queue_send(local_error_connection, 0,
                                                         bytes_from_text("x"));
    const auto local_error_update = local_error_connection.on_core_result(
        local_error_result(), coquic::quic::QuicCoreTimePoint{});
    ASSERT_TRUE(local_error_update.terminal_failure);
    ASSERT_EQ(send_stream_inputs_from(local_error_update).size(), 1u);
    EXPECT_TRUE(local_error_connection.is_closed());

    coquic::http3::Http3Connection failed_connection(coquic::http3::Http3ConnectionConfig{});
    coquic::http3::Http3ConnectionTestAccess::queue_send(failed_connection, 0,
                                                         bytes_from_text("x"));
    const auto failed_update =
        failed_connection.on_core_result(failed_result(), coquic::quic::QuicCoreTimePoint{});
    ASSERT_TRUE(failed_update.terminal_failure);
    ASSERT_EQ(send_stream_inputs_from(failed_update).size(), 1u);
    EXPECT_TRUE(failed_connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, HandshakeReadyOmitsUnsetMaxFieldSectionSizeSetting) {
    const coquic::http3::Http3SettingsSnapshot settings{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 3,
        .max_field_section_size = std::nullopt,
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
}

TEST(QuicHttp3ConnectionTest, ClosedInternalGuardsSkipStartupAndPeerUniFinProcessing) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::http3::Http3ConnectionTestAccess::set_closed(connection, true);
    coquic::http3::Http3ConnectionTestAccess::queue_startup_streams(connection);
    coquic::http3::Http3ConnectionTestAccess::set_peer_uni_stream_kind_control(connection, 3);
    coquic::http3::Http3ConnectionTestAccess::set_peer_uni_stream_kind_encoder(connection, 7);
    coquic::http3::Http3ConnectionTestAccess::set_peer_uni_stream_kind_decoder(connection, 11);
    coquic::http3::Http3ConnectionTestAccess::handle_peer_uni_stream_data(
        connection, 3, std::span<const std::byte>{}, true);
    coquic::http3::Http3ConnectionTestAccess::handle_peer_uni_stream_data(
        connection, 7, bytes_from_ints({0x01}), false);
    coquic::http3::Http3ConnectionTestAccess::handle_peer_uni_stream_data(
        connection, 11, bytes_from_ints({0x01}), false);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ClosedQueueHelpersAreNoops) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::http3::Http3ConnectionTestAccess::set_closed(connection, true);
    coquic::http3::Http3ConnectionTestAccess::queue_connection_close(
        connection, coquic::http3::Http3ErrorCode::internal_error, "ignored");
    coquic::http3::Http3ConnectionTestAccess::queue_stream_error(
        connection, 0, coquic::http3::Http3ErrorCode::message_error);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, QueueSendSkipsEmptyWritesAndCoalescesTrailingFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{});

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, false);
    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);
    update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_TRUE(sends[0].bytes.empty());
    EXPECT_TRUE(sends[0].fin);

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 1, bytes_from_text("x"));
    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);
    update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 1u);
    EXPECT_EQ(sends[0].bytes, bytes_from_text("x"));
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_TRUE(sends[1].bytes.empty());
    EXPECT_TRUE(sends[1].fin);

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0, bytes_from_text("x"));
    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);

    update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, bytes_from_text("x"));
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleIgnoresLocalUnidirectionalReceiveData) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(2, bytes_from_ints({0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, QueueSendDoesNotCoalesceAcrossNonSendPendingInputs) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
    };

    prime_server_transport(connection);
    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);
    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_TRUE(sends[0].bytes.empty());
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderDuplicateInstructionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(7, encoder_stream_bytes({0x01})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_encoder_stream_error));
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderStreamBuffersTruncatedNameReferenceInstructions) {
    coquic::http3::Http3Connection incomplete_name_reference(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    const auto incomplete_name_reference_update = incomplete_name_reference.on_core_result(
        receive_result(7, encoder_stream_bytes({0xff})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(incomplete_name_reference_update).has_value());
    EXPECT_TRUE(incomplete_name_reference_update.core_inputs.empty());

    coquic::http3::Http3Connection missing_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    const auto missing_value_update = missing_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes({0xc1})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(missing_value_update).has_value());
    EXPECT_TRUE(missing_value_update.core_inputs.empty());

    coquic::http3::Http3Connection truncated_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    const auto truncated_value_update = truncated_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes({0xc1, 0x7f})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(truncated_value_update).has_value());
    EXPECT_TRUE(truncated_value_update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderStreamBuffersTruncatedLiteralNameInstructions) {
    coquic::http3::Http3Connection incomplete_name_length(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    const auto incomplete_name_length_update = incomplete_name_length.on_core_result(
        receive_result(7, encoder_stream_bytes({0x5f})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(incomplete_name_length_update).has_value());
    EXPECT_TRUE(incomplete_name_length_update.core_inputs.empty());

    auto missing_value_instruction = bytes_from_ints({0x4a});
    append_ascii_bytes(missing_value_instruction, "custom-key");
    coquic::http3::Http3Connection missing_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    const auto missing_value_update = missing_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes(missing_value_instruction)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(missing_value_update).has_value());
    EXPECT_TRUE(missing_value_update.core_inputs.empty());

    auto truncated_value_instruction = missing_value_instruction;
    truncated_value_instruction.push_back(std::byte{0x7f});
    coquic::http3::Http3Connection truncated_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    const auto truncated_value_update = truncated_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes(truncated_value_instruction)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(truncated_value_update).has_value());
    EXPECT_TRUE(truncated_value_update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderStreamConsumesMultibyteStringLiteralLengths) {
    auto instruction = bytes_from_ints({0x4a});
    append_ascii_bytes(instruction, "custom-key");
    instruction.push_back(std::byte{0x7f});
    instruction.push_back(std::byte{0x03});
    instruction.insert(instruction.end(), 130u, static_cast<std::byte>('a'));

    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings =
            {
                .qpack_max_table_capacity = 512,
            },
    });

    const auto update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes(instruction)), coquic::quic::QuicCoreTimePoint{});

    EXPECT_TRUE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest,
     PeerQpackDecoderSectionAcknowledgmentWithoutOutstandingSectionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(11, decoder_stream_bytes({0x81})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decoder_stream_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleInvalidRequestFieldSectionDeltaBasePrefixClosesConnection) {
    coquic::http3::Http3Connection incomplete(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    const auto incomplete_update = incomplete.on_core_result(
        receive_result(0, raw_headers_frame_bytes(bytes_from_ints({0x00}))),
        coquic::quic::QuicCoreTimePoint{});
    const auto incomplete_close = close_input_from(incomplete_update);
    ASSERT_TRUE(incomplete_close.has_value());
    EXPECT_EQ(
        close_application_error_code(incomplete_close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));

    auto overflowing_prefix = bytes_from_ints({0x00});
    const auto overflow = overflowing_qpack_field_section_prefix_bytes();
    overflowing_prefix.insert(overflowing_prefix.end(), overflow.begin(), overflow.end());
    coquic::http3::Http3Connection overflowing(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    const auto overflowing_update =
        overflowing.on_core_result(receive_result(0, raw_headers_frame_bytes(overflowing_prefix)),
                                   coquic::quic::QuicCoreTimePoint{});
    const auto overflowing_close = close_input_from(overflowing_update);
    ASSERT_TRUE(overflowing_close.has_value());
    EXPECT_EQ(
        close_application_error_code(overflowing_close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsTwoDigitResponseStatus) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    const auto result = connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                                               .status = 99,
                                                           });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ConnectionTest, ClientRoleFinishRequestAllowsExactDeclaredContentLength) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 1,
                                         })
                    .has_value());
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("x")).has_value());

    const auto finish = connection.finish_request(0);

    ASSERT_TRUE(finish.has_value());
    EXPECT_TRUE(finish.value());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestFinWithTruncatedFrameTypeVarintResetsStream) {
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    const auto update = connection.on_core_result(receive_result(0, bytes_from_ints({0x40}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

    const auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));

    const auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));
}

TEST(QuicHttp3ConnectionTest, QueueStreamErrorCancelsBlockedPeerRequestAndFlushesDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    coquic::http3::Http3ConnectionTestAccess::set_peer_request_blocked_initial_headers(connection,
                                                                                       0);
    coquic::http3::Http3ConnectionTestAccess::decoder(connection)
        .pending_field_sections.push_back({
            .stream_id = 0,
            .required_insert_count = 1,
        });

    coquic::http3::Http3ConnectionTestAccess::queue_stream_error(
        connection, 0, coquic::http3::Http3ErrorCode::message_error);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 11u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

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
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerRequestStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, QueueStreamErrorCancelsBlockedLocalRequestAndFlushesDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::set_local_request_blocked_response_headers(connection,
                                                                                         0);
    coquic::http3::Http3ConnectionTestAccess::decoder(connection)
        .pending_field_sections.push_back({
            .stream_id = 0,
            .required_insert_count = 1,
        });

    coquic::http3::Http3ConnectionTestAccess::queue_stream_error(
        connection, 0, coquic::http3::Http3ErrorCode::message_error);

    const auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 10u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

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
    EXPECT_FALSE(connection.finish_request(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseStreamWithoutMatchingLocalRequest) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(0, std::span<const std::byte>{}),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

} // namespace

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

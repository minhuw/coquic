#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#define private public
#include "src/quic/http09_server.h"
#undef private
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::QuicCore;
using coquic::quic::QuicCoreResult;
using coquic::quic::QuicCoreSendStreamData;
using coquic::quic::QuicHttp09ServerConfig;
using coquic::quic::QuicHttp09ServerEndpoint;

QuicCoreResult drive_server_endpoint_on_result(QuicHttp09ServerEndpoint &endpoint, QuicCore &server,
                                               const QuicCoreResult &result,
                                               coquic::quic::QuicCoreTimePoint now) {
    const auto endpoint_update = endpoint.on_core_result(result, now);
    return coquic::quic::test::advance_core_with_inputs(server, endpoint_update.core_inputs, now);
}

void drive_quic_handshake(QuicCore &client, QuicCore &server) {
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());
}

TEST(QuicHttp09ServerTest, ServesFileBodyOnRequestedBidirectionalStream) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /hello.txt\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        request_result, server, coquic::quic::test::test_time(1));
    const auto response_from_server = drive_server_endpoint_on_result(
        endpoint, server, request_on_server, coquic::quic::test::test_time(2));
    const auto response_on_client = coquic::quic::test::relay_send_datagrams_to_peer(
        response_from_server, client, coquic::quic::test::test_time(2));
    const auto received = coquic::quic::test::received_stream_data_from(response_on_client);

    ASSERT_FALSE(received.empty());
    std::vector<std::byte> body;
    bool saw_fin = false;
    for (const auto &chunk : received) {
        EXPECT_EQ(chunk.stream_id, 0u);
        body.insert(body.end(), chunk.bytes.begin(), chunk.bytes.end());
        saw_fin = saw_fin || chunk.fin;
    }

    EXPECT_EQ(coquic::quic::test::string_from_bytes(body), "hello");
    EXPECT_TRUE(saw_fin);
}

TEST(QuicHttp09ServerTest, RejectsPathTraversalRequest) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /../../secret\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        request_result, server, coquic::quic::test::test_time(1));

    drive_server_endpoint_on_result(endpoint, server, request_on_server,
                                    coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ServerTest, RejectsRequestLineWithTrailingBytesAfterNewline) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /hello.txt\r\nEXTRA"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        request_result, server, coquic::quic::test::test_time(1));
    drive_server_endpoint_on_result(endpoint, server, request_on_server,
                                    coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ServerTest, RejectsFinBeforeCompleteRequestLine) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /hello.txt"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        request_result, server, coquic::quic::test::test_time(1));
    drive_server_endpoint_on_result(endpoint, server, request_on_server,
                                    coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ServerTest, RejectsOverlongRequestWithoutTerminator) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    std::string overlong = "GET /";
    overlong.append(static_cast<std::string::size_type>(16u * 1024u), 'a');
    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string(overlong),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto request_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        request_result, server, coquic::quic::test::test_time(1));
    drive_server_endpoint_on_result(endpoint, server, request_on_server,
                                    coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(endpoint.pending_requests_.empty());
}

TEST(QuicHttp09ServerTest, ErasesPendingRequestStateAfterCompletedRequest) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto first = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /hello.txt"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto first_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        first, server, coquic::quic::test::test_time(1));
    drive_server_endpoint_on_result(endpoint, server, first_on_server,
                                    coquic::quic::test::test_time(2));
    ASSERT_EQ(endpoint.pending_requests_.size(), 1u);

    const auto second = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(3));
    const auto second_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        second, server, coquic::quic::test::test_time(3));
    drive_server_endpoint_on_result(endpoint, server, second_on_server,
                                    coquic::quic::test::test_time(4));

    EXPECT_FALSE(endpoint.has_failed());
    EXPECT_TRUE(endpoint.pending_requests_.empty());
}

TEST(QuicHttp09ServerTest, ErasesPendingRequestStateWhenStreamFails) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto first = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /hello"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto first_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        first, server, coquic::quic::test::test_time(1));
    drive_server_endpoint_on_result(endpoint, server, first_on_server,
                                    coquic::quic::test::test_time(2));
    ASSERT_EQ(endpoint.pending_requests_.size(), 1u);

    const auto second = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string(""),
            .fin = true,
        },
        coquic::quic::test::test_time(3));
    const auto second_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        second, server, coquic::quic::test::test_time(3));
    drive_server_endpoint_on_result(endpoint, server, second_on_server,
                                    coquic::quic::test::test_time(4));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(endpoint.pending_requests_.empty());
}

TEST(QuicHttp09ServerTest, MissingFileCausesStreamLocalResetWithoutEndpointFailure) {
    coquic::quic::test::ScopedTempDir document_root;

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /missing.txt\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_on_server = coquic::quic::test::relay_send_datagrams_to_peer(
        request_result, server, coquic::quic::test::test_time(1));
    const auto endpoint_update =
        endpoint.on_core_result(request_on_server, coquic::quic::test::test_time(2));

    ASSERT_EQ(endpoint_update.core_inputs.size(), 2u);
    EXPECT_TRUE(
        std::holds_alternative<coquic::quic::QuicCoreResetStream>(endpoint_update.core_inputs[0]));
    EXPECT_TRUE(
        std::holds_alternative<coquic::quic::QuicCoreStopSending>(endpoint_update.core_inputs[1]));
    EXPECT_FALSE(endpoint.has_failed());
}

} // namespace

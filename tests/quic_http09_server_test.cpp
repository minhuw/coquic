#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <variant>
#include <vector>

#include "src/quic/http09_server.h"
#include "tests/quic_test_utils.h"

namespace coquic::quic::test {

struct QuicHttp09ServerEndpointTestPeer {
    static std::size_t pending_request_count(const QuicHttp09ServerEndpoint &endpoint) {
        return endpoint.pending_requests_.size();
    }

    static std::size_t pending_response_count(const QuicHttp09ServerEndpoint &endpoint) {
        return endpoint.pending_responses_.size();
    }

    static void inject_bad_pending_response(QuicHttp09ServerEndpoint &endpoint,
                                            std::uint64_t stream_id,
                                            const std::filesystem::path &path) {
        auto &response = endpoint.pending_responses_[stream_id];
        response.file = std::ifstream(path, std::ios::binary);
        response.file.setstate(std::ios::badbit);
    }
};

} // namespace coquic::quic::test

namespace {

using coquic::quic::QuicCore;
using coquic::quic::QuicCoreEffect;
using coquic::quic::QuicCoreReceiveStreamData;
using coquic::quic::QuicCoreResult;
using coquic::quic::QuicCoreSendStreamData;
using coquic::quic::QuicHttp09EndpointUpdate;
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

QuicCoreResult single_receive_result(std::uint64_t stream_id, std::string_view text, bool fin) {
    QuicCoreResult result;
    result.effects.push_back(QuicCoreEffect{
        QuicCoreReceiveStreamData{
            .stream_id = stream_id,
            .bytes = coquic::quic::test::bytes_from_string(text),
            .fin = fin,
        },
    });
    return result;
}

std::vector<QuicCoreSendStreamData>
send_stream_inputs_from(const QuicHttp09EndpointUpdate &update) {
    std::vector<QuicCoreSendStreamData> out;
    for (const auto &input : update.core_inputs) {
        if (const auto *send = std::get_if<QuicCoreSendStreamData>(&input)) {
            out.push_back(*send);
        }
    }
    return out;
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

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});
    const auto update =
        endpoint.on_core_result(single_receive_result(0, "GET /hello.txt\r\nEXTRA", true),
                                coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(update.terminal_failure);
}

TEST(QuicHttp09ServerTest, RejectsFinBeforeCompleteRequestLine) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});
    const auto update = endpoint.on_core_result(single_receive_result(0, "GET /hello.txt", true),
                                                coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(update.terminal_failure);
}

TEST(QuicHttp09ServerTest, RejectsOverlongRequestWithoutTerminator) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    std::string overlong = "GET /";
    overlong.append(static_cast<std::string::size_type>(16u * 1024u), 'a');
    const auto update = endpoint.on_core_result(single_receive_result(0, overlong, false),
                                                coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_EQ(coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_request_count(endpoint),
              0u);
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
    ASSERT_EQ(coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_request_count(endpoint),
              1u);

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
    EXPECT_EQ(coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_request_count(endpoint),
              0u);
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
    ASSERT_EQ(coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_request_count(endpoint),
              1u);

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
    EXPECT_EQ(coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_request_count(endpoint),
              0u);
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

TEST(QuicHttp09ServerTest, DirectoryRequestCausesStreamLocalResetWithoutEndpointFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    std::filesystem::create_directories(document_root.path() / "assets");

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /assets\r\n"),
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

TEST(QuicHttp09ServerTest, UnreadableFileCausesStreamLocalResetWithoutEndpointFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("secret.txt", "top-secret");
    std::filesystem::permissions(document_root.path() / "secret.txt", std::filesystem::perms::none);

    QuicCore client(coquic::quic::test::make_client_core_config());
    QuicCore server(coquic::quic::test::make_server_core_config());
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    drive_quic_handshake(client, server);

    const auto request_result = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /secret.txt\r\n"),
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

TEST(QuicHttp09ServerTest, RejectsNonGetRequestLine) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto update = endpoint.on_core_result(
        single_receive_result(0, "POST /hello.txt\r\n", true), coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(update.terminal_failure);
}

TEST(QuicHttp09ServerTest, RejectsReceiveDataOnServerInitiatedStreamId) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto update = endpoint.on_core_result(
        single_receive_result(1, "GET /hello.txt\r\n", true), coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(update.terminal_failure);
}

TEST(QuicHttp09ServerTest, RejectsReceiveDataOnPeerInitiatedUnidirectionalStreamId) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto update = endpoint.on_core_result(
        single_receive_result(2, "GET /hello.txt\r\n", true), coquic::quic::test::test_time(2));

    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(update.terminal_failure);
}

TEST(QuicHttp09ServerTest, KeepsPendingRequestOpenAcrossEmptyNonFinChunks) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto update = endpoint.on_core_result(single_receive_result(0, "", false),
                                                coquic::quic::test::test_time(2));

    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(endpoint.has_failed());
    EXPECT_EQ(coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_request_count(endpoint),
              1u);
}

TEST(QuicHttp09ServerTest, PollWithoutPendingResponsesHasNoWork) {
    coquic::quic::test::ScopedTempDir document_root;
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto update = endpoint.poll(coquic::quic::test::test_time(1));
    EXPECT_FALSE(update.has_pending_work);
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp09ServerTest, FailsWhenCoreReportsLocalError) {
    coquic::quic::test::ScopedTempDir document_root;
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    coquic::quic::QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = std::nullopt,
    };

    const auto update = endpoint.on_core_result(result, coquic::quic::test::test_time(1));
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ServerTest, PollAfterFailureReturnsTerminalFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    coquic::quic::QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = std::nullopt,
    };
    endpoint.on_core_result(result, coquic::quic::test::test_time(1));

    const auto update = endpoint.poll(coquic::quic::test::test_time(2));
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
}

TEST(QuicHttp09ServerTest, OnCoreResultAfterFailureReturnsTerminalFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    coquic::quic::QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = std::nullopt,
    };
    endpoint.on_core_result(result, coquic::quic::test::test_time(1));

    const auto repeated =
        endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(2));
    EXPECT_TRUE(repeated.terminal_failure);
    EXPECT_FALSE(repeated.terminal_success);
}

TEST(QuicHttp09ServerTest, EmptyFileStillProducesFinOnlyResponse) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("empty.txt", "");

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto update = endpoint.on_core_result(
        single_receive_result(0, "GET /empty.txt\r\n", true), coquic::quic::test::test_time(1));
    ASSERT_FALSE(endpoint.has_failed());
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_TRUE(sends[0].bytes.empty());
    EXPECT_TRUE(sends[0].fin);
    EXPECT_FALSE(update.has_pending_work);
}

TEST(QuicHttp09ServerTest, RejectsReceiveDataAfterStreamAlreadyCompleted) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto first = endpoint.on_core_result(single_receive_result(0, "GET /hello.txt\r\n", true),
                                               coquic::quic::test::test_time(1));
    EXPECT_FALSE(first.terminal_failure);
    EXPECT_FALSE(endpoint.has_failed());

    const auto second = endpoint.on_core_result(
        single_receive_result(0, "GET /hello.txt\r\n", true), coquic::quic::test::test_time(2));
    EXPECT_TRUE(second.terminal_failure);
    EXPECT_FALSE(second.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ServerTest, StreamsLargeFileIncrementallyAcrossPollCalls) {
    coquic::quic::test::ScopedTempDir document_root;
    std::string body;
    body.append(static_cast<std::string::size_type>(64u * 1024u), 'x');
    document_root.write_file("large.bin", body);

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    auto update = endpoint.on_core_result(single_receive_result(0, "GET /large.bin\r\n", true),
                                          coquic::quic::test::test_time(1));
    ASSERT_FALSE(endpoint.has_failed());
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_TRUE(update.has_pending_work);

    std::size_t total = sends[0].bytes.size();
    bool saw_fin = sends[0].fin;
    for (int i = 0; i < 16 && !saw_fin; ++i) {
        update = endpoint.poll(coquic::quic::test::test_time(2 + i));
        sends = send_stream_inputs_from(update);
        ASSERT_LE(sends.size(), 1u);
        if (sends.empty()) {
            continue;
        }
        total += sends[0].bytes.size();
        saw_fin = saw_fin || sends[0].fin;
    }

    EXPECT_TRUE(saw_fin);
    EXPECT_EQ(total, body.size());
}

TEST(QuicHttp09ServerTest, PollProcessesAtMostOnePendingResponsePerCall) {
    coquic::quic::test::ScopedTempDir document_root;
    std::string body;
    body.append(static_cast<std::string::size_type>(64u * 1024u), 'x');
    document_root.write_file("alpha.bin", body);
    document_root.write_file("beta.bin", body);

    QuicCoreResult result;
    result.effects.push_back(QuicCoreEffect{
        QuicCoreReceiveStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /alpha.bin\r\n"),
            .fin = true,
        },
    });
    result.effects.push_back(QuicCoreEffect{
        QuicCoreReceiveStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("GET /beta.bin\r\n"),
            .fin = true,
        },
    });

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto initial = endpoint.on_core_result(result, coquic::quic::test::test_time(1));
    EXPECT_FALSE(initial.terminal_failure);
    EXPECT_EQ(
        coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_response_count(endpoint), 2u);

    const auto update = endpoint.poll(coquic::quic::test::test_time(2));
    const auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_TRUE(update.has_pending_work);
    EXPECT_EQ(
        coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_response_count(endpoint), 2u);
}

TEST(QuicHttp09ServerTest, RejectsMoreRequestDataWhileResponseRemainsPending) {
    coquic::quic::test::ScopedTempDir document_root;
    std::string body;
    body.append(static_cast<std::string::size_type>(64u * 1024u), 'x');
    document_root.write_file("large.bin", body);

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});

    const auto first = endpoint.on_core_result(single_receive_result(0, "GET /large.bin\r\n", true),
                                               coquic::quic::test::test_time(1));
    EXPECT_FALSE(first.terminal_failure);
    EXPECT_EQ(
        coquic::quic::test::QuicHttp09ServerEndpointTestPeer::pending_response_count(endpoint), 1u);

    const auto second = endpoint.on_core_result(single_receive_result(0, "late-data", false),
                                                coquic::quic::test::test_time(2));
    EXPECT_TRUE(second.terminal_failure);
    EXPECT_FALSE(second.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ServerTest, PollQueuesStreamLocalErrorForBadPendingResponse) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello");

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = document_root.path()});
    coquic::quic::test::QuicHttp09ServerEndpointTestPeer::inject_bad_pending_response(
        endpoint, 0, document_root.path() / "hello.txt");

    const auto update = endpoint.poll(coquic::quic::test::test_time(1));
    ASSERT_EQ(update.core_inputs.size(), 2u);
    EXPECT_TRUE(std::holds_alternative<coquic::quic::QuicCoreResetStream>(update.core_inputs[0]));
    EXPECT_TRUE(std::holds_alternative<coquic::quic::QuicCoreStopSending>(update.core_inputs[1]));
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(update.has_pending_work);
}

} // namespace

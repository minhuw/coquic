#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <variant>
#include <vector>

#include "src/quic/http09_client.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::QuicCoreEffect;
using coquic::quic::QuicCoreReceiveStreamData;
using coquic::quic::QuicCoreResult;
using coquic::quic::QuicCoreSendStreamData;
using coquic::quic::QuicCoreStateChange;
using coquic::quic::QuicCoreStateEvent;
using coquic::quic::QuicHttp09ClientConfig;
using coquic::quic::QuicHttp09ClientEndpoint;
using coquic::quic::QuicHttp09EndpointUpdate;
using coquic::quic::QuicHttp09Request;

QuicCoreResult handshake_ready_result() {
    QuicCoreResult result;
    result.effects.push_back(QuicCoreEffect{
        QuicCoreStateEvent{
            .change = QuicCoreStateChange::handshake_ready,
        },
    });
    return result;
}

QuicCoreResult receive_result(std::uint64_t stream_id, std::string_view text, bool fin) {
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

std::string read_file_bytes(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

QuicHttp09Request request_for_target(std::string target) {
    const auto path = std::filesystem::path(target).relative_path();
    return QuicHttp09Request{
        .url = std::string("https://example.test") + target,
        .authority = "example.test",
        .request_target = std::move(target),
        .relative_output_path = path,
    };
}

TEST(QuicHttp09ClientTest, OpensOneBidirectionalStreamPerRequestAfterHandshake) {
    const auto now = coquic::quic::test::test_time();
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests =
            {
                request_for_target("/alpha.txt"),
                request_for_target("/beta.txt"),
            },
        .download_root = std::filesystem::path("/downloads"),
    });

    const auto on_handshake = endpoint.on_core_result(handshake_ready_result(), now);
    EXPECT_TRUE(on_handshake.has_pending_work);

    const auto update = endpoint.poll(now);
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, coquic::quic::test::bytes_from_string("GET /alpha.txt\r\n"));
    EXPECT_TRUE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 4u);
    EXPECT_EQ(sends[1].bytes, coquic::quic::test::bytes_from_string("GET /beta.txt\r\n"));
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp09ClientTest, WritesDownloadedResponseBodiesToFilesystem) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/hello.txt")},
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto on_receive =
        endpoint.on_core_result(receive_result(0, "hello", true), coquic::quic::test::test_time(1));
    EXPECT_TRUE(on_receive.terminal_success);
    EXPECT_FALSE(on_receive.terminal_failure);

    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello");
}

TEST(QuicHttp09ClientTest, ReportsSuccessOnlyAfterAllStreamsFinishWithFin) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests =
            {
                request_for_target("/a.txt"),
                request_for_target("/b.txt"),
            },
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto first = endpoint.on_core_result(receive_result(0, "partial", false),
                                               coquic::quic::test::test_time(1));
    EXPECT_FALSE(first.terminal_success);
    EXPECT_FALSE(first.terminal_failure);

    const auto second =
        endpoint.on_core_result(receive_result(4, "done", true), coquic::quic::test::test_time(2));
    EXPECT_FALSE(second.terminal_success);
    EXPECT_FALSE(second.terminal_failure);

    const auto third =
        endpoint.on_core_result(receive_result(0, "", true), coquic::quic::test::test_time(3));
    EXPECT_TRUE(third.terminal_success);
    EXPECT_FALSE(third.terminal_failure);
}

TEST(QuicHttp09ClientTest, AppendsMultipleReceiveChunksToSameOutputFile) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/chunked.txt")},
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto first =
        endpoint.on_core_result(receive_result(0, "hel", false), coquic::quic::test::test_time(1));
    EXPECT_FALSE(first.terminal_success);
    EXPECT_FALSE(first.terminal_failure);
    EXPECT_EQ(read_file_bytes(download_root.path() / "chunked.txt"), "hel");

    const auto second =
        endpoint.on_core_result(receive_result(0, "lo", true), coquic::quic::test::test_time(2));
    EXPECT_TRUE(second.terminal_success);
    EXPECT_FALSE(second.terminal_failure);
    EXPECT_EQ(read_file_bytes(download_root.path() / "chunked.txt"), "hello");
}

TEST(QuicHttp09ClientTest, FailsDeterministicallyWhenDirectoryCreationFails) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir temp_root;
    const auto blocking_file = temp_root.path() / "not-a-directory";
    temp_root.write_file("not-a-directory", "x");

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/out.txt")},
        .download_root = blocking_file,
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto update =
        endpoint.on_core_result(receive_result(0, "data", true), coquic::quic::test::test_time(1));

    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

} // namespace

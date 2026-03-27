#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
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
using coquic::quic::QuicCoreLocalErrorCode;
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

QuicCoreResult failed_state_result() {
    QuicCoreResult result;
    result.effects.push_back(QuicCoreEffect{
        QuicCoreStateEvent{
            .change = QuicCoreStateChange::failed,
        },
    });
    return result;
}

QuicCoreStateChange invalid_state_change() {
    constexpr std::uint8_t raw = 0xff;
    QuicCoreStateChange change{};
    std::memcpy(&change, &raw, sizeof(change));
    return change;
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

QuicCoreResult local_error_result(QuicCoreLocalErrorCode code, std::uint64_t stream_id) {
    QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = code,
        .stream_id = stream_id,
    };
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

TEST(QuicHttp09ClientTest, PollBeforeHandshakeHasNoPendingWork) {
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/alpha.txt")},
        .download_root = std::filesystem::path("/downloads"),
    });

    const auto update = endpoint.poll(coquic::quic::test::test_time());
    EXPECT_FALSE(update.has_pending_work);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp09ClientTest, OpensNextBidirectionalStreamAfterHandshake) {
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

    const auto first_update = endpoint.poll(now);
    const auto first_sends = send_stream_inputs_from(first_update);

    ASSERT_EQ(first_sends.size(), 1u);
    EXPECT_EQ(first_sends[0].stream_id, 0u);
    EXPECT_EQ(first_sends[0].bytes, coquic::quic::test::bytes_from_string("GET /alpha.txt\r\n"));
    EXPECT_TRUE(first_sends[0].fin);

    const auto first_accepted =
        endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(1));
    EXPECT_TRUE(first_accepted.has_pending_work);

    const auto second_update = endpoint.poll(coquic::quic::test::test_time(1));
    const auto second_sends = send_stream_inputs_from(second_update);
    ASSERT_EQ(second_sends.size(), 1u);
    EXPECT_EQ(second_sends[0].stream_id, 4u);
    EXPECT_EQ(second_sends[0].bytes, coquic::quic::test::bytes_from_string("GET /beta.txt\r\n"));
    EXPECT_TRUE(second_sends[0].fin);
}

TEST(QuicHttp09ClientTest, DoesNotReissueRequestsAfterInitialPoll) {
    const auto now = coquic::quic::test::test_time();
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/alpha.txt")},
        .download_root = std::filesystem::path("/downloads"),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    const auto first = endpoint.poll(now);
    EXPECT_FALSE(first.core_inputs.empty());

    const auto second = endpoint.poll(coquic::quic::test::test_time(1));
    EXPECT_FALSE(second.has_pending_work);
    EXPECT_FALSE(second.terminal_success);
    EXPECT_FALSE(second.terminal_failure);
    EXPECT_TRUE(second.core_inputs.empty());
}

TEST(QuicHttp09ClientTest, CompletesImmediatelyWhenNoRequestsAreConfigured) {
    const auto now = coquic::quic::test::test_time();
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {},
        .download_root = std::filesystem::path("/downloads"),
    });

    const auto on_handshake = endpoint.on_core_result(handshake_ready_result(), now);
    EXPECT_TRUE(on_handshake.terminal_success);
    EXPECT_FALSE(on_handshake.terminal_failure);
    EXPECT_TRUE(endpoint.is_complete());
    EXPECT_FALSE(endpoint.has_failed());
}

TEST(QuicHttp09ClientTest, IgnoresUnknownStateEventsAfterCompletion) {
    const auto now = coquic::quic::test::test_time();
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {},
        .download_root = std::filesystem::path("/downloads"),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    const auto initial = endpoint.poll(now);
    ASSERT_TRUE(initial.terminal_success);

    QuicCoreResult result;
    result.effects.push_back(QuicCoreEffect{
        QuicCoreStateEvent{
            .change = invalid_state_change(),
        },
    });

    const auto update = endpoint.on_core_result(result, coquic::quic::test::test_time(1));
    EXPECT_TRUE(update.terminal_success);
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(endpoint.is_complete());
    EXPECT_FALSE(endpoint.has_failed());
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
    endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(1));
    endpoint.poll(coquic::quic::test::test_time(1));
    endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(2));

    const auto first = endpoint.on_core_result(receive_result(0, "partial", false),
                                               coquic::quic::test::test_time(3));
    EXPECT_FALSE(first.terminal_success);
    EXPECT_FALSE(first.terminal_failure);

    const auto second =
        endpoint.on_core_result(receive_result(4, "done", true), coquic::quic::test::test_time(4));
    EXPECT_FALSE(second.terminal_success);
    EXPECT_FALSE(second.terminal_failure);

    const auto third =
        endpoint.on_core_result(receive_result(0, "", true), coquic::quic::test::test_time(5));
    EXPECT_TRUE(third.terminal_success);
    EXPECT_FALSE(third.terminal_failure);
}

TEST(QuicHttp09ClientTest, RetriesOpeningRequestAfterStreamLimitBackpressure) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests =
            {
                request_for_target("/alpha.txt"),
                request_for_target("/beta.txt"),
            },
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);
    endpoint.on_core_result(QuicCoreResult{}, coquic::quic::test::test_time(1));

    const auto blocked_send = endpoint.poll(coquic::quic::test::test_time(2));
    const auto blocked_sends = send_stream_inputs_from(blocked_send);
    ASSERT_EQ(blocked_sends.size(), 1u);
    EXPECT_EQ(blocked_sends[0].stream_id, 4u);

    const auto blocked =
        endpoint.on_core_result(local_error_result(QuicCoreLocalErrorCode::invalid_stream_id, 4),
                                coquic::quic::test::test_time(3));
    EXPECT_TRUE(blocked.handled_local_error);
    EXPECT_FALSE(blocked.terminal_failure);
    EXPECT_FALSE(blocked.has_pending_work);

    const auto completed =
        endpoint.on_core_result(receive_result(0, "done", true), coquic::quic::test::test_time(4));
    EXPECT_FALSE(completed.terminal_failure);
    EXPECT_TRUE(completed.has_pending_work);

    const auto retried = endpoint.poll(coquic::quic::test::test_time(5));
    const auto retried_sends = send_stream_inputs_from(retried);
    ASSERT_EQ(retried_sends.size(), 1u);
    EXPECT_EQ(retried_sends[0].stream_id, 4u);
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

TEST(QuicHttp09ClientTest, FailsWhenCoreReportsLocalError) {
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/hello.txt")},
        .download_root = std::filesystem::path("/downloads"),
    });

    QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = std::nullopt,
    };

    const auto update = endpoint.on_core_result(result, coquic::quic::test::test_time());
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());

    const auto repeated = endpoint.on_core_result(receive_result(0, "ignored", true),
                                                  coquic::quic::test::test_time(1));
    EXPECT_TRUE(repeated.terminal_failure);
}

TEST(QuicHttp09ClientTest, FailsWhenCoreReportsFailedStateEvent) {
    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/hello.txt")},
        .download_root = std::filesystem::path("/downloads"),
    });

    const auto update =
        endpoint.on_core_result(failed_state_result(), coquic::quic::test::test_time());
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
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

TEST(QuicHttp09ClientTest, FailsWhenConfiguredRequestTargetEscapesDownloadRoot) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests =
            {
                QuicHttp09Request{
                    .url = "https://example.test//escape",
                    .authority = "example.test",
                    .request_target = "//escape",
                    .relative_output_path = std::filesystem::path("escape"),
                },
            },
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto update =
        endpoint.on_core_result(receive_result(0, "data", true), coquic::quic::test::test_time(1));
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ClientTest, FailsWhenResponseArrivesOnUnknownStream) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/hello.txt")},
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto update =
        endpoint.on_core_result(receive_result(4, "oops", true), coquic::quic::test::test_time(1));
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());

    const auto polled = endpoint.poll(coquic::quic::test::test_time(2));
    EXPECT_TRUE(polled.terminal_failure);
    EXPECT_FALSE(polled.terminal_success);
}

TEST(QuicHttp09ClientTest, FailsWhenCompletedStreamReceivesMoreData) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/hello.txt")},
        .download_root = download_root.path(),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto first =
        endpoint.on_core_result(receive_result(0, "hello", true), coquic::quic::test::test_time(1));
    EXPECT_TRUE(first.terminal_success);
    EXPECT_TRUE(endpoint.is_complete());

    const auto second = endpoint.on_core_result(receive_result(0, "again", false),
                                                coquic::quic::test::test_time(2));
    EXPECT_TRUE(second.terminal_failure);
    EXPECT_FALSE(second.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ClientTest, FailsWhenOutputWriteReportsStreamError) {
    const auto now = coquic::quic::test::test_time();
    ASSERT_TRUE(std::filesystem::exists("/dev/full"));

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/full")},
        .download_root = std::filesystem::path("/dev"),
    });

    endpoint.on_core_result(handshake_ready_result(), now);
    endpoint.poll(now);

    const auto update =
        endpoint.on_core_result(receive_result(0, "data", true), coquic::quic::test::test_time(1));
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_FALSE(update.terminal_success);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp09ClientTest, FailsWhenOutputPathCannotBeOpened) {
    const auto now = coquic::quic::test::test_time();
    coquic::quic::test::ScopedTempDir download_root;
    std::filesystem::create_directory(download_root.path() / "existing-dir");

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = {request_for_target("/existing-dir")},
        .download_root = download_root.path(),
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

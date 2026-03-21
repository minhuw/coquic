#include <filesystem>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/http09.h"

namespace {

std::vector<std::byte> bytes_from_ascii(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char ch : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
}

TEST(QuicHttp09Test, ParsesRequestsEnvAsSpaceSeparatedAbsoluteUrls) {
    const auto parsed =
        coquic::quic::parse_http09_requests_env("https://example.test/a https://example.test/b/c");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed.value().size(), 2u);
    EXPECT_EQ(parsed.value()[0].request_target, "/a");
    EXPECT_EQ(parsed.value()[1].request_target, "/b/c");
}

TEST(QuicHttp09Test, RejectsMixedAuthoritiesInSingleClientRun) {
    const auto parsed =
        coquic::quic::parse_http09_requests_env("https://a.test/x https://b.test/y");
    EXPECT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, coquic::quic::CodecErrorCode::http09_parse_error);
}

TEST(QuicHttp09Test, RejectsUnsafeRequestTargetsDuringRequestEnvParse) {
    EXPECT_FALSE(
        coquic::quic::parse_http09_requests_env("https://example.test/../secret").has_value());
    EXPECT_FALSE(
        coquic::quic::parse_http09_requests_env("https://example.test/a/../b").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_requests_env("https://example.test/a?b").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_requests_env("https://example.test/a#b").has_value());
}

TEST(QuicHttp09Test, UsesGenerousTransferFlowControlProfileForTransferCase) {
    const auto config = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    EXPECT_EQ(config.initial_max_data, 32u * 1024u * 1024u);
    EXPECT_EQ(config.initial_max_stream_data_bidi_local, 16u * 1024u * 1024u);
}

TEST(QuicHttp09Test, ResolvesRequestTargetUnderRootWithoutDiscardingRoot) {
    const auto resolved =
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/a/b.bin");
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved.value(), std::filesystem::path("/tmp/downloads/a/b.bin"));
}

TEST(QuicHttp09Test, RejectsTraversalQueriesAndFragmentsWhenResolvingPath) {
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/../secret").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/a/../b").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/a?b").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/a#b").has_value());
}

TEST(QuicHttp09Test, ParsesRequestTargetFromCrLfTerminatedLine) {
    const auto parsed = coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /a\r\n"));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed.value(), "/a");
}

TEST(QuicHttp09Test, ParsesRequestTargetFromLfTerminatedLine) {
    const auto parsed = coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /b\n"));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed.value(), "/b");
}

TEST(QuicHttp09Test, ParsesOnlyFirstRequestLineWhenBufferHasTrailingBytes) {
    const auto parsed =
        coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /c\r\nEXTRA"));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed.value(), "/c");
}

TEST(QuicHttp09Test, ReportsTruncatedInputForPartialRequestLine) {
    const auto parsed = coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /partial"));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicHttp09Test, RejectsTabCharacterInRequestTarget) {
    const auto parsed =
        coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /\tbad\r\n"));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, coquic::quic::CodecErrorCode::http09_parse_error);
}

} // namespace

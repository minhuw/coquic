#include <filesystem>

#include <gtest/gtest.h>

#include "src/quic/http09.h"

namespace {

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
}

TEST(QuicHttp09Test, UsesSmallTransferFlowControlProfileForTransferCase) {
    const auto config = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    EXPECT_EQ(config.initial_max_data, 64u * 1024u);
    EXPECT_EQ(config.initial_max_stream_data_bidi_local, 16u * 1024u);
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
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/a?b").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/a#b").has_value());
}

} // namespace

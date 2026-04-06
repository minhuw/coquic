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

TEST(QuicHttp09Test, RejectsEmptyRequestsEnvAndUrlsWithoutAuthority) {
    EXPECT_FALSE(coquic::quic::parse_http09_requests_env("").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_requests_env("https://").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_requests_env("https:///a").has_value());
}

TEST(QuicHttp09Test, AcceptsRequestsEnvWithLeadingAndTrailingSpaces) {
    const auto parsed = coquic::quic::parse_http09_requests_env(
        "  https://example.test/a  https://example.test/b/c   ");
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed.value().size(), 2u);
    EXPECT_EQ(parsed.value()[0].request_target, "/a");
    EXPECT_EQ(parsed.value()[1].request_target, "/b/c");
}

TEST(QuicHttp09Test, NormalizesAuthorityWithoutPathToSlashAndRejectsWrongScheme) {
    const auto parsed = coquic::quic::parse_http09_requests_env("https://example.test");
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed.value().size(), 1u);
    EXPECT_EQ(parsed.value()[0].authority, "example.test");
    EXPECT_EQ(parsed.value()[0].request_target, "/");

    EXPECT_FALSE(coquic::quic::parse_http09_requests_env("http://example.test/a").has_value());
}

TEST(QuicHttp09Test, UsesGenerousTransferFlowControlProfileForTransferCase) {
    const auto config = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    EXPECT_EQ(config.initial_max_data, 32u * 1024u * 1024u);
    EXPECT_EQ(config.initial_max_stream_data_bidi_local, 16u * 1024u * 1024u);
}

TEST(QuicHttp09Test, MigrationAliasesReuseTransferTransportAndTlsProfiles) {
    const auto transfer_client = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    const auto transfer_server = coquic::quic::http09_server_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    const auto transfer_tls = coquic::quic::http09_tls_cipher_suites_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);

    for (const auto testcase : {coquic::quic::QuicHttp09Testcase::rebind_port,
                                coquic::quic::QuicHttp09Testcase::rebind_addr,
                                coquic::quic::QuicHttp09Testcase::connectionmigration}) {
        const auto client = coquic::quic::http09_client_transport_for_testcase(testcase);
        EXPECT_EQ(client.initial_max_data, transfer_client.initial_max_data);
        EXPECT_EQ(client.initial_max_stream_data_bidi_local,
                  transfer_client.initial_max_stream_data_bidi_local);

        const auto server = coquic::quic::http09_server_transport_for_testcase(testcase);
        EXPECT_EQ(server.initial_max_streams_bidi, transfer_server.initial_max_streams_bidi);

        EXPECT_EQ(coquic::quic::http09_tls_cipher_suites_for_testcase(testcase), transfer_tls);
    }
}

TEST(QuicHttp09Test, KeyUpdateReusesTransferTransportAndTlsProfiles) {
    const auto transfer_client = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    const auto transfer_server = coquic::quic::http09_server_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);
    const auto transfer_tls = coquic::quic::http09_tls_cipher_suites_for_testcase(
        coquic::quic::QuicHttp09Testcase::transfer);

    const auto keyupdate_client = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::keyupdate);
    EXPECT_EQ(keyupdate_client.initial_max_data, transfer_client.initial_max_data);
    EXPECT_EQ(keyupdate_client.initial_max_stream_data_bidi_local,
              transfer_client.initial_max_stream_data_bidi_local);

    const auto keyupdate_server = coquic::quic::http09_server_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::keyupdate);
    EXPECT_EQ(keyupdate_server.initial_max_streams_bidi, transfer_server.initial_max_streams_bidi);

    EXPECT_EQ(coquic::quic::http09_tls_cipher_suites_for_testcase(
                  coquic::quic::QuicHttp09Testcase::keyupdate),
              transfer_tls);
}

TEST(QuicHttp09Test, UsesExtendedIdleTimeoutProfileForMulticonnectCase) {
    const auto config = coquic::quic::http09_client_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::multiconnect);
    EXPECT_EQ(config.max_idle_timeout, 180000u);
}

TEST(QuicHttp09Test, UsesExpandedServerStreamProfileForResumptionAndZeroRttCases) {
    const auto resumption = coquic::quic::http09_server_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::resumption);
    EXPECT_EQ(resumption.initial_max_streams_bidi, 64u);

    const auto zero_rtt = coquic::quic::http09_server_transport_for_testcase(
        coquic::quic::QuicHttp09Testcase::zerortt);
    EXPECT_EQ(zero_rtt.initial_max_streams_bidi, 64u);
}

TEST(QuicHttp09Test, UsesStableZeroRttContextAcrossDifferentGetRequestSets) {
    const auto warmup =
        coquic::quic::parse_http09_requests_env("https://example.test/warmup-only.txt");
    ASSERT_TRUE(warmup.has_value());

    const auto transfer = coquic::quic::parse_http09_requests_env(
        "https://example.test/warmup-only.txt https://example.test/final.txt");
    ASSERT_TRUE(transfer.has_value());

    const auto warmup_context = coquic::quic::http09_zero_rtt_application_context(warmup.value());
    const auto transfer_context =
        coquic::quic::http09_zero_rtt_application_context(transfer.value());
    EXPECT_FALSE(warmup_context.empty());
    EXPECT_EQ(warmup_context, transfer_context);
}

TEST(QuicHttp09Test, EmptyRequestSetProducesEmptyZeroRttContext) {
    const auto context = coquic::quic::http09_zero_rtt_application_context(
        std::span<const coquic::quic::QuicHttp09Request>{});
    EXPECT_TRUE(context.empty());
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

TEST(QuicHttp09Test, RejectsMalformedTargetsWhenResolvingPath) {
    EXPECT_FALSE(coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "relative").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "//absolute").has_value());
    EXPECT_FALSE(
        coquic::quic::resolve_http09_path_under_root("/tmp/downloads", "/nested/.").has_value());
}

TEST(QuicHttp09Test, RejectsRelativeRootsThatLoseTheirLexicalPrefix) {
    EXPECT_FALSE(coquic::quic::resolve_http09_path_under_root(".", "/payload.bin").has_value());
}

TEST(QuicHttp09Test, RejectsAbsoluteHttpsRequestWithDoubleSlashPath) {
    EXPECT_FALSE(
        coquic::quic::parse_http09_requests_env("https://example.test//absolute").has_value());
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

TEST(QuicHttp09Test, RejectsEmptyRequestLine) {
    const auto parsed = coquic::quic::parse_http09_request_target(bytes_from_ascii("\n"));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, coquic::quic::CodecErrorCode::http09_parse_error);
}

TEST(QuicHttp09Test, RejectsTabCharacterInRequestTarget) {
    const auto parsed =
        coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /\tbad\r\n"));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, coquic::quic::CodecErrorCode::http09_parse_error);
}

TEST(QuicHttp09Test, RejectsDeleteCharacterInRequestTarget) {
    const auto parsed =
        coquic::quic::parse_http09_request_target(bytes_from_ascii("GET /\x7f\r\n"));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, coquic::quic::CodecErrorCode::http09_parse_error);
}

TEST(QuicHttp09Test, RejectsEmptyAndRelativeRequestTargets) {
    EXPECT_FALSE(
        coquic::quic::parse_http09_request_target(bytes_from_ascii("GET \r\n")).has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_request_target(bytes_from_ascii("GET relative\r\n"))
                     .has_value());
}

} // namespace

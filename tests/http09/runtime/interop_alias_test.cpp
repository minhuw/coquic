#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialRunnerAliasesViaCliFlags) {
    const char *multiconnect_argv[] = {"coquic",       "interop-client", "--testcase",
                                       "multiconnect", "--requests",     "https://localhost/a.txt"};
    const auto multiconnect =
        coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(multiconnect_argv));
    ASSERT_TRUE(multiconnect.has_value());
    const auto multiconnect_runtime = multiconnect.value_or(coquic::quic::Http09RuntimeConfig{});
    EXPECT_EQ(multiconnect_runtime.testcase, coquic::quic::QuicHttp09Testcase::multiconnect);

    const char *chacha20_argv[] = {"coquic",   "interop-client", "--testcase",
                                   "chacha20", "--requests",     "https://localhost/a.txt"};
    const auto chacha20 =
        coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(chacha20_argv));
    ASSERT_TRUE(chacha20.has_value());
    const auto chacha20_runtime = chacha20.value_or(coquic::quic::Http09RuntimeConfig{});
    EXPECT_EQ(chacha20_runtime.testcase, coquic::quic::QuicHttp09Testcase::chacha20);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialMulticonnectTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "multiconnect");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt https://localhost/b.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialV2Testcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "v2");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase, coquic::quic::QuicHttp09Testcase::v2);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialEcnTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "ecn");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase, coquic::quic::QuicHttp09Testcase::ecn);
}

TEST(QuicHttp09RuntimeTest, RuntimeTreatsAmplificationLimitEnvironmentAliasAsTransfer) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "amplificationlimit");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::transfer);
}

TEST(QuicHttp09RuntimeTest, RuntimeTreatsAmplificationLimitCliAliasAsTransfer) {
    const char *argv[] = {"coquic",     "interop-client",
                          "--testcase", "amplificationlimit",
                          "--requests", "https://localhost/a.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::transfer);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialResumptionAndZeroRttTestcases) {
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "resumption");
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
                  coquic::quic::QuicHttp09Testcase::resumption);
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
                  coquic::quic::QuicHttp09Testcase::zerortt);
    }
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialKeyUpdateTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "keyupdate");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::keyupdate);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsKeyUpdateCliFlag) {
    const char *argv[] = {"coquic",    "interop-client", "--testcase",
                          "keyupdate", "--requests",     "https://localhost/hello.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::keyupdate);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialRebindPortTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "rebind-port");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::rebind_port);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsRebindAddrCliFlag) {
    const char *argv[] = {"coquic",      "interop-client", "--testcase",
                          "rebind-addr", "--requests",     "https://localhost/hello.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::rebind_addr);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialConnectionMigrationTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "connectionmigration");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::connectionmigration);
}

} // namespace

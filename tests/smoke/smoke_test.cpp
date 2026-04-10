#include <gtest/gtest.h>

#include "src/http09/http09_runtime.h"
#include "src/http09/http09_runtime_test_hooks.h"

TEST(QuicSmokeTest, RuntimeHealthCheckInitializesLoggingAndSeesOpenSsl) {
    coquic::http09::test::reset_runtime_logging_state_for_tests();
    EXPECT_FALSE(coquic::http09::test::runtime_logging_ready_for_tests());
    EXPECT_TRUE(coquic::http09::test::runtime_openssl_available_for_tests());

    const auto runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::health_check,
    };
    EXPECT_EQ(coquic::http09::run_http09_runtime(runtime), 0);
    EXPECT_TRUE(coquic::http09::test::runtime_logging_ready_for_tests());
}

#include <gtest/gtest.h>

#include "src/http09/http09_runtime.h"

TEST(QuicSmokeTest, RuntimeHealthCheckSucceeds) {
    const auto runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::health_check,
    };
    EXPECT_EQ(coquic::http09::run_http09_runtime(runtime), 0);
}

#include <gtest/gtest.h>

#include "src/coquic.h"

TEST(ProjectNameTest, ReturnsRepositoryName) {
    EXPECT_EQ(coquic::project_name(), std::string_view{"coquic"});
}

TEST(OpenSSLTest, ReportsAvailableVersion) {
    EXPECT_TRUE(coquic::openssl_available());
}

TEST(LoggingTest, InitializesProjectLogger) {
    EXPECT_FALSE(coquic::logging_ready());

    coquic::init_logging();

    EXPECT_TRUE(coquic::logging_ready());
}

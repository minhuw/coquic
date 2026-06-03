#ifndef COQUIC_TESTS_SUPPORT_GTEST_COMPAT_H
#define COQUIC_TESTS_SUPPORT_GTEST_COMPAT_H

#if defined(__has_include)
#if __has_include(<gtest/gtest.h>)
#include <gtest/gtest.h>
#define COQUIC_TESTS_SUPPORT_HAS_REAL_GTEST 1
#endif
#endif

#ifndef COQUIC_TESTS_SUPPORT_HAS_REAL_GTEST

#include <string>
#include <utility>

namespace testing {

class Test {};

template <typename T> class TestWithParam : public Test {
  public:
    const T &GetParam() const;
};

template <typename T> struct TestParamInfo {
    T param;
};

class AssertionResult {
  public:
    explicit operator bool() const {
        return true;
    }

    template <typename T> AssertionResult &operator<<(T &&) {
        return *this;
    }
};

template <typename T> AssertionResult assertion_value_for_analysis(T &&value) {
    (void)std::forward<T>(value);
    return AssertionResult{};
}

template <typename T, typename U>
AssertionResult assertion_comparison_for_analysis(T &&left, U &&right) {
    (void)std::forward<T>(left);
    (void)std::forward<U>(right);
    return AssertionResult{};
}

inline AssertionResult AssertionSuccess() {
    return AssertionResult{};
}

inline AssertionResult AssertionFailure() {
    return AssertionResult{};
}

namespace internal {

inline void CaptureStderr() {
}
inline void CaptureStdout() {
}
inline std::string GetCapturedStderr() {
    return {};
}
inline std::string GetCapturedStdout() {
    return {};
}

} // namespace internal

template <typename... T> int Values(T &&...) {
    return 0;
}

inline int ExitedWithCode(int) {
    return 0;
}

} // namespace testing

#define GTEST_HAS_DEATH_TEST 1

#define TEST(test_suite_name, test_name)                                                           \
    class test_suite_name##_##test_name##_Test : public ::testing::Test {                          \
      private:                                                                                     \
        void TestBody();                                                                           \
    };                                                                                             \
    void test_suite_name##_##test_name##_Test::TestBody()

#define TEST_P(test_suite_name, test_name)                                                         \
    class test_suite_name##_##test_name##_Test : public test_suite_name {                          \
      private:                                                                                     \
        void TestBody();                                                                           \
    };                                                                                             \
    void test_suite_name##_##test_name##_Test::TestBody()

#define INSTANTIATE_TEST_SUITE_P(prefix, test_suite_name, ...)                                     \
    namespace prefix##_##test_suite_name##_instantiation {                                         \
        inline void instantiate_for_analysis() {                                                   \
            (void)(__VA_ARGS__);                                                                   \
        }                                                                                          \
    }

#define EXPECT_TRUE(condition) ::testing::assertion_value_for_analysis(condition)
#define EXPECT_FALSE(condition) ::testing::assertion_value_for_analysis(!(condition))
#define ASSERT_TRUE(condition) EXPECT_TRUE(condition)
#define ASSERT_FALSE(condition) EXPECT_FALSE(condition)

#define EXPECT_EQ(left, right) ::testing::assertion_comparison_for_analysis(left, right)
#define EXPECT_NE(left, right) ::testing::assertion_comparison_for_analysis(left, right)
#define EXPECT_LT(left, right) ::testing::assertion_comparison_for_analysis(left, right)
#define EXPECT_LE(left, right) ::testing::assertion_comparison_for_analysis(left, right)
#define EXPECT_GT(left, right) ::testing::assertion_comparison_for_analysis(left, right)
#define EXPECT_GE(left, right) ::testing::assertion_comparison_for_analysis(left, right)
#define ASSERT_EQ(left, right) EXPECT_EQ(left, right)
#define ASSERT_NE(left, right) EXPECT_NE(left, right)
#define ASSERT_LT(left, right) EXPECT_LT(left, right)
#define ASSERT_LE(left, right) EXPECT_LE(left, right)
#define ASSERT_GT(left, right) EXPECT_GT(left, right)
#define ASSERT_GE(left, right) EXPECT_GE(left, right)
#define EXPECT_DOUBLE_EQ(left, right) EXPECT_EQ(left, right)

#define EXPECT_THROW(statement, exception_type)                                                    \
    (::testing::AssertionSuccess() << ([&] {                                                        \
         if (false) {                                                                               \
             try {                                                                                  \
                 statement;                                                                         \
             } catch (const exception_type &) {                                                     \
             }                                                                                      \
         }                                                                                          \
     }(),                                                                                           \
                                      ""))

#define EXPECT_DEATH(statement, matcher)                                                           \
    (::testing::AssertionSuccess() << ([&] {                                                        \
         if (false) {                                                                               \
             statement;                                                                             \
         }                                                                                          \
     }(),                                                                                           \
                                      (void)(matcher), ""))

#define EXPECT_EXIT(statement, predicate, matcher)                                                 \
    (::testing::AssertionSuccess() << ([&] {                                                        \
         if (false) {                                                                               \
             statement;                                                                             \
         }                                                                                          \
     }(),                                                                                           \
                                      (void)(predicate), (void)(matcher), ""))

#define ADD_FAILURE() ::testing::AssertionFailure()
#define FAIL() ::testing::AssertionFailure()
#define GTEST_FAIL() ::testing::AssertionFailure()
#define GTEST_SKIP() ::testing::AssertionSuccess()
#define SUCCEED() static_cast<void>(0)

#endif

#endif // COQUIC_TESTS_SUPPORT_GTEST_COMPAT_H

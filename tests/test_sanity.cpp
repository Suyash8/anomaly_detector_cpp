#include <gtest/gtest.h>

// This is a basic test to ensure the framework is set up correctly
// It doesn't test our code, just that GTest itself works
TEST(FrameworkSanityCheck, BasicAssertions) {
  // A trivial test that should always pass
  EXPECT_STRNE("hello", "world");
  EXPECT_EQ(7 * 6, 42);
  ASSERT_TRUE(true);
}
#include "utils/utils.hpp"
#include <gtest/gtest.h>

// --- Tests for ip_string_to_uint32 ---
TEST(UtilsTest, IPStringToUint32) {
  EXPECT_EQ(Utils::ip_string_to_uint32("192.168.1.1"), 3232235777);
  EXPECT_EQ(Utils::ip_string_to_uint32("0.0.0.0"), 0);
  EXPECT_EQ(Utils::ip_string_to_uint32("255.255.255.255"), 4294967295);
  EXPECT_EQ(Utils::ip_string_to_uint32("127.0.0.1"), 2130706433);
  // Invalid inputs
  EXPECT_EQ(Utils::ip_string_to_uint32("not.an.ip"), 0);
  EXPECT_EQ(Utils::ip_string_to_uint32("192.168.1"), 0);
  EXPECT_EQ(Utils::ip_string_to_uint32("192.168.1.256"), 0);
  EXPECT_EQ(Utils::ip_string_to_uint32(""), 0);
}

// --- Tests for parse_cidr ---
TEST(UtilsTest, ParseCIDR) {
  auto cidr1 = Utils::parse_cidr("192.168.1.100/24");
  ASSERT_TRUE(cidr1.has_value());
  EXPECT_EQ(cidr1->network_address, 3232235776); // 192.168.1.0
  EXPECT_EQ(cidr1->netmask, 4294967040);         // 255.255.255.0

  auto cidr2 = Utils::parse_cidr("10.0.0.1/32");
  ASSERT_TRUE(cidr2.has_value());
  EXPECT_TRUE(cidr2->contains(Utils::ip_string_to_uint32("10.0.0.1")));
  EXPECT_FALSE(cidr2->contains(Utils::ip_string_to_uint32("10.0.0.2")));

  auto cidr3 = Utils::parse_cidr("8.8.8.8"); // No mask should default to /32
  ASSERT_TRUE(cidr3.has_value());
  EXPECT_EQ(cidr3->netmask, 4294967295);

  // Invalid CIDRs
  EXPECT_FALSE(Utils::parse_cidr("192.168.1.1/33").has_value());
  EXPECT_FALSE(Utils::parse_cidr("not.an.ip/24").has_value());
  EXPECT_FALSE(Utils::parse_cidr("192.168.1.1/foo").has_value());
}

// --- Tests for convert_log_time_to_ms ---
TEST(UtilsTest, ConvertLogTimeToMs) {
  // Example from Nginx log format
  auto time1 = Utils::convert_log_time_to_ms("01/Jan/2023:12:00:01 +0000");
  ASSERT_TRUE(time1.has_value());
  EXPECT_EQ(*time1, 1672574401000); // Known UTC epoch in ms

  // Test with a different timezone
  auto time2 = Utils::convert_log_time_to_ms("23/May/2025:08:30:00 -0500");
  ASSERT_TRUE(time2.has_value());
  // 08:30 -0500 is 13:30 UTC
  EXPECT_EQ(*time2, 1748007000000);

  // Invalid formats
  EXPECT_FALSE(Utils::convert_log_time_to_ms("not a time").has_value());
  EXPECT_FALSE(
      Utils::convert_log_time_to_ms("01/Jann/2023:12:00:01 +0000").has_value());
  EXPECT_FALSE(Utils::convert_log_time_to_ms("").has_value());
  EXPECT_FALSE(Utils::convert_log_time_to_ms("-").has_value());
}

// --- Tests for url_decode ---
TEST(UtilsTest, URLDecode) {
  EXPECT_EQ(Utils::url_decode("hello+world"), "hello world");
  EXPECT_EQ(Utils::url_decode("foo%20bar"), "foo bar");
  EXPECT_EQ(Utils::url_decode("%2Fetc%2Fpasswd"), "/etc/passwd");
  EXPECT_EQ(Utils::url_decode("invalid%2g"),
            "invalid%2g"); // Handles invalid hex
  EXPECT_EQ(Utils::url_decode(""), "");
}
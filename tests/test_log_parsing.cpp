#include "core/log_entry.hpp"
#include <gtest/gtest.h>

TEST(LogParsingTest, CorrectlyParsesValidLine) {
  // A known-good sample line from the project's data
  std::string line =
      "192.168.0.1|-|01/Jan/2023:12:00:01 +0000|0.120|0.100|GET /index.html "
      "HTTP/1.1|200|1024|https://example.com|Mozilla/5.0 (X11; Linux "
      "x86_64)|example.com|US|127.0.0.1:80|abc123|0.020";
  auto entry_opt = LogEntry::parse_from_string(line, 1);

  // Assert that parsing succeeded
  ASSERT_TRUE(entry_opt.has_value());
  const auto &entry = *entry_opt;

  // Assert key fields are correct
  EXPECT_EQ(entry.ip_address, "192.168.0.1");
  EXPECT_EQ(entry.original_line_number, 1);
  ASSERT_TRUE(entry.parsed_timestamp_ms.has_value());
  EXPECT_EQ(*entry.parsed_timestamp_ms, 1672574401000);

  ASSERT_TRUE(entry.request_time_s.has_value());
  EXPECT_DOUBLE_EQ(*entry.request_time_s, 0.120);

  EXPECT_EQ(entry.request_method, "GET");
  EXPECT_EQ(entry.request_path, "/index.html");
  EXPECT_EQ(entry.request_protocol, "HTTP/1.1");

  ASSERT_TRUE(entry.http_status_code.has_value());
  EXPECT_EQ(*entry.http_status_code, 200);

  ASSERT_TRUE(entry.bytes_sent.has_value());
  EXPECT_EQ(*entry.bytes_sent, 1024);

  EXPECT_EQ(entry.user_agent, "Mozilla/5.0 (X11; Linux x86_64)");
}

TEST(LogParsingTest, CorrectlyRejectsMalformedLine) {
  // A malformed sample line from the project's data
  std::string line =
      "1.2.3.4|this is a malformed log line with not enough fields";
  auto entry_opt = LogEntry::parse_from_string(line, 2);

  // Assert that parsing correctly failed and returned nullopt
  ASSERT_FALSE(entry_opt.has_value());
}

TEST(LogParsingTest, CorrectlyRejectsLineWithInvalidTimestamp) {
  // A line that is structurally correct but has a critical field that cannot be
  // parsed
  std::string line =
      "192.168.0.1|-|INVALID_TIMESTAMP|0.120|0.100|GET /index.html "
      "HTTP/1.1|200|1024|https://example.com|Mozilla/"
      "5.0|example.com|US|127.0.0.1:80|abc123|0.020";
  auto entry_opt = LogEntry::parse_from_string(line, 3);

  // Parsing should fail because the timestamp is critical for the engine's
  // operation
  ASSERT_FALSE(entry_opt.has_value());
}

TEST(LogParsingTest, HandlesURLDecodingInPath) {
  std::string line =
      "192.168.0.1|-|01/Jan/2023:12:00:01 +0000|0.120|0.100|GET "
      "/some%2Fpath%20with%2Bspaces HTTP/1.1|200|1024|-|-|-|-|-|-|-";
  auto entry_opt = LogEntry::parse_from_string(line, 4);

  ASSERT_TRUE(entry_opt.has_value());
  EXPECT_EQ(entry_opt->request_path, "/some/path with spaces");
}
#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

struct LogEntry {
  std::string raw_log_line;
  uint64_t original_line_number;

  // Most essential data
  std::string_view ip_address;
  std::string_view timestamp_str;
  std::optional<uint64_t> parsed_timestamp_ms;

  std::string_view request_method;
  std::string request_path;
  std::string_view request_protocol;

  std::optional<int> http_status_code;
  std::optional<double> request_time_s;
  std::optional<double> upstream_response_time_s;
  std::optional<uint64_t> bytes_sent;

  std::string_view remote_user;
  std::string_view referer;
  std::string_view user_agent;
  std::string_view host;
  std::string_view country_code;
  std::string_view upstream_addr;
  std::string_view x_request_id;
  std::string_view accept_encoding;

  bool successfully_parsed_structure; // Indicates if field count was okay and
                                      // basic string assignments happened

  // Default constructor
  LogEntry();

  // Static function to create LogEntry from raw string
  static std::optional<LogEntry>
  parse_from_string(std::string &&log_line, uint64_t line_num,
                    bool verbose_warnings = true);

private:
  // Helper function to parse "request" field (into request_method,
  // request_path, request_protocol)
  static void parse_request_details(std::string_view full_request_field,
                                    std::string_view &out_method,
                                    std::string &out_path,
                                    std::string_view &out_protocol);
};

#endif // LOG_ENTRY_HPP
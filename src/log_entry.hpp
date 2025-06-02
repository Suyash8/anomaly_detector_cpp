#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include <cstdint>
#include <string>
struct LogEntry {
  std::string raw_log_line;
  uint64_t original_line_number;

  // Most essential data
  std::string ip_address;
  std::string timestamp_str;
  uint64_t parsed_timestamp_ms;

  std::string request_method;
  std::string request_path;
  std::string request_protocol;

  int http_status_code;

  double request_time;
  double upstream_response_time;

  uint64_t bytes_sent;

  std::string remote_user;
  std::string referer;
  std::string user_agent;
  std::string host;
  std::string country_code;
  std::string upstream_addr;
  std::string x_request_id;
  std::string accept_encoding;

  // A simple flag to indicate if parsing was successful
  bool successfully_parsed;

  // Default constructor
  LogEntry();

  // Static function to create LogEntry from raw string
  static LogEntry parse_from_string(const std::string &log_line,
                                    uint64_t line_num,
                                    bool verbose_warnings = true);

private:
  // Helper function to parse "request" field (into request_method,
  // request_path, request_protocol)
  static void parse_request_details(const std::string &full_request_field,
                                    std::string &out_method,
                                    std::string &out_path,
                                    std::string &out_protocol);
};

#endif // LOG_ENTRY_HPP
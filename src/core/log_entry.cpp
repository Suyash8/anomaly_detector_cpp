#include "log_entry.hpp"
#include "utils/utils.hpp"

#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

LogEntry::LogEntry()
    : original_line_number(0),
      // std::optional fields are default constructed to std::nullopt
      successfully_parsed_structure(false) {}

void LogEntry::parse_request_details(std::string_view full_request_field,
                                     std::string_view &out_method,
                                     std::string &out_path,
                                     std::string_view &out_protocol) {
  if (full_request_field == "-") {
    out_method = "-";
    out_path = "-";
    out_protocol = "-";
    return;
  }

  // Find the first space for the method
  size_t method_end = full_request_field.find(' ');
  if (method_end == std::string_view::npos) {
    // Malformed, treat the whole thing as the path
    out_method = "-";
    out_path = std::string(full_request_field);
    out_protocol = "-";
    return;
  }
  out_method = full_request_field.substr(0, method_end);

  // Find the last space for the protocol
  size_t protocol_start = full_request_field.rfind(' ');
  if (protocol_start == std::string_view::npos ||
      protocol_start <= method_end) {
    // No protocol found, or it's the same space as the method end
    out_path = std::string(full_request_field.substr(method_end + 1));
    out_protocol = "-";
    return;
  }
  out_protocol = full_request_field.substr(protocol_start + 1);
  // The path is everything in between
  out_path = std::string(full_request_field.substr(
      method_end + 1, protocol_start - (method_end + 1)));

  if (out_path.empty())
    out_path = "/";
}

std::optional<LogEntry> LogEntry::parse_from_string(std::string &&log_line,
                                                    uint64_t line_num,
                                                    bool verbose_warnings) {
  LogEntry entry;
  entry.raw_log_line = std::move(log_line);
  entry.original_line_number = line_num;
  entry.successfully_parsed_structure = false;

  std::vector<std::string_view> fields =
      Utils::split_string_view(entry.raw_log_line, '|');

  const int EXPECTED_FIELDS_COUNT = 15;

  if (fields.size() != EXPECTED_FIELDS_COUNT) {
    if (verbose_warnings)
      std::cerr << "Warning (Line " << line_num << "): Expected "
                << EXPECTED_FIELDS_COUNT << " fields, but found "
                << fields.size() << ". Skipping line." << std::endl;
    return std::nullopt;
  }

  // Basic string fields
  entry.ip_address = fields[0];
  entry.remote_user = fields[1];
  entry.timestamp_str = fields[2];
  entry.referer = fields[8];
  entry.user_agent = fields[9];
  entry.host = fields[10];
  entry.country_code = fields[11];
  entry.upstream_addr = fields[12];
  entry.x_request_id = fields[13];
  entry.accept_encoding = fields[14];

  entry.successfully_parsed_structure = true;

  // Attempt to parse critical fields
  entry.parsed_timestamp_ms =
      Utils::convert_log_time_to_ms(std::string(entry.timestamp_str));
  if (!entry.parsed_timestamp_ms) {
    if (verbose_warnings)
      std::cerr << "Warning (Line " << line_num
                << "): Failed to parse timestamp. Critical." << std::endl;
    return std::nullopt;
  }

  entry.request_time_s = Utils::string_to_number<double>(fields[3]);
  entry.upstream_response_time_s = Utils::string_to_number<double>(fields[4]);

  parse_request_details(fields[5], entry.request_method, entry.request_path,
                        entry.request_protocol);

  Utils::trim_inplace(entry.request_path);

  entry.request_path = Utils::url_decode(entry.request_path);

  entry.http_status_code = Utils::string_to_number<int>(fields[6]);
  if (!entry.http_status_code && fields[6] != "-") {
    if (verbose_warnings)
      std::cerr << "Warning (Line " << line_num
                << "): Failed to parse status code: " << fields[6]
                << ". Critical." << std::endl;
    return std::nullopt;
  }

  entry.bytes_sent = Utils::string_to_number<uint64_t>(fields[7]);

  return entry;
}
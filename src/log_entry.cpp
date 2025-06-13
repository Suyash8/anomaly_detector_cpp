#include "log_entry.hpp"
#include "utils.hpp"
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

LogEntry::LogEntry()
    : original_line_number(0),
      // std::optional fields are default constructed to std::nullopt
      successfully_parsed_structure(false) {}

void LogEntry::parse_request_details(const std::string &full_request_field,
                                     std::string &out_method,
                                     std::string &out_path,
                                     std::string &out_protocol) {
  if (full_request_field == "-") {
    out_method = "-";
    out_path = "-";
    out_protocol = "-";
    return;
  }

  std::istringstream request_stream(full_request_field);
  request_stream >> out_method >> out_path >> out_protocol;

  // If protocol is empty, it means that it might be a simple "METHOD /path"
  // request or the parsing did not capture it. For robustness, default is empty
  if (out_method.empty())
    out_method = "-"; // Should not happen if field not "-"
  if (out_path.empty())
    out_path = "/"; // Default to root path if empty
  if (out_protocol.empty())
    out_protocol = "-";
}

std::optional<LogEntry> LogEntry::parse_from_string(const std::string &log_line,
                                                    uint64_t line_num,
                                                    bool verbose_warnings) {
  LogEntry entry;
  entry.raw_log_line = log_line;
  entry.original_line_number = line_num;

  entry.successfully_parsed_structure = false;

  std::vector<std::string> fields = Utils::split_string(log_line, '|');

  const int EXPECTED_FIELDS_COUNT = 15;

  if (fields.size() != EXPECTED_FIELDS_COUNT) {
    if (verbose_warnings)
      std::cerr << "Warning (Line " << line_num << "): Expected"
                << EXPECTED_FIELDS_COUNT << " fields, but found "
                << fields.size() << ". Skipping line." << std::endl;
    return std::nullopt;
  }

  // Basic string fields
  entry.ip_address = Utils::trim_copy(fields[0]);
  entry.remote_user = Utils::trim_copy(fields[1]);
  entry.timestamp_str = Utils::trim_copy(fields[2]);
  entry.referer = Utils::trim_copy(fields[8]);
  entry.user_agent = Utils::trim_copy(fields[9]);
  entry.host = Utils::trim_copy(fields[10]);
  entry.country_code = Utils::trim_copy(fields[11]);
  entry.upstream_addr = Utils::trim_copy(fields[12]);
  entry.x_request_id = Utils::trim_copy(fields[13]);
  entry.accept_encoding = Utils::trim_copy(fields[14]);

  entry.successfully_parsed_structure = true;

  // Attempt to parse critical fields. If any fail, we might consider the whole
  // entry invalid.
  entry.parsed_timestamp_ms =
      Utils::convert_log_time_to_ms(entry.timestamp_str);
  if (!entry.parsed_timestamp_ms) {
    if (verbose_warnings)
      std::cerr << "Warning (Line " << line_num
                << "): Failed to parse timestamp. Critical." << std::endl;
    return std::nullopt; // Timestamp is crucial
  }

  entry.request_time_s = Utils::string_to_number<double>(fields[3]);
  entry.upstream_response_time_s = Utils::string_to_number<double>(fields[4]);

  parse_request_details(fields[5], entry.request_method, entry.request_path,
                        entry.request_protocol);
  Utils::trim_inplace(entry.request_method);
  Utils::trim_inplace(entry.request_path);
  Utils::trim_inplace(entry.request_protocol);

  entry.http_status_code = Utils::string_to_number<int>(fields[6]);
  if (!entry.http_status_code &&
      fields[6] != "-") { // If parsing failed AND it wasn't just a "-"
    if (verbose_warnings)
      std::cerr << "Warning (Line " << line_num
                << "): Failed to parse status code: " << fields[6]
                << ". Critical." << std::endl;
    return std::nullopt; // Status code is crucial
  }

  entry.bytes_sent = Utils::string_to_number<uint64_t>(fields[7]);
  // bytes_sent might be less critical to fail entire parsing for, depends on
  // requirements. If it's "-", string_to_number will return 0, which is
  // acceptable.

  // If all critical parsing steps were okay (timestamp, status), return the
  // entry.
  return entry;
}
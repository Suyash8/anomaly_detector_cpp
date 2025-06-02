#include "log_entry.hpp"
#include "utils.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

LogEntry::LogEntry()
    : original_line_number(0), parsed_timestamp_ms(0), http_status_code(0),
      bytes_sent(0), successfully_parsed(false) {}

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
    out_path = "-";
  if (out_protocol.empty())
    out_protocol = "-";
}

LogEntry LogEntry::parse_from_string(const std::string &log_line,
                                     uint64_t line_num, bool verbose_warnings) {
  LogEntry entry;
  entry.raw_log_line = log_line;
  entry.original_line_number = line_num;

  entry.successfully_parsed = false;

  std::vector<std::string> fields = Utils::split_string(log_line, '|');

  const int EXPECTED_FIELDS_COUNT = 15;

  if (fields.size() != EXPECTED_FIELDS_COUNT) {
    // std::cerr << "Warning (Line " << line_num << "): Expected"
    //           << EXPECTED_FIELDS_COUNT << " fields, but found " <<
    //           fields.size()
    //           << ". Skipping line." << std::endl;
    return entry;
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

  entry.parsed_timestamp_ms =
      Utils::convert_log_time_to_ms(entry.timestamp_str);

  // Parse request time (Field 3) - naive for now
  try {
    if (fields[3] != "-")
      entry.request_time = std::stod(fields[3]);
    else {
      // Handle appropriately, (0.0 or a flag)
      entry.request_time = 0.0;
    }
  } catch (std::invalid_argument &e) {
    if (verbose_warnings)
      std::cerr << "Warning: (Line " << line_num
                << "): Invalid request time format: " << fields[3] << std::endl;
  } catch (std::out_of_range &e) {
    if (verbose_warnings)
      std::cerr << "Warning: (Line " << line_num
                << "): Request time out of range: " << fields[3] << std::endl;
  }

  // Parse upstream response time (Field 4)
  try {
    if (fields[4] != "-")
      entry.upstream_response_time = std::stod(fields[4]);
    else
      entry.upstream_response_time = 0.0;
  } catch (std::invalid_argument &e) {
    if (verbose_warnings)
      std::cerr << "Warning: (Line " << line_num
                << "): Invalid upstream response time format: " << fields[4]
                << std::endl;
  } catch (std::out_of_range &e) {
    if (verbose_warnings)
      std::cerr << "Warning: (Line " << line_num
                << "): Upstream response time out of range: " << fields[4]
                << std::endl;
  }

  // Parse request field (Field 5)
  parse_request_details(fields[5], entry.request_method, entry.request_path,
                        entry.request_protocol);

  // Parse status code (Field 6)
  try {
    if (fields[6] != "-")
      entry.http_status_code = std::stoi(fields[6]);
    else
      entry.http_status_code = 0;
  } catch (std::invalid_argument &e) {
    std::cerr << "Critical: (Line " << line_num
              << "): Invalid HTTP status code format: " << fields[6]
              << std::endl;
    return entry; // Critical parsing failure
  } catch (std::out_of_range &e) {
    std::cerr << "Critical: (Line " << line_num
              << "): HTTP status code out of range: " << fields[6] << std::endl;
    return entry; // Critical parsing failure
  }

  // Parse bytes sent (Field 7)
  try {
    if (fields[7] != "-")
      entry.bytes_sent = std::stoi(fields[7]);
    else
      entry.bytes_sent = 0;
  } catch (std::invalid_argument &e) {
    if (verbose_warnings)
      std::cerr << "Warning: (Line " << line_num
                << "): Invalid bytes sent format: " << fields[7] << std::endl;
  } catch (std::out_of_range &e) {
    if (verbose_warnings)
      std::cerr << "Warning: (Line " << line_num
                << "): Bytes sent out of range: " << fields[7] << std::endl;
  }

  entry.successfully_parsed = true;
  return entry;
}
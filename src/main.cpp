#include "log_entry.hpp"
#include "utils.hpp"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main() {
  std::cout << "Starting Anomaly Detection Engine..." << std::endl;

  uint64_t start = Utils::get_current_time_ms();

  // Trying to read the sample log file
  std::string log_filepath = "data/fake.log";
  std::ifstream log_file(log_filepath);

  if (!log_file.is_open()) {
    std::cerr << "Error: Could not open log file: " << log_filepath
              << std::endl;
    return 1;
  }

  std::cout << "Successfully opened log file: " << log_filepath << std::endl;

  std::string current_line;
  uint64_t line_counter = 0;
  int successfully_parsed_count = 0;
  int skipped_line_count = 0;

  while (std::getline(log_file, current_line)) {
    line_counter++;

    LogEntry entry =
        LogEntry::parse_from_string(current_line, line_counter, false);

    if (entry.successfully_parsed) {
      successfully_parsed_count++;
      // Print some details for the first few successfully parsed entries
      if (successfully_parsed_count <= 5) {
        std::cout << "Parsed (Line " << entry.original_line_number
                  << "): " << "IP=" << entry.ip_address << ", TimestampStr="
                  << entry.timestamp_str
                  // << ", ParsedTS(dummy)=" << entry.parsed_timestamp_ms //
                  // will be 0 or dummy
                  << ", Status=" << entry.http_status_code
                  << ", Method=" << entry.request_method
                  << ", Path=" << entry.request_path
                  << ", Protocol=" << entry.request_protocol
                  << ", Bytes=" << entry.bytes_sent
                  << ", UA=" << entry.user_agent.substr(0, 20)
                  << (entry.user_agent.size() > 20 ? "..." : "") << std::endl;
      }
    } else {
      skipped_line_count++;
      if (skipped_line_count <=
          5) { // Print info for the first few skipped lines
        std::cerr << "Skipped line " << line_counter
                  << " due to parsing issues. Raw: "
                  << current_line.substr(0, 100)
                  << (current_line.size() > 100 ? "..." : "") << std::endl;
      }
    }
  }

  log_file.close();

  uint64_t stop = Utils::get_current_time_ms();
  std::cout << "\n---Processing Summary---" << std::endl;
  std::cout << "Total lines read: " << line_counter << std::endl;
  std::cout << "Successfully parsed entries: " << successfully_parsed_count
            << std::endl;
  std::cout << "Skipped entries (parsing failed): " << skipped_line_count
            << std::endl;

  std::cout << "Anomaly Detection Engine finished" << std::endl;
  std::cout << "Time taken: " << (stop - start) << " ms" << std::endl;

  return 0;
}
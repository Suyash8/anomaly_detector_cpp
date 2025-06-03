#include "log_entry.hpp"
#include "utils.hpp"
#include <chrono>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <optional>
#include <string>

int main() {
  std::ios_base::sync_with_stdio(false); // Potentially faster I/O
  std::cin.tie(nullptr);                 // Untie cin from cout

  std::cout << "Starting Anomaly Detection Engine..." << std::endl;

  // Trying to read the sample log file
  std::string log_filepath = "data/sample_logs.txt";
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

  auto time_start = std::chrono::high_resolution_clock::now();

  while (std::getline(log_file, current_line)) {
    line_counter++;

    std::optional<LogEntry> entry_opt =
        LogEntry::parse_from_string(current_line, line_counter, false);

    if (entry_opt) {
      successfully_parsed_count++;
      const LogEntry &entry = *entry_opt; // Dereference to get the LogEntry

      // Print some details for the first few successfully parsed entries
      if (successfully_parsed_count <= 10) {
        std::cout << "Parsed (Line " << entry.original_line_number
                  << "): " << "IP=" << entry.ip_address;
        if (entry.parsed_timestamp_ms)
          std::cout << ", Timestamp=" << *entry.parsed_timestamp_ms;
        else
          std::cout << ", Timestamp=N/A";

        if (entry.http_status_code)
          std::cout << ", Status=" << *entry.http_status_code;
        else
          std::cout << ", Status=N/A";

        std::cout << ", Path=" << entry.request_path;

        if (entry.bytes_sent)
          std::cout << ", Bytes=" << *entry.bytes_sent;
        else
          std::cout << ", Bytes=N/A";

        std::cout << std::endl;
      }
    } else {
      skipped_line_count++;
      if (skipped_line_count <= 10 || skipped_line_count % 1000 == 0) {
        std::cerr << "Skipped line " << line_counter
                  << " due to parsing issues. Raw: "
                  << current_line.substr(0, 100)
                  << (current_line.size() > 100 ? "..." : "") << std::endl;
      }
    }
  }

  log_file.close();

  auto time_end = std::chrono::high_resolution_clock::now();
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         time_end - time_start)
                         .count();
  std::cout << "\n---Processing Summary---" << std::endl;
  std::cout << "Total lines read: " << line_counter << std::endl;
  std::cout << "Successfully parsed entries: " << successfully_parsed_count
            << std::endl;
  std::cout << "Skipped entries (parsing failed): " << skipped_line_count
            << std::endl;
  std::cout << "Total processing time: " << duration_ms << " ms" << std::endl;
  if (duration_ms > 0 && line_counter > 0)
    std::cout << "Processing rate: " << (line_counter * 1000 / duration_ms)
              << " lines/sec" << std::endl;

  std::cout << "Anomaly Detection Engine finished" << std::endl;
  return 0;
}
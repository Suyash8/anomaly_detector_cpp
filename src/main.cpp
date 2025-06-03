#include "config.hpp"
#include "log_entry.hpp"
#include "utils.hpp"

#include <chrono>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <istream>
#include <optional>
#include <string>

int main(int argc, char *argv[]) {
  std::ios_base::sync_with_stdio(false); // Potentially faster I/O
  std::cin.tie(nullptr);                 // Untie cin from cout

  std::cout << "Starting Anomaly Detection Engine..." << std::endl;

  std::string config_file_to_load = "config.ini";
  if (argc > 1) {
    config_file_to_load = argv[1];
    std::cout << "Using command-line specified config file: "
              << config_file_to_load << std::endl;
  }

  // Load configuration
  if (!Config::load_configuration(config_file_to_load)) {
    // load_configuration already prints a warning.
    // The program continues with default values in GlobalAppConfig.
  }

  const Config::AppConfig &current_config = Config::get_app_config();

  // Now use the configuration values
  std::cout << "--- Current Configuration ---" << std::endl;
  std::cout << "Log Input Path: " << current_config.log_input_path << std::endl;
  std::cout << "Allowlist Path: " << current_config.allowlist_path << std::endl;
  std::cout << "Tier 1 Enabled: "
            << (current_config.tier1_enabled ? "Yes" : "No") << std::endl;
  std::cout << "Tier 1 Max Requests/IP: "
            << current_config.tier1_max_requests_per_ip_in_window << std::endl;
  std::cout << "Tier 1 Window (s): "
            << current_config.tier1_window_duration_seconds << std::endl;
  std::cout << "-----------------------------" << std::endl;

  std::istream *p_log_stream = nullptr;
  std::ifstream log_file_stream;

  if (current_config.log_input_path == "stdin") {
    p_log_stream = &std::cin;
    std::cout << "Reading logs from stdin. Type logs and press Enter. Ctrl+D "
                 "(Linux/macOS) or Ctrl+Z then enter (Windows) to end."
              << std::endl;
  } else {
    log_file_stream.open(current_config.log_input_path);

    if (!log_file_stream.is_open()) {
      std::cerr << "Error: Could not open log file: "
                << current_config.log_input_path << std::endl;
      return 1;
    }

    p_log_stream = &log_file_stream;
    std::cout << "Successfully opened log file: "
              << current_config.log_input_path << std::endl;
  }

  std::istream &log_input = *p_log_stream;

  std::string current_line;
  uint64_t line_counter = 0;
  int successfully_parsed_count = 0;
  int skipped_line_count = 0;

  auto time_start = std::chrono::high_resolution_clock::now();

  while (std::getline(log_input, current_line)) {
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
    // Progress update for file processing
    if (current_config.log_input_path != "stdin" &&
        line_counter % 200000 == 0) { // Print every 200k lines for files
      std::cout << "Progress: Read " << line_counter << " lines..."
                << std::endl;
    }
  }

  if (log_file_stream.is_open())
    log_file_stream.close();

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
#include "alert_manager.hpp"
#include "analysis_engine.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "rule_engine.hpp"

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

  Config::ConfigManager config_manager;
  std::string config_file_to_load = "config.ini";
  if (argc > 1)
    config_file_to_load = argv[1];
  config_manager.load_configuration(config_file_to_load);

  auto current_config = config_manager.get_config();

  // --- Initialize Core Components ---
  AlertManager alert_manager_instance;
  alert_manager_instance.initialize(*current_config);

  AnalysisEngine analysis_engine_instance(*current_config);
  RuleEngine rule_engine_instance(alert_manager_instance, *current_config);

  // --- Log Processing ---
  std::istream *p_log_stream = nullptr;
  std::ifstream log_file_stream;

  if (current_config->log_input_path == "stdin") {
    p_log_stream = &std::cin;
    std::cout << "Reading logs from stdin. Type logs and press Enter. Ctrl+D "
                 "(Linux/macOS) or Ctrl+Z then enter (Windows) to end."
              << std::endl;
  } else {
    log_file_stream.open(current_config->log_input_path);

    if (!log_file_stream.is_open()) {
      std::cerr << "Error: Could not open log file: "
                << current_config->log_input_path << std::endl;
      return 1;
    }

    p_log_stream = &log_file_stream;
    std::cout << "Successfully opened log file: "
              << current_config->log_input_path << std::endl;
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
      const LogEntry &current_log_entry =
          *entry_opt; // Dereference to get the LogEntry

      // Analyze Log entry
      AnalyzedEvent analyzed_event =
          analysis_engine_instance.process_and_analyze(current_log_entry);

      // Evaluate rules based on the analyzed event
      rule_engine_instance.evaluate_rules(analyzed_event);

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
    if (current_config->log_input_path != "stdin" &&
        line_counter % 200000 == 0) { // Print every 200k lines for files
      auto now = std::chrono::high_resolution_clock::now();
      auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - time_start)
                            .count();

      if (elapsed_ms > 0)
        std::cout << "Progress: Read " << line_counter << " lines ("
                  << (line_counter * 1000 / elapsed_ms) << " lines/sec)."
                  << std::endl;
      else
        std::cout << "Progress: Read " << line_counter << " lines."
                  << std::endl;
    }
  }

  if (log_file_stream.is_open())
    log_file_stream.close();

  alert_manager_instance.flush_all_alerts();

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
}
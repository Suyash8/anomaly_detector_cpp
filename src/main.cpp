#include "alert_manager.hpp"
#include "analysis_engine.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "rule_engine.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <istream>
#include <optional>
#include <string>

// Global atomic flags for signal handling
std::atomic<bool> g_shutdown_requested = false;
std::atomic<bool> g_reload_config_requested = false;
std::atomic<bool> g_reset_state_requested = false;
std::atomic<bool> g_pause_requested = false;
std::atomic<bool> g_resume_requested = false;

// A simple, safe signal handler function
void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    g_shutdown_requested = true;
  } else if (signum == SIGHUP) {
    g_reload_config_requested = true;
  } else if (signum == SIGUSR1) {
    g_reset_state_requested = true;
  } else if (signum == SIGUSR2) {
    g_pause_requested = true;
  } else if (signum == SIGCONT) {
    g_resume_requested = true;
  }
}

int main(int argc, char *argv[]) {
  std::ios_base::sync_with_stdio(false); // Potentially faster I/O
  std::cin.tie(nullptr);                 // Untie cin from cout

  std::cout << "Starting Anomaly Detection Engine..." << std::endl;

  // Register all signal handlers
  struct sigaction action;
  action.sa_handler = signal_handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;

  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGHUP, &action, NULL);
  sigaction(SIGUSR1, &action, NULL);
  sigaction(SIGUSR2, &action, NULL); // Pause
  sigaction(SIGCONT, &action, NULL); // Resume

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

  // Load state on startup
  if (current_config->state_persistence_enabled) {
    std::cout << "State persistence enabled. Attempting to load state from: "
              << current_config->state_file_path << std::endl;
    if (analysis_engine_instance.load_state(current_config->state_file_path))
      std::cout << "Successfully loaded previous engine state." << std::endl;
    else
      std::cout << "No previous state file found or file was invalid. Starting "
                   "with a fresh state."
                << std::endl;
  }

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

    // Periodic Pruning
    if (current_config->state_pruning_enabled &&
        current_config->state_prune_interval_events > 0 &&
        line_counter % current_config->state_prune_interval_events == 0) {

      uint64_t latest_ts = analysis_engine_instance.get_max_timestamp_seen();
      analysis_engine_instance.run_pruning(latest_ts);
    }

    // Periodic Saving
    if (current_config->state_persistence_enabled &&
        current_config->state_save_interval_events > 0 &&
        line_counter % current_config->state_save_interval_events == 0) {

      std::cout << "Periodically saving engine state..." << std::endl;
      analysis_engine_instance.save_state(current_config->state_file_path);
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

  // Final save on graceful exit
  if (current_config->state_persistence_enabled) {
    std::cout << "Processing finished. Saving final engine state..."
              << std::endl;
    analysis_engine_instance.save_state(current_config->state_file_path);
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
#include "alert_manager.hpp"
#include "analysis_engine.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "rule_engine.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <istream>
#include <optional>
#include <string>
#include <sys/types.h>
#include <thread>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <termios.h>
#include <unistd.h>
#endif

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

// --- RAII helper for raw terminal mode (POSIX only) ---
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
struct TerminalManager {
  termios original_termios;
  bool is_valid = false;

  TerminalManager() {
    // Get current terminal settings
    if (tcgetattr(STDIN_FILENO, &original_termios) == 0) {
      termios raw = original_termios;
      // Disable canonical mode (line buffering) and echo
      raw.c_lflag &= ~(ICANON | ECHO);
      // Apply the new settings immediately
      tcsetattr(STDIN_FILENO, TCSANOW, &raw);
      is_valid = true;
    }
  }

  ~TerminalManager() {
    // Restore original settings on destruction
    if (is_valid)
      tcsetattr(STDIN_FILENO, TCSANOW, &original_termios);
  }
};
#endif

// --- Keyboard listener thread function ---
void keyboard_listener_thread() {
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  TerminalManager tm;
  if (!tm.is_valid)
    return;

  char c;
  while (!g_shutdown_requested) {
    // Read one character from stdin
    ssize_t bytes_read = read(STDIN_FILENO, &c, 1);

    if (bytes_read > 0)
      switch (c) {
      // case 3: // Ctrl+C
      case 4: // Ctrl+D
        g_shutdown_requested = true;
        break;
      case 18: // Ctrl+R (Reload)
        g_reload_config_requested = true;
        break;
      case 5: // Ctrl+E (rEset)
        g_reset_state_requested = true;
        break;
      case 16: // Ctrl+P (Pause)
        g_pause_requested = true;
        break;
      case 17: // Ctrl+Q (Resume - 'Q' is next to 'P')
        g_resume_requested = true;
        break;
      }
    else if (bytes_read == 0)
      g_shutdown_requested = true;
    else if (errno == EINTR)
      continue;
    else
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
#else
  // On non-POSIX systems, this thread does nothing
  std::cout
      << "Interactive keyboard shortcuts are not supported on this platform."
      << std::endl;
#endif
}

enum class ServiceState { RUNNING, PAUSED };

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

  std::thread keyboard_thread(keyboard_listener_thread);

  std::cout << "\nInteractive Controls:\n"
            << "  Ctrl+C / Ctrl+D: Shutdown Gracefully\n"
            << "  Ctrl+R:          Reload Configuration\n"
            << "  Ctrl+E:          Reset Engine State\n"
            << "  Ctrl+P:          Pause Processing\n"
            << "  Ctrl+Q:          Resume Processing\n\n";

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
      g_shutdown_requested = true;
      if (keyboard_thread.joinable())
        keyboard_thread.join();
      return 1;
    }

    p_log_stream = &log_file_stream;
    std::cout << "Successfully opened log file: "
              << current_config->log_input_path << std::endl;
  }

  std::istream &log_input = *p_log_stream;

  // Load state on startup
  if (current_config->state_persistence_enabled) {
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
  ServiceState current_state = ServiceState::RUNNING;
  bool first_pause_message = true;

  while (!g_shutdown_requested) {
    // --- Signal Polling and State Transition Block ---
    if (g_reset_state_requested.exchange(false)) {
      std::cout << "\n[Action] Resetting engine state (Ctrl+E)..." << std::endl;
      analysis_engine_instance.reset_in_memory_state();
      if (current_config->state_persistence_enabled)
        if (std::remove(current_config->state_file_path.c_str()) == 0)
          std::cout << "  -> Deleted persisted state file: "
                    << current_config->state_file_path << std::endl;
      first_pause_message = true;
    }

    if (g_reload_config_requested.exchange(false)) {
      std::cout << "\n[Action] Reloading configuration (Ctrl+R) from "
                << config_file_to_load << "..." << std::endl;
      if (config_manager.load_configuration(config_file_to_load)) {
        current_config = config_manager.get_config();

        alert_manager_instance.reconfigure(*current_config);
        rule_engine_instance.reconfigure(*current_config);
        analysis_engine_instance.reconfigure(*current_config);
        std::cout << "  -> Configuration reloaded successfully." << std::endl;
      } else
        std::cerr
            << "  -> Failed to reload configuration. Keeping old settings."
            << std::endl;
      first_pause_message = true;
    }

    if (g_resume_requested.exchange(false)) {
      if (current_state == ServiceState::PAUSED) {
        std::cout << "\n[Action] Resuming processing (Ctrl+Q)..." << std::endl;
        current_state = ServiceState::RUNNING;
        first_pause_message = true;
      }
    }

    if (g_pause_requested.exchange(false)) {
      if (current_state == ServiceState::RUNNING) {
        std::cout << "\n[Action] Pausing processing (Ctrl+P)..." << std::endl;
        current_state = ServiceState::PAUSED;
      }
    }

    // --- State-Specific Action Block ---
    if (current_state == ServiceState::RUNNING) {
      if (std::getline(log_input, current_line)) {
        line_counter++;

        // --- Standard Log Processing ---
        std::optional<LogEntry> entry_opt =
            LogEntry::parse_from_string(current_line, line_counter, false);

        if (entry_opt) {
          successfully_parsed_count++;
          const auto &current_log_entry = *entry_opt;
          auto analyzed_event =
              analysis_engine_instance.process_and_analyze(current_log_entry);
          rule_engine_instance.evaluate_rules(analyzed_event);

        } else {
          skipped_line_count++;
        }

        // --- Periodic Tasks ---
        if (current_config->state_pruning_enabled &&
            current_config->state_prune_interval_events > 0 &&
            line_counter % current_config->state_prune_interval_events == 0) {
          analysis_engine_instance.run_pruning(
              analysis_engine_instance.get_max_timestamp_seen());
        }

        if (current_config->state_persistence_enabled &&
            current_config->state_save_interval_events > 0 &&
            line_counter % current_config->state_save_interval_events == 0) {
          analysis_engine_instance.save_state(current_config->state_file_path);
        }

        // Progress update for file processing
        // if (current_config->log_input_path != "stdin" &&
        //     line_counter % 200000 == 0) { // Print every 200k lines for files
        //   auto now = std::chrono::high_resolution_clock::now();
        //   auto elapsed_ms =
        //       std::chrono::duration_cast<std::chrono::milliseconds>(now -
        //                                                             time_start)
        //           .count();

        //   if (elapsed_ms > 0)
        //     std::cout << "Progress: Read " << line_counter << " lines ("
        //               << (line_counter * 1000 / elapsed_ms) << " lines/sec)."
        //               << std::endl;
        //   else
        //     std::cout << "Progress: Read " << line_counter << " lines."
        //               << std::endl;
        // }

      } else {
        // End of File (or closed stdin) reached
        if (current_config->live_monitoring_enabled) {
          current_state = ServiceState::PAUSED;
          if (log_input.eof())
            log_input.clear();
        } else {
          g_shutdown_requested = true;
        }
      }
    } else if (current_state == ServiceState::PAUSED) {
      // --- Efficient Sleep State ---
      if (first_pause_message) {
        std::cout << "[Status] Paused. Waiting for input or signals..."
                  << std::endl;
        first_pause_message = false;
      }

      std::this_thread::sleep_for(
          // std::chrono::seconds(current_config->live_monitoring_sleep_seconds));
          std::chrono::milliseconds(100));
    }
  }

  // --- Final Save on Graceful Exit ---
  if (keyboard_thread.joinable()) {
    pthread_kill(keyboard_thread.native_handle(), SIGCONT);
    keyboard_thread.join();
  }

  std::cout << "\nProcessing finished or shutdown signal received."
            << std::endl;

  if (current_config->state_persistence_enabled) {
    std::cout << "Saving final engine state..." << std::endl;
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
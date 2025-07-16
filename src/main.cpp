#include "analysis/analysis_engine.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "core/metrics_manager.hpp"
#include "detection/rule_engine.hpp"
#include "io/db/mongo_manager.hpp"
#include "io/log_readers/base_log_reader.hpp"
#include "io/log_readers/file_log_reader.hpp"
#include "io/log_readers/mongo_log_reader.hpp"
#include "io/web/web_server.hpp"
#include "models/model_manager.hpp"
#include "utils/thread_safe_queue.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <istream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <thread>
#include <utility>
#include <vector>

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

// --- Reader thread function ---
void log_reader_thread(ILogReader &reader, ThreadSafeQueue<LogEntry> &queue,
                       const std::atomic<bool> &shutdown_flag) {
  LOG(LogLevel::INFO, LogComponent::IO_READER, "Log reader thread started.");
  while (!shutdown_flag) {
    std::vector<LogEntry> log_batch = reader.get_next_batch();
    if (!log_batch.empty())
      for (auto &entry : log_batch)
        queue.push(std::move(entry));
    else
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  LOG(LogLevel::INFO, LogComponent::IO_READER,
      "Log reader thread shutting down.");
  queue.shutdown();
}

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

  // --- Load Configuration ---
  Config::ConfigManager config_manager;
  std::string config_file_to_load = "config.ini";
  if (argc > 1)
    config_file_to_load = argv[1];
  config_manager.load_configuration(config_file_to_load);

  auto current_config = config_manager.get_config();
  auto model_manager = std::make_shared<ModelManager>(*current_config);

  // --- Initialize Logging ---
  LogManager::instance().configure(current_config->logging);

  LOG(LogLevel::INFO, LogComponent::CORE,
      "Anomaly Detection Engine starting up...");
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  LOG(LogLevel::DEBUG, LogComponent::CORE, "PID: " << getpid());
#endif
  // --- Initialize Core Components ---
  AlertManager alert_manager_instance;
  alert_manager_instance.initialize(*current_config);

  AnalysisEngine analysis_engine_instance(*current_config);
  RuleEngine rule_engine_instance(alert_manager_instance, *current_config,
                                  model_manager);

  // --- Initialize Web Server ---
  WebServer web_server(config_manager.get_config()->monitoring.web_server_host,
                       config_manager.get_config()->monitoring.web_server_port,
                       MetricsManager::instance(), alert_manager_instance,
                       analysis_engine_instance);
  web_server.start();

  // --- Metrics Registration ---
  // TODO: Update metrics for multithreaded context
  /*
  auto *logs_processed_twc =
      MetricsManager::instance().register_time_window_counter(
          "ad_logs_processed", "Timestamped counter for processed logs to "
                               "calculate windowed rates.");

  auto *batch_processing_timer = MetricsManager::instance().register_histogram(
      "ad_batch_processing_duration_seconds",
      "Latency of processing a batch of logs.");

  auto *ip_states_gauge = MetricsManager::instance().register_gauge(
      "ad_active_ip_states", "Current number of IP states held in memory.");
  auto *path_states_gauge = MetricsManager::instance().register_gauge(
      "ad_active_path_states", "Current number of Path states held in memory.");
  auto *session_states_gauge = MetricsManager::instance().register_gauge(
      "ad_active_session_states",
      "Current number of Session states held in memory.");
  auto *ip_req_window_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_request_window\"}",
      "Total number of events across all IP request rate sliding windows.");
  auto *ip_login_window_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_failed_login_window\"}",
      "Total number of events across all IP failed login sliding windows.");
  auto *ip_html_window_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_html_request_window\"}",
      "Total number of events across all IP HTML request sliding windows.");
  auto *ip_asset_window_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_asset_request_window\"}",
      "Total number of events across all IP asset request sliding windows.");
  auto *ip_ua_window_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_ua_window\"}",
      "Total number of events across all IP User-Agent sliding windows.");
  auto *ip_paths_set_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_paths_seen_set\"}",
      "Total number of unique paths stored across all IP states.");
  auto *ip_historical_ua_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"ip_historical_ua_set\"}",
      "Total number of unique historical User-Agents stored across all IP "
      "states.");
  auto *session_req_window_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"session_request_window\"}",
      "Total number of events across all Session request rate sliding "
      "windows.");
  auto *session_unique_paths_gauge = MetricsManager::instance().register_gauge(
      "ad_state_elements_total{type=\"session_unique_paths\"}",
      "Total number of unique paths stored across all Session states.");
  auto *session_unique_user_agents_gauge =
      MetricsManager::instance().register_gauge(
          "ad_state_elements_total{type=\"session_unique_user_agents\"}",
          "Total number of unique User-Agents stored across all Session "
          "states.");
  */

  // --- Log Reader Factory ---
  std::unique_ptr<ILogReader> log_reader;
  std::shared_ptr<MongoManager> mongo_manager;
  LOG(LogLevel::INFO, LogComponent::IO_READER,
      "Initializing log reader of type: " << current_config->log_source_type);

  if (current_config->log_source_type == "file") {
    auto reader =
        std::make_unique<FileLogReader>(current_config->log_input_path);
    if (!reader->is_open()) {
      LOG(LogLevel::FATAL, LogComponent::IO_READER,
          "Failed to open log source file: " << current_config->log_input_path
                                             << ". Exiting.");
      return 1;
    }
    log_reader = std::move(reader);
  } else if (current_config->log_source_type == "mongodb") {
    mongo_manager =
        std::make_shared<MongoManager>(current_config->mongo_log_source.uri);
    log_reader = std::make_unique<MongoLogReader>(
        mongo_manager, current_config->mongo_log_source,
        current_config->reader_state_path);
    LOG(LogLevel::INFO, LogComponent::IO_READER,
        "Initialized MongoDB log reader.");
  } else {
    LOG(LogLevel::FATAL, LogComponent::CORE,
        "Invalid log_source_type configured: "
            << current_config->log_source_type << ". Exiting.");
    return 1;
  }

  // --- Central Log Queue ---
  ThreadSafeQueue<LogEntry> log_queue;
  std::thread reader_thread(log_reader_thread, std::ref(*log_reader),
                            std::ref(log_queue),
                            std::ref(g_shutdown_requested));

  // --- Worker Pool Setup ---
  // We subtract 2 to leave one core for the Log Reader thread and one for the
  // OS/Alerting/Dispatching
  const unsigned int num_workers =
      std::max(1u, std::thread::hardware_concurrency() - 2);
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Initializing with " << num_workers << " worker threads.");
  std::vector<std::unique_ptr<ThreadSafeQueue<LogEntry>>> worker_queues;
  for (unsigned int i = 0; i < num_workers; ++i)
    worker_queues.push_back(std::make_unique<ThreadSafeQueue<LogEntry>>());
  std::vector<std::thread> worker_threads;

  // Load state on startup
  if (current_config->state_persistence_enabled) {
    if (analysis_engine_instance.load_state(current_config->state_file_path))
      LOG(LogLevel::INFO, LogComponent::STATE_PERSIST,
          "Successfully loaded previous engine state.");
    else
      LOG(LogLevel::INFO, LogComponent::STATE_PERSIST,
          "No previous state file found or file was invalid. Starting with a "
          "fresh state.");
  }

  uint64_t total_processed_count = 0;
  auto time_start = std::chrono::high_resolution_clock::now();
  ServiceState current_state = ServiceState::RUNNING;
  bool first_pause_message = true;

  while (!g_shutdown_requested) {
    // --- Signal Polling and State Transition Block ---
    if (g_reset_state_requested.exchange(false)) {
      LOG(LogLevel::INFO, LogComponent::CORE,
          "SIGUSR1 or Ctrl+E detected. Resetting engine state...");
      analysis_engine_instance.reset_in_memory_state();
      if (current_config->state_persistence_enabled)
        if (std::remove(current_config->state_file_path.c_str()) == 0)
          LOG(LogLevel::INFO, LogComponent::STATE_PERSIST,
              "Deleted persisted state file: "
                  << current_config->state_file_path);
      first_pause_message = true;
    }

    if (g_reload_config_requested.exchange(false)) {
      LOG(LogLevel::INFO, LogComponent::CORE,
          "SIGHUP or Ctrl+R detected. Reloading configuration from "
              << config_file_to_load << "...");
      if (config_manager.load_configuration(config_file_to_load)) {
        current_config = config_manager.get_config();
        LogManager::instance().configure(current_config->logging);
        LOG(LogLevel::INFO, LogComponent::CONFIG,
            "Logger has been reconfigured.");
        alert_manager_instance.reconfigure(*current_config);
        rule_engine_instance.reconfigure(*current_config);
        analysis_engine_instance.reconfigure(*current_config);
        LOG(LogLevel::INFO, LogComponent::CONFIG,
            "All components reconfigured successfully.");
      } else
        LOG(LogLevel::ERROR, LogComponent::CONFIG,
            "Failed to reload configuration. Keeping old settings.");
      first_pause_message = true;
    }

    if (g_resume_requested.exchange(false) &&
        current_state == ServiceState::PAUSED) {
      LOG(LogLevel::INFO, LogComponent::CORE,
          "SIGCONT or Ctrl+Q detected. Resuming processing...");
      current_state = ServiceState::RUNNING;
      first_pause_message = true;
    }

    if (g_pause_requested.exchange(false) &&
        current_state == ServiceState::RUNNING) {
      LOG(LogLevel::INFO, LogComponent::CORE,
          "SIGUSR2 or Ctrl+P detected. Pausing processing...");
      current_state = ServiceState::PAUSED;
    }

    // --- State-Specific Action Block ---
    if (current_state == ServiceState::RUNNING) {
      std::optional<LogEntry> log_entry_opt = log_queue.wait_and_pop();

      if (!log_entry_opt) {
        if (g_shutdown_requested) {
          LOG(LogLevel::INFO, LogComponent::CORE,
              "Log queue is empty and shutdown is requested. Exiting loop.");
          break;
        }
        continue;
      }

      LogEntry &log_entry = *log_entry_opt;

      // --- Dispatcher Logic ---
      if (!log_entry.ip_address.empty()) {
        std::hash<std::string_view> hasher;
        size_t worker_index = hasher(log_entry.ip_address) % num_workers;
        worker_queues[worker_index]->push(std::move(log_entry));
      }

      total_processed_count++;

      // --- Periodic Tasks ---
      if (current_config->log_source_type != "stdin" &&
          total_processed_count % 10000 == 0) {
        LOG(LogLevel::DEBUG, LogComponent::CORE,
            "Progress: Dispatched "
                << total_processed_count << " logs to workers ("
                << (total_processed_count * 1000 /
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::high_resolution_clock::now() - time_start)
                        .count())
                << " lines/sec).");
      }
    } else if (current_state == ServiceState::PAUSED) {
      // --- Efficient Sleep State ---
      if (first_pause_message) {
        LOG(LogLevel::INFO, LogComponent::CORE,
            "Processing is paused. Waiting for input or signals...");
        first_pause_message = false;
      }

      std::this_thread::sleep_for(
          std::chrono::seconds(current_config->live_monitoring_sleep_seconds));
    }
  }

  // --- Shutdown Notification for Workers ---
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Main dispatch loop finished. Notifying worker queues to shut down...");
  for (auto &queue : worker_queues)
    queue->shutdown();

  // --- Final Save on Graceful Exit ---
  if (reader_thread.joinable())
    reader_thread.join();

  if (keyboard_thread.joinable()) {
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    pthread_kill(keyboard_thread.native_handle(), SIGCONT);
#endif
    keyboard_thread.join();
  }

  web_server.stop();

  LOG(LogLevel::INFO, LogComponent::CORE,
      "Processing finished or shutdown signal received.");

  if (current_config->state_persistence_enabled) {
    LOG(LogLevel::INFO, LogComponent::CORE, "Saving final engine state...");
    analysis_engine_instance.save_state(current_config->state_file_path);
  }

  alert_manager_instance.flush_all_alerts();

  auto time_end = std::chrono::high_resolution_clock::now();
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         time_end - time_start)
                         .count();

  LOG(LogLevel::INFO, LogComponent::CORE, "---Processing Summary---");
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Total entries processed: " << total_processed_count);
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Total processing time: " << duration_ms << " ms");
  if (duration_ms > 0 && total_processed_count > 0)
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Processing rate: " << (total_processed_count * 1000 / duration_ms)
                            << " lines/sec");
  LOG(LogLevel::INFO, LogComponent::CORE, "Anomaly Detection Engine finished.");
}
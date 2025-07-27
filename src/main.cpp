#include "analysis/analysis_engine.hpp"
#include "analysis/prometheus_anomaly_detector.hpp"
#include "analysis/prometheus_client.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "core/memory_manager.hpp"
#include "core/memory_profiler_hooks.hpp"
#include "core/metrics_manager.hpp"
#include "core/metrics_registry.hpp"
#include "core/resource_pool_manager.hpp"
#include "detection/rule_engine.hpp"
#include "io/db/mongo_manager.hpp"
#include "io/log_readers/base_log_reader.hpp"
#include "io/log_readers/file_log_reader.hpp"
#include "io/log_readers/mongo_log_reader.hpp"
#include "io/web/web_server.hpp"
#include "learning/dynamic_learning_engine.hpp"
#include "models/model_manager.hpp"
#include "utils/error_recovery_manager.hpp"
#include "utils/graceful_degradation_manager.hpp"
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

// Global component instances for lifecycle management
std::shared_ptr<memory::MemoryManager> g_memory_manager;
std::shared_ptr<learning::DynamicLearningEngine> g_learning_engine;
std::shared_ptr<resource::ResourcePoolManager> g_resource_pool_manager;

// Global error handling and recovery components
std::shared_ptr<error_recovery::ErrorRecoveryManager> g_error_recovery_manager;
std::shared_ptr<graceful_degradation::GracefulDegradationManager>
    g_degradation_manager;

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

// --- Worker thread function ---
void worker_thread(int worker_id, ThreadSafeQueue<LogEntry> &queue,
                   AnalysisEngine &analysis_engine, RuleEngine &rule_engine,
                   learning::DynamicLearningEngine &learning_engine,
                   const std::atomic<bool> &shutdown_flag) {
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Worker thread " << worker_id << " started.");

  // Performance monitoring
  uint64_t processed_count = 0;
  auto last_report_time = std::chrono::steady_clock::now();

  while (!shutdown_flag) {
    std::optional<LogEntry> log_entry_opt = queue.wait_and_pop();

    if (!log_entry_opt) {
      if (shutdown_flag || queue.empty()) {
        LOG(LogLevel::INFO, LogComponent::CORE,
            "Worker " << worker_id << " shutting down.");
        break;
      }
      continue;
    }

    LogEntry &log_entry = *log_entry_opt;

    if (log_entry.successfully_parsed_structure) {
      // Use resource pooling for analyzed events
      auto analyzed_event = analysis_engine.process_and_analyze(log_entry);

      // Feed data to learning engine for adaptive threshold updates
      auto timestamp_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count();

      // Update baselines for different entity types using available metrics
      if (analyzed_event.current_ip_request_count_in_window.has_value()) {
        std::string ip_addr(analyzed_event.raw_log.ip_address);
        learning_engine.update_baseline(
            "ip", ip_addr,
            static_cast<double>(
                analyzed_event.current_ip_request_count_in_window.value()),
            timestamp_ms);
      }

      if (!analyzed_event.raw_log.request_path.empty()) {
        learning_engine.update_baseline(
            "path", analyzed_event.raw_log.request_path,
            analyzed_event.path_error_event_zscore.value_or(0.0), timestamp_ms);
      }

      // Update session-based learning if session data is available
      if (analyzed_event.raw_session_state.has_value()) {
        std::string session_key =
            std::string(analyzed_event.raw_log.ip_address) + "_session";
        learning_engine.update_baseline(
            "session", session_key,
            analyzed_event.derived_session_features.has_value() ? 1.0 : 0.0,
            timestamp_ms);
      }

      // Evaluate rules with updated baselines
      rule_engine.evaluate_rules(analyzed_event);

      processed_count++;

      // Periodic performance reporting (every 10 seconds)
      auto now = std::chrono::steady_clock::now();
      if (std::chrono::duration_cast<std::chrono::seconds>(now -
                                                           last_report_time)
              .count() >= 10) {
        LOG(LogLevel::DEBUG, LogComponent::CORE,
            "Worker " << worker_id << " processed " << processed_count
                      << " events");
        last_report_time = now;
      }

      // Check for memory pressure periodically
      if (processed_count % 1000 == 0 && g_memory_manager) {
        if (g_memory_manager->is_memory_pressure()) {
          LOG(LogLevel::WARN, LogComponent::CORE,
              "Worker "
                  << worker_id
                  << " detected memory pressure, triggering optimization");
          g_memory_manager->trigger_compaction();
        }
      }
    }
  }

  LOG(LogLevel::INFO, LogComponent::CORE,
      "Worker " << worker_id << " finished. Processed " << processed_count
                << " events total.");
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
      case 3: // Ctrl+C
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

// Configure error recovery for system components
void configure_error_recovery(const Config::AppConfig &config) {
  if (!g_error_recovery_manager || !g_degradation_manager) {
    return;
  }

  // Configure error recovery for MongoDB operations
  error_recovery::RecoveryConfig mongo_config;
  mongo_config.strategy = error_recovery::RecoveryStrategy::CIRCUIT_BREAK;
  mongo_config.max_retries = 3;
  mongo_config.base_delay = std::chrono::milliseconds(500);
  mongo_config.circuit_config.failure_threshold = 5;
  mongo_config.circuit_config.timeout = std::chrono::milliseconds(30000);
  g_error_recovery_manager->register_component("mongodb", mongo_config);

  // Configure error recovery for log processing
  error_recovery::RecoveryConfig log_processing_config;
  log_processing_config.strategy = error_recovery::RecoveryStrategy::RETRY;
  log_processing_config.max_retries = 2;
  log_processing_config.base_delay = std::chrono::milliseconds(100);
  g_error_recovery_manager->register_component("log_processing",
                                               log_processing_config);

  // Configure error recovery for analysis engine
  error_recovery::RecoveryConfig analysis_config;
  analysis_config.strategy = error_recovery::RecoveryStrategy::FALLBACK;
  analysis_config.max_retries = 1;
  analysis_config.fallback_func = []() -> bool {
    // Simple fallback: just log that analysis was skipped
    LOG(LogLevel::WARN, LogComponent::ANALYSIS_LIFECYCLE,
        "Analysis fallback activated - skipping detailed analysis");
    return true;
  };
  g_error_recovery_manager->register_component("analysis_engine",
                                               analysis_config);

  // Configure graceful degradation services
  graceful_degradation::ServiceConfig threat_intel_service;
  threat_intel_service.priority = graceful_degradation::Priority::MEDIUM;
  threat_intel_service.auto_recovery = true;
  threat_intel_service.degradation_callback =
      [](graceful_degradation::DegradationMode mode) {
        switch (mode) {
        case graceful_degradation::DegradationMode::REDUCED:
          LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
              "Threat intel service degraded to reduced mode");
          break;
        case graceful_degradation::DegradationMode::MINIMAL:
          LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
              "Threat intel service degraded to minimal mode");
          break;
        case graceful_degradation::DegradationMode::DISABLED:
          LOG(LogLevel::ERROR, LogComponent::IO_THREATINTEL,
              "Threat intel service disabled due to resource pressure");
          break;
        default:
          LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
              "Threat intel service operating normally");
          break;
        }
      };
  g_degradation_manager->register_service("threat_intel", threat_intel_service);

  graceful_degradation::ServiceConfig ml_service;
  ml_service.priority = graceful_degradation::Priority::LOW;
  ml_service.auto_recovery = true;
  ml_service.degradation_callback =
      [](graceful_degradation::DegradationMode mode) {
        switch (mode) {
        case graceful_degradation::DegradationMode::REDUCED:
          LOG(LogLevel::WARN, LogComponent::ML_LIFECYCLE,
              "ML services degraded - reduced model complexity");
          break;
        case graceful_degradation::DegradationMode::DISABLED:
          LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
              "ML services disabled due to resource pressure");
          break;
        default:
          LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
              "ML services operating normally");
          break;
        }
      };
  g_degradation_manager->register_service("ml_services", ml_service);

  // Set degradation thresholds based on config
  graceful_degradation::DegradationThresholds thresholds;
  thresholds.cpu_threshold_medium = 75.0;
  thresholds.cpu_threshold_high = 90.0;
  thresholds.memory_threshold_medium = 80.0;
  thresholds.memory_threshold_high = 95.0;
  thresholds.queue_threshold_medium = 2000;
  thresholds.queue_threshold_high = 10000;
  g_degradation_manager->set_degradation_thresholds(thresholds);
}

// Component initialization and dependency injection
struct ComponentManager {
  std::shared_ptr<memory::MemoryManager> memory_manager;
  std::shared_ptr<learning::DynamicLearningEngine> learning_engine;
  std::shared_ptr<resource::ResourcePoolManager> resource_pool_manager;
  std::shared_ptr<prometheus::PrometheusMetricsExporter> metrics_exporter;

  bool initialize(const Config::AppConfig &config) {
    LOG(LogLevel::INFO, LogComponent::CORE, "Initializing core components...");

    // Initialize Memory Manager first (foundation for everything else)
    memory::MemoryConfig memory_config;
    memory_config.max_total_memory_mb =
        config.memory_management.max_memory_usage_mb;
    memory_config.pressure_threshold_mb =
        config.memory_management.memory_pressure_threshold_mb;
    memory_config.auto_compaction_enabled =
        config.memory_management.enable_memory_compaction;
    memory_config.detailed_tracking_enabled = false; // Set based on debug mode

    memory_manager = std::make_shared<memory::MemoryManager>(memory_config);
    if (!memory_manager) {
      LOG(LogLevel::FATAL, LogComponent::CORE,
          "Failed to initialize MemoryManager");
      return false;
    }

// Enable memory profiling for debug builds or if explicitly requested
#ifdef DEBUG
    profiling::MemoryProfiler::instance().enable(true);
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Memory profiling enabled for debug build");
#endif

    // Initialize Resource Pool Manager (depends on Memory Manager)
    resource_pool_manager =
        std::make_shared<resource::ResourcePoolManager>(memory_config);
    if (!resource_pool_manager) {
      LOG(LogLevel::FATAL, LogComponent::CORE,
          "Failed to initialize ResourcePoolManager");
      return false;
    }

    // Initialize Dynamic Learning Engine
    learning_engine = std::make_shared<learning::DynamicLearningEngine>(
        config.dynamic_learning);
    if (!learning_engine) {
      LOG(LogLevel::FATAL, LogComponent::CORE,
          "Failed to initialize DynamicLearningEngine");
      return false;
    }

    // Initialize Prometheus Metrics Exporter if enabled
    if (config.prometheus.enabled) {
      prometheus::PrometheusMetricsExporter::Config prometheus_config;
      prometheus_config.host = config.prometheus.host;
      prometheus_config.port = config.prometheus.port;
      prometheus_config.metrics_path = config.prometheus.metrics_path;
      prometheus_config.health_path = config.prometheus.health_path;
      prometheus_config.scrape_interval =
          std::chrono::seconds(config.prometheus.scrape_interval_seconds);
      prometheus_config.replace_web_server =
          config.prometheus.replace_web_server;

      metrics_exporter =
          std::make_shared<prometheus::PrometheusMetricsExporter>(
              prometheus_config);
      if (!metrics_exporter || !metrics_exporter->start_server()) {
        LOG(LogLevel::ERROR, LogComponent::CORE,
            "Failed to initialize PrometheusMetricsExporter");
        return false;
      }
    }

    // Set global references for signal handlers and emergency shutdown
    g_memory_manager = memory_manager;
    g_learning_engine = learning_engine;
    g_resource_pool_manager = resource_pool_manager;

    // Initialize Error Recovery Manager
    g_error_recovery_manager =
        std::make_shared<error_recovery::ErrorRecoveryManager>();
    if (!g_error_recovery_manager) {
      LOG(LogLevel::FATAL, LogComponent::CORE,
          "Failed to initialize ErrorRecoveryManager");
      return false;
    }

    // Initialize Graceful Degradation Manager
    g_degradation_manager =
        std::make_shared<graceful_degradation::GracefulDegradationManager>();
    if (!g_degradation_manager) {
      LOG(LogLevel::FATAL, LogComponent::CORE,
          "Failed to initialize GracefulDegradationManager");
      return false;
    }

    // Configure error recovery for core components
    configure_error_recovery(config);

    LOG(LogLevel::INFO, LogComponent::CORE,
        "All core components initialized successfully");
    return true;
  }

  void shutdown() {
    LOG(LogLevel::INFO, LogComponent::CORE, "Shutting down core components...");

    // Shutdown in reverse dependency order
    if (metrics_exporter) {
      metrics_exporter->stop_server();
      metrics_exporter.reset();
    }

    if (learning_engine) {
      // Learning engine will save state in destructor
      learning_engine.reset();
    }

    if (resource_pool_manager) {
      // Get final statistics
      auto stats = resource_pool_manager->get_statistics();
      LOG(LogLevel::INFO, LogComponent::CORE,
          "Resource pool final stats - LogEntry hit rate: "
              << stats.log_entry_stats.hit_rate() * 100.0
              << "%, AnalyzedEvent hit rate: "
              << stats.analyzed_event_stats.hit_rate() * 100.0 << "%");
      resource_pool_manager.reset();
    }

    if (memory_manager) {
// Generate memory report if profiling was enabled
#ifdef DEBUG
      auto report = profiling::MemoryProfiler::instance().generate_report();
      LOG(LogLevel::INFO, LogComponent::CORE,
          "Final memory report:\n"
              << report);
      profiling::MemoryProfiler::instance().export_to_file(
          "memory_profile_final.txt");
#endif

      memory_manager.reset();
    }

    // Clear global references
    g_memory_manager.reset();
    g_learning_engine.reset();
    g_resource_pool_manager.reset();

    // Clear error recovery components
    if (g_error_recovery_manager) {
      auto stats = g_error_recovery_manager->get_all_stats();
      LOG(LogLevel::INFO, LogComponent::CORE,
          "Error recovery final stats - Total errors handled: "
              << g_error_recovery_manager->get_total_errors());
      g_error_recovery_manager.reset();
    }

    if (g_degradation_manager) {
      auto degraded_services = g_degradation_manager->get_degraded_services();
      if (!degraded_services.empty()) {
        LOG(LogLevel::WARN, LogComponent::CORE,
            "Services still degraded at shutdown: "
                << degraded_services.size());
      }
      g_degradation_manager.reset();
    }

    LOG(LogLevel::INFO, LogComponent::CORE, "Core component shutdown complete");
  }

  void reconfigure(const Config::AppConfig &config) {
    LOG(LogLevel::INFO, LogComponent::CORE, "Reconfiguring core components...");

    // Reconfigure memory manager
    if (memory_manager) {
      memory::MemoryConfig memory_config;
      memory_config.max_total_memory_mb =
          config.memory_management.max_memory_usage_mb;
      memory_config.pressure_threshold_mb =
          config.memory_management.memory_pressure_threshold_mb;
      memory_config.auto_compaction_enabled =
          config.memory_management.enable_memory_compaction;

      // Note: MemoryManager doesn't have a reconfigure method, so we'll log the
      // intention
      LOG(LogLevel::DEBUG, LogComponent::CORE,
          "Memory manager reconfiguration requested (not yet implemented)");
    }

    // Learning engine will automatically adapt to new data patterns
    if (learning_engine) {
      LOG(LogLevel::DEBUG, LogComponent::CORE,
          "Learning engine will adapt to new configuration patterns");
    }

    LOG(LogLevel::INFO, LogComponent::CORE,
        "Core component reconfiguration complete");
  }

  void handle_memory_pressure() {
    if (resource_pool_manager) {
      resource_pool_manager->handle_memory_pressure();
    }
    if (memory_manager) {
      memory_manager->trigger_compaction();
      memory_manager->trigger_eviction();
    }
  }
};

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

  // --- Initialize Logging ---
  LogManager::instance().configure(current_config->logging);

  LOG(LogLevel::INFO, LogComponent::CORE,
      "Anomaly Detection Engine starting up...");
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  LOG(LogLevel::DEBUG, LogComponent::CORE, "PID: " << getpid());
#endif

  // --- Initialize Core Components ---
  ComponentManager component_manager;
  if (!component_manager.initialize(*current_config)) {
    LOG(LogLevel::FATAL, LogComponent::CORE,
        "Failed to initialize core components. Exiting.");
    return 1;
  }

  auto model_manager = std::make_shared<ModelManager>(*current_config);
  auto alert_manager_instance = std::make_shared<AlertManager>();
  alert_manager_instance->initialize(*current_config);

  // --- Metrics Registration ---
  // TODO: Update metrics for multithreaded context
  auto *logs_processed_twc =
      MetricsManager::instance().register_time_window_counter(
          "ad_logs_processed", "Timestamped counter for processed logs to "
                               "calculate windowed rates.");

  /*
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
  const unsigned int num_workers =
      std::max(1u, std::thread::hardware_concurrency() - 2);
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Initializing with " << num_workers << " worker threads.");
  std::vector<std::unique_ptr<ThreadSafeQueue<LogEntry>>> worker_queues;
  std::vector<std::unique_ptr<AnalysisEngine>> analysis_engines;
  std::vector<std::unique_ptr<RuleEngine>> rule_engines;
  std::vector<std::thread> worker_threads;

  for (unsigned int i = 0; i < num_workers; ++i) {
    worker_queues.push_back(std::make_unique<ThreadSafeQueue<LogEntry>>());
    auto analysis_engine = std::make_unique<AnalysisEngine>(*current_config);
    auto rule_engine = std::make_unique<RuleEngine>(
        *alert_manager_instance, *current_config, model_manager);
    analysis_engines.push_back(std::move(analysis_engine));
    rule_engines.push_back(std::move(rule_engine));
  }

  // --- Tier 4 (Prometheus Anomaly Detection) Initialization ---
  std::shared_ptr<analysis::PrometheusAnomalyDetector> tier4_detector;
  if (current_config->tier4.enabled) {
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Initializing Tier 4 Prometheus anomaly detection...");

    // Create Prometheus client config
    PrometheusClientConfig client_config;
    client_config.endpoint_url = current_config->tier4.prometheus_url;
    client_config.timeout =
        std::chrono::seconds(current_config->tier4.query_timeout_seconds);
    client_config.bearer_token = current_config->tier4.auth_token;

    // Create Prometheus client
    auto prometheus_client = std::make_shared<PrometheusClient>(client_config);

    // Create anomaly detector
    tier4_detector = std::make_shared<analysis::PrometheusAnomalyDetector>(
        prometheus_client);

    // Set detector for all rule engines
    for (auto &rule_engine : rule_engines) {
      rule_engine->set_tier4_anomaly_detector(tier4_detector);
    }

    LOG(LogLevel::INFO, LogComponent::CORE,
        "Tier 4 Prometheus anomaly detection initialized with URL: "
            << current_config->tier4.prometheus_url);
  } else {
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Tier 4 Prometheus anomaly detection disabled in configuration");
  }

  // --- Prometheus Metrics Exporter Integration ---
  auto metrics_exporter = component_manager.metrics_exporter;
  if (metrics_exporter) {
    // Set metrics exporter for alert manager
    alert_manager_instance->set_metrics_exporter(metrics_exporter);

    // If configured to replace web server, set up the necessary dependencies
    if (current_config->prometheus.replace_web_server) {
      // Set the alert manager for the metrics exporter
      metrics_exporter->set_alert_manager(alert_manager_instance);

      // Create a non-owning shared_ptr to the first analysis engine
      // This is safe because the analysis_engines vector owns the engine and
      // outlives the metrics_exporter
      auto analysis_engine_ptr = std::shared_ptr<AnalysisEngine>(
          analysis_engines[0].get(), [](AnalysisEngine *) {});
      metrics_exporter->set_analysis_engine(analysis_engine_ptr);

      LOG(LogLevel::INFO, LogComponent::CORE,
          "Prometheus metrics exporter configured with endpoints:"
          "\n  - "
              << current_config->prometheus.metrics_path
              << " (metrics)"
                 "\n  - "
              << current_config->prometheus.health_path
              << " (health check)"
                 "\n  - /api/v1/operations/alerts (alerts API)"
                 "\n  - /api/v1/operations/state (state API)");
    }
  }

  // --- Web Server Initialization ---
  std::unique_ptr<WebServer> web_server;
  if (!current_config->prometheus.enabled ||
      (current_config->prometheus.enabled &&
       !current_config->prometheus.replace_web_server)) {
    // Only start the web server if Prometheus is not enabled or if it's enabled
    // but not configured to replace the web server
    auto &memory_gauge = MetricsRegistry::instance().create_gauge(
        "memory_usage_bytes", "Memory usage in bytes");

    // Check if we need to use a different port when both systems are running
    int web_server_port = current_config->monitoring.web_server_port;
    if (current_config->prometheus.enabled &&
        current_config->prometheus.port == web_server_port) {
      // Use a different port to avoid conflict
      web_server_port++;
      LOG(LogLevel::WARN, LogComponent::CORE,
          "Web server port conflicts with Prometheus port. Using port "
              << web_server_port << " instead.");
    }

    web_server = std::make_unique<WebServer>(
        current_config->monitoring.web_server_host, web_server_port,
        MetricsRegistry::instance(), *alert_manager_instance,
        *analysis_engines[0], memory_gauge);
    web_server->start();
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Web server started on " << current_config->monitoring.web_server_host
                                 << ":" << web_server_port);
  } else {
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Custom web server disabled as Prometheus metrics exporter is "
        "configured to replace it");
  }

  // --- Set metrics exporter for worker components ---
  if (metrics_exporter) {
    for (unsigned int i = 0; i < num_workers; ++i) {
      analysis_engines[i]->set_metrics_exporter(metrics_exporter);
      rule_engines[i]->set_metrics_exporter(metrics_exporter);
    }
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Prometheus metrics exporter set for all worker components");
  } // --- Launch Worker Threads ---
  for (unsigned int i = 0; i < num_workers; ++i) {
    worker_threads.emplace_back(worker_thread, i, std::ref(*worker_queues[i]),
                                std::ref(*analysis_engines[i]),
                                std::ref(*rule_engines[i]),
                                std::ref(*component_manager.learning_engine),
                                std::ref(g_shutdown_requested));
  }

  // State loading must happen after engines are created but before workers
  // (current_config->state_persistence_enabled) { ... }

  uint64_t total_processed_count = 0;
  auto time_start = std::chrono::high_resolution_clock::now();
  ServiceState current_state = ServiceState::RUNNING;
  bool first_pause_message = true;

  while (!g_shutdown_requested) {
    // --- Signal Polling and State Transition Block ---
    if (g_reset_state_requested.exchange(false)) {
      LOG(LogLevel::WARN, LogComponent::CORE,
          "SIGUSR1 or Ctrl+E detected. Resetting all worker engine states...");
      for (auto &engine : analysis_engines)
        engine->reset_in_memory_state();

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

        // Reconfigure core components
        component_manager.reconfigure(*current_config);

        alert_manager_instance->reconfigure(*current_config);

        // Reconfigure all worker engines
        for (auto &engine : analysis_engines)
          engine->reconfigure(*current_config);
        for (auto &engine : rule_engines)
          engine->reconfigure(*current_config);
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
              "Log queue is empty and shutdown is requested. Exiting dispatch "
              "loop.");
          break;
        }
        continue;
      }

      LogEntry &log_entry = *log_entry_opt;

      // --- Dispatcher Logic ---
      logs_processed_twc->record_event();

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

        // Check memory pressure every 10k processed entries
        if (g_memory_manager && g_memory_manager->is_memory_pressure()) {
          LOG(LogLevel::WARN, LogComponent::CORE,
              "Memory pressure detected, triggering optimizations");
          component_manager.handle_memory_pressure();
        }
      }

      // More frequent memory pressure checks for high-volume scenarios
      if (total_processed_count % 1000 == 0) {
        if (g_memory_manager &&
            g_memory_manager->get_memory_pressure_level() > 2) {
          LOG(LogLevel::WARN, LogComponent::CORE,
              "High memory pressure detected, triggering immediate compaction");
          g_memory_manager->trigger_compaction();
        }
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

  LOG(LogLevel::INFO, LogComponent::CORE, "Joining worker threads...");
  for (auto &t : worker_threads)
    if (t.joinable())
      t.join();
  LOG(LogLevel::INFO, LogComponent::CORE, "Worker threads joined.");

  if (keyboard_thread.joinable()) {
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    pthread_kill(keyboard_thread.native_handle(), SIGCONT);
#endif
    keyboard_thread.join();
  }

  // Stop web server or Prometheus exporter
  if (web_server) {
    web_server->stop();
    LOG(LogLevel::INFO, LogComponent::CORE, "Web server stopped");
  }

  // Shutdown core components
  component_manager.shutdown();

  LOG(LogLevel::INFO, LogComponent::CORE,
      "Processing finished or shutdown signal received.");

  // State saving is disabled for now
  // if (current_config->state_persistence_enabled) { ... }

  alert_manager_instance->flush_all_alerts();

  auto time_end = std::chrono::high_resolution_clock::now();
  auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         time_end - time_start)
                         .count();

  LOG(LogLevel::INFO, LogComponent::CORE, "---Processing Summary---");
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Total entries dispatched: " << total_processed_count);
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Total processing time: " << duration_ms << " ms");
  if (duration_ms > 0 && total_processed_count > 0)
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Dispatch rate: " << (total_processed_count * 1000 / duration_ms)
                          << " lines/sec");
  LOG(LogLevel::INFO, LogComponent::CORE, "Anomaly Detection Engine finished.");
}
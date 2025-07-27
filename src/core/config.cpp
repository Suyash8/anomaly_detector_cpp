#include "config.hpp"
#include "logger.hpp"
#include "utils/utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace Config {

AppConfig GlobalAppConfig;

LogLevel string_to_log_level(const std::string &level_str_raw) {
  std::string level_str = Utils::trim_copy(level_str_raw);
  std::transform(level_str.begin(), level_str.end(), level_str.begin(),
                 ::toupper);
  if (level_str == "TRACE")
    return LogLevel::TRACE;
  if (level_str == "DEBUG")
    return LogLevel::DEBUG;
  if (level_str == "INFO")
    return LogLevel::INFO;
  if (level_str == "WARN")
    return LogLevel::WARN;
  if (level_str == "ERROR")
    return LogLevel::ERROR;
  if (level_str == "FATAL")
    return LogLevel::FATAL;
  return LogLevel::INFO; // A safe default
}

const std::map<std::string, LogComponent> key_to_component_map = {
    {"core", LogComponent::CORE},
    {"config", LogComponent::CONFIG},
    {"io.reader", LogComponent::IO_READER},
    {"io.dispatch", LogComponent::IO_DISPATCH},
    {"io.threatintel", LogComponent::IO_THREATINTEL},
    {"analysis.lifecycle", LogComponent::ANALYSIS_LIFECYCLE},
    {"analysis.window", LogComponent::ANALYSIS_WINDOW},
    {"analysis.stats", LogComponent::ANALYSIS_STATS},
    {"analysis.zscore", LogComponent::ANALYSIS_ZSCORE},
    {"analysis.session", LogComponent::ANALYSIS_SESSION},
    {"rules.eval", LogComponent::RULES_EVAL},
    {"rules.t1", LogComponent::RULES_T1_HEURISTIC},
    {"rules.t2", LogComponent::RULES_T2_STATISTICAL},
    {"rules.t3", LogComponent::RULES_T3_ML},
    {"ml.features", LogComponent::ML_FEATURES},
    {"ml.inference", LogComponent::ML_INFERENCE},
    {"ml.lifecycle", LogComponent::ML_LIFECYCLE},
    {"state.persist", LogComponent::STATE_PERSIST},
    {"state.prune", LogComponent::STATE_PRUNE}};

// Convert string to boolean using common truthy values
bool string_to_bool(std::string &val_str_raw) {
  std::string val_str = Utils::trim_copy(val_str_raw);
  std::transform(val_str.begin(), val_str.end(), val_str.begin(), ::tolower);
  return (val_str == "true" || val_str == "1" || val_str == "yes" ||
          val_str == "on");
}

// Validation functions for configuration parameters
bool validate_prometheus_config(const PrometheusConfig &config,
                                std::vector<std::string> &errors) {
  bool valid = true;

  if (config.port < 1 || config.port > 65535) {
    errors.push_back("Prometheus port must be between 1 and 65535");
    valid = false;
  }

  if (config.scrape_interval_seconds < 1 ||
      config.scrape_interval_seconds > 3600) {
    errors.push_back(
        "Prometheus scrape interval must be between 1 and 3600 seconds");
    valid = false;
  }

  if (config.max_metrics_age_seconds < 60 ||
      config.max_metrics_age_seconds > 86400) {
    errors.push_back(
        "Prometheus max metrics age must be between 60 and 86400 seconds");
    valid = false;
  }

  if (config.metrics_path.empty() || config.metrics_path[0] != '/') {
    errors.push_back("Prometheus metrics path must start with '/'");
    valid = false;
  }

  if (config.health_path.empty() || config.health_path[0] != '/') {
    errors.push_back("Prometheus health path must start with '/'");
    valid = false;
  }

  return valid;
}

bool validate_dynamic_learning_config(const DynamicLearningConfig &config,
                                      std::vector<std::string> &errors) {
  bool valid = true;

  if (config.learning_window_hours < 1 ||
      config.learning_window_hours > 168) { // 1 week max
    errors.push_back("Dynamic learning window must be between 1 and 168 hours");
    valid = false;
  }

  if (config.confidence_threshold < 0.5 || config.confidence_threshold > 1.0) {
    errors.push_back(
        "Dynamic learning confidence threshold must be between 0.5 and 1.0");
    valid = false;
  }

  if (config.min_samples_for_learning < 10 ||
      config.min_samples_for_learning > 10000) {
    errors.push_back(
        "Dynamic learning minimum samples must be between 10 and 10000");
    valid = false;
  }

  if (config.seasonal_detection_sensitivity < 0.1 ||
      config.seasonal_detection_sensitivity > 1.0) {
    errors.push_back("Dynamic learning seasonal detection sensitivity must be "
                     "between 0.1 and 1.0");
    valid = false;
  }

  if (config.baseline_update_interval_seconds < 60 ||
      config.baseline_update_interval_seconds > 86400) {
    errors.push_back("Dynamic learning baseline update interval must be "
                     "between 60 and 86400 seconds");
    valid = false;
  }

  if (config.threshold_change_max_percent < 1.0 ||
      config.threshold_change_max_percent > 500.0) {
    errors.push_back("Dynamic learning threshold change max percent must be "
                     "between 1.0 and 500.0");
    valid = false;
  }

  // Enhanced adaptive threshold validation
  if (config.default_percentile_95 < 0.5 ||
      config.default_percentile_95 > 1.0) {
    errors.push_back(
        "Dynamic learning default 95th percentile must be between 0.5 and 1.0");
    valid = false;
  }

  if (config.default_percentile_99 < 0.5 ||
      config.default_percentile_99 > 1.0) {
    errors.push_back(
        "Dynamic learning default 99th percentile must be between 0.5 and 1.0");
    valid = false;
  }

  if (config.default_percentile_95 >= config.default_percentile_99) {
    errors.push_back(
        "Dynamic learning 95th percentile must be less than 99th percentile");
    valid = false;
  }

  if (config.threshold_cache_ttl_seconds < 10 ||
      config.threshold_cache_ttl_seconds > 3600) {
    errors.push_back("Dynamic learning threshold cache TTL must be between 10 "
                     "and 3600 seconds");
    valid = false;
  }

  if (config.security_critical_max_change_percent < 1.0 ||
      config.security_critical_max_change_percent > 100.0) {
    errors.push_back("Dynamic learning security critical max change percent "
                     "must be between 1.0 and 100.0");
    valid = false;
  }

  if (config.max_audit_entries_per_entity < 10 ||
      config.max_audit_entries_per_entity > 1000) {
    errors.push_back("Dynamic learning max audit entries per entity must be "
                     "between 10 and 1000");
    valid = false;
  }

  if (config.failed_login_threshold_for_critical < 1 ||
      config.failed_login_threshold_for_critical > 100) {
    errors.push_back("Dynamic learning failed login threshold for critical "
                     "marking must be between 1 and 100");
    valid = false;
  }

  return valid;
}

bool validate_tier4_config(const Tier4Config &config,
                           std::vector<std::string> &errors) {
  bool valid = true;

  if (config.enabled && config.prometheus_url.empty()) {
    errors.push_back(
        "Tier4 Prometheus URL cannot be empty when Tier4 is enabled");
    valid = false;
  }

  if (config.query_timeout_seconds < 1 || config.query_timeout_seconds > 300) {
    errors.push_back("Tier4 query timeout must be between 1 and 300 seconds");
    valid = false;
  }

  if (config.evaluation_interval_seconds < 10 ||
      config.evaluation_interval_seconds > 3600) {
    errors.push_back(
        "Tier4 evaluation interval must be between 10 and 3600 seconds");
    valid = false;
  }

  if (config.max_concurrent_queries < 1 ||
      config.max_concurrent_queries > 100) {
    errors.push_back("Tier4 max concurrent queries must be between 1 and 100");
    valid = false;
  }

  if (config.circuit_breaker_failure_threshold < 1 ||
      config.circuit_breaker_failure_threshold > 50) {
    errors.push_back(
        "Tier4 circuit breaker failure threshold must be between 1 and 50");
    valid = false;
  }

  if (config.circuit_breaker_recovery_timeout_seconds < 10 ||
      config.circuit_breaker_recovery_timeout_seconds > 3600) {
    errors.push_back("Tier4 circuit breaker recovery timeout must be between "
                     "10 and 3600 seconds");
    valid = false;
  }

  return valid;
}

bool validate_memory_management_config(const MemoryManagementConfig &config,
                                       std::vector<std::string> &errors) {
  bool valid = true;

  if (config.max_memory_usage_mb < 64 ||
      config.max_memory_usage_mb > 32768) { // 64MB to 32GB
    errors.push_back(
        "Memory management max memory usage must be between 64 and 32768 MB");
    valid = false;
  }

  if (config.memory_pressure_threshold_mb >= config.max_memory_usage_mb) {
    errors.push_back("Memory management pressure threshold must be less than "
                     "max memory usage");
    valid = false;
  }

  if (config.eviction_check_interval_seconds < 10 ||
      config.eviction_check_interval_seconds > 3600) {
    errors.push_back("Memory management eviction check interval must be "
                     "between 10 and 3600 seconds");
    valid = false;
  }

  if (config.eviction_threshold_percent < 50.0 ||
      config.eviction_threshold_percent > 95.0) {
    errors.push_back("Memory management eviction threshold percent must be "
                     "between 50.0 and 95.0");
    valid = false;
  }

  if (config.state_object_ttl_seconds < 300 ||
      config.state_object_ttl_seconds > 86400) {
    errors.push_back("Memory management state object TTL must be between 300 "
                     "and 86400 seconds");
    valid = false;
  }

  return valid;
}

bool validate_performance_monitoring_config(
    const PerformanceMonitoringConfig &config,
    std::vector<std::string> &errors) {
  bool valid = true;

  if (config.metrics_collection_interval_ms < 100 ||
      config.metrics_collection_interval_ms > 60000) {
    errors.push_back("Performance monitoring metrics collection interval must "
                     "be between 100 and 60000 ms");
    valid = false;
  }

  if (config.max_latency_samples_per_component < 100 ||
      config.max_latency_samples_per_component > 100000) {
    errors.push_back("Performance monitoring max latency samples per component "
                     "must be between 100 and 100000");
    valid = false;
  }

  if (config.max_cpu_usage_percent < 10.0 ||
      config.max_cpu_usage_percent > 100.0) {
    errors.push_back("Performance monitoring max CPU usage percent must be "
                     "between 10.0 and 100.0");
    valid = false;
  }

  if (config.max_memory_usage_bytes < 104857600 ||
      config.max_memory_usage_bytes > 17179869184) { // 100MB to 16GB
    errors.push_back("Performance monitoring max memory usage must be between "
                     "100MB and 16GB");
    valid = false;
  }

  if (config.max_queue_depth < 100 || config.max_queue_depth > 1000000) {
    errors.push_back("Performance monitoring max queue depth must be between "
                     "100 and 1000000");
    valid = false;
  }

  if (config.max_avg_latency_ms < 10 || config.max_avg_latency_ms > 60000) {
    errors.push_back("Performance monitoring max average latency must be "
                     "between 10 and 60000 ms");
    valid = false;
  }

  if (config.max_error_rate_percent < 0.1 ||
      config.max_error_rate_percent > 50.0) {
    errors.push_back("Performance monitoring max error rate percent must be "
                     "between 0.1 and 50.0");
    valid = false;
  }

  if (config.moderate_load_shed_percentage < 1.0 ||
      config.moderate_load_shed_percentage > 50.0) {
    errors.push_back("Performance monitoring moderate load shed percentage "
                     "must be between 1.0 and 50.0");
    valid = false;
  }

  if (config.high_load_shed_percentage < 5.0 ||
      config.high_load_shed_percentage > 75.0) {
    errors.push_back("Performance monitoring high load shed percentage must be "
                     "between 5.0 and 75.0");
    valid = false;
  }

  if (config.critical_load_shed_percentage < 10.0 ||
      config.critical_load_shed_percentage > 95.0) {
    errors.push_back("Performance monitoring critical load shed percentage "
                     "must be between 10.0 and 95.0");
    valid = false;
  }

  if (config.monitoring_loop_interval_seconds < 1 ||
      config.monitoring_loop_interval_seconds > 300) {
    errors.push_back("Performance monitoring loop interval must be between 1 "
                     "and 300 seconds");
    valid = false;
  }

  if (config.max_profile_samples_per_function < 100 ||
      config.max_profile_samples_per_function > 10000) {
    errors.push_back("Performance monitoring max profile samples per function "
                     "must be between 100 and 10000");
    valid = false;
  }

  if (config.profile_report_interval_seconds < 30 ||
      config.profile_report_interval_seconds > 3600) {
    errors.push_back("Performance monitoring profile report interval must be "
                     "between 30 and 3600 seconds");
    valid = false;
  }

  if (config.performance_report_interval_seconds < 10 ||
      config.performance_report_interval_seconds > 3600) {
    errors.push_back("Performance monitoring performance report interval must "
                     "be between 10 and 3600 seconds");
    valid = false;
  }

  return valid;
}

bool validate_error_handling_config(const ErrorHandlingConfig &config,
                                    std::vector<std::string> &errors) {
  bool valid = true;

  if (config.circuit_breaker_failure_threshold < 1 ||
      config.circuit_breaker_failure_threshold > 100) {
    errors.push_back("Error handling circuit breaker failure threshold must be "
                     "between 1 and 100");
    valid = false;
  }

  if (config.circuit_breaker_timeout_ms < 100 ||
      config.circuit_breaker_timeout_ms > 300000) {
    errors.push_back("Error handling circuit breaker timeout must be between "
                     "100 and 300000 ms");
    valid = false;
  }

  if (config.circuit_breaker_recovery_timeout_ms < 1000 ||
      config.circuit_breaker_recovery_timeout_ms > 600000) {
    errors.push_back("Error handling circuit breaker recovery timeout must be "
                     "between 1000 and 600000 ms");
    valid = false;
  }

  if (config.max_retry_attempts < 0 || config.max_retry_attempts > 10) {
    errors.push_back(
        "Error handling max retry attempts must be between 0 and 10");
    valid = false;
  }

  if (config.initial_retry_delay_ms < 1 ||
      config.initial_retry_delay_ms > 60000) {
    errors.push_back(
        "Error handling initial retry delay must be between 1 and 60000 ms");
    valid = false;
  }

  if (config.max_retry_delay_ms < 1000 || config.max_retry_delay_ms > 300000) {
    errors.push_back(
        "Error handling max retry delay must be between 1000 and 300000 ms");
    valid = false;
  }

  if (config.retry_backoff_multiplier < 1.1 ||
      config.retry_backoff_multiplier > 10.0) {
    errors.push_back(
        "Error handling retry backoff multiplier must be between 1.1 and 10.0");
    valid = false;
  }

  if (config.cpu_threshold_for_degradation < 50.0 ||
      config.cpu_threshold_for_degradation > 100.0) {
    errors.push_back("Error handling CPU threshold for degradation must be "
                     "between 50.0 and 100.0");
    valid = false;
  }

  if (config.memory_threshold_for_degradation_mb < 100 ||
      config.memory_threshold_for_degradation_mb > 32768) {
    errors.push_back("Error handling memory threshold for degradation must be "
                     "between 100 and 32768 MB");
    valid = false;
  }

  if (config.queue_depth_threshold_for_degradation < 1000 ||
      config.queue_depth_threshold_for_degradation > 1000000) {
    errors.push_back("Error handling queue depth threshold for degradation "
                     "must be between 1000 and 1000000");
    valid = false;
  }

  if (config.error_rate_threshold_for_degradation < 1.0 ||
      config.error_rate_threshold_for_degradation > 100.0) {
    errors.push_back("Error handling error rate threshold for degradation must "
                     "be between 1.0 and 100.0");
    valid = false;
  }

  // Validate recovery strategy values
  std::vector<std::string> valid_strategies = {"RETRY", "CIRCUIT_BREAK",
                                               "FALLBACK", "FAIL_FAST"};
  auto validate_strategy = [&](const std::string &strategy,
                               const std::string &context) {
    if (std::find(valid_strategies.begin(), valid_strategies.end(), strategy) ==
        valid_strategies.end()) {
      errors.push_back("Error handling " + context +
                       " recovery strategy must be one of: RETRY, "
                       "CIRCUIT_BREAK, FALLBACK, FAIL_FAST");
      return false;
    }
    return true;
  };

  if (!validate_strategy(config.default_recovery_strategy, "default"))
    valid = false;
  if (!validate_strategy(config.prometheus_recovery_strategy, "prometheus"))
    valid = false;
  if (!validate_strategy(config.database_recovery_strategy, "database"))
    valid = false;
  if (!validate_strategy(config.file_io_recovery_strategy, "file I/O"))
    valid = false;
  if (!validate_strategy(config.network_recovery_strategy, "network"))
    valid = false;

  if (config.max_errors_per_minute < 1 ||
      config.max_errors_per_minute > 10000) {
    errors.push_back(
        "Error handling max errors per minute must be between 1 and 10000");
    valid = false;
  }

  if (config.error_burst_limit < 1 || config.error_burst_limit > 1000) {
    errors.push_back(
        "Error handling error burst limit must be between 1 and 1000");
    valid = false;
  }

  if (config.recovery_statistics_interval_seconds < 10 ||
      config.recovery_statistics_interval_seconds > 3600) {
    errors.push_back("Error handling recovery statistics interval must be "
                     "between 10 and 3600 seconds");
    valid = false;
  }

  // Validate log level
  std::vector<std::string> valid_log_levels = {"DEBUG", "INFO", "WARN",
                                               "ERROR"};
  if (std::find(valid_log_levels.begin(), valid_log_levels.end(),
                config.recovery_log_level) == valid_log_levels.end()) {
    errors.push_back("Error handling recovery log level must be one of: DEBUG, "
                     "INFO, WARN, ERROR");
    valid = false;
  }

  return valid;
}

bool validate_app_config(const AppConfig &config,
                         std::vector<std::string> &errors) {
  bool valid = true;

  // Validate new configuration sections
  if (!validate_prometheus_config(config.prometheus, errors)) {
    valid = false;
  }

  if (!validate_dynamic_learning_config(config.dynamic_learning, errors)) {
    valid = false;
  }

  if (!validate_tier4_config(config.tier4, errors)) {
    valid = false;
  }

  if (!validate_memory_management_config(config.memory_management, errors)) {
    valid = false;
  }

  if (!validate_performance_monitoring_config(config.performance_monitoring,
                                              errors)) {
    valid = false;
  }

  if (!validate_error_handling_config(config.error_handling, errors)) {
    valid = false;
  }

  // Cross-component validation
  if (config.prometheus.enabled && config.prometheus.replace_web_server &&
      config.monitoring.web_server_port == config.prometheus.port) {
    errors.push_back("Prometheus and monitoring cannot use the same port when "
                     "replace_web_server is enabled");
    valid = false;
  }

  if (config.tier4.enabled && !config.prometheus.enabled) {
    errors.push_back(
        "Tier4 requires Prometheus to be enabled for metrics export");
    valid = false;
  }

  return valid;
}

bool parse_config_into(const std::string &filepath, AppConfig &config) {
  // By default, everything is set to a high level (WARN)
  for (const auto &pair : key_to_component_map) {
    config.logging.log_levels[pair.second] = LogLevel::WARN;
  }
  // Except for CORE, which we want to see INFO messages from by default
  config.logging.log_levels[LogComponent::CORE] = LogLevel::INFO;

  std::cout << "Attempting to load configuration from " << filepath
            << std::endl;
  std::ifstream config_file(filepath);

  if (!config_file.is_open()) {
    std::cerr << "Warning: Could not open config file '" << filepath
              << "'. Using default configuration values." << std::endl;
    return false;
  }

  std::string line;
  std::string current_section;

  int line_num = 0;
  while (std::getline(config_file, line)) {
    line_num++;
    std::string trimmed_line = Utils::trim_copy(line);

    // Skip empty lines and comments
    if (trimmed_line.empty() || trimmed_line[0] == '#' ||
        trimmed_line[0] == ';')
      continue;

    // Section header [SectionName]
    if (trimmed_line[0] == '[' && trimmed_line.back() == ']') {
      current_section =
          Utils::trim_copy(trimmed_line.substr(1, trimmed_line.length() - 2));
      continue;
    }

    // Key-value pair parsing
    size_t delimiter_pos = trimmed_line.find('=');
    if (delimiter_pos == std::string::npos) {
      std::cerr << "Warning (Config Line " << line_num
                << "): Invalid format (missing '='): " << trimmed_line
                << std::endl;
      continue;
    }

    std::string key = Utils::trim_copy(trimmed_line.substr(0, delimiter_pos));
    std::string value =
        Utils::trim_copy(trimmed_line.substr(delimiter_pos + 1));

    if (key.empty()) {
      std::cerr << "Warning (Config Line " << line_num << "): Empty key found."
                << std::endl;
      continue;
    }

    try {
      // Global (non-section) keys
      if (current_section.empty()) {
        if (key == Keys::LOG_SOURCE_TYPE)
          config.log_source_type = value;
        else if (key == Keys::LOG_INPUT_PATH)
          config.log_input_path = value;
        else if (key == Keys::READER_STATE_PATH)
          config.reader_state_path = value;
        else if (key == Keys::ALLOWLIST_PATH)
          config.allowlist_path = value;
        else if (key == Keys::ALERTS_TO_STDOUT)
          config.alerts_to_stdout = string_to_bool(value);
        else if (key == Keys::ALERTS_TO_FILE)
          config.alerts_to_file = string_to_bool(value);
        else if (key == Keys::ALERT_OUTPUT_PATH)
          config.alert_output_path = value;
        else if (key == Keys::STATE_PERSISTENCE_ENABLED)
          config.state_persistence_enabled = string_to_bool(value);
        else if (key == Keys::STATE_FILE_PATH)
          config.state_file_path = value;
        else if (key == Keys::STATE_SAVE_INTERVAL_EVENTS)
          config.state_save_interval_events =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.state_save_interval_events);
        else if (key == Keys::STATE_PRUNING_ENABLED)
          config.state_pruning_enabled = string_to_bool(value);
        else if (key == Keys::STATE_TTL_SECONDS)
          config.state_ttl_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.state_ttl_seconds);
        else if (key == Keys::STATE_PRUNE_INTERVAL_EVENTS)
          config.state_prune_interval_events =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.state_prune_interval_events);
        else if (key == Keys::LIVE_MONITORING_ENABLED)
          config.live_monitoring_enabled = string_to_bool(value);
        else if (key == Keys::LIVE_MONITORING_SLEEP_SECONDS)
          config.live_monitoring_sleep_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.live_monitoring_sleep_seconds);
        else if (key == Keys::STATE_FILE_MAGIC)
          config.state_file_magic =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.state_file_magic);
        else if (key == Keys::ALERT_THROTTLE_DURATION_SECONDS)
          config.alert_throttle_duration_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.alert_throttle_duration_seconds);
        else if (key == Keys::ALERT_THROTTLE_MAX_ALERTS)
          config.alert_throttle_max_alerts =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.alert_throttle_max_alerts);
        else if (key == Keys::ML_DATA_COLLECTION_ENABLED)
          config.ml_data_collection_enabled = string_to_bool(value);
        else if (key == Keys::ML_DATA_COLLECTION_PATH)
          config.ml_data_collection_path = value;
        else
          config.custom_settings[key] = value;

        // Tier 1 settings
      } else if (current_section == "Tier1") {
        if (key == Keys::T1_ENABLED)
          config.tier1.enabled = string_to_bool(value);
        else if (key == Keys::T1_SLIDING_WINDOW_SECONDS)
          config.tier1.sliding_window_duration_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.tier1.sliding_window_duration_seconds);
        else if (key == Keys::T1_MAX_REQUESTS_PER_IP)
          config.tier1.max_requests_per_ip_in_window =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_requests_per_ip_in_window);
        else if (key == Keys::T1_MAX_FAILED_LOGINS_PER_IP)
          config.tier1.max_failed_logins_per_ip =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_failed_logins_per_ip);
        else if (key == Keys::T1_FAILED_LOGIN_STATUS_CODES) {
          std::vector<short> codes;
          std::string code_str;
          std::istringstream stream(value);
          while (std::getline(stream, code_str, ','))
            if (auto code_opt =
                    Utils::string_to_number<short>(Utils::trim_copy(code_str)))
              codes.push_back(*code_opt);

          if (!codes.empty())
            config.tier1.failed_login_status_codes = codes;
        } else if (key == Keys::T1_CHECK_UA_ANOMALIES)
          config.tier1.check_user_agent_anomalies = string_to_bool(value);
        else if (key == Keys::T1_HEADLESS_BROWSER_STRINGS) {
          std::vector<std::string> substrings = Utils::split_string(value, ',');
          if (!substrings.empty())
            config.tier1.headless_browser_substrings = substrings;
        } else if (key == Keys::T1_MIN_CHROME_VERSION)
          config.tier1.min_chrome_version =
              Utils::string_to_number<int>(value).value_or(
                  config.tier1.min_chrome_version);
        else if (key == Keys::T1_MIN_FIREFOX_VERSION)
          config.tier1.min_firefox_version =
              Utils::string_to_number<int>(value).value_or(
                  config.tier1.min_firefox_version);
        else if (key == Keys::T1_MAX_UNIQUE_UAS_PER_IP)
          config.tier1.max_unique_uas_per_ip_in_window =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_unique_uas_per_ip_in_window);
        else if (key == Keys::T1_HTML_PATH_SUFFIXES) {
          std::vector<std::string> suffixes = Utils::split_string(value, ',');
          if (!suffixes.empty())
            config.tier1.html_path_suffixes = suffixes;
        } else if (key == Keys::T1_HTML_EXACT_PATHS) {
          std::vector<std::string> exact_paths =
              Utils::split_string(value, ',');
          if (!exact_paths.empty())
            config.tier1.html_exact_paths = exact_paths;
        } else if (key == Keys::T1_ASSET_PATH_PREFIXES) {
          std::vector<std::string> prefixes = Utils::split_string(value, ',');
          if (!prefixes.empty())
            config.tier1.asset_path_prefixes = prefixes;
        } else if (key == Keys::T1_ASSET_PATH_SUFFIXES) {
          std::vector<std::string> suffixes = Utils::split_string(value, ',');
          if (!suffixes.empty())
            config.tier1.asset_path_suffixes = suffixes;
        } else if (key == Keys::T1_MIN_HTML_REQUESTS_FOR_RATIO)
          config.tier1.min_html_requests_for_ratio_check =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.min_html_requests_for_ratio_check);
        else if (key == Keys::T1_MIN_ASSETS_PER_HTML_RATIO)
          config.tier1.min_assets_per_html_ratio =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.min_assets_per_html_ratio);

        // Suspicious path/UA/sensitive substrings
        else if (key == Keys::T1_SUSPICIOUS_PATH_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              config.tier1.suspicious_path_substrings.push_back(trimmed_substr);
          }
        } else if (key == Keys::T1_SUSPICIOUS_UA_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              config.tier1.suspicious_ua_substrings.push_back(trimmed_substr);
          }
        } else if (key == Keys::T1_SENSITIVE_PATH_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              config.tier1.sensitive_path_substrings.push_back(trimmed_substr);
          }
        } else if (key == Keys::T1_SESSION_TRACKING_ENABLED)
          config.tier1.session_tracking_enabled = string_to_bool(value);
        else if (key == Keys::T1_SESSION_KEY_COMPONENTS) {
          std::vector<std::string> components = Utils::split_string(value, ',');
          if (!components.empty())
            config.tier1.session_key_components = components;
        } else if (key == Keys::T1_SESSION_INACTIVITY_TTL_SECONDS)
          config.tier1.session_inactivity_ttl_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.tier1.session_inactivity_ttl_seconds);
        else if (key == Keys::T1_MAX_FAILED_LOGINS_PER_SESSION)
          config.tier1.max_failed_logins_per_session =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier1.max_failed_logins_per_session);
        else if (key == Keys::T1_MAX_REQUESTS_PER_SESSION_IN_WINDOW)
          config.tier1.max_requests_per_session_in_window =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier1.max_requests_per_session_in_window);
        else if (key == Keys::T1_MAX_UA_CHANGES_PER_SESSION)
          config.tier1.max_ua_changes_per_session =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier1.max_ua_changes_per_session);
        else if (key == Keys::T1_MAX_UNIQUE_PATHS_STORED_PER_IP)
          config.tier1.max_unique_paths_stored_per_ip =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_unique_paths_stored_per_ip);
        else if (key == Keys::T1_SCORE_MISSING_UA)
          config.tier1.score_missing_ua =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_missing_ua);
        else if (key == Keys::T1_SCORE_OUTDATED_BROWSER)
          config.tier1.score_outdated_browser =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_outdated_browser);
        else if (key == Keys::T1_SCORE_KNOWN_BAD_UA)
          config.tier1.score_known_bad_ua =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_known_bad_ua);
        else if (key == Keys::T1_SCORE_HEADLESS_BROWSER)
          config.tier1.score_headless_browser =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_headless_browser);
        else if (key == Keys::T1_SCORE_UA_CYCLING)
          config.tier1.score_ua_cycling =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_ua_cycling);
        else if (key == Keys::T1_SCORE_SUSPICIOUS_PATH)
          config.tier1.score_suspicious_path =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_suspicious_path);
        else if (key == Keys::T1_SCORE_SENSITIVE_PATH_NEW_IP)
          config.tier1.score_sensitive_path_new_ip =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_sensitive_path_new_ip);

        // Tier 2 settings
      } else if (current_section == "Tier2") {
        if (key == Keys::T2_ENABLED)
          config.tier2.enabled = string_to_bool(value);
        else if (key == Keys::T2_Z_SCORE_THRESHOLD)
          config.tier2.z_score_threshold =
              Utils::string_to_number<double>(value).value_or(
                  config.tier2.z_score_threshold);
        else if (key == Keys::T2_MIN_SAMPLES_FOR_Z_SCORE)
          config.tier2.min_samples_for_z_score =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier2.min_samples_for_z_score);
        else if (key == Keys::T2_HISTORICAL_DEVIATION_FACTOR)
          config.tier2.historical_deviation_factor =
              Utils::string_to_number<double>(value).value_or(
                  config.tier2.historical_deviation_factor);

        // Tier 3 settings
      } else if (current_section == "Tier3") {
        if (key == Keys::T3_ENABLED)
          config.tier3.enabled = string_to_bool(value);
        else if (key == Keys::T3_MODEL_PATH)
          config.tier3.model_path = value;
        else if (key == Keys::T3_ANOMALY_SCORE_THRESHOLD)
          config.tier3.anomaly_score_threshold =
              Utils::string_to_number<double>(value).value_or(
                  config.tier3.anomaly_score_threshold);
        else if (key == Keys::T3_MODEL_METADATA_PATH)
          config.tier3.model_metadata_path = value;
        else if (key == Keys::T3_AUTO_RETRAINING_ENABLED)
          config.tier3.automated_retraining_enabled = string_to_bool(value);
        else if (key == Keys::T3_RETRAINING_INTERVAL_S)
          config.tier3.retraining_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier3.retraining_interval_seconds);
        else if (key == Keys::T3_TRAINING_SCRIPT_PATH)
          config.tier3.training_script_path = value;

        // Alerting Settings
      } else if (current_section == "Alerting") {
        if (key == Keys::AL_FILE_ENABLED)
          config.alerting.file_enabled = string_to_bool(value);
        else if (key == Keys::AL_SYSLOG_ENABLED)
          config.alerting.syslog_enabled = string_to_bool(value);
        else if (key == Keys::AL_HTTP_ENABLED)
          config.alerting.http_enabled = string_to_bool(value);
        else if (key == Keys::AL_HTTP_WEBHOOK_URL)
          config.alerting.http_webhook_url = value;

        // Threat Intel Settings
      } else if (current_section == "ThreatIntel") {
        if (key == Keys::TI_ENABLED)
          config.threat_intel.enabled = string_to_bool(value);
        else if (key == Keys::TI_FEED_URLS) {
          std::vector<std::string> feed_urls = Utils::split_string(value, ',');
          if (!feed_urls.empty())
            config.threat_intel.feed_urls = feed_urls;
        } else if (key == Keys::TI_UPDATE_INTERVAL_SECONDS)
          config.threat_intel.update_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.threat_intel.update_interval_seconds);

        // Mongo Settings
      } else if (current_section == "MongoLogSource") {
        if (key == Keys::MO_URI)
          config.mongo_log_source.uri = value;
        else if (key == Keys::MO_DATABASE)
          config.mongo_log_source.database = value;
        else if (key == Keys::MO_COLLECTION)
          config.mongo_log_source.collection = value;
        else if (key == Keys::MO_TIMESTAMP_FIELD_NAME)
          config.mongo_log_source.timestamp_field_name = value;

        // Logging Settings
      } else if (current_section == "Logging") {
        if (key == Keys::LOGGING_DEFAULT_LEVEL) {
          LogLevel default_level = string_to_log_level(value);
          for (auto &pair : config.logging.log_levels)
            pair.second = default_level;
        } else {
          auto comp_it = key_to_component_map.find(key);
          if (comp_it != key_to_component_map.end())
            config.logging.log_levels[comp_it->second] =
                string_to_log_level(value);
          else if (key.length() > 2 && key.substr(key.length() - 2) == ".*") {
            // Wildcard match, e.g., "analysis.* = DEBUG"
            std::string prefix = key.substr(0, key.length() - 1);
            for (const auto &pair : key_to_component_map) {
              if (component_to_string(pair.second) != nullptr &&
                  std::string(component_to_string(pair.second))
                          .rfind(prefix, 0) == 0)
                config.logging.log_levels[pair.second] =
                    string_to_log_level(value);
            }
          }
        }

        // Monitoring Settings
      } else if (current_section == "Monitoring") {
        if (key == Keys::MONITORING_ENABLE_DEEP_TIMING)
          config.monitoring.enable_deep_timing = string_to_bool(value);
        else if (key == Keys::MONITORING_WEB_SERVER_HOST)
          config.monitoring.web_server_host = value;
        else if (key == Keys::MONITORING_WEB_SERVER_PORT)
          config.monitoring.web_server_port =
              Utils::string_to_number<int>(value).value_or(
                  config.monitoring.web_server_port);

        // Prometheus Settings
      } else if (current_section == "Prometheus") {
        if (key == Keys::PROMETHEUS_ENABLED)
          config.prometheus.enabled = string_to_bool(value);
        else if (key == Keys::PROMETHEUS_HOST)
          config.prometheus.host = value;
        else if (key == Keys::PROMETHEUS_PORT)
          config.prometheus.port = Utils::string_to_number<int>(value).value_or(
              config.prometheus.port);
        else if (key == Keys::PROMETHEUS_METRICS_PATH)
          config.prometheus.metrics_path = value;
        else if (key == Keys::PROMETHEUS_HEALTH_PATH)
          config.prometheus.health_path = value;
        else if (key == Keys::PROMETHEUS_SCRAPE_INTERVAL_SECONDS)
          config.prometheus.scrape_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.prometheus.scrape_interval_seconds);
        else if (key == Keys::PROMETHEUS_REPLACE_WEB_SERVER)
          config.prometheus.replace_web_server = string_to_bool(value);
        else if (key == Keys::PROMETHEUS_MAX_METRICS_AGE_SECONDS)
          config.prometheus.max_metrics_age_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.prometheus.max_metrics_age_seconds);

        // Dynamic Learning Settings
      } else if (current_section == "DynamicLearning") {
        if (key == Keys::DL_ENABLED)
          config.dynamic_learning.enabled = string_to_bool(value);
        else if (key == Keys::DL_LEARNING_WINDOW_HOURS)
          config.dynamic_learning.learning_window_hours =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.dynamic_learning.learning_window_hours);
        else if (key == Keys::DL_CONFIDENCE_THRESHOLD)
          config.dynamic_learning.confidence_threshold =
              Utils::string_to_number<double>(value).value_or(
                  config.dynamic_learning.confidence_threshold);
        else if (key == Keys::DL_MIN_SAMPLES_FOR_LEARNING)
          config.dynamic_learning.min_samples_for_learning =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.dynamic_learning.min_samples_for_learning);
        else if (key == Keys::DL_SEASONAL_DETECTION_SENSITIVITY)
          config.dynamic_learning.seasonal_detection_sensitivity =
              Utils::string_to_number<double>(value).value_or(
                  config.dynamic_learning.seasonal_detection_sensitivity);
        else if (key == Keys::DL_BASELINE_UPDATE_INTERVAL_SECONDS)
          config.dynamic_learning.baseline_update_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.dynamic_learning.baseline_update_interval_seconds);
        else if (key == Keys::DL_ENABLE_MANUAL_OVERRIDES)
          config.dynamic_learning.enable_manual_overrides =
              string_to_bool(value);
        else if (key == Keys::DL_THRESHOLD_CHANGE_MAX_PERCENT)
          config.dynamic_learning.threshold_change_max_percent =
              Utils::string_to_number<double>(value).value_or(
                  config.dynamic_learning.threshold_change_max_percent);

        // Tier4 Settings
      } else if (current_section == "Tier4") {
        if (key == Keys::T4_ENABLED)
          config.tier4.enabled = string_to_bool(value);
        else if (key == Keys::T4_PROMETHEUS_URL)
          config.tier4.prometheus_url = value;
        else if (key == Keys::T4_QUERY_TIMEOUT_SECONDS)
          config.tier4.query_timeout_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier4.query_timeout_seconds);
        else if (key == Keys::T4_EVALUATION_INTERVAL_SECONDS)
          config.tier4.evaluation_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier4.evaluation_interval_seconds);
        else if (key == Keys::T4_MAX_CONCURRENT_QUERIES)
          config.tier4.max_concurrent_queries =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier4.max_concurrent_queries);
        else if (key == Keys::T4_AUTH_TOKEN)
          config.tier4.auth_token = value;
        else if (key == Keys::T4_ENABLE_CIRCUIT_BREAKER)
          config.tier4.enable_circuit_breaker = string_to_bool(value);
        else if (key == Keys::T4_CIRCUIT_BREAKER_FAILURE_THRESHOLD)
          config.tier4.circuit_breaker_failure_threshold =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier4.circuit_breaker_failure_threshold);
        else if (key == Keys::T4_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECONDS)
          config.tier4.circuit_breaker_recovery_timeout_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.tier4.circuit_breaker_recovery_timeout_seconds);

        // Memory Management Settings
      } else if (current_section == "MemoryManagement") {
        if (key == Keys::MM_ENABLED)
          config.memory_management.enabled = string_to_bool(value);
        else if (key == Keys::MM_MAX_MEMORY_USAGE_MB)
          config.memory_management.max_memory_usage_mb =
              Utils::string_to_number<size_t>(value).value_or(
                  config.memory_management.max_memory_usage_mb);
        else if (key == Keys::MM_MEMORY_PRESSURE_THRESHOLD_MB)
          config.memory_management.memory_pressure_threshold_mb =
              Utils::string_to_number<size_t>(value).value_or(
                  config.memory_management.memory_pressure_threshold_mb);
        else if (key == Keys::MM_ENABLE_OBJECT_POOLING)
          config.memory_management.enable_object_pooling =
              string_to_bool(value);
        else if (key == Keys::MM_EVICTION_CHECK_INTERVAL_SECONDS)
          config.memory_management.eviction_check_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.memory_management.eviction_check_interval_seconds);
        else if (key == Keys::MM_EVICTION_THRESHOLD_PERCENT)
          config.memory_management.eviction_threshold_percent =
              Utils::string_to_number<double>(value).value_or(
                  config.memory_management.eviction_threshold_percent);
        else if (key == Keys::MM_ENABLE_MEMORY_COMPACTION)
          config.memory_management.enable_memory_compaction =
              string_to_bool(value);
        else if (key == Keys::MM_STATE_OBJECT_TTL_SECONDS)
          config.memory_management.state_object_ttl_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.memory_management.state_object_ttl_seconds);
      } else if (current_section == "PerformanceMonitoring") {
        if (key == "enabled")
          config.performance_monitoring.enabled = string_to_bool(value);
        else if (key == "enable_profiling")
          config.performance_monitoring.enable_profiling =
              string_to_bool(value);
        else if (key == "enable_load_shedding")
          config.performance_monitoring.enable_load_shedding =
              string_to_bool(value);
        else if (key == "metrics_collection_interval_ms")
          config.performance_monitoring.metrics_collection_interval_ms =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.performance_monitoring.metrics_collection_interval_ms);
        else if (key == "max_latency_samples_per_component")
          config.performance_monitoring.max_latency_samples_per_component =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.performance_monitoring
                      .max_latency_samples_per_component);
        else if (key == "max_cpu_usage_percent")
          config.performance_monitoring.max_cpu_usage_percent =
              Utils::string_to_number<double>(value).value_or(
                  config.performance_monitoring.max_cpu_usage_percent);
        else if (key == "max_memory_usage_bytes")
          config.performance_monitoring.max_memory_usage_bytes =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.performance_monitoring.max_memory_usage_bytes);
        else if (key == "max_queue_depth")
          config.performance_monitoring.max_queue_depth =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.performance_monitoring.max_queue_depth);
        else if (key == "max_avg_latency_ms")
          config.performance_monitoring.max_avg_latency_ms =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.performance_monitoring.max_avg_latency_ms);
        else if (key == "max_error_rate_percent")
          config.performance_monitoring.max_error_rate_percent =
              Utils::string_to_number<double>(value).value_or(
                  config.performance_monitoring.max_error_rate_percent);
        else if (key == "moderate_load_shed_percentage")
          config.performance_monitoring.moderate_load_shed_percentage =
              Utils::string_to_number<double>(value).value_or(
                  config.performance_monitoring.moderate_load_shed_percentage);
        else if (key == "high_load_shed_percentage")
          config.performance_monitoring.high_load_shed_percentage =
              Utils::string_to_number<double>(value).value_or(
                  config.performance_monitoring.high_load_shed_percentage);
        else if (key == "critical_load_shed_percentage")
          config.performance_monitoring.critical_load_shed_percentage =
              Utils::string_to_number<double>(value).value_or(
                  config.performance_monitoring.critical_load_shed_percentage);
        else if (key == "monitoring_loop_interval_seconds")
          config.performance_monitoring.monitoring_loop_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.performance_monitoring
                      .monitoring_loop_interval_seconds);
        else if (key == "enable_function_profiling")
          config.performance_monitoring.enable_function_profiling =
              string_to_bool(value);
        else if (key == "max_profile_samples_per_function")
          config.performance_monitoring.max_profile_samples_per_function =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.performance_monitoring
                      .max_profile_samples_per_function);
        else if (key == "profile_report_interval_seconds")
          config.performance_monitoring.profile_report_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.performance_monitoring
                      .profile_report_interval_seconds);
        else if (key == "enable_performance_reports")
          config.performance_monitoring.enable_performance_reports =
              string_to_bool(value);
        else if (key == "performance_report_path")
          config.performance_monitoring.performance_report_path = value;
        else if (key == "performance_report_interval_seconds")
          config.performance_monitoring.performance_report_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.performance_monitoring
                      .performance_report_interval_seconds);
      } else if (current_section == "ErrorHandling") {
        if (key == "enabled")
          config.error_handling.enabled = string_to_bool(value);
        else if (key == "enable_circuit_breaker")
          config.error_handling.enable_circuit_breaker = string_to_bool(value);
        else if (key == "circuit_breaker_failure_threshold")
          config.error_handling.circuit_breaker_failure_threshold =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.circuit_breaker_failure_threshold);
        else if (key == "circuit_breaker_timeout_ms")
          config.error_handling.circuit_breaker_timeout_ms =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.circuit_breaker_timeout_ms);
        else if (key == "circuit_breaker_recovery_timeout_ms")
          config.error_handling.circuit_breaker_recovery_timeout_ms =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.circuit_breaker_recovery_timeout_ms);
        else if (key == "enable_error_recovery")
          config.error_handling.enable_error_recovery = string_to_bool(value);
        else if (key == "max_retry_attempts")
          config.error_handling.max_retry_attempts =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.max_retry_attempts);
        else if (key == "initial_retry_delay_ms")
          config.error_handling.initial_retry_delay_ms =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.initial_retry_delay_ms);
        else if (key == "max_retry_delay_ms")
          config.error_handling.max_retry_delay_ms =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.max_retry_delay_ms);
        else if (key == "retry_backoff_multiplier")
          config.error_handling.retry_backoff_multiplier =
              Utils::string_to_number<double>(value).value_or(
                  config.error_handling.retry_backoff_multiplier);
        else if (key == "enable_graceful_degradation")
          config.error_handling.enable_graceful_degradation =
              string_to_bool(value);
        else if (key == "cpu_threshold_for_degradation")
          config.error_handling.cpu_threshold_for_degradation =
              Utils::string_to_number<double>(value).value_or(
                  config.error_handling.cpu_threshold_for_degradation);
        else if (key == "memory_threshold_for_degradation_mb")
          config.error_handling.memory_threshold_for_degradation_mb =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.error_handling.memory_threshold_for_degradation_mb);
        else if (key == "queue_depth_threshold_for_degradation")
          config.error_handling.queue_depth_threshold_for_degradation =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.error_handling.queue_depth_threshold_for_degradation);
        else if (key == "error_rate_threshold_for_degradation")
          config.error_handling.error_rate_threshold_for_degradation =
              Utils::string_to_number<double>(value).value_or(
                  config.error_handling.error_rate_threshold_for_degradation);
        else if (key == "default_recovery_strategy")
          config.error_handling.default_recovery_strategy = value;
        else if (key == "prometheus_recovery_strategy")
          config.error_handling.prometheus_recovery_strategy = value;
        else if (key == "database_recovery_strategy")
          config.error_handling.database_recovery_strategy = value;
        else if (key == "file_io_recovery_strategy")
          config.error_handling.file_io_recovery_strategy = value;
        else if (key == "network_recovery_strategy")
          config.error_handling.network_recovery_strategy = value;
        else if (key == "enable_error_rate_limiting")
          config.error_handling.enable_error_rate_limiting =
              string_to_bool(value);
        else if (key == "max_errors_per_minute")
          config.error_handling.max_errors_per_minute =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.max_errors_per_minute);
        else if (key == "error_burst_limit")
          config.error_handling.error_burst_limit =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.error_burst_limit);
        else if (key == "recovery_statistics_interval_seconds")
          config.error_handling.recovery_statistics_interval_seconds =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.error_handling.recovery_statistics_interval_seconds);
        else if (key == "log_recovery_attempts")
          config.error_handling.log_recovery_attempts = string_to_bool(value);
        else if (key == "recovery_log_level")
          config.error_handling.recovery_log_level = value;
      }
    } catch (const std::invalid_argument &e) {
      std::cerr << "Warning (Config Line " << line_num
                << "): Invalid value for key '" << key << "': '" << value
                << "' - " << e.what() << std::endl;
    } catch (const std::out_of_range &e) {
      std::cerr << "Warning (Config Line " << line_num
                << "): Value out of range for key '" << key << "': '" << value
                << "' - " << e.what() << std::endl;
    }
  }

  config_file.close();
  std::cout << "Configuration loaded successfully from " << filepath
            << std::endl;
  return true;
}

bool ConfigManager::load_configuration(const std::string &filepath) {
  config_filepath_ = filepath;
  auto new_config = std::make_shared<AppConfig>();

  // Use the parsing logic to fill the new config object
  if (!parse_config_into(filepath, *new_config)) {
    std::cerr << "Failed to parse configuration file: " << filepath
              << ". Keeping existing settings." << std::endl;
    return false;
  }

  // Validate the configuration
  std::vector<std::string> validation_errors;
  if (!validate_app_config(*new_config, validation_errors)) {
    std::cerr << "Configuration validation failed:" << std::endl;
    for (const auto &error : validation_errors) {
      std::cerr << "  - " << error << std::endl;
    }
    std::cerr << "Keeping existing settings." << std::endl;
    return false;
  }

  // Atomically swap the pointer
  std::lock_guard<std::mutex> lock(config_mutex_);
  current_config_ = new_config;
  std::cout << "Configuration loaded and validated successfully from "
            << config_filepath_ << std::endl;
  return true;
}

std::shared_ptr<const AppConfig> ConfigManager::get_config() const {
  std::lock_guard<std::mutex> lock(config_mutex_);
  return current_config_;
}

} // namespace Config
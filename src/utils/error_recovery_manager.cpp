#include "error_recovery_manager.hpp"
#include <algorithm>
#include <cmath>
#include <thread>

namespace error_recovery {

ErrorRecoveryManager::ErrorRecoveryManager() {
  // Constructor implementation
}

void ErrorRecoveryManager::register_component(const std::string &component,
                                              const RecoveryConfig &config) {
  std::lock_guard<std::mutex> lock(components_mutex_);

  auto [it, inserted] = components_.emplace(component, ComponentState{});
  if (inserted) {
    it->second.config = config;
    it->second.stats = RecoveryStats{};
    it->second.last_error = ErrorInfo{};
    it->second.last_recovery_attempt = std::chrono::system_clock::now();

    // Create circuit breaker if strategy requires it
    if (config.strategy == RecoveryStrategy::CIRCUIT_BREAK) {
      it->second.circuit_breaker =
          std::make_shared<circuit_breaker::CircuitBreaker>(
              component + "_circuit", config.circuit_config);
    }
  }
}

void ErrorRecoveryManager::update_config(const std::string &component,
                                         const RecoveryConfig &config) {
  std::lock_guard<std::mutex> lock(components_mutex_);
  auto it = components_.find(component);
  if (it != components_.end()) {
    it->second.config = config;

    // Update circuit breaker if strategy changed
    if (config.strategy == RecoveryStrategy::CIRCUIT_BREAK) {
      if (!it->second.circuit_breaker) {
        it->second.circuit_breaker =
            std::make_shared<circuit_breaker::CircuitBreaker>(
                component + "_circuit", config.circuit_config);
      }
    } else {
      it->second.circuit_breaker.reset();
    }
  }
}

bool ErrorRecoveryManager::execute_with_recovery(const std::string &component,
                                                 const std::string &operation,
                                                 std::function<bool()> func) {
  ComponentState &state = get_or_create_component(component);

  if (!state.recovery_enabled.load()) {
    // Recovery disabled, execute once
    try {
      bool success = func();
      update_component_stats(component, success);
      return success;
    } catch (...) {
      report_error(component, operation, "Exception during operation",
                   ErrorSeverity::MEDIUM);
      update_component_stats(component, false);
      return false;
    }
  }

  bool success = false;

  switch (state.config.strategy) {
  case RecoveryStrategy::RETRY:
    success = execute_with_retry(component, func, state.config);
    break;

  case RecoveryStrategy::CIRCUIT_BREAK:
    success = execute_with_circuit_breaker(component, func);
    break;

  case RecoveryStrategy::FALLBACK:
    success = execute_with_fallback(component, func, state.config);
    break;

  case RecoveryStrategy::FAIL_FAST:
    try {
      success = func();
    } catch (...) {
      success = false;
    }
    break;

  case RecoveryStrategy::NONE:
  default:
    try {
      success = func();
    } catch (...) {
      success = false;
    }
    break;
  }

  update_component_stats(component, success);
  return success;
}

void ErrorRecoveryManager::report_error(const std::string &component,
                                        const std::string &operation,
                                        const std::string &message,
                                        ErrorSeverity severity) {
  std::lock_guard<std::mutex> lock(components_mutex_);
  ComponentState &state = get_or_create_component(component);

  // Update error info
  state.last_error.component = component;
  state.last_error.operation = operation;
  state.last_error.message = message;
  state.last_error.severity = severity;
  state.last_error.timestamp = std::chrono::system_clock::now();
  state.last_error.occurrence_count++;

  // Update severity
  state.current_severity.store(severity);

  // Update stats
  state.stats.total_errors++;
  state.stats.last_error_time = state.last_error.timestamp;

  total_system_errors_.fetch_add(1);
}

void ErrorRecoveryManager::trigger_recovery(const std::string &component) {
  std::lock_guard<std::mutex> lock(components_mutex_);
  auto it = components_.find(component);
  if (it != components_.end()) {
    it->second.last_recovery_attempt = std::chrono::system_clock::now();
    it->second.stats.last_recovery_time = it->second.last_recovery_attempt;

    // Reset circuit breaker if present
    if (it->second.circuit_breaker) {
      it->second.circuit_breaker->reset();
    }
  }
}

void ErrorRecoveryManager::disable_recovery(const std::string &component) {
  ComponentState &state = get_or_create_component(component);
  state.recovery_enabled.store(false);
}

void ErrorRecoveryManager::enable_recovery(const std::string &component) {
  ComponentState &state = get_or_create_component(component);
  state.recovery_enabled.store(true);
}

bool ErrorRecoveryManager::is_component_healthy(
    const std::string &component) const {
  std::lock_guard<std::mutex> lock(components_mutex_);
  auto it = components_.find(component);
  if (it == components_.end()) {
    return true; // Unknown components are considered healthy
  }

  ErrorSeverity severity = it->second.current_severity.load();
  return severity <= ErrorSeverity::LOW;
}

ErrorSeverity ErrorRecoveryManager::get_component_severity(
    const std::string &component) const {
  std::lock_guard<std::mutex> lock(components_mutex_);
  auto it = components_.find(component);
  if (it == components_.end()) {
    return ErrorSeverity::LOW;
  }
  return it->second.current_severity.load();
}

RecoveryStats
ErrorRecoveryManager::get_recovery_stats(const std::string &component) const {
  std::lock_guard<std::mutex> lock(components_mutex_);
  auto it = components_.find(component);
  if (it == components_.end()) {
    return RecoveryStats{};
  }
  return it->second.stats;
}

bool ErrorRecoveryManager::is_system_healthy() const {
  std::lock_guard<std::mutex> lock(components_mutex_);
  for (const auto &[name, state] : components_) {
    ErrorSeverity severity = state.current_severity.load();
    if (severity >= ErrorSeverity::HIGH) {
      return false;
    }
  }
  return true;
}

std::vector<std::string> ErrorRecoveryManager::get_failing_components() const {
  std::vector<std::string> failing;
  std::lock_guard<std::mutex> lock(components_mutex_);

  for (const auto &[name, state] : components_) {
    ErrorSeverity severity = state.current_severity.load();
    if (severity > ErrorSeverity::LOW) {
      failing.push_back(name);
    }
  }
  return failing;
}

size_t ErrorRecoveryManager::get_total_errors() const {
  return total_system_errors_.load();
}

std::shared_ptr<circuit_breaker::CircuitBreaker>
ErrorRecoveryManager::get_circuit_breaker(const std::string &component) {
  std::lock_guard<std::mutex> lock(components_mutex_);
  auto it = components_.find(component);
  if (it != components_.end()) {
    return it->second.circuit_breaker;
  }
  return nullptr;
}

void ErrorRecoveryManager::reset_stats(const std::string &component) {
  std::lock_guard<std::mutex> lock(components_mutex_);

  if (component.empty()) {
    // Reset all components
    for (auto &[name, state] : components_) {
      state.stats = RecoveryStats{};
      state.current_severity.store(ErrorSeverity::LOW);
      if (state.circuit_breaker) {
        state.circuit_breaker->reset();
      }
    }
    total_system_errors_.store(0);
  } else {
    auto it = components_.find(component);
    if (it != components_.end()) {
      it->second.stats = RecoveryStats{};
      it->second.current_severity.store(ErrorSeverity::LOW);
      if (it->second.circuit_breaker) {
        it->second.circuit_breaker->reset();
      }
    }
  }
}

std::unordered_map<std::string, RecoveryStats>
ErrorRecoveryManager::get_all_stats() const {
  std::unordered_map<std::string, RecoveryStats> all_stats;
  std::lock_guard<std::mutex> lock(components_mutex_);

  for (const auto &[name, state] : components_) {
    all_stats[name] = state.stats;
  }
  return all_stats;
}

bool ErrorRecoveryManager::execute_with_retry(const std::string &component,
                                              std::function<bool()> func,
                                              const RecoveryConfig &config) {
  for (size_t attempt = 0; attempt <= config.max_retries; ++attempt) {
    try {
      if (func()) {
        if (attempt > 0) {
          // Recovery successful after retry
          update_component_stats(component, true);
        }
        return true;
      }
    } catch (...) {
      // Exception occurred
    }

    // If not the last attempt, wait before retrying
    if (attempt < config.max_retries) {
      auto delay = calculate_delay(attempt, config);
      std::this_thread::sleep_for(delay);
    }
  }

  // All retries failed
  report_error(component, "retry_operation", "All retry attempts failed",
               ErrorSeverity::MEDIUM);
  return false;
}

bool ErrorRecoveryManager::execute_with_circuit_breaker(
    const std::string &component, std::function<bool()> func) {
  ComponentState &state = get_or_create_component(component);

  if (!state.circuit_breaker) {
    // Fallback to direct execution if no circuit breaker
    try {
      return func();
    } catch (...) {
      return false;
    }
  }

  auto result = state.circuit_breaker->execute<bool>(func, false);
  return result.first && result.second;
}

bool ErrorRecoveryManager::execute_with_fallback(const std::string &component,
                                                 std::function<bool()> func,
                                                 const RecoveryConfig &config) {
  try {
    if (func()) {
      return true;
    }
  } catch (...) {
    // Primary function failed
  }

  // Try fallback if available
  if (config.fallback_func) {
    try {
      bool fallback_success = config.fallback_func();
      if (fallback_success) {
        update_component_stats(component, true,
                               true); // Mark as fallback activation
      }
      return fallback_success;
    } catch (...) {
      report_error(component, "fallback_operation", "Fallback function failed",
                   ErrorSeverity::HIGH);
    }
  }

  return false;
}

std::chrono::milliseconds
ErrorRecoveryManager::calculate_delay(size_t attempt,
                                      const RecoveryConfig &config) const {
  double delay_ms =
      config.base_delay.count() * std::pow(config.backoff_multiplier, attempt);
  delay_ms = std::min(delay_ms, static_cast<double>(config.max_delay.count()));
  return std::chrono::milliseconds(static_cast<long>(delay_ms));
}

void ErrorRecoveryManager::update_component_stats(const std::string &component,
                                                  bool success,
                                                  bool used_fallback) {
  std::lock_guard<std::mutex> lock(components_mutex_);
  ComponentState &state = get_or_create_component(component);

  if (success) {
    state.stats.successful_recoveries++;
    state.current_severity.store(ErrorSeverity::LOW);
  } else {
    state.stats.failed_recoveries++;
  }

  if (used_fallback) {
    state.stats.fallback_activations++;
  }
}

ErrorRecoveryManager::ComponentState &
ErrorRecoveryManager::get_or_create_component(const std::string &component) {
  // Note: This assumes the mutex is already locked by the caller
  auto it = components_.find(component);
  if (it == components_.end()) {
    // Create default component state
    ComponentState state;
    state.config = RecoveryConfig{}; // Default config
    state.stats = RecoveryStats{};
    state.last_error = ErrorInfo{};
    state.last_recovery_attempt = std::chrono::system_clock::now();

    auto [inserted_it, success] =
        components_.emplace(component, std::move(state));
    return inserted_it->second;
  }
  return it->second;
}

} // namespace error_recovery

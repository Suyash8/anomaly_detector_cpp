#pragma once

#include "circuit_breaker.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace error_recovery {

// Recovery strategies
enum class RecoveryStrategy {
  NONE,          // No recovery attempt
  RETRY,         // Simple retry with backoff
  CIRCUIT_BREAK, // Use circuit breaker pattern
  FALLBACK,      // Use fallback mechanism
  FAIL_FAST      // Fail immediately without retry
};

// Error severity levels
enum class ErrorSeverity {
  LOW,     // Warning level, system continues normally
  MEDIUM,  // Error level, degraded operation
  HIGH,    // Critical error, major functionality lost
  CRITICAL // System-wide failure, emergency shutdown
};

// Recovery configuration
struct RecoveryConfig {
  RecoveryStrategy strategy = RecoveryStrategy::RETRY;
  size_t max_retries = 3;
  std::chrono::milliseconds base_delay = std::chrono::milliseconds(100);
  double backoff_multiplier = 2.0;
  std::chrono::milliseconds max_delay = std::chrono::milliseconds(5000);

  // Circuit breaker config for CIRCUIT_BREAK strategy
  circuit_breaker::CircuitBreaker::Config circuit_config;

  // Fallback function
  std::function<bool()> fallback_func;
};

// Error information
struct ErrorInfo {
  std::string component;
  std::string operation;
  std::string message;
  ErrorSeverity severity;
  std::chrono::system_clock::time_point timestamp;
  size_t occurrence_count = 1;
};

// Recovery statistics
struct RecoveryStats {
  size_t total_errors = 0;
  size_t successful_recoveries = 0;
  size_t failed_recoveries = 0;
  size_t fallback_activations = 0;
  std::chrono::system_clock::time_point last_error_time;
  std::chrono::system_clock::time_point last_recovery_time;
};

class ErrorRecoveryManager {
public:
  ErrorRecoveryManager();
  ~ErrorRecoveryManager() = default;

  // Configuration
  void register_component(const std::string &component,
                          const RecoveryConfig &config);
  void update_config(const std::string &component,
                     const RecoveryConfig &config);

  // Error handling and recovery
  template <typename T>
  bool execute_with_recovery(const std::string &component,
                             const std::string &operation,
                             std::function<T()> func, T &result,
                             const T &default_value = T{});

  bool execute_with_recovery(const std::string &component,
                             const std::string &operation,
                             std::function<bool()> func);

  // Manual error reporting
  void report_error(const std::string &component, const std::string &operation,
                    const std::string &message,
                    ErrorSeverity severity = ErrorSeverity::MEDIUM);

  // Recovery control
  void trigger_recovery(const std::string &component);
  void disable_recovery(const std::string &component);
  void enable_recovery(const std::string &component);

  // State queries
  bool is_component_healthy(const std::string &component) const;
  ErrorSeverity get_component_severity(const std::string &component) const;
  RecoveryStats get_recovery_stats(const std::string &component) const;

  // System-wide status
  bool is_system_healthy() const;
  std::vector<std::string> get_failing_components() const;
  size_t get_total_errors() const;

  // Circuit breaker access
  std::shared_ptr<circuit_breaker::CircuitBreaker>
  get_circuit_breaker(const std::string &component);

  // Metrics and monitoring
  void reset_stats(const std::string &component = "");
  std::unordered_map<std::string, RecoveryStats> get_all_stats() const;

private:
  struct ComponentState {
    RecoveryConfig config;
    RecoveryStats stats;
    ErrorInfo last_error;
    std::shared_ptr<circuit_breaker::CircuitBreaker> circuit_breaker;
    std::atomic<bool> recovery_enabled{true};
    std::atomic<ErrorSeverity> current_severity{ErrorSeverity::LOW};
    std::chrono::system_clock::time_point last_recovery_attempt;

    // Make ComponentState movable
    ComponentState() = default;
    ComponentState(const ComponentState &) = delete;
    ComponentState &operator=(const ComponentState &) = delete;

    ComponentState(ComponentState &&other) noexcept
        : config(std::move(other.config)), stats(std::move(other.stats)),
          last_error(std::move(other.last_error)),
          circuit_breaker(std::move(other.circuit_breaker)),
          recovery_enabled(other.recovery_enabled.load()),
          current_severity(other.current_severity.load()),
          last_recovery_attempt(std::move(other.last_recovery_attempt)) {}

    ComponentState &operator=(ComponentState &&other) noexcept {
      if (this != &other) {
        config = std::move(other.config);
        stats = std::move(other.stats);
        last_error = std::move(other.last_error);
        circuit_breaker = std::move(other.circuit_breaker);
        recovery_enabled.store(other.recovery_enabled.load());
        current_severity.store(other.current_severity.load());
        last_recovery_attempt = std::move(other.last_recovery_attempt);
      }
      return *this;
    }
  };

  bool execute_with_retry(const std::string &component,
                          std::function<bool()> func,
                          const RecoveryConfig &config);

  bool execute_with_circuit_breaker(const std::string &component,
                                    std::function<bool()> func);

  bool execute_with_fallback(const std::string &component,
                             std::function<bool()> func,
                             const RecoveryConfig &config);

  std::chrono::milliseconds calculate_delay(size_t attempt,
                                            const RecoveryConfig &config) const;
  void update_component_stats(const std::string &component, bool success,
                              bool used_fallback = false);
  ComponentState &get_or_create_component(const std::string &component);

  mutable std::mutex components_mutex_;
  std::unordered_map<std::string, ComponentState> components_;
  std::atomic<size_t> total_system_errors_{0};
};

// Template implementation
template <typename T>
bool ErrorRecoveryManager::execute_with_recovery(const std::string &component,
                                                 const std::string &operation,
                                                 std::function<T()> func,
                                                 T &result,
                                                 const T &default_value) {

  auto bool_func = [&func, &result]() -> bool {
    try {
      result = func();
      return true;
    } catch (...) {
      return false;
    }
  };

  bool success = execute_with_recovery(component, operation, bool_func);
  if (!success) {
    result = default_value;
  }
  return success;
}

} // namespace error_recovery

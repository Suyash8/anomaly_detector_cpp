#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace circuit_breaker {

enum class State {
  CLOSED,   // Normal operation
  OPEN,     // Circuit breaker open, rejecting calls
  HALF_OPEN // Testing if service has recovered
};

class CircuitBreaker {
public:
  struct Config {
    size_t failure_threshold;
    std::chrono::milliseconds timeout;
    size_t success_threshold;
    size_t rolling_window_size;
    std::chrono::milliseconds reset_timeout;

    Config()
        : failure_threshold(5), timeout(std::chrono::milliseconds(60000)),
          success_threshold(3), rolling_window_size(10),
          reset_timeout(std::chrono::milliseconds(300000)) {}
  };

  explicit CircuitBreaker(const std::string &name,
                          const Config &config = Config{});
  ~CircuitBreaker() = default;

  // Execute function with circuit breaker protection
  template <typename T>
  std::pair<bool, T> execute(std::function<T()> func, T default_value = T{});

  // Manually record success/failure
  void record_success();
  void record_failure();

  // State queries
  State get_state() const { return state_.load(); }
  std::string get_state_string() const;
  size_t get_failure_count() const { return failure_count_.load(); }
  size_t get_success_count() const { return success_count_.load(); }

  // Metrics for monitoring
  struct Metrics {
    size_t total_calls = 0;
    size_t successful_calls = 0;
    size_t failed_calls = 0;
    size_t rejected_calls = 0;
    std::chrono::system_clock::time_point last_failure_time;
    std::chrono::system_clock::time_point last_state_change;
  };

  Metrics get_metrics() const;
  void reset();

private:
  void transition_to_state(State new_state);
  bool should_attempt_reset() const;
  void update_rolling_window(bool success);
  std::string get_state_string_for_state(State state) const;

  const std::string name_;
  const Config config_;

  std::atomic<State> state_{State::CLOSED};
  std::atomic<size_t> failure_count_{0};
  std::atomic<size_t> success_count_{0};
  std::atomic<size_t> consecutive_failures_{0};
  std::atomic<size_t> consecutive_successes_{0};

  mutable std::mutex metrics_mutex_;
  Metrics metrics_;
  std::chrono::system_clock::time_point last_failure_time_;
  std::chrono::system_clock::time_point state_change_time_;

  // Rolling window for failure rate calculation
  std::vector<bool> rolling_window_;
  size_t window_index_{0};
  bool window_filled_{false};
};

template <typename T>
std::pair<bool, T> CircuitBreaker::execute(std::function<T()> func,
                                           T default_value) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  metrics_.total_calls++;

  State current_state = state_.load();

  // Check if we should attempt reset from OPEN to HALF_OPEN
  if (current_state == State::OPEN && should_attempt_reset()) {
    transition_to_state(State::HALF_OPEN);
    current_state = State::HALF_OPEN;
  }

  // Reject calls when circuit is OPEN
  if (current_state == State::OPEN) {
    metrics_.rejected_calls++;
    return {false, default_value};
  }

  try {
    T result = func();
    record_success();
    metrics_.successful_calls++;
    return {true, result};
  } catch (...) {
    record_failure();
    metrics_.failed_calls++;
    return {false, default_value};
  }
}

} // namespace circuit_breaker

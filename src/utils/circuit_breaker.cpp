#include "circuit_breaker.hpp"

namespace circuit_breaker {

CircuitBreaker::CircuitBreaker(const std::string &name, const Config &config)
    : name_(name), config_(config),
      rolling_window_(config.rolling_window_size, true) {
  state_change_time_ = std::chrono::system_clock::now();
  metrics_.last_state_change = state_change_time_;
}

void CircuitBreaker::record_success() {
  consecutive_failures_.store(0);
  consecutive_successes_.fetch_add(1);
  success_count_.fetch_add(1);

  update_rolling_window(true);

  State current_state = state_.load();

  // Transition from HALF_OPEN to CLOSED after enough successes
  if (current_state == State::HALF_OPEN &&
      consecutive_successes_.load() >= config_.success_threshold) {
    transition_to_state(State::CLOSED);
  }
}

void CircuitBreaker::record_failure() {
  consecutive_successes_.store(0);
  consecutive_failures_.fetch_add(1);
  failure_count_.fetch_add(1);

  std::lock_guard<std::mutex> lock(metrics_mutex_);
  last_failure_time_ = std::chrono::system_clock::now();
  metrics_.last_failure_time = last_failure_time_;

  update_rolling_window(false);

  State current_state = state_.load();

  // Transition to OPEN if failure threshold exceeded
  if ((current_state == State::CLOSED || current_state == State::HALF_OPEN) &&
      consecutive_failures_.load() >= config_.failure_threshold) {
    transition_to_state(State::OPEN);
  }

  // Transition back to OPEN from HALF_OPEN on any failure
  else if (current_state == State::HALF_OPEN) {
    transition_to_state(State::OPEN);
  }
}

std::string CircuitBreaker::get_state_string() const {
  switch (state_.load()) {
  case State::CLOSED:
    return "CLOSED";
  case State::OPEN:
    return "OPEN";
  case State::HALF_OPEN:
    return "HALF_OPEN";
  default:
    return "UNKNOWN";
  }
}

CircuitBreaker::Metrics CircuitBreaker::get_metrics() const {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  return metrics_;
}

void CircuitBreaker::reset() {
  std::lock_guard<std::mutex> lock(metrics_mutex_);

  state_.store(State::CLOSED);
  failure_count_.store(0);
  success_count_.store(0);
  consecutive_failures_.store(0);
  consecutive_successes_.store(0);

  // Reset rolling window
  std::fill(rolling_window_.begin(), rolling_window_.end(), true);
  window_index_ = 0;
  window_filled_ = false;

  // Reset metrics
  metrics_ = Metrics{};
  state_change_time_ = std::chrono::system_clock::now();
  metrics_.last_state_change = state_change_time_;
}

void CircuitBreaker::transition_to_state(State new_state) {
  State old_state = state_.exchange(new_state);
  if (old_state != new_state) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    state_change_time_ = std::chrono::system_clock::now();
    metrics_.last_state_change = state_change_time_;
  }
}

bool CircuitBreaker::should_attempt_reset() const {
  auto now = std::chrono::system_clock::now();
  auto time_since_state_change =
      std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                            state_change_time_);
  return time_since_state_change >= config_.timeout;
}

void CircuitBreaker::update_rolling_window(bool success) {
  rolling_window_[window_index_] = success;
  window_index_ = (window_index_ + 1) % config_.rolling_window_size;

  if (!window_filled_ && window_index_ == 0) {
    window_filled_ = true;
  }
}

std::string CircuitBreaker::get_state_string_for_state(State state) const {
  switch (state) {
  case State::CLOSED:
    return "CLOSED";
  case State::OPEN:
    return "OPEN";
  case State::HALF_OPEN:
    return "HALF_OPEN";
  default:
    return "UNKNOWN";
  }
}

} // namespace circuit_breaker

#ifndef STATE_OBJECT_ALLOCATOR_HPP
#define STATE_OBJECT_ALLOCATOR_HPP

#include "analysis/per_ip_state.hpp"
#include "analysis/per_path_state.hpp"
#include "analysis/per_session_state.hpp"
#include "core/memory_manager.hpp"
#include "utils/sliding_window.hpp"
#include "utils/stats_tracker.hpp"
#include <iostream> // For logging fallback
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace resource {

// Forward declarations
class StateObjectAllocator;

// RAII wrapper for pooled state objects
template <typename StateType> class PooledState {
public:
  PooledState() = default;

  PooledState(std::unique_ptr<StateType> state,
              std::function<void(std::unique_ptr<StateType>)> return_fn)
      : state_(std::move(state)), return_fn_(std::move(return_fn)) {}

  PooledState(const PooledState &) = delete;
  PooledState &operator=(const PooledState &) = delete;

  PooledState(PooledState &&other) noexcept
      : state_(std::move(other.state_)),
        return_fn_(std::move(other.return_fn_)) {}

  PooledState &operator=(PooledState &&other) noexcept {
    if (this != &other) {
      reset();
      state_ = std::move(other.state_);
      return_fn_ = std::move(other.return_fn_);
    }
    return *this;
  }

  ~PooledState() { reset(); }

  StateType *get() const { return state_.get(); }
  StateType *operator->() const { return state_.get(); }
  StateType &operator*() const { return *state_; }

  explicit operator bool() const { return static_cast<bool>(state_); }

  void reset() {
    if (state_ && return_fn_) {
      return_fn_(std::move(state_));
      return_fn_ = nullptr;
    }
  }

private:
  std::unique_ptr<StateType> state_;
  std::function<void(std::unique_ptr<StateType>)> return_fn_;
};

// Specialized allocator for state objects with type-specific optimizations
template <typename StateType> class StatePool {
public:
  explicit StatePool(size_t initial_size = 50, size_t max_size = 500)
      : max_size_(max_size) {

    // Pre-allocate state objects
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.reserve(initial_size);
    for (size_t i = 0; i < initial_size; ++i) {
      pool_.emplace_back(create_state_object());
    }

    std::cout << "[StatePool] Initialized with " << initial_size
              << " objects, max_size: " << max_size << std::endl;
  }

  PooledState<StateType> acquire() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!pool_.empty()) {
      auto state = std::move(pool_.back());
      pool_.pop_back();

      // Reset state object for reuse
      reset_state_object(*state);

      return PooledState<StateType>(
          std::move(state), [this](std::unique_ptr<StateType> returned_state) {
            this->release(std::move(returned_state));
          });
    } else {
      // Pool exhausted, create new object
      auto state = create_state_object();

      return PooledState<StateType>(
          std::move(state), [this](std::unique_ptr<StateType> returned_state) {
            this->release(std::move(returned_state));
          });
    }
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
  }

  void shrink_to_fit() {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.shrink_to_fit();
  }

private:
  void release(std::unique_ptr<StateType> state) {
    if (!state)
      return;

    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.size() < max_size_) {
      pool_.push_back(std::move(state));
    }
    // If pool is full, let the object be destroyed
  }

  std::unique_ptr<StateType> create_state_object() {
    return std::make_unique<StateType>();
  }

  void reset_state_object(StateType & /*state*/) {
    // Default implementation - state objects can be left as-is for reuse
    // Individual specializations will handle specific reset logic
  }

  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<StateType>> pool_;
  size_t max_size_;
};

// Specialized reset functions for different state types
template <>
inline void StatePool<PerIpState>::reset_state_object(PerIpState &state) {
  // Reset PerIpState to clean state based on actual structure
  state.paths_seen_by_ip.clear();
  state.historical_user_agents.clear();
  state.last_known_user_agent.clear();

  // Reset sliding windows by creating new instances
  state.request_timestamps_window = SlidingWindow<uint64_t>(
      state.default_duration_ms, state.default_elements_limit);
  state.failed_login_timestamps_window = SlidingWindow<uint64_t>(
      state.default_duration_ms, state.default_elements_limit);
  state.html_request_timestamps = SlidingWindow<uint64_t>(
      state.default_duration_ms, state.default_elements_limit);
  state.asset_request_timestamps = SlidingWindow<uint64_t>(
      state.default_duration_ms, state.default_elements_limit);
  state.recent_unique_ua_window = SlidingWindow<std::string>(
      state.default_duration_ms, state.default_elements_limit);

  // Reset statistics trackers by creating new instances
  state.request_time_tracker = StatsTracker();
  state.bytes_sent_tracker = StatsTracker();
  state.error_rate_tracker = StatsTracker();
  state.requests_in_window_count_tracker = StatsTracker();

  // Reset timestamps
  state.last_seen_timestamp_ms = 0;
  state.ip_first_seen_timestamp_ms = 0;
}

template <>
inline void StatePool<PerPathState>::reset_state_object(PerPathState &state) {
  // Reset PerPathState to clean state based on actual structure

  // Reset statistics trackers by creating new instances
  state.request_time_tracker = StatsTracker();
  state.bytes_sent_tracker = StatsTracker();
  state.error_rate_tracker = StatsTracker();
  state.request_volume_tracker = StatsTracker();

  // Reset timestamp
  state.last_seen_timestamp_ms = 0;
}

template <>
inline void
StatePool<PerSessionState>::reset_state_object(PerSessionState &state) {
  // Reset PerSessionState to clean state based on actual structure
  state.unique_paths_visited.clear();
  state.unique_user_agents.clear();
  state.request_history.clear();
  state.http_method_counts.clear();

  // Reset sliding windows
  state.request_timestamps_window = SlidingWindow<uint64_t>(
      state.default_duration_ms, state.default_elements_limit);

  // Reset statistics trackers
  state.request_time_tracker = StatsTracker();
  state.bytes_sent_tracker = StatsTracker();

  // Reset timestamps and counters
  state.session_start_timestamp_ms = 0;
  state.last_seen_timestamp_ms = 0;
  state.request_count = 0;
  state.failed_login_attempts = 0;
  state.error_4xx_count = 0;
  state.error_5xx_count = 0;
}

// Central state object allocator
class StateObjectAllocator {
public:
  StateObjectAllocator(
      const memory::MemoryConfig &config = memory::MemoryConfig{})
      : memory_manager_(std::make_shared<memory::MemoryManager>(config)),
        ip_state_pool_(config.default_pool_size / 4, config.max_pool_size / 4),
        path_state_pool_(config.default_pool_size / 8,
                         config.max_pool_size / 8),
        session_state_pool_(config.default_pool_size / 4,
                            config.max_pool_size / 4) {

    std::cout << "[StateObjectAllocator] Initialized with pool sizes - "
              << "IP: " << (config.default_pool_size / 4) << "/"
              << (config.max_pool_size / 4)
              << ", Path: " << (config.default_pool_size / 8) << "/"
              << (config.max_pool_size / 8)
              << ", Session: " << (config.default_pool_size / 4) << "/"
              << (config.max_pool_size / 4) << std::endl;
  }

  // Acquire state objects
  PooledState<PerIpState> acquire_ip_state() {
    return ip_state_pool_.acquire();
  }

  PooledState<PerPathState> acquire_path_state() {
    return path_state_pool_.acquire();
  }

  PooledState<PerSessionState> acquire_session_state() {
    return session_state_pool_.acquire();
  }

  // Memory management
  void handle_memory_pressure() {
    if (memory_manager_->is_memory_pressure()) {
      std::cout
          << "[StateObjectAllocator] Memory pressure detected, shrinking pools"
          << std::endl;

      ip_state_pool_.shrink_to_fit();
      path_state_pool_.shrink_to_fit();
      session_state_pool_.shrink_to_fit();

      memory_manager_->trigger_compaction();
    }
  }

  // Statistics
  struct AllocatorStatistics {
    size_t ip_pool_size;
    size_t path_pool_size;
    size_t session_pool_size;
    size_t total_memory_usage;
  };

  AllocatorStatistics get_statistics() const {
    AllocatorStatistics stats;
    stats.ip_pool_size = ip_state_pool_.size();
    stats.path_pool_size = path_state_pool_.size();
    stats.session_pool_size = session_state_pool_.size();
    stats.total_memory_usage = memory_manager_->get_total_memory_usage();
    return stats;
  }

  std::shared_ptr<memory::MemoryManager> get_memory_manager() const {
    return memory_manager_;
  }

private:
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  StatePool<PerIpState> ip_state_pool_;
  StatePool<PerPathState> path_state_pool_;
  StatePool<PerSessionState> session_state_pool_;
};

// Factory functions for creating state objects with memory tracking
namespace state_factory {

template <typename StateType, typename... Args>
std::unique_ptr<StateType>
create_tracked_state(const std::string & /*component*/, Args &&...args) {
  auto state = std::make_unique<StateType>(std::forward<Args>(args)...);

  // Track allocation in profiler if enabled
#ifdef ENABLE_MEMORY_PROFILING
  profiling::MemoryProfiler::instance().track_allocation(
      state.get(), sizeof(StateType), component, __FUNCTION__);
#endif

  return state;
}

// Optimized factory for bulk state creation
template <typename StateType>
std::vector<std::unique_ptr<StateType>>
create_state_batch(size_t count, const std::string &component) {

  std::vector<std::unique_ptr<StateType>> states;
  states.reserve(count);

  for (size_t i = 0; i < count; ++i) {
    states.emplace_back(create_tracked_state<StateType>(component));
  }

  std::cout << "[StateFactory] Created batch of " << count
            << " state objects for component: " << component << std::endl;

  return states;
}

} // namespace state_factory

} // namespace resource

#endif // STATE_OBJECT_ALLOCATOR_HPP

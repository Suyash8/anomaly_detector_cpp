#ifndef MEMORY_PROFILER_HOOKS_HPP
#define MEMORY_PROFILER_HOOKS_HPP

#include "core/logger.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace profiling {

// Allocation tracking data
struct AllocationInfo {
  size_t size;
  std::string component;
  std::string function;
  std::chrono::steady_clock::time_point timestamp;
  void *stack_trace[16]; // Store stack trace for debugging
  size_t stack_depth;
};

// Memory usage snapshot
struct MemorySnapshot {
  std::chrono::steady_clock::time_point timestamp;
  size_t total_allocated;
  size_t total_freed;
  size_t current_usage;
  size_t peak_usage;
  size_t allocation_count;
  size_t deallocation_count;
  std::unordered_map<std::string, size_t> component_usage;
};

// Performance timing data
struct PerformanceTimer {
  std::chrono::high_resolution_clock::time_point start_time;
  std::chrono::duration<double> accumulated_time{0};
  size_t call_count = 0;

  void start() { start_time = std::chrono::high_resolution_clock::now(); }

  void stop() {
    auto end_time = std::chrono::high_resolution_clock::now();
    accumulated_time += end_time - start_time;
    call_count++;
  }

  double average_time_ms() const {
    return call_count > 0 ? (accumulated_time.count() * 1000.0) / call_count
                          : 0.0;
  }

  double total_time_ms() const { return accumulated_time.count() * 1000.0; }
};

// RAII timer for automatic timing
class ScopedTimer {
public:
  explicit ScopedTimer(PerformanceTimer &timer) : timer_(timer) {
    timer_.start();
  }

  ~ScopedTimer() { timer_.stop(); }

private:
  PerformanceTimer &timer_;
};

// Memory profiler with detailed tracking
class MemoryProfiler {
public:
  static MemoryProfiler &instance() {
    static MemoryProfiler instance;
    return instance;
  }

  // Enable/disable profiling
  void enable(bool detailed_tracking = false) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = true;
    detailed_tracking_ = detailed_tracking;
    start_time_ = std::chrono::steady_clock::now();

    LOG(LogLevel::INFO, LogComponent::CORE,
        "Memory profiler enabled (detailed: " << detailed_tracking << ")");
  }

  void disable() {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = false;

    LOG(LogLevel::INFO, LogComponent::CORE,
        "Memory profiler disabled. Total allocations tracked: "
            << allocation_count_.load());
  }

  // Track memory allocation
  void track_allocation(void *ptr, size_t size, const std::string &component,
                        const std::string &function = "") {
    if (!enabled_)
      return;

    std::lock_guard<std::mutex> lock(mutex_);

    AllocationInfo info;
    info.size = size;
    info.component = component;
    info.function = function;
    info.timestamp = std::chrono::steady_clock::now();
    info.stack_depth = 0; // TODO: Implement stack trace capture

    allocations_[ptr] = info;
    total_allocated_ += size;
    current_usage_ += size;
    peak_usage_ = std::max(peak_usage_, current_usage_);
    allocation_count_++;

    // Update component statistics
    component_usage_[component] += size;

    if (detailed_tracking_ && allocation_count_ % 1000 == 0) {
      LOG(LogLevel::DEBUG, LogComponent::CORE,
          "Memory allocation #"
              << allocation_count_.load() << ": " << size << " bytes from "
              << component << " (current: " << current_usage_
              << " bytes, peak: " << peak_usage_ << " bytes)");
    }
  }

  // Track memory deallocation
  void track_deallocation(void *ptr, const std::string &component = "") {
    if (!enabled_)
      return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(ptr);
    if (it != allocations_.end()) {
      size_t size = it->second.size;
      const std::string &alloc_component = it->second.component;

      total_freed_ += size;
      current_usage_ -= size;
      deallocation_count_++;

      // Update component statistics
      if (component_usage_[alloc_component] >= size) {
        component_usage_[alloc_component] -= size;
      }

      allocations_.erase(it);

      if (detailed_tracking_ && deallocation_count_ % 1000 == 0) {
        LOG(LogLevel::DEBUG, LogComponent::CORE,
            "Memory deallocation #" << deallocation_count_.load() << ": "
                                    << size << " bytes from " << alloc_component
                                    << " (current: " << current_usage_
                                    << " bytes)");
      }
    }
  }

  // Create memory snapshot
  MemorySnapshot create_snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);

    MemorySnapshot snapshot;
    snapshot.timestamp = std::chrono::steady_clock::now();
    snapshot.total_allocated = total_allocated_;
    snapshot.total_freed = total_freed_;
    snapshot.current_usage = current_usage_;
    snapshot.peak_usage = peak_usage_;
    snapshot.allocation_count = allocation_count_;
    snapshot.deallocation_count = deallocation_count_;
    snapshot.component_usage = component_usage_;

    return snapshot;
  }

  // Performance timing
  PerformanceTimer &get_timer(const std::string &name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return timers_[name];
  }

  // Generate comprehensive report
  std::string generate_report() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream report;
    auto now = std::chrono::steady_clock::now();
    auto runtime =
        std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);

    report << "=== Memory Profiler Report ===\n";
    report << "Runtime: " << runtime.count() << " seconds\n";
    report << "Total Allocated: " << total_allocated_ << " bytes\n";
    report << "Total Freed: " << total_freed_ << " bytes\n";
    report << "Current Usage: " << current_usage_ << " bytes\n";
    report << "Peak Usage: " << peak_usage_ << " bytes\n";
    report << "Allocations: " << allocation_count_ << "\n";
    report << "Deallocations: " << deallocation_count_ << "\n";

    if (!component_usage_.empty()) {
      report << "\n=== Usage by Component ===\n";
      std::vector<std::pair<std::string, size_t>> sorted_components(
          component_usage_.begin(), component_usage_.end());
      std::sort(
          sorted_components.begin(), sorted_components.end(),
          [](const auto &a, const auto &b) { return a.second > b.second; });

      for (const auto &[component, usage] : sorted_components) {
        double percentage =
            total_allocated_ > 0
                ? (static_cast<double>(usage) / total_allocated_) * 100.0
                : 0.0;
        report << component << ": " << usage << " bytes (" << std::fixed
               << std::setprecision(2) << percentage << "%)\n";
      }
    }

    if (!timers_.empty()) {
      report << "\n=== Performance Timers ===\n";
      for (const auto &[name, timer] : timers_) {
        report << name << ": " << timer.call_count << " calls, "
               << "avg " << std::fixed << std::setprecision(3)
               << timer.average_time_ms() << "ms, "
               << "total " << std::fixed << std::setprecision(3)
               << timer.total_time_ms() << "ms\n";
      }
    }

    // Memory leak detection
    if (!allocations_.empty()) {
      report << "\n=== Potential Memory Leaks ===\n";
      report << "Outstanding allocations: " << allocations_.size() << "\n";

      std::unordered_map<std::string, size_t> leak_by_component;
      for (const auto &[ptr, info] : allocations_) {
        leak_by_component[info.component] += info.size;
      }

      for (const auto &[component, leaked_bytes] : leak_by_component) {
        report << component << ": " << leaked_bytes << " bytes\n";
      }
    }

    return report.str();
  }

  // Export detailed data to file
  void export_to_file(const std::string &filename) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ofstream file(filename);
    if (!file.is_open()) {
      LOG(LogLevel::ERROR, LogComponent::CORE,
          "Failed to open profiler output file: " << filename);
      return;
    }

    file << generate_report();

    // Export allocation details if available
    if (detailed_tracking_ && !allocations_.empty()) {
      file << "\n=== Detailed Allocations ===\n";
      file << "Address,Size,Component,Function,Timestamp\n";

      for (const auto &[ptr, info] : allocations_) {
        auto timestamp_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                info.timestamp.time_since_epoch())
                .count();
        file << ptr << "," << info.size << "," << info.component << ","
             << info.function << "," << timestamp_ms << "\n";
      }
    }

    LOG(LogLevel::INFO, LogComponent::CORE,
        "Memory profiler report exported to: " << filename);
  }

  // Reset all statistics
  void reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    allocations_.clear();
    component_usage_.clear();
    timers_.clear();
    total_allocated_ = 0;
    total_freed_ = 0;
    current_usage_ = 0;
    peak_usage_ = 0;
    allocation_count_ = 0;
    deallocation_count_ = 0;
    start_time_ = std::chrono::steady_clock::now();

    LOG(LogLevel::INFO, LogComponent::CORE, "Memory profiler statistics reset");
  }

private:
  MemoryProfiler() = default;

  mutable std::mutex mutex_;
  std::atomic<bool> enabled_{false};
  bool detailed_tracking_ = false;

  std::unordered_map<void *, AllocationInfo> allocations_;
  std::unordered_map<std::string, size_t> component_usage_;
  std::unordered_map<std::string, PerformanceTimer> timers_;

  size_t total_allocated_ = 0;
  size_t total_freed_ = 0;
  size_t current_usage_ = 0;
  size_t peak_usage_ = 0;
  std::atomic<size_t> allocation_count_{0};
  std::atomic<size_t> deallocation_count_{0};

  std::chrono::steady_clock::time_point start_time_;
};

// Convenience macros for profiling
#define PROFILE_MEMORY_ALLOC(ptr, size, component)                             \
  profiling::MemoryProfiler::instance().track_allocation(ptr, size, component, \
                                                         __FUNCTION__)

#define PROFILE_MEMORY_FREE(ptr)                                               \
  profiling::MemoryProfiler::instance().track_deallocation(ptr)

#define PROFILE_TIMER_START(name)                                              \
  auto &timer_##name = profiling::MemoryProfiler::instance().get_timer(#name); \
  profiling::ScopedTimer scoped_timer_##name(timer_##name)

#define PROFILE_FUNCTION() PROFILE_TIMER_START(__FUNCTION__)

// Smart pointer with profiling
template <typename T> class ProfiledUniquePtr {
public:
  ProfiledUniquePtr() = default;

  explicit ProfiledUniquePtr(T *ptr, const std::string &component = "unknown")
      : ptr_(ptr), component_(component) {
    if (ptr_) {
      PROFILE_MEMORY_ALLOC(ptr_, sizeof(T), component_);
    }
  }

  ~ProfiledUniquePtr() { reset(); }

  ProfiledUniquePtr(const ProfiledUniquePtr &) = delete;
  ProfiledUniquePtr &operator=(const ProfiledUniquePtr &) = delete;

  ProfiledUniquePtr(ProfiledUniquePtr &&other) noexcept
      : ptr_(other.ptr_), component_(std::move(other.component_)) {
    other.ptr_ = nullptr;
  }

  ProfiledUniquePtr &operator=(ProfiledUniquePtr &&other) noexcept {
    if (this != &other) {
      reset();
      ptr_ = other.ptr_;
      component_ = std::move(other.component_);
      other.ptr_ = nullptr;
    }
    return *this;
  }

  T *get() const { return ptr_; }
  T *operator->() const { return ptr_; }
  T &operator*() const { return *ptr_; }

  explicit operator bool() const { return ptr_ != nullptr; }

  void reset(T *new_ptr = nullptr) {
    if (ptr_) {
      PROFILE_MEMORY_FREE(ptr_);
      delete ptr_;
    }
    ptr_ = new_ptr;
    if (ptr_) {
      PROFILE_MEMORY_ALLOC(ptr_, sizeof(T), component_);
    }
  }

  T *release() {
    T *result = ptr_;
    ptr_ = nullptr;
    return result;
  }

private:
  T *ptr_ = nullptr;
  std::string component_;
};

// Factory function for profiled unique pointers
template <typename T, typename... Args>
ProfiledUniquePtr<T> make_profiled_unique(const std::string &component,
                                          Args &&...args) {
  return ProfiledUniquePtr<T>(new T(std::forward<Args>(args)...), component);
}

} // namespace profiling

#endif // MEMORY_PROFILER_HOOKS_HPP

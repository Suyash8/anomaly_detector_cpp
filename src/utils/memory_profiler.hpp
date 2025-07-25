#ifndef MEMORY_PROFILER_HPP
#define MEMORY_PROFILER_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace memory {

// Memory allocation tracking and profiling
struct AllocationInfo {
  size_t size;
  std::chrono::steady_clock::time_point timestamp;
  std::string location; // __FILE__ ":" __LINE__
  std::string
      component; // Component name (e.g., "AnalysisEngine", "RuleEngine")
};

struct ComponentMemoryStats {
  std::atomic<size_t> total_allocated{0};
  std::atomic<size_t> total_deallocated{0};
  std::atomic<size_t> current_usage{0};
  std::atomic<size_t> peak_usage{0};
  std::atomic<size_t> allocation_count{0};
  std::atomic<size_t> deallocation_count{0};

  // Fragmentation tracking
  std::atomic<size_t> total_fragmentation{0};
  std::atomic<size_t> average_allocation_size{0};

  // Timing metrics
  std::atomic<uint64_t> total_allocation_time_ns{0};
  std::atomic<uint64_t> total_deallocation_time_ns{0};

  // Copy constructor
  ComponentMemoryStats(const ComponentMemoryStats &other)
      : total_allocated(other.total_allocated.load()),
        total_deallocated(other.total_deallocated.load()),
        current_usage(other.current_usage.load()),
        peak_usage(other.peak_usage.load()),
        allocation_count(other.allocation_count.load()),
        deallocation_count(other.deallocation_count.load()),
        total_fragmentation(other.total_fragmentation.load()),
        average_allocation_size(other.average_allocation_size.load()),
        total_allocation_time_ns(other.total_allocation_time_ns.load()),
        total_deallocation_time_ns(other.total_deallocation_time_ns.load()) {}

  // Copy assignment operator
  ComponentMemoryStats &operator=(const ComponentMemoryStats &other) {
    if (this != &other) {
      total_allocated.store(other.total_allocated.load());
      total_deallocated.store(other.total_deallocated.load());
      current_usage.store(other.current_usage.load());
      peak_usage.store(other.peak_usage.load());
      allocation_count.store(other.allocation_count.load());
      deallocation_count.store(other.deallocation_count.load());
      total_fragmentation.store(other.total_fragmentation.load());
      average_allocation_size.store(other.average_allocation_size.load());
      total_allocation_time_ns.store(other.total_allocation_time_ns.load());
      total_deallocation_time_ns.store(other.total_deallocation_time_ns.load());
    }
    return *this;
  }

  // Default constructor
  ComponentMemoryStats() = default;
};

struct SystemMemoryMetrics {
  size_t total_heap_usage = 0;
  size_t total_stack_usage = 0;
  size_t total_mmap_usage = 0;
  size_t total_fragmentation = 0;
  double fragmentation_ratio = 0.0;

  // Cache metrics
  size_t l1_cache_misses = 0;
  size_t l2_cache_misses = 0;
  size_t l3_cache_misses = 0;
  double cache_hit_ratio = 0.0;

  // Memory bandwidth utilization
  double memory_bandwidth_utilization = 0.0;
  size_t memory_pressure_level = 0; // 0=low, 1=medium, 2=high, 3=critical
};

class MemoryProfiler {
public:
  static MemoryProfiler &instance();

  // Memory tracking
  void track_allocation(void *ptr, size_t size, const std::string &component,
                        const std::string &location);
  void track_deallocation(void *ptr, const std::string &component);

  // Statistics and reporting
  ComponentMemoryStats get_component_stats(const std::string &component) const;
  SystemMemoryMetrics get_system_metrics() const;
  std::vector<std::string> get_tracked_components() const;

  // Memory heat map generation
  struct AllocationHotspot {
    std::string location;
    std::string component;
    size_t total_allocations;
    size_t total_size;
    double average_size;
    double frequency_per_second;
  };

  std::vector<AllocationHotspot>
  get_allocation_hotspots(size_t top_n = 10) const;

  // Real-time monitoring
  void start_monitoring();
  void stop_monitoring();
  bool is_monitoring() const { return monitoring_enabled_; }

  // Memory pressure detection
  bool is_memory_pressure() const;
  size_t get_memory_pressure_level() const; // 0-3 scale

  // Profiling configuration
  void set_profiling_enabled(bool enabled) { profiling_enabled_ = enabled; }
  void set_detailed_tracking(bool enabled) { detailed_tracking_ = enabled; }
  void set_sampling_rate(double rate) { sampling_rate_ = rate; } // 0.0-1.0

  // Report generation
  std::string generate_memory_report() const;
  void export_memory_metrics_prometheus(std::string &output) const;

  // Memory optimization hints
  struct OptimizationHint {
    std::string component;
    std::string issue;
    std::string recommendation;
    size_t potential_savings;
    int priority; // 1=critical, 2=high, 3=medium, 4=low
  };

  std::vector<OptimizationHint> analyze_and_suggest_optimizations() const;

private:
  MemoryProfiler() = default;
  ~MemoryProfiler() = default;

  void update_system_metrics();
  void detect_fragmentation();
  void analyze_allocation_patterns();

  mutable std::mutex stats_mutex_;
  std::unordered_map<std::string, ComponentMemoryStats> component_stats_;
  std::unordered_map<void *, AllocationInfo> active_allocations_;

  std::atomic<bool> profiling_enabled_{false};
  std::atomic<bool> monitoring_enabled_{false};
  std::atomic<bool> detailed_tracking_{false};
  std::atomic<double> sampling_rate_{1.0};

  SystemMemoryMetrics cached_system_metrics_;
  std::chrono::steady_clock::time_point last_metrics_update_;

  // Memory pressure thresholds (configurable)
  size_t memory_pressure_threshold_mb_ = 1024; // 1GB
  size_t memory_critical_threshold_mb_ = 2048; // 2GB
};

// Convenience macros for memory tracking
#define TRACK_ALLOCATION(ptr, size, component)                                 \
  do {                                                                         \
    if (memory::MemoryProfiler::instance().is_monitoring()) {                  \
      memory::MemoryProfiler::instance().track_allocation(                     \
          ptr, size, component, __FILE__ ":" + std::to_string(__LINE__));      \
    }                                                                          \
  } while (0)

#define TRACK_DEALLOCATION(ptr, component)                                     \
  do {                                                                         \
    if (memory::MemoryProfiler::instance().is_monitoring()) {                  \
      memory::MemoryProfiler::instance().track_deallocation(ptr, component);   \
    }                                                                          \
  } while (0)

// RAII memory tracker for automatic tracking
template <typename T> class TrackedAllocator {
public:
  using value_type = T;

  TrackedAllocator(const std::string &component) : component_(component) {}

  template <typename U>
  TrackedAllocator(const TrackedAllocator<U> &other)
      : component_(other.component_) {}

  T *allocate(size_t n) {
    auto start = std::chrono::steady_clock::now();
    T *ptr = static_cast<T *>(std::aligned_alloc(alignof(T), n * sizeof(T)));
    auto end = std::chrono::steady_clock::now();

    if (ptr) {
      TRACK_ALLOCATION(ptr, n * sizeof(T), component_);

      // Track allocation timing
      auto duration =
          std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
      (void)duration; // TODO: Store timing statistics
    }

    return ptr;
  }

  void deallocate(T *ptr, size_t /* n */) {
    auto start = std::chrono::steady_clock::now();
    TRACK_DEALLOCATION(ptr, component_);
    std::free(ptr);
    auto end = std::chrono::steady_clock::now();

    // Track deallocation timing
    auto duration =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    (void)duration; // TODO: Store timing statistics
  }

  std::string component_;
};

template <typename T, typename U>
bool operator==(const TrackedAllocator<T> &, const TrackedAllocator<U> &) {
  return true;
}

template <typename T, typename U>
bool operator!=(const TrackedAllocator<T> &, const TrackedAllocator<U> &) {
  return false;
}

} // namespace memory

#endif // MEMORY_PROFILER_HPP

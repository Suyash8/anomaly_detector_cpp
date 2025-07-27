#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace AnomalyDetector {

// Forward declarations
class MetricsCollector;
class LoadShedder;
class PerformanceProfiler;

// Performance metrics structure
struct PerformanceMetrics {
  // Timing metrics
  std::atomic<uint64_t> total_processing_time_ns{0};
  std::atomic<uint64_t> avg_processing_time_ns{0};
  std::atomic<uint64_t> min_processing_time_ns{UINT64_MAX};
  std::atomic<uint64_t> max_processing_time_ns{0};

  // Throughput metrics
  std::atomic<uint64_t> requests_per_second{0};
  std::atomic<uint64_t> total_requests{0};
  std::atomic<uint64_t> completed_requests{0};
  std::atomic<uint64_t> failed_requests{0};

  // Resource metrics
  std::atomic<double> cpu_usage_percent{0.0};
  std::atomic<uint64_t> memory_usage_bytes{0};
  std::atomic<uint64_t> queue_depth{0};
  std::atomic<uint64_t> active_threads{0};

  // Latency percentiles (protected by mutex)
  mutable std::mutex latency_mutex;
  std::vector<uint64_t> latency_samples;
  double p50_latency_ns = 0.0;
  double p95_latency_ns = 0.0;
  double p99_latency_ns = 0.0;

  // Copy constructor and assignment operator
  PerformanceMetrics() = default;
  PerformanceMetrics(const PerformanceMetrics &other);
  PerformanceMetrics &operator=(const PerformanceMetrics &other);

  void update_latency_percentiles();
  void add_latency_sample(uint64_t latency_ns);
  void reset();
}; // Performance thresholds for load shedding
struct PerformanceThresholds {
  double max_cpu_usage_percent = 80.0;
  uint64_t max_memory_usage_bytes = 1024 * 1024 * 1024; // 1GB
  uint64_t max_queue_depth = 10000;
  uint64_t max_avg_latency_ms = 1000;
  double max_error_rate_percent = 5.0;

  // Load shedding levels
  enum class LoadLevel { NORMAL = 0, MODERATE = 1, HIGH = 2, CRITICAL = 3 };

  LoadLevel determine_load_level(const PerformanceMetrics &metrics) const;
};

// High-resolution timer for performance measurement
class PerformanceTimer {
private:
  std::chrono::high_resolution_clock::time_point start_time_;
  std::chrono::high_resolution_clock::time_point end_time_;
  bool is_running_ = false;

public:
  void start();
  void stop();
  uint64_t elapsed_nanoseconds() const;
  uint64_t elapsed_microseconds() const;
  uint64_t elapsed_milliseconds() const;

  // RAII timer for automatic measurement
  class ScopedTimer {
  private:
    PerformanceTimer &timer_;
    std::function<void(uint64_t)> callback_;

  public:
    ScopedTimer(PerformanceTimer &timer,
                std::function<void(uint64_t)> callback = nullptr);
    ~ScopedTimer();
  };
};

// Metrics collector for aggregating performance data
class MetricsCollector {
private:
  std::unordered_map<std::string, std::unique_ptr<PerformanceMetrics>>
      component_metrics_;
  mutable std::mutex metrics_mutex_;

  // Background thread for metrics collection
  std::thread collection_thread_;
  std::atomic<bool> should_stop_{false};
  std::condition_variable collection_cv_;
  std::mutex collection_mutex_;

  // Collection interval
  std::chrono::milliseconds collection_interval_{1000}; // 1 second

  void collection_loop();
  void collect_system_metrics();

public:
  MetricsCollector();
  ~MetricsCollector();

  // Component registration
  void register_component(const std::string &component_name);
  void unregister_component(const std::string &component_name);

  // Metrics updates
  void record_processing_time(const std::string &component, uint64_t time_ns);
  void record_request(const std::string &component);
  void record_completion(const std::string &component);
  void record_failure(const std::string &component);
  void record_queue_depth(const std::string &component, uint64_t depth);
  void record_thread_count(const std::string &component, uint64_t count);

  // Metrics retrieval
  PerformanceMetrics get_component_metrics(const std::string &component) const;
  PerformanceMetrics get_aggregate_metrics() const;
  std::vector<std::string> get_registered_components() const;

  // Control
  void start_collection();
  void stop_collection();
  void set_collection_interval(std::chrono::milliseconds interval);

  // Statistics
  void reset_metrics(const std::string &component = "");
  void print_metrics_summary() const;
};

// Load shedding mechanism for performance protection
class LoadShedder {
public:
  enum class SheddingStrategy {
    NONE = 0,
    DROP_OLDEST = 1,
    DROP_NEWEST = 2,
    DROP_RANDOM = 3,
    DROP_LOWEST_PRIORITY = 4
  };

  enum class Priority { LOW = 0, NORMAL = 1, HIGH = 2, CRITICAL = 3 };

private:
  std::atomic<bool> shedding_enabled_{false};
  std::atomic<SheddingStrategy> current_strategy_{SheddingStrategy::NONE};
  std::atomic<double> shedding_percentage_{0.0};

  PerformanceThresholds thresholds_;
  const MetricsCollector *metrics_collector_;

  // Statistics
  std::atomic<uint64_t> total_requests_{0};
  std::atomic<uint64_t> shed_requests_{0};

  mutable std::mutex shed_mutex_;
  std::random_device rd_;
  mutable std::mt19937 gen_;
  mutable std::uniform_real_distribution<> dis_;

public:
  LoadShedder(const MetricsCollector *collector);

  // Configuration
  void set_thresholds(const PerformanceThresholds &thresholds);
  void set_strategy(SheddingStrategy strategy);
  void enable_shedding(bool enabled);

  // Decision making
  bool should_shed_request(Priority priority = Priority::NORMAL);
  void update_shedding_parameters();

  // Statistics
  double get_shed_rate() const;
  uint64_t get_total_requests() const;
  uint64_t get_shed_requests() const;
  void reset_statistics();

  // Status
  bool is_shedding_active() const;
  SheddingStrategy get_current_strategy() const;
  double get_shedding_percentage() const;
};

// Advanced performance profiler with call stack tracking
class PerformanceProfiler {
private:
  struct ProfileEntry {
    std::string function_name;
    uint64_t total_time_ns = 0;
    uint64_t call_count = 0;
    uint64_t min_time_ns = UINT64_MAX;
    uint64_t max_time_ns = 0;
    std::vector<uint64_t> samples;

    void add_sample(uint64_t time_ns);
    double get_average_time_ns() const;
    void reset();
  };

  std::unordered_map<std::string, ProfileEntry> profile_data_;
  mutable std::mutex profile_mutex_;

  // Call stack tracking
  thread_local static std::vector<std::string> call_stack_;
  thread_local static std::vector<
      std::chrono::high_resolution_clock::time_point>
      timing_stack_;

public:
  PerformanceProfiler();
  ~PerformanceProfiler();

  // Profiling control
  void start_profiling(const std::string &function_name);
  void end_profiling(const std::string &function_name);

  // RAII profiler for automatic measurement
  class ScopedProfiler {
  private:
    PerformanceProfiler &profiler_;
    std::string function_name_;
    std::chrono::high_resolution_clock::time_point start_time_;

  public:
    ScopedProfiler(PerformanceProfiler &profiler,
                   const std::string &function_name);
    ~ScopedProfiler();
  };

  // Data retrieval
  std::vector<std::pair<std::string, ProfileEntry>> get_profile_data() const;
  ProfileEntry get_function_profile(const std::string &function_name) const;

  // Analysis
  void print_profile_report() const;
  void save_profile_report(const std::string &filename) const;
  void reset_profile_data();

  // Hot path detection
  std::vector<std::string> get_hottest_functions(size_t count = 10) const;
  std::vector<std::string> get_slowest_functions(size_t count = 10) const;
};

// Main performance monitor coordinator
class PerformanceMonitor {
private:
  std::unique_ptr<MetricsCollector> metrics_collector_;
  std::unique_ptr<LoadShedder> load_shedder_;
  std::unique_ptr<PerformanceProfiler> profiler_;

  // Configuration
  bool profiling_enabled_ = false;
  bool load_shedding_enabled_ = false;

  // Monitoring thread
  std::thread monitor_thread_;
  std::atomic<bool> monitoring_active_{false};
  std::condition_variable monitor_cv_;
  std::mutex monitor_mutex_;

  void monitoring_loop();

public:
  PerformanceMonitor();
  ~PerformanceMonitor();

  // Lifecycle
  void start_monitoring();
  void stop_monitoring();

  // Component access
  MetricsCollector *get_metrics_collector() const;
  LoadShedder *get_load_shedder() const;
  PerformanceProfiler *get_profiler() const;

  // Configuration
  void enable_profiling(bool enabled);
  void enable_load_shedding(bool enabled);
  void set_performance_thresholds(const PerformanceThresholds &thresholds);

  // Convenience methods
  void register_component(const std::string &component_name);
  bool should_shed_request(
      LoadShedder::Priority priority = LoadShedder::Priority::NORMAL);

  // Reporting
  void generate_performance_report() const;
  void save_performance_report(const std::string &filename) const;

  // Timer creation (for external use)
  PerformanceTimer create_timer();
  PerformanceProfiler::ScopedProfiler
  create_scoped_profiler(const std::string &function_name);
};

// Macro for easy function profiling
#define PROFILE_FUNCTION(monitor)                                              \
  auto _profiler = (monitor)->create_scoped_profiler(__FUNCTION__)

#define PROFILE_SCOPE(monitor, name)                                           \
  auto _profiler = (monitor)->create_scoped_profiler(name)

} // namespace AnomalyDetector

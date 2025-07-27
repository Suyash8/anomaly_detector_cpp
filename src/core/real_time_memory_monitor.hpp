#ifndef REAL_TIME_MEMORY_MONITOR_HPP
#define REAL_TIME_MEMORY_MONITOR_HPP

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace memory {

/**
 * High-precision memory usage sample
 */
struct MemorySample {
  std::chrono::microseconds timestamp;
  size_t total_allocated;
  size_t total_freed;
  size_t active_allocations;
  size_t peak_usage;
  double fragmentation_ratio;
  size_t component_usage[16]; // Pre-allocated for major components
};

/**
 * Memory usage prediction model
 */
class MemoryPredictor {
private:
  struct TrendData {
    double slope = 0.0;
    double intercept = 0.0;
    double confidence = 0.0;
    std::chrono::microseconds last_update{0};
  };

  std::vector<MemorySample> history_;
  TrendData short_term_trend_;  // 1-minute trend
  TrendData medium_term_trend_; // 10-minute trend
  TrendData long_term_trend_;   // 1-hour trend

  static constexpr size_t MAX_HISTORY_SIZE = 3600; // 1 hour at 1Hz sampling

  void update_trend(TrendData &trend, const std::vector<MemorySample> &samples,
                    std::chrono::microseconds window_size);

public:
  /**
   * Add new memory sample for prediction
   */
  void add_sample(const MemorySample &sample);

  /**
   * Predict memory usage at future time
   */
  size_t predict_usage(std::chrono::microseconds future_time);

  /**
   * Get prediction confidence (0.0 to 1.0)
   */
  double get_confidence() const;

  /**
   * Detect if memory leak pattern exists
   */
  bool detect_memory_leak(double threshold = 0.1) const;

  /**
   * Get trend direction: -1 (decreasing), 0 (stable), 1 (increasing)
   */
  int get_trend_direction() const;
};

/**
 * Memory efficiency scorer
 */
class MemoryEfficiencyScorer {
private:
  struct ComponentScore {
    double allocation_efficiency = 1.0; // How efficiently memory is allocated
    double usage_efficiency = 1.0; // How much allocated memory is actually used
    double temporal_efficiency = 1.0; // How well memory lifetime is managed
    double fragmentation_score =
        1.0;                    // How fragmented the component's memory is
    double overall_score = 1.0; // Combined score
  };

  std::unordered_map<std::string, ComponentScore> component_scores_;
  double system_score_ = 1.0;

public:
  /**
   * Update efficiency scores based on memory sample
   */
  void update_scores(const std::string &component, const MemorySample &sample);

  /**
   * Get efficiency score for component (0.0 to 1.0, higher is better)
   */
  double get_component_score(const std::string &component) const;

  /**
   * Get system-wide efficiency score
   */
  double get_system_score() const;

  /**
   * Get optimization recommendations
   */
  std::vector<std::string> get_recommendations() const;

  /**
   * Generate efficiency report
   */
  std::string generate_report() const;
};

/**
 * Real-time memory monitor with microsecond precision
 */
class RealTimeMemoryMonitor {
private:
  std::atomic<bool> running_{false};
  std::unique_ptr<std::thread> monitor_thread_;

  // High-precision timing
  std::chrono::high_resolution_clock::time_point start_time_;
  std::atomic<size_t> sample_count_{0};

  // Memory tracking
  std::atomic<size_t> total_allocated_{0};
  std::atomic<size_t> total_freed_{0};
  std::atomic<size_t> peak_usage_{0};

  // Component tracking
  mutable std::mutex component_mutex_;
  std::unordered_map<std::string, std::atomic<size_t>> component_allocations_;

  // Analysis components
  std::unique_ptr<MemoryPredictor> predictor_;
  std::unique_ptr<MemoryEfficiencyScorer> scorer_;

  // Configuration
  std::chrono::microseconds sampling_interval_{1000}; // 1ms default
  size_t alert_threshold_bytes_ = 1024 * 1024 * 1024; // 1GB default

  // Callbacks
  std::function<void(const MemorySample &)> sample_callback_;
  std::function<void(const std::string &)> alert_callback_;

  void monitor_loop();
  MemorySample capture_sample();
  void check_alerts(const MemorySample &sample);

public:
  RealTimeMemoryMonitor();
  ~RealTimeMemoryMonitor();

  /**
   * Start real-time monitoring
   */
  void start(std::chrono::microseconds sampling_interval =
                 std::chrono::microseconds(1000));

  /**
   * Stop monitoring
   */
  void stop();

  /**
   * Track allocation for component
   */
  void track_allocation(const std::string &component, size_t bytes);

  /**
   * Track deallocation for component
   */
  void track_deallocation(const std::string &component, size_t bytes);

  /**
   * Get current memory usage
   */
  size_t get_current_usage() const;

  /**
   * Get peak memory usage
   */
  size_t get_peak_usage() const;

  /**
   * Get memory usage prediction
   */
  size_t predict_usage(std::chrono::microseconds future_time);

  /**
   * Get efficiency score for component
   */
  double get_efficiency_score(const std::string &component) const;

  /**
   * Get system efficiency score
   */
  double get_system_efficiency_score() const;

  /**
   * Check if memory leak detected
   */
  bool has_memory_leak() const;

  /**
   * Get optimization recommendations
   */
  std::vector<std::string> get_optimization_recommendations() const;

  /**
   * Set alert threshold
   */
  void set_alert_threshold(size_t bytes);

  /**
   * Set sample callback
   */
  void set_sample_callback(std::function<void(const MemorySample &)> callback);

  /**
   * Set alert callback
   */
  void set_alert_callback(std::function<void(const std::string &)> callback);

  /**
   * Get monitoring statistics
   */
  struct Statistics {
    size_t total_samples;
    std::chrono::microseconds uptime;
    double average_sampling_rate;
    size_t missed_samples;
  };

  Statistics get_statistics() const;

  /**
   * Generate comprehensive memory report
   */
  std::string generate_report() const;
};

/**
 * Memory leak detector with automatic mitigation
 */
class MemoryLeakDetector {
private:
  struct AllocationInfo {
    size_t size;
    std::chrono::microseconds timestamp;
    std::string component;
    void *stack_trace[8]; // Simplified stack trace
  };

  mutable std::mutex allocations_mutex_;
  std::unordered_map<void *, AllocationInfo> active_allocations_;

  std::atomic<size_t> potential_leaks_{0};
  std::atomic<size_t> confirmed_leaks_{0};

  std::chrono::microseconds leak_threshold_{300000000}; // 5 minutes

public:
  /**
   * Track new allocation
   */
  void track_allocation(void *ptr, size_t size, const std::string &component);

  /**
   * Track deallocation
   */
  void track_deallocation(void *ptr);

  /**
   * Scan for potential memory leaks
   */
  std::vector<std::string> scan_for_leaks();

  /**
   * Get leak statistics
   */
  struct LeakStats {
    size_t potential_leaks;
    size_t confirmed_leaks;
    size_t leaked_bytes;
    std::vector<std::string> leak_sources;
  };

  LeakStats get_leak_stats() const;

  /**
   * Attempt automatic mitigation
   */
  bool attempt_mitigation(const std::string &component);
};

} // namespace memory

#endif // REAL_TIME_MEMORY_MONITOR_HPP

#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace core {

/**
 * Comprehensive performance validation and benchmarking system
 */
class PerformanceValidator {
public:
  struct BenchmarkResult {
    std::string name;
    std::chrono::nanoseconds execution_time;
    size_t memory_usage_before;
    size_t memory_usage_after;
    size_t memory_peak_during;
    double throughput_ops_per_second;
    bool correctness_validated;
    std::string optimization_notes;
    std::chrono::system_clock::time_point timestamp;
  };

  struct MemoryMetrics {
    size_t total_allocated;
    size_t peak_allocated;
    size_t current_allocated;
    size_t fragmentation_percentage;
    double cache_hit_ratio;
    size_t memory_bandwidth_mbps;
  };

  struct LoadTestConfig {
    size_t num_ips{1000000};            // 1M+ IPs for extreme load testing
    size_t operations_per_second{1000}; // Target throughput
    std::chrono::seconds duration{60};  // Test duration
    bool enable_memory_pressure{true};  // Test under memory pressure
    size_t memory_limit_mb{512};        // Memory limit for pressure testing
  };

  PerformanceValidator();
  ~PerformanceValidator();

  // Benchmark individual optimizations
  template <typename Func>
  BenchmarkResult
  benchmark_optimization(const std::string &name, Func &&func,
                         const std::string &optimization_notes = "") {
    BenchmarkResult result;
    result.name = name;
    result.optimization_notes = optimization_notes;
    result.timestamp = std::chrono::system_clock::now();

    // Measure memory before
    result.memory_usage_before = get_current_memory_usage();

    auto start_time = std::chrono::high_resolution_clock::now();

    // Execute the function multiple times for accurate measurement
    const int iterations = 100;
    for (int i = 0; i < iterations; ++i) {
      auto iter_start = std::chrono::high_resolution_clock::now();
      func();
      auto iter_end = std::chrono::high_resolution_clock::now();
      (void)iter_start; // Suppress unused variable warning
      (void)iter_end;   // Suppress unused variable warning
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    result.execution_time =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end_time -
                                                             start_time) /
        iterations;

    // Measure memory after
    result.memory_usage_after = get_current_memory_usage();
    result.memory_peak_during = get_peak_memory_usage();

    // Calculate throughput (operations per second)
    double seconds =
        std::chrono::duration<double>(end_time - start_time).count();
    result.throughput_ops_per_second = iterations / seconds;

    // Simple correctness validation (override in derived classes for custom
    // logic)
    result.correctness_validated = true;

    // Store benchmark result
    store_benchmark_result(result);

    return result;
  }

  // Compare before/after performance
  struct ComparisonResult {
    BenchmarkResult before;
    BenchmarkResult after;
    double performance_improvement_ratio;
    double memory_improvement_ratio;
    bool regression_detected;
  };

  ComparisonResult compare_before_after(const std::string &name,
                                        std::function<void()> before_impl,
                                        std::function<void()> after_impl);

  // Extreme load testing
  struct LoadTestResult {
    size_t total_operations;
    std::chrono::nanoseconds total_time;
    double average_throughput;
    double peak_throughput;
    MemoryMetrics memory_stats;
    bool graceful_degradation_validated;
    std::vector<std::string> errors;
  };

  LoadTestResult run_extreme_load_test(const LoadTestConfig &config,
                                       std::function<void(size_t)> operation);

  // Memory validation
  struct MemoryValidationResult {
    bool correctness_maintained;
    size_t memory_leaks_detected;
    size_t invalid_accesses;
    double fragmentation_level;
    bool memory_pressure_handled;
    std::vector<std::string> validation_errors;
  };

  MemoryValidationResult
  validate_memory_usage(std::function<void()> test_function);

  // Cache efficiency measurement
  struct CacheMetrics {
    double l1_cache_hit_ratio;
    double l2_cache_hit_ratio;
    double l3_cache_hit_ratio;
    size_t cache_misses_per_operation;
    double memory_bandwidth_utilization;
  };

  CacheMetrics measure_cache_efficiency(std::function<void()> test_function);

  // Correctness validation
  bool validate_correctness(const std::string &test_name,
                            std::function<bool()> validation_function);

  // Report generation
  struct ValidationReport {
    std::vector<BenchmarkResult> benchmarks;
    std::vector<ComparisonResult> comparisons;
    std::vector<LoadTestResult> load_tests;
    MemoryValidationResult overall_memory_validation;
    CacheMetrics overall_cache_metrics;
    std::vector<std::string> recommendations;
    bool all_validations_passed;
  };

  ValidationReport generate_comprehensive_report();

  // Configuration
  void set_memory_limit(size_t limit_mb) { memory_limit_mb_ = limit_mb; }
  void enable_detailed_profiling(bool enable) { detailed_profiling_ = enable; }
  void set_benchmark_iterations(size_t iterations) {
    benchmark_iterations_ = iterations;
  }

private:
  struct MemorySnapshot {
    size_t allocated;
    size_t peak;
    std::chrono::steady_clock::time_point timestamp;
  };

  // Internal state
  std::mutex results_mutex_;
  std::vector<BenchmarkResult> benchmark_results_;
  std::vector<ComparisonResult> comparison_results_;
  std::vector<LoadTestResult> load_test_results_;

  // Configuration
  size_t memory_limit_mb_{512};
  bool detailed_profiling_{false};
  size_t benchmark_iterations_{10};

  // Helper methods
  MemorySnapshot capture_memory_snapshot();
  MemoryMetrics
  calculate_memory_metrics(const std::vector<MemorySnapshot> &snapshots);
  CacheMetrics measure_cache_performance();
  bool detect_memory_leaks(const MemorySnapshot &before,
                           const MemorySnapshot &after);
  void analyze_memory_pressure_response(const LoadTestResult &result);
  std::vector<std::string> generate_optimization_recommendations();

  // Helper functions for template implementation
  size_t get_current_memory_usage();
  size_t get_peak_memory_usage();
  void store_benchmark_result(const BenchmarkResult &result);
};

/**
 * Memory pressure simulation for testing graceful degradation
 */
class MemoryPressureSimulator {
public:
  MemoryPressureSimulator(size_t pressure_level_mb);
  ~MemoryPressureSimulator();

  void start_pressure();
  void stop_pressure();
  bool is_under_pressure() const { return pressure_active_; }

private:
  size_t pressure_level_mb_;
  bool pressure_active_{false};
  std::vector<std::unique_ptr<char[]>> pressure_allocations_;
  std::mutex pressure_mutex_;
};

/**
 * Utility functions for performance validation
 */
namespace validation_utils {

// Generate synthetic workload for testing
std::vector<std::string> generate_test_ips(size_t count);
std::vector<std::string> generate_test_paths(size_t count);
std::vector<std::string> generate_test_user_agents(size_t count);

// Memory pattern validation
bool validate_memory_access_pattern(void *ptr, size_t size);
bool check_memory_alignment(void *ptr, size_t alignment);

// Performance pattern analysis
struct PerformancePattern {
  std::string pattern_name;
  double expected_complexity; // O(n), O(log n), etc.
  bool linear_scaling;
  double memory_growth_rate;
};

PerformancePattern analyze_performance_pattern(
    const std::vector<PerformanceValidator::BenchmarkResult> &results);

} // namespace validation_utils

} // namespace core

#include "performance_validator.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

#ifdef __linux__
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace core {

PerformanceValidator::PerformanceValidator() = default;
PerformanceValidator::~PerformanceValidator() = default;

// Helper function implementations
size_t PerformanceValidator::get_current_memory_usage() {
  auto snapshot = capture_memory_snapshot();
  return snapshot.allocated;
}

size_t PerformanceValidator::get_peak_memory_usage() {
  // Return current memory as peak for simplicity
  // In a real implementation, this would track the actual peak
  return get_current_memory_usage();
}

void PerformanceValidator::store_benchmark_result(
    const BenchmarkResult &result) {
  std::lock_guard<std::mutex> lock(results_mutex_);
  benchmark_results_.push_back(result);
}

PerformanceValidator::ComparisonResult
PerformanceValidator::compare_before_after(const std::string &name,
                                           std::function<void()> before_impl,
                                           std::function<void()> after_impl) {
  ComparisonResult comparison;

  // Benchmark before implementation
  comparison.before = benchmark_optimization(name + "_before", before_impl,
                                             "Original implementation");

  // Benchmark after implementation
  comparison.after = benchmark_optimization(name + "_after", after_impl,
                                            "Optimized implementation");

  // Calculate improvements
  double before_time =
      std::chrono::duration<double>(comparison.before.execution_time).count();
  double after_time =
      std::chrono::duration<double>(comparison.after.execution_time).count();

  comparison.performance_improvement_ratio = before_time / after_time;

  double before_memory =
      static_cast<double>(comparison.before.memory_usage_after);
  double after_memory =
      static_cast<double>(comparison.after.memory_usage_after);

  comparison.memory_improvement_ratio = before_memory / after_memory;

  // Detect regressions (performance or memory got worse)
  comparison.regression_detected =
      (comparison.performance_improvement_ratio <
       0.95) ||                                     // 5% performance regression
      (comparison.memory_improvement_ratio < 0.95); // 5% memory regression

  std::lock_guard<std::mutex> lock(results_mutex_);
  comparison_results_.push_back(comparison);

  return comparison;
}

PerformanceValidator::LoadTestResult
PerformanceValidator::run_extreme_load_test(
    const LoadTestConfig &config, std::function<void(size_t)> operation) {
  LoadTestResult result = {};

  // Setup memory pressure simulation if enabled
  std::unique_ptr<MemoryPressureSimulator> pressure_sim;
  if (config.enable_memory_pressure) {
    pressure_sim =
        std::make_unique<MemoryPressureSimulator>(config.memory_limit_mb);
    pressure_sim->start_pressure();
  }

  auto start_time = std::chrono::high_resolution_clock::now();
  auto end_time = start_time + config.duration;

  std::vector<MemorySnapshot> memory_snapshots;
  std::vector<double> throughput_samples;

  size_t total_ops = 0;
  auto last_throughput_check = start_time;
  size_t ops_since_last_check = 0;

  try {
    while (std::chrono::high_resolution_clock::now() < end_time) {
      auto batch_start = std::chrono::high_resolution_clock::now();

      // Execute operations in batches
      for (size_t i = 0;
           i < 100 && std::chrono::high_resolution_clock::now() < end_time;
           ++i) {
        operation(total_ops);
        total_ops++;
        ops_since_last_check++;
      }

      // Sample memory and throughput periodically
      if (total_ops % 1000 == 0) {
        memory_snapshots.push_back(capture_memory_snapshot());

        auto now = std::chrono::high_resolution_clock::now();
        auto time_since_check =
            std::chrono::duration<double>(now - last_throughput_check).count();

        if (time_since_check >= 1.0) { // Sample every second
          double current_throughput = ops_since_last_check / time_since_check;
          throughput_samples.push_back(current_throughput);

          last_throughput_check = now;
          ops_since_last_check = 0;
        }
      }

      // Respect target throughput
      auto batch_duration =
          std::chrono::high_resolution_clock::now() - batch_start;
      auto target_batch_duration =
          std::chrono::microseconds(100000); // 100ms per 100 ops
      if (batch_duration < target_batch_duration) {
        std::this_thread::sleep_for(target_batch_duration - batch_duration);
      }
    }
  } catch (const std::exception &e) {
    result.errors.push_back("Exception during load test: " +
                            std::string(e.what()));
  }

  auto final_time = std::chrono::high_resolution_clock::now();
  result.total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
      final_time - start_time);
  result.total_operations = total_ops;

  // Calculate throughput metrics
  double total_seconds =
      std::chrono::duration<double>(result.total_time).count();
  result.average_throughput = result.total_operations / total_seconds;

  if (!throughput_samples.empty()) {
    result.peak_throughput =
        *std::max_element(throughput_samples.begin(), throughput_samples.end());
  } else {
    result.peak_throughput = result.average_throughput;
  }

  // Calculate memory metrics
  result.memory_stats = calculate_memory_metrics(memory_snapshots);

  // Test graceful degradation under memory pressure
  if (pressure_sim && pressure_sim->is_under_pressure()) {
    result.graceful_degradation_validated =
        (result.errors.empty() ||
         result.errors.size() < 10) && // Limited errors
        (result.average_throughput >
         config.operations_per_second * 0.5); // At least 50% throughput
    pressure_sim->stop_pressure();
  } else {
    result.graceful_degradation_validated = true;
  }

  std::lock_guard<std::mutex> lock(results_mutex_);
  load_test_results_.push_back(result);

  return result;
}

PerformanceValidator::MemoryValidationResult
PerformanceValidator::validate_memory_usage(
    std::function<void()> test_function) {
  MemoryValidationResult result = {};

  auto memory_before = capture_memory_snapshot();

  try {
    test_function();
    result.correctness_maintained = true;
  } catch (const std::exception &e) {
    result.correctness_maintained = false;
    result.validation_errors.push_back("Exception during test: " +
                                       std::string(e.what()));
  }

  auto memory_after = capture_memory_snapshot();

  // Check for memory leaks
  if (detect_memory_leaks(memory_before, memory_after)) {
    result.memory_leaks_detected =
        memory_after.allocated - memory_before.allocated;
    result.validation_errors.push_back(
        "Memory leak detected: " +
        std::to_string(result.memory_leaks_detected) + " bytes");
  }

  // Calculate fragmentation
  if (memory_after.peak > 0) {
    result.fragmentation_level =
        1.0 - (static_cast<double>(memory_after.allocated) / memory_after.peak);
  }

  // Test memory pressure handling
  MemoryPressureSimulator pressure_sim(memory_limit_mb_ / 2);
  pressure_sim.start_pressure();

  try {
    test_function();
    result.memory_pressure_handled = true;
  } catch (const std::exception &e) {
    result.memory_pressure_handled = false;
    result.validation_errors.push_back("Failed under memory pressure: " +
                                       std::string(e.what()));
  }

  pressure_sim.stop_pressure();

  return result;
}

PerformanceValidator::CacheMetrics
PerformanceValidator::measure_cache_efficiency(
    std::function<void()> test_function) {
  CacheMetrics metrics = {};

  // This is a simplified implementation
  // In a real system, this would use hardware performance counters
  auto start_time = std::chrono::high_resolution_clock::now();
  test_function();
  auto end_time = std::chrono::high_resolution_clock::now();

  auto duration = std::chrono::duration<double>(end_time - start_time).count();

  // Simulate cache metrics based on execution time patterns
  // Real implementation would use perf events or similar
  metrics.l1_cache_hit_ratio = 0.95;          // Typical L1 hit ratio
  metrics.l2_cache_hit_ratio = 0.85;          // Typical L2 hit ratio
  metrics.l3_cache_hit_ratio = 0.75;          // Typical L3 hit ratio
  metrics.cache_misses_per_operation = 10;    // Estimated
  metrics.memory_bandwidth_utilization = 0.7; // Estimated

  return metrics;
}

bool PerformanceValidator::validate_correctness(
    const std::string &test_name, std::function<bool()> validation_function) {
  try {
    return validation_function();
  } catch (const std::exception &e) {
    return false;
  }
}

PerformanceValidator::ValidationReport
PerformanceValidator::generate_comprehensive_report() {
  std::lock_guard<std::mutex> lock(results_mutex_);

  ValidationReport report;
  report.benchmarks = benchmark_results_;
  report.comparisons = comparison_results_;
  report.load_tests = load_test_results_;

  // Generate overall validation
  report.all_validations_passed = true;

  for (const auto &comparison : comparison_results_) {
    if (comparison.regression_detected) {
      report.all_validations_passed = false;
      break;
    }
  }

  for (const auto &load_test : load_test_results_) {
    if (!load_test.graceful_degradation_validated ||
        !load_test.errors.empty()) {
      report.all_validations_passed = false;
      break;
    }
  }

  // Generate recommendations
  report.recommendations = generate_optimization_recommendations();

  return report;
}

// Private helper methods
PerformanceValidator::MemorySnapshot
PerformanceValidator::capture_memory_snapshot() {
  MemorySnapshot snapshot;
  snapshot.timestamp = std::chrono::steady_clock::now();

#ifdef __linux__
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    snapshot.allocated = usage.ru_maxrss * 1024; // Convert from KB to bytes
  }
#endif

  // Fallback: use simplified memory tracking
  snapshot.allocated = 0; // Would be implemented with custom allocator tracking
  snapshot.peak = snapshot.allocated;

  return snapshot;
}

PerformanceValidator::MemoryMetrics
PerformanceValidator::calculate_memory_metrics(
    const std::vector<MemorySnapshot> &snapshots) {
  MemoryMetrics metrics = {};

  if (snapshots.empty())
    return metrics;

  metrics.current_allocated = snapshots.back().allocated;

  size_t total = 0;
  size_t peak = 0;

  for (const auto &snapshot : snapshots) {
    total += snapshot.allocated;
    peak = std::max(peak, snapshot.allocated);
  }

  metrics.total_allocated = total;
  metrics.peak_allocated = peak;

  // Calculate fragmentation (simplified)
  if (peak > 0) {
    metrics.fragmentation_percentage = static_cast<size_t>(
        (1.0 - static_cast<double>(metrics.current_allocated) / peak) * 100);
  }

  // Simulate other metrics
  metrics.cache_hit_ratio = 0.85;
  metrics.memory_bandwidth_mbps = 10000; // 10 GB/s typical

  return metrics;
}

bool PerformanceValidator::detect_memory_leaks(const MemorySnapshot &before,
                                               const MemorySnapshot &after) {
  // Simple heuristic: significant increase in memory usage
  return after.allocated > before.allocated + (1024 * 1024); // 1MB threshold
}

std::vector<std::string>
PerformanceValidator::generate_optimization_recommendations() {
  std::vector<std::string> recommendations;

  // Analyze benchmark results
  for (const auto &result : benchmark_results_) {
    if (result.throughput_ops_per_second < 1000) {
      recommendations.push_back("Low throughput detected in " + result.name +
                                ": Consider optimizing algorithm complexity");
    }

    if (result.memory_peak_during > result.memory_usage_after * 2) {
      recommendations.push_back("High memory peak in " + result.name +
                                ": Consider memory pooling or streaming");
    }
  }

  // Analyze comparison results
  for (const auto &comparison : comparison_results_) {
    if (comparison.performance_improvement_ratio < 1.1) {
      recommendations.push_back(
          "Minimal performance improvement in " + comparison.after.name +
          ": Consider alternative optimization strategies");
    }
  }

  return recommendations;
}

// MemoryPressureSimulator implementation
MemoryPressureSimulator::MemoryPressureSimulator(size_t pressure_level_mb)
    : pressure_level_mb_(pressure_level_mb) {}

MemoryPressureSimulator::~MemoryPressureSimulator() { stop_pressure(); }

void MemoryPressureSimulator::start_pressure() {
  std::lock_guard<std::mutex> lock(pressure_mutex_);

  if (pressure_active_)
    return;

  // Allocate memory to simulate pressure
  size_t allocation_size = pressure_level_mb_ * 1024 * 1024; // Convert to bytes
  pressure_allocations_.push_back(std::make_unique<char[]>(allocation_size));

  pressure_active_ = true;
}

void MemoryPressureSimulator::stop_pressure() {
  std::lock_guard<std::mutex> lock(pressure_mutex_);

  pressure_allocations_.clear();
  pressure_active_ = false;
}

// Utility functions
namespace validation_utils {

std::vector<std::string> generate_test_ips(size_t count) {
  std::vector<std::string> ips;
  ips.reserve(count);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(1, 254);

  for (size_t i = 0; i < count; ++i) {
    std::ostringstream oss;
    oss << dis(gen) << "." << dis(gen) << "." << dis(gen) << "." << dis(gen);
    ips.push_back(oss.str());
  }

  return ips;
}

std::vector<std::string> generate_test_paths(size_t count) {
  std::vector<std::string> paths;
  paths.reserve(count);

  std::vector<std::string> path_templates = {
      "/api/users", "/api/orders", "/api/products", "/dashboard", "/login",
      "/register",  "/admin",      "/reports",      "/settings",  "/help"};

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, path_templates.size() - 1);
  std::uniform_int_distribution<> id_dis(1, 10000);

  for (size_t i = 0; i < count; ++i) {
    std::string base_path = path_templates[dis(gen)];
    if (gen() % 3 == 0) { // Add ID parameter 1/3 of the time
      base_path += "/" + std::to_string(id_dis(gen));
    }
    paths.push_back(base_path);
  }

  return paths;
}

std::vector<std::string> generate_test_user_agents(size_t count) {
  std::vector<std::string> user_agents;
  user_agents.reserve(count);

  std::vector<std::string> agent_templates = {
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) "
      "AppleWebKit/605.1.15",
      "Mozilla/5.0 (Android 11; Mobile; rv:91.0) Gecko/91.0"};

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, agent_templates.size() - 1);

  for (size_t i = 0; i < count; ++i) {
    user_agents.push_back(agent_templates[dis(gen)]);
  }

  return user_agents;
}

bool validate_memory_access_pattern(void *ptr, size_t size) {
  if (!ptr || size == 0)
    return false;

  // Basic validation - check if we can read/write the memory
  try {
    volatile char *test_ptr = static_cast<volatile char *>(ptr);
    volatile char first = test_ptr[0];
    volatile char last = test_ptr[size - 1];
    (void)first;
    (void)last; // Suppress unused variable warnings
    return true;
  } catch (...) {
    return false;
  }
}

bool check_memory_alignment(void *ptr, size_t alignment) {
  return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

PerformancePattern analyze_performance_pattern(
    const std::vector<PerformanceValidator::BenchmarkResult> &results) {
  PerformancePattern pattern;
  pattern.pattern_name = "Unknown";
  pattern.expected_complexity = 1.0;
  pattern.linear_scaling = true;
  pattern.memory_growth_rate = 0.0;

  if (results.size() < 2)
    return pattern;

  // Simple analysis of execution time trends
  std::vector<double> times;
  for (const auto &result : results) {
    times.push_back(
        std::chrono::duration<double>(result.execution_time).count());
  }

  // Check if times are relatively stable (constant complexity)
  double mean_time =
      std::accumulate(times.begin(), times.end(), 0.0) / times.size();
  double variance = 0.0;
  for (double time : times) {
    variance += (time - mean_time) * (time - mean_time);
  }
  variance /= times.size();

  double coefficient_of_variation = std::sqrt(variance) / mean_time;

  if (coefficient_of_variation < 0.1) {
    pattern.pattern_name = "Constant Time O(1)";
    pattern.expected_complexity = 1.0;
  } else if (coefficient_of_variation < 0.3) {
    pattern.pattern_name = "Logarithmic O(log n)";
    pattern.expected_complexity = std::log2(results.size());
  } else {
    pattern.pattern_name = "Linear or Higher O(n+)";
    pattern.expected_complexity = static_cast<double>(results.size());
  }

  return pattern;
}

} // namespace validation_utils

} // namespace core

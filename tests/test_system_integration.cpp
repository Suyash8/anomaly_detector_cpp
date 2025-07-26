#include "../src/core/performance_validator.hpp"
#include "../src/core/production_hardening.hpp"
#include "../src/core/prometheus_metrics_exporter.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

using namespace core;

class SystemIntegrationTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Setup test environment
    metrics_exporter_ = std::make_unique<PrometheusMetricsExporter>();
    validator_ = std::make_unique<PerformanceValidator>();
    hardening_ = std::make_unique<ProductionHardening>(metrics_exporter_.get());
    debugger_ = std::make_unique<MemoryDebugger>();
    ab_testing_ = std::make_unique<ABTestingFramework>();
  }

  void TearDown() override { hardening_->stop_monitoring(); }

  std::unique_ptr<PrometheusMetricsExporter> metrics_exporter_;
  std::unique_ptr<PerformanceValidator> validator_;
  std::unique_ptr<ProductionHardening> hardening_;
  std::unique_ptr<MemoryDebugger> debugger_;
  std::unique_ptr<ABTestingFramework> ab_testing_;
};

// Test comprehensive performance validation
TEST_F(SystemIntegrationTest, PerformanceValidation) {
  // Test basic benchmarking
  auto result = validator_->benchmark_optimization(
      "test_function",
      []() {
        // Simulate some work
        std::vector<int> data(1000);
        std::iota(data.begin(), data.end(), 0);
        std::sort(data.begin(), data.end());
      },
      "Sorting optimization test");

  EXPECT_EQ(result.name, "test_function");
  EXPECT_GT(result.execution_time.count(), 0);
  EXPECT_TRUE(result.correctness_validated);
  EXPECT_EQ(result.optimization_notes, "Sorting optimization test");
}

TEST_F(SystemIntegrationTest, BeforeAfterComparison) {
  // Test performance comparison
  auto before_impl = []() {
    // Inefficient implementation
    std::vector<int> data(1000);
    for (size_t i = 0; i < data.size(); ++i) {
      data[i] = static_cast<int>(i);
    }
    // Bubble sort (inefficient)
    for (size_t i = 0; i < data.size(); ++i) {
      for (size_t j = 0; j < data.size() - 1; ++j) {
        if (data[j] > data[j + 1]) {
          std::swap(data[j], data[j + 1]);
        }
      }
    }
  };

  auto after_impl = []() {
    // Efficient implementation
    std::vector<int> data(1000);
    std::iota(data.begin(), data.end(), 0);
    std::sort(data.begin(), data.end());
  };

  auto comparison = validator_->compare_before_after("sorting_optimization",
                                                     before_impl, after_impl);

  EXPECT_GT(comparison.performance_improvement_ratio, 1.0);
  EXPECT_FALSE(comparison.regression_detected);
}

TEST_F(SystemIntegrationTest, ExtremeLoadTesting) {
  PerformanceValidator::LoadTestConfig config;
  config.num_ips = 1000; // Smaller test size
  config.operations_per_second = 100;
  config.duration = std::chrono::seconds(5);
  config.enable_memory_pressure = false; // Disable for unit test

  size_t operation_count = 0;
  auto operation = [&operation_count](size_t op_id) {
    // Simulate log processing
    operation_count++;
    std::string ip = "192.168.1." + std::to_string(op_id % 255);
    std::string path = "/api/test/" + std::to_string(op_id);
    // Simulate some processing
    std::hash<std::string> hasher;
    volatile size_t hash = hasher(ip + path);
    (void)hash; // Suppress unused variable warning
  };

  auto result = validator_->run_extreme_load_test(config, operation);

  EXPECT_GT(result.total_operations, 0);
  EXPECT_GT(result.average_throughput, 0);
  EXPECT_TRUE(result.graceful_degradation_validated);
  EXPECT_TRUE(result.errors.empty());
}

TEST_F(SystemIntegrationTest, MemoryValidation) {
  auto test_function = []() {
    // Allocate and free memory
    std::vector<std::unique_ptr<char[]>> allocations;
    for (int i = 0; i < 100; ++i) {
      allocations.push_back(std::make_unique<char[]>(1024));
    }
    // Memory is automatically freed when vector goes out of scope
  };

  auto result = validator_->validate_memory_usage(test_function);

  EXPECT_TRUE(result.correctness_maintained);
  EXPECT_LT(result.fragmentation_level, 0.5); // Less than 50% fragmentation
}

TEST_F(SystemIntegrationTest, CacheEfficiencyMeasurement) {
  auto test_function = []() {
    // Create cache-friendly access pattern
    std::vector<int> data(10000);
    std::iota(data.begin(), data.end(), 0);

    // Sequential access (cache-friendly)
    volatile int sum = 0;
    for (const auto &value : data) {
      sum += value;
    }
    (void)sum; // Suppress unused variable warning
  };

  auto metrics = validator_->measure_cache_efficiency(test_function);

  EXPECT_GT(metrics.l1_cache_hit_ratio, 0.8);
  EXPECT_GT(metrics.l2_cache_hit_ratio, 0.7);
  EXPECT_GT(metrics.memory_bandwidth_utilization, 0.0);
}

TEST_F(SystemIntegrationTest, CorrectnessValidation) {
  auto validation_function = []() -> bool {
    // Test that optimization maintains correctness
    std::vector<int> original = {5, 2, 8, 1, 9};
    std::vector<int> optimized = original;

    // Original sort
    std::sort(original.begin(), original.end());

    // "Optimized" sort (same algorithm for this test)
    std::sort(optimized.begin(), optimized.end());

    return original == optimized;
  };

  bool result =
      validator_->validate_correctness("sort_correctness", validation_function);
  EXPECT_TRUE(result);
}

TEST_F(SystemIntegrationTest, ComprehensiveReport) {
  // Run some benchmarks first
  validator_->benchmark_optimization("test1", []() {
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  });

  validator_->benchmark_optimization("test2", []() {
    std::this_thread::sleep_for(std::chrono::microseconds(200));
  });

  auto report = validator_->generate_comprehensive_report();

  EXPECT_EQ(report.benchmarks.size(), 2);
  EXPECT_GE(report.recommendations.size(), 0);
}

// Test production hardening and monitoring
TEST_F(SystemIntegrationTest, ProductionMonitoring) {
  // Setup alert callback
  std::vector<ProductionHardening::MemoryAlert> received_alerts;
  hardening_->register_alert_callback(
      [&received_alerts](const ProductionHardening::MemoryAlert &alert) {
        received_alerts.push_back(alert);
      });

  // Start monitoring
  hardening_->start_monitoring();

  // Simulate high memory usage
  ProductionHardening::MemoryMetrics metrics;
  metrics.total_allocated = 1000 * 1024 * 1024;  // 1GB
  metrics.current_allocated = 900 * 1024 * 1024; // 900MB
  metrics.peak_allocated = 950 * 1024 * 1024;    // 950MB
  metrics.usage_percentage = 90.0;               // 90% - should trigger alert
  metrics.fragmentation_percentage = 25.0;
  metrics.allocations_per_second = 100;
  metrics.deallocations_per_second = 95;

  hardening_->update_memory_metrics(metrics);

  // Allow some time for processing
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Check that alert was fired
  EXPECT_GT(received_alerts.size(), 0);

  if (!received_alerts.empty()) {
    EXPECT_EQ(received_alerts[0].type,
              ProductionHardening::MemoryAlert::Type::USAGE_HIGH);
    EXPECT_GE(received_alerts[0].severity,
              ProductionHardening::MemoryAlert::Severity::WARNING);
  }

  auto stats = hardening_->get_monitoring_stats();
  EXPECT_GT(stats.total_alerts_fired, 0);
}

TEST_F(SystemIntegrationTest, AutoResponseSystem) {
  // Setup auto-response
  bool auto_response_triggered = false;
  hardening_->register_auto_response(
      ProductionHardening::MemoryAlert::Type::USAGE_HIGH,
      [&auto_response_triggered](
          const ProductionHardening::MemoryAlert &alert) -> bool {
        auto_response_triggered = true;
        return true; // Indicate successful response
      });

  hardening_->start_monitoring();

  // Trigger high memory usage alert
  ProductionHardening::MemoryMetrics metrics;
  metrics.usage_percentage = 95.0; // Critical level
  hardening_->update_memory_metrics(metrics);

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  EXPECT_TRUE(auto_response_triggered);
}

TEST_F(SystemIntegrationTest, ManualInterventions) {
  EXPECT_TRUE(hardening_->trigger_garbage_collection());
  EXPECT_TRUE(hardening_->trigger_memory_compaction());
  EXPECT_TRUE(hardening_->trigger_cache_cleanup());
  EXPECT_TRUE(hardening_->enable_memory_pressure_mode());
  EXPECT_TRUE(hardening_->disable_memory_pressure_mode());

  auto stats = hardening_->get_monitoring_stats();
  EXPECT_EQ(stats.manual_interventions, 5);
}

// Test memory debugging tools
TEST_F(SystemIntegrationTest, MemoryDebugging) {
  debugger_->enable_tracking(true);

  // Simulate allocations
  void *ptr1 = malloc(1024);
  void *ptr2 = malloc(2048);
  debugger_->track_allocation(ptr1, 1024, "test_function:line_10", "test_tag");
  debugger_->track_allocation(ptr2, 2048, "test_function:line_15", "test_tag");

  auto analysis = debugger_->analyze_heap();
  EXPECT_EQ(analysis.total_allocations, 2);
  EXPECT_EQ(analysis.total_size, 3072);
  EXPECT_EQ(analysis.largest_allocation, 2048);

  // Test leak detection
  auto potential_leaks =
      debugger_->find_potential_leaks(std::chrono::seconds(0));
  EXPECT_EQ(potential_leaks.size(),
            2); // Both allocations are "leaks" immediately

  // Clean up
  debugger_->track_deallocation(ptr1);
  debugger_->track_deallocation(ptr2);
  free(ptr1);
  free(ptr2);

  auto final_analysis = debugger_->analyze_heap();
  EXPECT_EQ(final_analysis.total_allocations, 0);
}

TEST_F(SystemIntegrationTest, MemoryPatternDetection) {
  debugger_->enable_tracking(true);

  // Create pattern: many small allocations from same location
  std::vector<void *> ptrs;
  for (int i = 0; i < 15; ++i) {
    void *ptr = malloc(64); // Small allocation
    ptrs.push_back(ptr);
    debugger_->track_allocation(ptr, 64, "frequent_allocator:line_5",
                                "small_objects");
  }

  auto patterns = debugger_->detect_allocation_patterns();
  EXPECT_GT(patterns.size(), 0);

  if (!patterns.empty()) {
    EXPECT_EQ(patterns[0].pattern_type, "Frequent Small Allocations");
    EXPECT_EQ(patterns[0].frequency, 15);
  }

  // Clean up
  for (void *ptr : ptrs) {
    debugger_->track_deallocation(ptr);
    free(ptr);
  }
}

// Test Grafana dashboard generation
TEST_F(SystemIntegrationTest, GrafanaDashboardGeneration) {
  GrafanaDashboardGenerator generator;

  GrafanaDashboardGenerator::DashboardConfig config;
  config.title = "Memory Optimization Dashboard";
  config.description = "Monitoring memory usage and optimization metrics";
  config.tags = {"memory", "performance"};

  auto dashboard_json =
      generator.generate_memory_optimization_dashboard(config);

  EXPECT_FALSE(dashboard_json.empty());
  EXPECT_NE(dashboard_json.find("Memory Optimization Dashboard"),
            std::string::npos);
  EXPECT_NE(dashboard_json.find("Memory Usage"), std::string::npos);

  auto alert_rules = generator.generate_prometheus_alert_rules();
  EXPECT_FALSE(alert_rules.empty());
  EXPECT_NE(alert_rules.find("HighMemoryUsage"), std::string::npos);
}

// Test A/B testing framework
TEST_F(SystemIntegrationTest, ABTestingFramework) {
  ABTestingFramework::TestConfig config;
  config.test_name = "memory_optimization_test";
  config.description = "Testing new memory allocation strategy";
  config.traffic_split = 0.5;
  config.duration = std::chrono::seconds(10);
  config.variant_a_setup = []() { /* Original implementation setup */ };
  config.variant_b_setup = []() { /* Optimized implementation setup */ };

  EXPECT_TRUE(ab_testing_->start_test(config));
  EXPECT_TRUE(ab_testing_->is_test_active("memory_optimization_test"));

  // Test variant assignment
  auto variant1 =
      ab_testing_->assign_variant("memory_optimization_test", "user1");
  auto variant2 = ab_testing_->assign_variant("memory_optimization_test",
                                              "user1"); // Same user
  EXPECT_EQ(variant1, variant2); // Should get same variant

  // Record some metrics
  ab_testing_->record_metric("memory_optimization_test", variant1,
                             "memory_usage", 100.0);
  ab_testing_->record_metric("memory_optimization_test", variant1, "throughput",
                             1000.0);

  // Stop test and analyze
  EXPECT_TRUE(ab_testing_->stop_test("memory_optimization_test"));
  EXPECT_FALSE(ab_testing_->is_test_active("memory_optimization_test"));

  auto completed_tests = ab_testing_->get_completed_tests();
  EXPECT_EQ(completed_tests.size(), 1);
  EXPECT_EQ(completed_tests[0].test_name, "memory_optimization_test");
}

// Integration test for the full validation pipeline
TEST_F(SystemIntegrationTest, FullValidationPipeline) {
  // 1. Setup monitoring
  hardening_->start_monitoring();

  // 2. Run performance validation
  auto benchmark_result =
      validator_->benchmark_optimization("full_pipeline_test", []() {
        // Simulate realistic workload
        std::vector<std::string> data;
        for (int i = 0; i < 1000; ++i) {
          data.push_back("test_string_" + std::to_string(i));
        }
        std::sort(data.begin(), data.end());
      });

  // 3. Test memory validation
  auto memory_result = validator_->validate_memory_usage([]() {
    std::vector<int> large_vector(10000);
    std::iota(large_vector.begin(), large_vector.end(), 0);
  });

  // 4. Update monitoring metrics
  ProductionHardening::MemoryMetrics metrics;
  metrics.usage_percentage = 75.0;         // Normal usage
  metrics.fragmentation_percentage = 15.0; // Low fragmentation
  hardening_->update_memory_metrics(metrics);

  // 5. Generate comprehensive report
  auto report = validator_->generate_comprehensive_report();

  // Verify all components worked
  EXPECT_GT(benchmark_result.execution_time.count(), 0);
  EXPECT_TRUE(memory_result.correctness_maintained);
  EXPECT_GT(report.benchmarks.size(), 0);
  EXPECT_TRUE(report.all_validations_passed);

  // 6. Generate Grafana dashboard
  GrafanaDashboardGenerator generator;
  GrafanaDashboardGenerator::DashboardConfig dashboard_config;
  dashboard_config.title = "System Integration Dashboard";

  auto dashboard =
      generator.generate_memory_optimization_dashboard(dashboard_config);
  EXPECT_FALSE(dashboard.empty());

  std::cout << "Full validation pipeline completed successfully!" << std::endl;
  std::cout << "Benchmark execution time: "
            << std::chrono::duration<double, std::milli>(
                   benchmark_result.execution_time)
                   .count()
            << " ms" << std::endl;
  std::cout << "Memory validation passed: "
            << memory_result.correctness_maintained << std::endl;
  std::cout << "Total benchmarks: " << report.benchmarks.size() << std::endl;
  std::cout << "All validations passed: " << report.all_validations_passed
            << std::endl;
}

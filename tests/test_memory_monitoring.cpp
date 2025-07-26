#include "core/dynamic_memory_manager.hpp"
#include "core/real_time_memory_monitor.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace memory;

class MemoryMonitoringTest : public ::testing::Test {
protected:
  void SetUp() override {}
  void TearDown() override {}
};

// Test MemoryPredictor functionality
TEST_F(MemoryMonitoringTest, MemoryPredictorBasicFunctionality) {
  MemoryPredictor predictor;

  // Add samples with increasing memory usage (simulating a leak)
  auto start_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());

  for (int i = 0; i < 10; ++i) {
    MemorySample sample;
    sample.timestamp = start_time + std::chrono::microseconds(
                                        i * 1000000); // 1 second intervals
    sample.active_allocations =
        1024 * 1024 + i * 100 * 1024; // Increasing by 100KB each sample
    sample.total_allocated = sample.active_allocations;
    sample.total_freed = 0;
    sample.peak_usage = sample.active_allocations;
    sample.fragmentation_ratio = 0.1;

    predictor.add_sample(sample);
  }

  // Test prediction
  auto future_time = start_time + std::chrono::microseconds(15 * 1000000);
  size_t predicted = predictor.predict_usage(future_time);

  // Should predict continued growth
  EXPECT_GT(predicted, 1024 * 1024);
  EXPECT_GT(predictor.get_confidence(), 0.5);

  // Should detect potential memory leak
  EXPECT_TRUE(predictor.detect_memory_leak(50000)); // 50KB/second threshold
  EXPECT_EQ(predictor.get_trend_direction(), 1);    // Increasing
}

// Test MemoryEfficiencyScorer
TEST_F(MemoryMonitoringTest, MemoryEfficiencyScorerBasicFunctionality) {
  MemoryEfficiencyScorer scorer;

  // Test with good efficiency (low fragmentation)
  MemorySample good_sample;
  good_sample.active_allocations = 1024 * 1024;
  good_sample.peak_usage = 1024 * 1024;
  good_sample.fragmentation_ratio = 0.05; // 5% fragmentation

  scorer.update_scores("test_component", good_sample);

  double score = scorer.get_component_score("test_component");
  EXPECT_GT(score, 0.8); // Should be a good score

  // Test with poor efficiency (high fragmentation)
  MemorySample bad_sample;
  bad_sample.active_allocations = 1024 * 1024;
  bad_sample.peak_usage = 2 * 1024 * 1024;
  bad_sample.fragmentation_ratio = 0.5; // 50% fragmentation

  scorer.update_scores("bad_component", bad_sample);

  double bad_score = scorer.get_component_score("bad_component");
  EXPECT_LT(bad_score, score); // Should be worse than good score

  // Test recommendations
  auto recommendations = scorer.get_recommendations();
  EXPECT_FALSE(recommendations.empty());
}

// Test RealTimeMemoryMonitor
TEST_F(MemoryMonitoringTest, RealTimeMemoryMonitorBasicFunctionality) {
  RealTimeMemoryMonitor monitor;

  // Test basic tracking
  monitor.track_allocation("test_component", 1024);
  EXPECT_EQ(monitor.get_current_usage(), 1024);

  monitor.track_allocation("test_component", 2048);
  EXPECT_EQ(monitor.get_current_usage(), 3072);

  monitor.track_deallocation("test_component", 1024);
  EXPECT_EQ(monitor.get_current_usage(), 2048);

  // Test peak tracking
  EXPECT_EQ(monitor.get_peak_usage(), 3072);

  // Test efficiency scoring
  double score = monitor.get_efficiency_score("test_component");
  EXPECT_GE(score, 0.0);
  EXPECT_LE(score, 1.0);
}

TEST_F(MemoryMonitoringTest, RealTimeMemoryMonitorCallbacks) {
  RealTimeMemoryMonitor monitor;

  std::atomic<int> sample_count{0};
  std::atomic<int> alert_count{0};

  // Set callbacks
  monitor.set_sample_callback(
      [&](const MemorySample &sample) { sample_count++; });

  monitor.set_alert_callback([&](const std::string &alert) { alert_count++; });

  // Set low threshold to trigger alerts
  monitor.set_alert_threshold(1024);

  // Start monitoring with high frequency
  monitor.start(std::chrono::microseconds(100)); // 100μs sampling

  // Generate some allocations
  for (int i = 0; i < 5; ++i) {
    monitor.track_allocation("test", 500);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  // Wait for some samples
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  monitor.stop();

  // Should have captured samples
  EXPECT_GT(sample_count.load(), 0);

  // Should have triggered alerts (allocation exceeds 1024 bytes)
  EXPECT_GT(alert_count.load(), 0);
}

// Test MemoryLeakDetector
TEST_F(MemoryMonitoringTest, MemoryLeakDetectorBasicFunctionality) {
  MemoryLeakDetector detector;

  // Simulate some allocations
  void *ptr1 = malloc(1024);
  void *ptr2 = malloc(2048);

  detector.track_allocation(ptr1, 1024, "component1");
  detector.track_allocation(ptr2, 2048, "component2");

  // Simulate one deallocation
  detector.track_deallocation(ptr1);
  free(ptr1);

  // Check initial stats (no leaks yet due to time threshold)
  auto stats = detector.get_leak_stats();
  EXPECT_EQ(stats.potential_leaks, 0);

  // Scan for leaks (should find none due to recent allocation)
  auto leaks = detector.scan_for_leaks();
  EXPECT_TRUE(leaks.empty());

  // Clean up
  detector.track_deallocation(ptr2);
  free(ptr2);
}

// Test AutoTuningPool
TEST_F(MemoryMonitoringTest, AutoTuningPoolBasicFunctionality) {
  PoolConfig config;
  config.initial_size = 4;
  config.max_size = 16;
  config.auto_grow_enabled = true;

  AutoTuningPool<std::vector<int>> pool(config);

  // Test initial state
  auto stats = pool.get_stats();
  EXPECT_EQ(stats.current_size, 4);
  EXPECT_EQ(stats.active_objects, 0);

  // Acquire objects
  std::vector<std::unique_ptr<std::vector<int>>> objects;
  for (int i = 0; i < 6; ++i) {
    objects.push_back(pool.acquire());
  }

  stats = pool.get_stats();
  EXPECT_GE(stats.current_size, 6); // Should have grown
  EXPECT_EQ(stats.active_objects, 6);

  // Release objects
  for (auto &obj : objects) {
    pool.release(std::move(obj));
  }
  objects.clear();

  stats = pool.get_stats();
  EXPECT_EQ(stats.active_objects, 0);

  // Test utilization calculation
  double utilization = pool.get_utilization();
  EXPECT_GE(utilization, 0.0);
  EXPECT_LE(utilization, 1.0);
}

// Test MemoryRebalancer
TEST_F(MemoryMonitoringTest, MemoryRebalancerBasicFunctionality) {
  MemoryRebalancer rebalancer;

  // Register components with different priorities
  rebalancer.register_component("high_priority", 1024 * 1024, 2.0);
  rebalancer.register_component("low_priority", 1024 * 1024, 0.5);

  // Test allocation requests
  EXPECT_TRUE(rebalancer.request_allocation("high_priority", 512 * 1024));
  EXPECT_TRUE(rebalancer.request_allocation("low_priority", 256 * 1024));

  // Check budgets
  auto high_budget = rebalancer.get_component_budget("high_priority");
  auto low_budget = rebalancer.get_component_budget("low_priority");

  EXPECT_EQ(high_budget.allocated_bytes, 512 * 1024);
  EXPECT_EQ(low_budget.allocated_bytes, 256 * 1024);

  // Test memory pressure
  double pressure = rebalancer.get_memory_pressure();
  EXPECT_GE(pressure, 0.0);
  EXPECT_LE(pressure, 1.0);

  // Test release
  rebalancer.release_allocation("high_priority", 256 * 1024);
  high_budget = rebalancer.get_component_budget("high_priority");
  EXPECT_EQ(high_budget.allocated_bytes, 256 * 1024);

  // Get system stats
  auto stats = rebalancer.get_system_stats();
  EXPECT_GT(stats.total_memory, 0);
  EXPECT_EQ(stats.num_components, 2);
}

// Test CompactionScheduler
TEST_F(MemoryMonitoringTest, CompactionSchedulerBasicFunctionality) {
  CompactionScheduler scheduler;

  std::atomic<int> compaction_count{0};

  // Register compaction function
  scheduler.register_component(
      "test_component",
      [&compaction_count]() -> bool {
        compaction_count++;
        return true; // Successful compaction
      },
      std::chrono::microseconds(100000), // 100ms interval for testing
      1.0);

  // Start scheduler
  scheduler.start();

  // Wait for some compactions
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  scheduler.stop();

  // Should have performed at least one compaction
  EXPECT_GT(compaction_count.load(), 0);

  // Test manual compaction
  int count_before = compaction_count.load();
  EXPECT_TRUE(scheduler.force_compaction("test_component"));
  EXPECT_GT(compaction_count.load(), count_before);

  // Test stats
  auto stats = scheduler.get_stats();
  EXPECT_GT(stats.total_jobs, 0);
  EXPECT_GT(stats.completed_compactions, 0);
}

// Test RuntimeMemoryOptimizer
TEST_F(MemoryMonitoringTest, RuntimeMemoryOptimizerBasicFunctionality) {
  RuntimeMemoryOptimizer optimizer;

  std::string received_param;
  std::string received_value;

  // Register handler
  optimizer.register_handler(
      "test_param", [&](const std::string &param, const std::string &value) {
        received_param = param;
        received_value = value;
      });

  // Test parameter setting
  optimizer.set_parameter("test_param", "test_value");
  EXPECT_EQ(optimizer.get_parameter("test_param"), "test_value");

  // Test profile setting
  auto profiles = optimizer.get_available_profiles();
  EXPECT_FALSE(profiles.empty());

  optimizer.set_profile("BALANCED");

  // Test minimal memory mode
  optimizer.enable_minimal_memory_mode();
  EXPECT_TRUE(optimizer.is_minimal_memory_mode());
}

// Test DynamicMemoryManager integration
TEST_F(MemoryMonitoringTest, DynamicMemoryManagerIntegration) {
  DynamicMemoryManager manager;

  // Initialize
  manager.initialize();

  // Register component
  std::atomic<int> compact_calls{0};
  manager.register_component("test_component", 1024 * 1024, 1.0,
                             [&compact_calls]() -> bool {
                               compact_calls++;
                               return true;
                             });

  // Test pool creation
  PoolConfig config;
  config.initial_size = 2;
  config.max_size = 8;

  auto *pool = manager.create_pool<std::string>("string_pool", config);
  ASSERT_NE(pool, nullptr);

  // Test pool usage
  auto obj1 = pool->acquire();
  auto obj2 = pool->acquire();
  ASSERT_NE(obj1, nullptr);
  ASSERT_NE(obj2, nullptr);

  pool->release(std::move(obj1));
  pool->release(std::move(obj2));

  // Test accessing existing pool
  auto *same_pool = manager.get_pool<std::string>("string_pool");
  EXPECT_EQ(pool, same_pool);

  // Generate status report
  std::string report = manager.generate_status_report();
  EXPECT_FALSE(report.empty());

  // Shutdown
  manager.shutdown();
}

// Performance test for high-frequency monitoring
TEST_F(MemoryMonitoringTest, HighFrequencyMonitoringPerformance) {
  RealTimeMemoryMonitor monitor;

  std::atomic<int> sample_count{0};
  monitor.set_sample_callback(
      [&](const MemorySample &sample) { sample_count++; });

  // Start high-frequency monitoring
  monitor.start(std::chrono::microseconds(10)); // 10μs sampling (100kHz)

  // Generate load
  for (int i = 0; i < 1000; ++i) {
    monitor.track_allocation("perf_test", 64);
    if (i % 100 == 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
  }

  // Run for a short time
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  monitor.stop();

  // Check statistics
  auto stats = monitor.get_statistics();
  EXPECT_GT(stats.total_samples, 0);
  EXPECT_GT(stats.average_sampling_rate, 1000); // Should be > 1kHz

  // Performance should be reasonable (< 50% missed samples)
  double miss_rate = static_cast<double>(stats.missed_samples) /
                     (stats.total_samples + stats.missed_samples);
  EXPECT_LT(miss_rate, 0.5);
}

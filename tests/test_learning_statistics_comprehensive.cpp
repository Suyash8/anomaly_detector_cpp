#include "core/config.hpp"
#include "learning/dynamic_learning_engine.hpp"
#include "learning/rolling_statistics.hpp"
#include "learning/seasonal_model.hpp"

#include <cmath>
#include <gtest/gtest.h>
#include <random>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

using namespace learning;

class RollingStatisticsTest : public ::testing::Test {
protected:
  void SetUp() override {
    gen.seed(42); // Fixed seed for reproducible tests
  }

  std::mt19937 gen;
};

TEST_F(RollingStatisticsTest, EWMAConvergence) {
  RollingStatistics stats(0.1, 100);

  // Test convergence to constant value
  for (int i = 0; i < 1000; ++i) {
    stats.add_value(10.0, i * 1000);
  }
  EXPECT_NEAR(stats.get_mean(), 10.0, 0.1);
  EXPECT_TRUE(stats.is_established(30));

  // Test adaptation to new level
  for (int i = 0; i < 100; ++i) {
    stats.add_value(20.0, (1000 + i) * 1000);
  }
  EXPECT_GT(stats.get_mean(), 15.0); // Should have moved towards 20
}

TEST_F(RollingStatisticsTest, VarianceCalculation) {
  RollingStatistics stats(0.1, 1000);
  std::normal_distribution<> dist(50.0, 10.0);

  for (int i = 0; i < 1000; ++i) {
    stats.add_value(dist(gen), i * 1000);
  }

  double variance = stats.get_variance();
  double std_dev = stats.get_standard_deviation();

  EXPECT_GT(variance, 0.0);
  EXPECT_NEAR(std_dev, std::sqrt(variance), 1e-10);
  EXPECT_NEAR(std_dev, 10.0, 3.0); // Should be close to true std dev
}

TEST_F(RollingStatisticsTest, PercentileAccuracy) {
  RollingStatistics stats(0.2, 1000);

  // Add uniform distribution from 0 to 999
  for (int i = 0; i < 1000; ++i) {
    stats.add_value(i, i * 1000);
  }

  EXPECT_NEAR(stats.get_percentile(0.5), 499.5, 5.0);
  EXPECT_NEAR(stats.get_percentile(0.95), 950, 10.0);
  EXPECT_NEAR(stats.get_percentile(0.99), 990, 10.0);
  EXPECT_NEAR(stats.get_percentile(0.01), 10, 10.0);
}

TEST_F(RollingStatisticsTest, BayesianConfidenceInterval) {
  RollingStatistics stats(0.1, 1000);
  std::normal_distribution<> dist(50.0, 10.0);

  for (int i = 0; i < 1000; ++i) {
    stats.add_value(dist(gen), i * 1000);
  }

  auto [lower_95, upper_95] = stats.get_confidence_interval(0.95);
  auto [lower_99, upper_99] = stats.get_confidence_interval(0.99);

  double mean = stats.get_mean();

  // 95% interval should contain the mean
  EXPECT_LT(lower_95, mean);
  EXPECT_GT(upper_95, mean);

  // 99% interval should be wider than 95% interval
  EXPECT_LT(lower_99, lower_95);
  EXPECT_GT(upper_99, upper_95);

  // Intervals should be reasonable for normal distribution
  double interval_95 = upper_95 - lower_95;
  EXPECT_GT(interval_95, 0.0);
  EXPECT_LT(interval_95, 50.0); // Not too wide
}

TEST_F(RollingStatisticsTest, ThreadSafety) {
  RollingStatistics stats(0.1, 1000);

  // This is a basic test - in practice you'd need multiple threads
  for (int i = 0; i < 100; ++i) {
    stats.add_value(i, i * 1000);
    double mean = stats.get_mean();
    size_t count = stats.get_sample_count();
    EXPECT_GE(count, 0);
    EXPECT_GE(mean, 0.0);
  }
}

class SeasonalModelTest : public ::testing::Test {
protected:
  void SetUp() override {
    base_time = 1720000000000; // July 2025
  }

  uint64_t base_time;
};

TEST_F(SeasonalModelTest, FourierAnalysisBasic) {
  SeasonalModel model(50);

  // Create synthetic hourly pattern with clear periodicity
  for (int day = 0; day < 10; ++day) {
    for (int hour = 0; hour < 24; ++hour) {
      // Simulate daily pattern: high during day, low at night
      double value = 10.0 + 5.0 * std::sin(2.0 * M_PI * hour / 24.0);
      uint64_t timestamp = base_time + (day * 24 + hour) * 3600000;
      model.add_observation(value, timestamp);
    }
  }

  model.update_pattern();
  EXPECT_TRUE(model.is_pattern_established());

  auto pattern = model.get_current_pattern();
  EXPECT_GT(pattern.confidence_score, 0.5);
  EXPECT_FALSE(pattern.dominant_hourly_frequencies.empty());
}

TEST_F(SeasonalModelTest, SeasonalFactorAccuracy) {
  SeasonalModel model(100);

  // Create synthetic data with known pattern
  for (int day = 0; day < 14; ++day) {
    for (int hour = 0; hour < 24; ++hour) {
      // Higher values during business hours (9-17)
      double value = (hour >= 9 && hour <= 17) ? 20.0 : 5.0;
      uint64_t timestamp = base_time + (day * 24 + hour) * 3600000;
      model.add_observation(value, timestamp);
    }
  }

  model.update_pattern();

  // Test seasonal factors
  uint64_t business_hour = base_time + 14 * 3600000; // 2PM
  uint64_t night_hour = base_time + 2 * 3600000;     // 2AM

  double business_factor = model.get_seasonal_factor(business_hour);
  double night_factor = model.get_seasonal_factor(night_hour);

  EXPECT_GT(business_factor, night_factor);
}

TEST_F(SeasonalModelTest, PatternEstablishment) {
  SeasonalModel model(100);

  EXPECT_FALSE(model.is_pattern_established());

  // Add insufficient data
  for (int i = 0; i < 50; ++i) {
    model.add_observation(10.0 + (i % 24), base_time + i * 3600000);
  }

  EXPECT_FALSE(model.is_pattern_established());

  // Add sufficient data
  for (int i = 50; i < 200; ++i) {
    model.add_observation(10.0 + (i % 24), base_time + i * 3600000);
  }

  model.update_pattern();
  EXPECT_TRUE(model.is_pattern_established());

  auto pattern = model.get_current_pattern();
  EXPECT_EQ(pattern.hourly_pattern.size(), 24);
  EXPECT_EQ(pattern.daily_pattern.size(), 7);
  EXPECT_EQ(pattern.weekly_pattern.size(), 4);
}

class DynamicLearningEngineTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Create configuration with security-critical auto-marking enabled
    Config::DynamicLearningConfig config;
    config.auto_mark_login_paths_critical = true;
    config.auto_mark_admin_paths_critical = true;
    config.auto_mark_high_failed_login_ips_critical = true;
    config.failed_login_threshold_for_critical =
        3; // Lower threshold for testing
    config.security_critical_max_change_percent = 10.0;

    engine = std::make_unique<DynamicLearningEngine>(config);
    base_time = 1720000000000;
  }

  std::unique_ptr<DynamicLearningEngine> engine;
  uint64_t base_time;
};

TEST_F(DynamicLearningEngineTest, BaselineEstablishment) {
  std::string ip = "192.168.1.100";

  // Add normal traffic
  for (int i = 0; i < 100; ++i) {
    engine->process_event("ip", ip, 100.0 + i % 10, base_time + i * 1000);
  }

  auto baseline = engine->get_baseline("ip", ip);
  ASSERT_NE(baseline, nullptr);
  EXPECT_TRUE(baseline->is_established);
  EXPECT_EQ(baseline->entity_type, "ip");
  EXPECT_EQ(baseline->entity_id, ip);
}

TEST_F(DynamicLearningEngineTest, AnomalyDetection) {
  std::string ip = "192.168.1.100";

  // Establish baseline with normal values
  for (int i = 0; i < 200; ++i) {
    engine->process_event("ip", ip, 100.0, base_time + i * 1000);
  }

  double anomaly_score = 0.0;

  // Test normal value
  EXPECT_FALSE(engine->is_anomalous("ip", ip, 102.0, anomaly_score));
  EXPECT_LT(anomaly_score, 3.0);

  // Test anomalous value
  EXPECT_TRUE(engine->is_anomalous("ip", ip, 200.0, anomaly_score));
  EXPECT_GT(anomaly_score, 3.0);
}

TEST_F(DynamicLearningEngineTest, DynamicThresholdCalculation) {
  std::string path = "/api/login";

  // Add varied data to establish percentiles
  std::mt19937 gen(42);
  std::normal_distribution<> dist(50.0, 10.0);

  for (int i = 0; i < 500; ++i) {
    double value = std::max(0.0, dist(gen));
    engine->process_event("path", path, value, base_time + i * 1000);
  }

  auto baseline = engine->get_baseline("path", path);
  ASSERT_NE(baseline, nullptr);

  double threshold_95 =
      engine->calculate_dynamic_threshold(*baseline, base_time, 0.95);
  double threshold_99 =
      engine->calculate_dynamic_threshold(*baseline, base_time, 0.99);

  EXPECT_GT(threshold_99, threshold_95);
  EXPECT_GT(threshold_95, baseline->statistics.get_mean());
}

TEST_F(DynamicLearningEngineTest, BaselineCleanup) {
  // Create multiple baselines
  for (int i = 0; i < 10; ++i) {
    std::string ip = "192.168.1." + std::to_string(i + 100);
    engine->process_event("ip", ip, 100.0, base_time + i * 1000);
  }

  EXPECT_EQ(engine->get_baseline_count(), 10);

  // Cleanup with very short TTL
  engine->cleanup_expired_baselines(base_time + 1000000, 500); // 500ms TTL

  EXPECT_LT(engine->get_baseline_count(), 10);
}

TEST_F(DynamicLearningEngineTest, EntitySeparation) {
  // Test that different entity types and IDs maintain separate baselines
  engine->process_event("ip", "1.2.3.4", 100.0, base_time);
  engine->process_event("ip", "1.2.3.5", 200.0, base_time);
  engine->process_event("path", "/api", 50.0, base_time);

  auto baseline1 = engine->get_baseline("ip", "1.2.3.4");
  auto baseline2 = engine->get_baseline("ip", "1.2.3.5");
  auto baseline3 = engine->get_baseline("path", "/api");

  ASSERT_NE(baseline1, nullptr);
  ASSERT_NE(baseline2, nullptr);
  ASSERT_NE(baseline3, nullptr);

  EXPECT_NE(baseline1.get(), baseline2.get());
  EXPECT_NE(baseline1.get(), baseline3.get());
  EXPECT_NE(baseline2.get(), baseline3.get());
}

TEST_F(DynamicLearningEngineTest, ThresholdChangeLoggingAndAudit) {
  std::string ip = "10.0.0.1";

  // Add initial values to establish baseline with consistent values
  for (int i = 0; i < 100; ++i) {
    engine->process_event("ip", ip, 100.0, base_time + i * 1000);
  }

  auto baseline = engine->get_baseline("ip", ip);
  ASSERT_NE(baseline, nullptr);
  ASSERT_TRUE(baseline->is_established);

  // Get initial audit log state
  auto initial_log = engine->get_threshold_audit_log("ip", ip);
  size_t initial_count = initial_log.size();

  // Add several significant outliers to ensure threshold change
  for (int i = 0; i < 10; ++i) {
    engine->process_event("ip", ip, 500.0 + i * 50.0,
                          base_time + (200 + i) * 1000);
  }

  // Check that audit log was updated
  auto updated_log = engine->get_threshold_audit_log("ip", ip);
  EXPECT_GT(updated_log.size(), initial_count);

  // Verify audit entry content if available
  if (!updated_log.empty()) {
    bool found_baseline_update = false;
    for (const auto &entry : updated_log) {
      if (entry.reason == "Baseline update") {
        found_baseline_update = true;
        EXPECT_EQ(entry.percentile, 0.95);
        EXPECT_TRUE(entry.operator_id.empty()); // Automatic update
        break;
      }
    }
    EXPECT_TRUE(found_baseline_update);
  }
}

TEST_F(DynamicLearningEngineTest, ManualOverrideThreshold) {
  std::string ip = "10.0.0.2";

  // Establish baseline
  for (int i = 0; i < 100; ++i) {
    engine->process_event("ip", ip, 100.0, base_time + i * 1000);
  }

  double normal_threshold = engine->get_entity_threshold("ip", ip, 0.95);
  EXPECT_FALSE(std::isnan(normal_threshold));

  // Test enhanced manual override with validation
  bool success = engine->set_manual_override_with_validation(
      "ip", ip, 42.0, "admin", "Security test");
  EXPECT_TRUE(success);

  double overridden = engine->get_entity_threshold("ip", ip, 0.95);
  EXPECT_DOUBLE_EQ(overridden, 42.0);

  // Check audit log for override
  auto audit_log = engine->get_threshold_audit_log("ip", ip);
  EXPECT_FALSE(audit_log.empty());

  auto latest_entry = std::find_if(audit_log.rbegin(), audit_log.rend(),
                                   [](const ThresholdAuditEntry &entry) {
                                     return entry.reason == "Security test";
                                   });
  EXPECT_NE(latest_entry, audit_log.rend());
  EXPECT_EQ(latest_entry->operator_id, "admin");
  EXPECT_EQ(latest_entry->new_threshold, 42.0);

  // Clear override
  engine->clear_manual_override("ip", ip);
  double after_clear = engine->get_entity_threshold("ip", ip, 0.95);
  EXPECT_DOUBLE_EQ(after_clear, normal_threshold);

  // Test invalid override (should fail)
  bool invalid_success = engine->set_manual_override_with_validation(
      "ip", ip, -5.0, "admin", "Invalid test");
  EXPECT_FALSE(invalid_success);

  // Test override without operator ID (should fail)
  bool no_operator_success = engine->set_manual_override_with_validation(
      "ip", ip, 50.0, "", "No operator test");
  EXPECT_FALSE(no_operator_success);
}

TEST_F(DynamicLearningEngineTest, ProcessAnalyzedEventIntegration) {
  AnalyzedEvent event({});
  event.raw_log.ip_address = "10.0.0.3";
  event.raw_log.request_time_s = 123.0;
  event.raw_log.parsed_timestamp_ms = base_time;
  engine->process_analyzed_event(event);

  // Check the correct entity type that the new implementation uses
  auto baseline = engine->get_baseline("ip_request_time", "10.0.0.3");
  ASSERT_NE(baseline, nullptr);
  EXPECT_TRUE(baseline->statistics.get_sample_count() > 0);
}

TEST_F(DynamicLearningEngineTest, PercentileBasedThresholdCalculation) {
  std::string entity = "test_entity";

  // Add varied data to create a distribution
  std::mt19937 gen(42);
  std::normal_distribution<> dist(100.0, 15.0);

  for (int i = 0; i < 1000; ++i) {
    double value = std::max(0.0, dist(gen));
    engine->process_event("test", entity, value, base_time + i * 1000);
  }

  // Test different percentiles
  double threshold_50 =
      engine->calculate_percentile_threshold("test", entity, 0.50);
  double threshold_90 =
      engine->calculate_percentile_threshold("test", entity, 0.90);
  double threshold_95 =
      engine->calculate_percentile_threshold("test", entity, 0.95);
  double threshold_99 =
      engine->calculate_percentile_threshold("test", entity, 0.99);

  // Verify ordering
  EXPECT_LT(threshold_50, threshold_90);
  EXPECT_LT(threshold_90, threshold_95);
  EXPECT_LT(threshold_95, threshold_99);

  // Test cache functionality
  double cached_95 =
      engine->calculate_percentile_threshold("test", entity, 0.95, true);
  EXPECT_DOUBLE_EQ(threshold_95, cached_95);

  // Test non-cached calculation
  double non_cached_95 =
      engine->calculate_percentile_threshold("test", entity, 0.95, false);
  EXPECT_DOUBLE_EQ(threshold_95, non_cached_95);
}

TEST_F(DynamicLearningEngineTest, SecurityCriticalEntityManagement) {
  std::string ip = "192.168.1.100";
  std::string path = "/admin/login";

  // Test marking entity as security critical
  engine->mark_entity_as_security_critical("ip", ip, 10.0);
  EXPECT_TRUE(engine->is_entity_security_critical("ip", ip));

  engine->mark_entity_as_security_critical("path", path, 5.0);
  EXPECT_TRUE(engine->is_entity_security_critical("path", path));

  // Establish baselines
  for (int i = 0; i < 100; ++i) {
    engine->process_event("ip", ip, 100.0 + i % 10, base_time + i * 1000);
    engine->process_event("path", path, 50.0 + i % 5, base_time + i * 1000);
  }

  auto ip_baseline = engine->get_baseline("ip", ip);
  auto path_baseline = engine->get_baseline("path", path);

  ASSERT_NE(ip_baseline, nullptr);
  ASSERT_NE(path_baseline, nullptr);

  EXPECT_TRUE(ip_baseline->is_security_critical);
  EXPECT_EQ(ip_baseline->max_threshold_change_percent, 10.0);

  EXPECT_TRUE(path_baseline->is_security_critical);
  EXPECT_EQ(path_baseline->max_threshold_change_percent, 5.0);

  // Test large manual override rejection for security-critical entity
  bool should_fail = engine->set_manual_override_with_validation(
      "ip", ip, 1000.0, "admin", "Large change test");
  EXPECT_FALSE(should_fail); // Should be rejected due to large change

  // Test acceptable override for security-critical entity
  double current_threshold = engine->get_entity_threshold("ip", ip, 0.95);
  double small_change = current_threshold * 1.05; // 5% increase
  bool should_succeed = engine->set_manual_override_with_validation(
      "ip", ip, small_change, "admin", "Small change test");
  EXPECT_TRUE(should_succeed);

  // Test unmarking
  engine->unmark_entity_as_security_critical("ip", ip);
  EXPECT_FALSE(engine->is_entity_security_critical("ip", ip));
}

TEST_F(DynamicLearningEngineTest, ThresholdCacheManagement) {
  std::string entity = "cache_test";

  // Establish baseline
  for (int i = 0; i < 100; ++i) {
    engine->process_event("test", entity, 100.0, base_time + i * 1000);
  }

  // First calculation should populate cache
  double threshold1 =
      engine->calculate_percentile_threshold("test", entity, 0.95, true);
  EXPECT_FALSE(std::isnan(threshold1));

  // Second calculation should use cache
  double threshold2 =
      engine->calculate_percentile_threshold("test", entity, 0.95, true);
  EXPECT_DOUBLE_EQ(threshold1, threshold2);

  // Invalidate cache
  engine->invalidate_threshold_cache("test", entity);

  // Should recalculate (might be slightly different due to floating point
  // precision)
  double threshold3 =
      engine->calculate_percentile_threshold("test", entity, 0.95, true);
  EXPECT_FALSE(std::isnan(threshold3));

  // Test global cache invalidation
  engine->invalidate_all_threshold_caches();

  // Should still work
  double threshold4 =
      engine->calculate_percentile_threshold("test", entity, 0.95, true);
  EXPECT_FALSE(std::isnan(threshold4));
}

TEST_F(DynamicLearningEngineTest, ThresholdAuditLogManagement) {
  std::string entity = "audit_test";

  // Establish baseline
  for (int i = 0; i < 50; ++i) {
    engine->process_event("test", entity, 100.0, base_time + i * 1000);
  }

  // Get initial audit log count
  auto initial_log = engine->get_threshold_audit_log("test", entity);
  size_t initial_count = initial_log.size();

  // Trigger several threshold changes
  for (int i = 0; i < 5; ++i) {
    engine->process_event("test", entity, 200.0 + i * 10,
                          base_time + (50 + i) * 1000);
  }

  // Check audit log growth
  auto updated_log = engine->get_threshold_audit_log("test", entity);
  EXPECT_GT(updated_log.size(), initial_count);

  // Test filtering by timestamp
  uint64_t midpoint = base_time + 52 * 1000;
  auto filtered_log = engine->get_threshold_audit_log("test", entity, midpoint);
  EXPECT_LE(filtered_log.size(), updated_log.size());

  // All filtered entries should have timestamp >= midpoint
  for (const auto &entry : filtered_log) {
    EXPECT_GE(entry.timestamp_ms, midpoint);
  }

  // Test manual override audit
  bool success = engine->set_manual_override_with_validation(
      "test", entity, 150.0, "test_admin", "Test override");
  EXPECT_TRUE(success);

  auto manual_log = engine->get_threshold_audit_log("test", entity);
  auto manual_entry = std::find_if(manual_log.rbegin(), manual_log.rend(),
                                   [](const ThresholdAuditEntry &entry) {
                                     return entry.reason == "Test override";
                                   });

  EXPECT_NE(manual_entry, manual_log.rend());
  EXPECT_EQ(manual_entry->operator_id, "test_admin");
  EXPECT_EQ(manual_entry->new_threshold, 150.0);

  // Clear audit log
  engine->clear_threshold_audit_log("test", entity);
  auto cleared_log = engine->get_threshold_audit_log("test", entity);
  EXPECT_TRUE(cleared_log.empty());
}

TEST_F(DynamicLearningEngineTest, EnhancedProcessAnalyzedEventWithSessions) {
  // Create a comprehensive AnalyzedEvent
  LogEntry log_entry;
  log_entry.ip_address = "10.0.0.100";
  log_entry.request_path = "/admin/dashboard";
  log_entry.request_time_s = 1.5;
  log_entry.bytes_sent = 2048;
  log_entry.parsed_timestamp_ms = base_time;

  AnalyzedEvent event(log_entry);
  event.ip_hist_error_rate_mean = 0.05;
  event.ip_hist_req_vol_mean = 10.0;
  event.current_ip_request_count_in_window = 25;
  event.current_ip_failed_login_count_in_window = 3;
  event.path_hist_req_time_mean = 1.2;
  event.path_hist_bytes_mean = 1500.0;
  event.path_hist_error_rate_mean = 0.02;

  // Create session state
  PerSessionState session_state;
  session_state.request_count = 15;
  session_state.failed_login_attempts = 2;
  session_state.error_4xx_count = 1;
  session_state.error_5xx_count = 0;
  event.raw_session_state = session_state;

  // Process the event
  engine->process_analyzed_event(event);

  // Verify that baselines were created for all entity types
  auto ip_request_time_baseline =
      engine->get_baseline("ip_request_time", "10.0.0.100");
  auto ip_bytes_baseline = engine->get_baseline("ip_bytes", "10.0.0.100");
  auto path_request_time_baseline =
      engine->get_baseline("path_request_time", "/admin/dashboard");
  auto session_request_count_baseline =
      engine->get_baseline("session_request_count", "10.0.0.100");

  EXPECT_NE(ip_request_time_baseline, nullptr);
  EXPECT_NE(ip_bytes_baseline, nullptr);
  EXPECT_NE(path_request_time_baseline, nullptr);
  EXPECT_NE(session_request_count_baseline, nullptr);

  // Verify security-critical marking for admin path
  EXPECT_TRUE(engine->is_entity_security_critical("path_request_time",
                                                  "/admin/dashboard"));
  EXPECT_TRUE(engine->is_entity_security_critical("path_error_rate",
                                                  "/admin/dashboard"));

  // Verify security-critical marking for high failed login count IP
  EXPECT_TRUE(
      engine->is_entity_security_critical("ip_failed_logins", "10.0.0.100"));
  EXPECT_TRUE(
      engine->is_entity_security_critical("ip_request_count", "10.0.0.100"));

  // Verify baseline values
  EXPECT_GT(ip_request_time_baseline->statistics.get_sample_count(), 0);
  EXPECT_GT(session_request_count_baseline->statistics.get_sample_count(), 0);
}

TEST_F(DynamicLearningEngineTest, ThresholdChangeValidationAndRejection) {
  std::string entity = "validation_test";

  // Establish stable baseline
  for (int i = 0; i < 200; ++i) {
    engine->process_event("test", entity, 100.0 + (i % 5),
                          base_time + i * 1000);
  }

  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);
  ASSERT_TRUE(baseline->is_established);

  // Mark as security critical with tight constraints
  engine->mark_entity_as_security_critical("test", entity, 5.0);

  double original_threshold =
      engine->get_entity_threshold("test", entity, 0.95);

  // Test gradual, acceptable updates
  bool success1 = engine->update_baseline_with_threshold_check(
      "test", entity, 103.0, base_time + 201 * 1000);
  EXPECT_TRUE(success1);

  // Test large change that should trigger warning but not rejection (for
  // automatic updates)
  bool success2 = engine->update_baseline_with_threshold_check(
      "test", entity, 200.0, base_time + 202 * 1000);
  EXPECT_TRUE(success2); // Automatic updates always succeed but log warnings

  // However, manual overrides should be rejected for large changes
  bool manual_reject = engine->set_manual_override_with_validation(
      "test", entity, 500.0, "admin", "Large manual change");
  EXPECT_FALSE(manual_reject);

  // But reasonable manual override should work
  double reasonable_override = original_threshold * 1.04; // 4% change
  bool manual_success = engine->set_manual_override_with_validation(
      "test", entity, reasonable_override, "admin", "Reasonable change");
  EXPECT_TRUE(manual_success);
}

TEST(DynamicLearningEngineTestConfig, SeasonalPatternDetectionAndConfidence) {
  Config::DynamicLearningConfig config;
  config.min_samples_for_seasonal_pattern = 1;
  config.min_samples_for_learning = 1;
  auto engine = std::make_unique<DynamicLearningEngine>(config);
  std::string entity = "seasonal_test";
  uint64_t base_time = 1720000000000;
  for (int day = 0; day < 10; ++day) {
    for (int hour = 0; hour < 24; ++hour) {
      double value = (hour == 12) ? 200.0 : 50.0;
      uint64_t ts = base_time + (day * 24 + hour) * 3600 * 1000;
      engine->process_event("test", entity, value, ts);
    }
  }
  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);
  baseline->seasonal_model.update_pattern();
  EXPECT_TRUE(baseline->seasonal_model.is_pattern_established());
  double confidence =
      baseline->seasonal_model.get_current_pattern().confidence_score;
  EXPECT_GT(confidence, 0.7);
  time_t t = base_time / 1000;
  struct tm tmval;
  localtime_r(&t, &tmval);
  tmval.tm_hour = 12;
  uint64_t ts12 = mktime(&tmval) * 1000;
  tmval.tm_hour = 0;
  uint64_t ts0 = mktime(&tmval) * 1000;
  double factor12 = baseline->seasonal_model.get_seasonal_factor(ts12);
  double factor0 = baseline->seasonal_model.get_seasonal_factor(ts0);
  EXPECT_GT(factor12, factor0);
}

TEST(DynamicLearningEngineTestConfig, TimeContextualBaselinesHourlyDaily) {
  Config::DynamicLearningConfig config;
  config.min_samples_for_seasonal_pattern = 1;
  config.min_samples_for_learning = 1;
  auto engine = std::make_unique<DynamicLearningEngine>(config);
  std::string entity = "contextual_test";
  uint64_t base_time = 1720000000000;
  for (int i = 0; i < 50; ++i) {
    time_t t = base_time / 1000;
    struct tm tmval;
    localtime_r(&t, &tmval);
    tmval.tm_hour = 3;
    tmval.tm_wday = 2;
    uint64_t ts = mktime(&tmval) * 1000 + i * 24 * 3600 * 1000;
    engine->process_event("test", entity, 100.0, ts);
  }
  for (int i = 0; i < 50; ++i) {
    time_t t = base_time / 1000;
    struct tm tmval;
    localtime_r(&t, &tmval);
    tmval.tm_hour = 15;
    tmval.tm_wday = 5;
    uint64_t ts = mktime(&tmval) * 1000 + i * 24 * 3600 * 1000;
    engine->process_event("test", entity, 200.0, ts);
  }
  int hour = 3;
  auto hourly_baseline = engine->get_contextual_baseline(
      "test", entity, DynamicLearningEngine::TimeContext::HOURLY, hour);
  ASSERT_NE(hourly_baseline, nullptr);
  EXPECT_TRUE(hourly_baseline->is_established);
  EXPECT_NEAR(hourly_baseline->statistics.get_mean(), 100.0, 1e-2);
  int day = 5;
  auto daily_baseline = engine->get_contextual_baseline(
      "test", entity, DynamicLearningEngine::TimeContext::DAILY, day);
  ASSERT_NE(daily_baseline, nullptr);
  EXPECT_TRUE(daily_baseline->is_established);
  EXPECT_NEAR(daily_baseline->statistics.get_mean(), 200.0, 1e-2);
}

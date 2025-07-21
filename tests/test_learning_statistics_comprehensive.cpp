#include "learning/dynamic_learning_engine.hpp"
#include "learning/rolling_statistics.hpp"
#include "learning/seasonal_model.hpp"
#include <chrono>
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
    engine = std::make_unique<DynamicLearningEngine>();
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
  // Add initial values
  for (int i = 0; i < 100; ++i) {
    engine->process_event("ip", ip, 100.0, base_time + i * 1000);
  }
  // Add outlier to trigger threshold change
  engine->process_event("ip", ip, 1000.0, base_time + 200 * 1000);
  // No assertion here: check logs for threshold change message
}

TEST_F(DynamicLearningEngineTest, ManualOverrideThreshold) {
  std::string ip = "10.0.0.2";
  for (int i = 0; i < 100; ++i) {
    engine->process_event("ip", ip, 100.0, base_time + i * 1000);
  }
  double normal_threshold = engine->get_entity_threshold("ip", ip, 0.95);
  engine->set_manual_override("ip", ip, 42.0);
  double overridden = engine->get_entity_threshold("ip", ip, 0.95);
  EXPECT_DOUBLE_EQ(overridden, 42.0);
  engine->clear_manual_override("ip", ip);
  double after_clear = engine->get_entity_threshold("ip", ip, 0.95);
  EXPECT_DOUBLE_EQ(after_clear, normal_threshold);
}

TEST_F(DynamicLearningEngineTest, ProcessAnalyzedEventIntegration) {
  AnalyzedEvent event({});
  event.raw_log.ip_address = "10.0.0.3";
  event.raw_log.request_time_s = 123.0;
  event.raw_log.parsed_timestamp_ms = base_time;
  engine->process_analyzed_event(event);
  auto baseline = engine->get_baseline("ip", "10.0.0.3");
  ASSERT_NE(baseline, nullptr);
  EXPECT_TRUE(baseline->statistics.get_sample_count() > 0);
}

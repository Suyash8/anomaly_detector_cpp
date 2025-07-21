#include "learning/dynamic_learning_engine.hpp"
#include "learning/rolling_statistics.hpp"
#include "learning/seasonal_model.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace learning;

TEST(RollingStatisticsTest, EWMAConvergence) {
  RollingStatistics stats(0.1, 100);
  for (int i = 0; i < 1000; ++i) {
    stats.add_value(10.0, i * 1000);
  }
  EXPECT_NEAR(stats.get_mean(), 10.0, 0.1);
}

TEST(RollingStatisticsTest, PercentileAccuracy) {
  RollingStatistics stats(0.2, 1000);
  for (int i = 0; i < 1000; ++i) {
    stats.add_value(i, i * 1000);
  }
  EXPECT_NEAR(stats.get_percentile(0.5), 499.5, 5.0);
  EXPECT_NEAR(stats.get_percentile(0.95), 950, 10.0);
}

TEST(RollingStatisticsTest, ConfidenceInterval) {
  RollingStatistics stats(0.1, 1000);
  std::mt19937 gen(42);
  std::normal_distribution<> dist(50.0, 10.0);
  for (int i = 0; i < 1000; ++i) {
    stats.add_value(dist(gen), i * 1000);
  }
  auto [lower, upper] = stats.get_confidence_interval(0.95);
  EXPECT_LT(lower, stats.get_mean());
  EXPECT_GT(upper, stats.get_mean());
  EXPECT_GT(upper - lower, 0.0); // Only require positive interval
}

TEST(SeasonalModelTest, PatternEstablishment) {
  SeasonalModel model(100);
  uint64_t base = 1720000000000;
  for (int i = 0; i < 200; ++i) {
    model.add_observation(10.0 + (i % 24), base + i * 3600000);
  }
  model.update_pattern();
  EXPECT_TRUE(model.is_pattern_established());
  auto pattern = model.get_current_pattern();
  EXPECT_EQ(pattern.hourly_pattern.size(), 24);
}

TEST(DynamicLearningEngineTest, BaselineLearningAndAnomaly) {
  DynamicLearningEngine engine;
  std::string ip = "1.2.3.4";
  uint64_t now = 1720000000000;
  for (int i = 0; i < 200; ++i) {
    engine.process_event("ip", ip, 100.0, now + i * 1000);
  }
  double score = 0.0;
  EXPECT_TRUE(engine.is_anomalous("ip", ip, 200.0, score));
  EXPECT_GT(score, 3.0);
}

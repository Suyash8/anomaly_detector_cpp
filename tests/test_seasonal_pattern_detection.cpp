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

class SeasonalPatternDetectionTest : public ::testing::Test {
protected:
  void SetUp() override {
    gen.seed(42);              // Fixed seed for reproducible tests
    base_time = 1720000000000; // July 2025

    // Create configuration with seasonal detection enabled
    Config::DynamicLearningConfig config;
    config.seasonal_detection_sensitivity = 0.8;
    config.min_samples_for_seasonal_pattern = 100;
    config.min_samples_for_contextual_baseline = 10;
    config.gradual_threshold_step =
        0.5; // Larger step for tests to see seasonal effects

    engine = std::make_unique<DynamicLearningEngine>(config);
  }

  std::mt19937 gen;
  uint64_t base_time;
  std::unique_ptr<DynamicLearningEngine> engine;

  // Helper to generate timestamps for specific hours
  uint64_t get_timestamp_for_hour(int day, int hour) {
    return base_time + (day * 24 + hour) * 3600000;
  }

  // Helper to generate timestamps for specific days
  uint64_t get_timestamp_for_day(int day, int hour = 12) {
    return base_time + day * 24 * 3600000 + hour * 3600000;
  }
};

TEST_F(SeasonalPatternDetectionTest, TimeOfDayPatternRecognition) {
  std::string entity = "time_of_day_test";

  // Create synthetic data with clear time-of-day pattern:
  // - High values during business hours (9-17)
  // - Low values during night hours (0-8, 18-23)
  for (int day = 0; day < 14; ++day) {
    for (int hour = 0; hour < 24; ++hour) {
      double value = (hour >= 9 && hour <= 17) ? 100.0 : 20.0;
      // Add some noise
      std::normal_distribution<> noise(0.0, 5.0);
      value += noise(gen);

      uint64_t timestamp = get_timestamp_for_hour(day, hour);
      engine->process_event("test", entity, value, timestamp);
    }
  }

  // Get baseline and verify pattern is established
  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);
  ASSERT_TRUE(baseline->is_established);

  // Force update of seasonal model
  baseline->seasonal_model.update_pattern();
  EXPECT_TRUE(baseline->seasonal_model.is_pattern_established());

  // Test thresholds at different times of day
  uint64_t business_hour = get_timestamp_for_hour(14, 12); // 12 PM
  uint64_t night_hour = get_timestamp_for_hour(14, 3);     // 3 AM

  double business_threshold =
      engine->calculate_adaptive_threshold("test", entity, business_hour, 0.95);
  double night_threshold =
      engine->calculate_adaptive_threshold("test", entity, night_hour, 0.95);

  // Business hour threshold should be higher than night threshold
  EXPECT_GT(business_threshold, night_threshold);

  // Test time context confidence
  double business_confidence =
      baseline->seasonal_model.get_time_context_confidence(business_hour);
  double night_confidence =
      baseline->seasonal_model.get_time_context_confidence(night_hour);

  // Both should have reasonable confidence after sufficient data
  EXPECT_GT(business_confidence, 0.5);
  EXPECT_GT(night_confidence, 0.5);
}

TEST_F(SeasonalPatternDetectionTest, DayOfWeekPatternRecognition) {
  std::string entity = "day_of_week_test";

  // Create synthetic data with clear day-of-week pattern:
  // - High values on weekdays (1-5)
  // - Low values on weekends (0, 6)
  // Generate enough data to establish pattern (need 100+ samples)
  for (int week = 0; week < 20; ++week) {
    for (int day = 0; day < 7; ++day) {
      double value = (day >= 1 && day <= 5) ? 100.0 : 30.0;
      // Add some noise
      std::normal_distribution<> noise(0.0, 5.0);
      value += noise(gen);

      uint64_t timestamp = get_timestamp_for_day(week * 7 + day);
      engine->process_event("test", entity, value, timestamp);
    }
  }

  // Get baseline and verify pattern is established
  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);
  ASSERT_TRUE(baseline->is_established);

  // Force update of seasonal model
  baseline->seasonal_model.update_pattern();
  EXPECT_TRUE(baseline->seasonal_model.is_pattern_established());

  // Test thresholds on different days of week
  // Monday (day 1)
  uint64_t monday = get_timestamp_for_day(15); // Some Monday
  // Sunday (day 0)
  uint64_t sunday = get_timestamp_for_day(14); // Some Sunday

  double weekday_threshold =
      engine->calculate_adaptive_threshold("test", entity, monday, 0.95);
  double weekend_threshold =
      engine->calculate_adaptive_threshold("test", entity, sunday, 0.95);

  // Weekday threshold should be higher than weekend threshold
  EXPECT_GT(weekday_threshold, weekend_threshold);
}

TEST_F(SeasonalPatternDetectionTest, MultipleBaselineModels) {
  std::string entity = "multiple_baselines_test";

  // Create synthetic data with both time-of-day and day-of-week patterns
  for (int week = 0; week < 4; ++week) {
    for (int day = 0; day < 7; ++day) {
      for (int hour = 0; hour < 24; ++hour) {
        // Base value depends on weekday/weekend
        double base_value = (day >= 1 && day <= 5) ? 100.0 : 50.0;

        // Adjust for time of day
        if (hour >= 9 && hour <= 17) {
          base_value *= 1.5; // Higher during business hours
        } else if (hour >= 0 && hour <= 5) {
          base_value *= 0.5; // Lower during night
        }

        // Add some noise
        std::normal_distribution<> noise(0.0, base_value * 0.1);
        double value = base_value + noise(gen);

        // Create proper timestamp using mktime to avoid timezone issues
        time_t base_t = base_time / 1000;
        struct tm tm_data;
        localtime_r(&base_t, &tm_data);
        tm_data.tm_mday += (week * 7 + day); // Add total days
        tm_data.tm_hour = hour;              // Set specific hour
        tm_data.tm_min = 0;
        tm_data.tm_sec = 0;
        uint64_t timestamp = mktime(&tm_data) * 1000;
        engine->process_event("test", entity, value, timestamp);
      }
    }
  }

  // Get baseline and verify pattern is established
  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);
  ASSERT_TRUE(baseline->is_established);

  // Force update of seasonal model
  baseline->seasonal_model.update_pattern();
  EXPECT_TRUE(baseline->seasonal_model.is_pattern_established());

  // Test contextual baselines
  // Create proper timestamps using mktime like the test validation expects
  time_t base_t = base_time / 1000;
  struct tm tm_monday, tm_sunday, tm_monday_night;

  // Monday at 12 PM
  localtime_r(&base_t, &tm_monday);
  tm_monday.tm_mday +=
      1; // Move to Monday (assuming base_time is around Sunday)
  tm_monday.tm_hour = 12;
  tm_monday.tm_min = 0;
  tm_monday.tm_sec = 0;
  uint64_t monday_noon = mktime(&tm_monday) * 1000;

  // Sunday at 12 PM
  localtime_r(&base_t, &tm_sunday);
  tm_sunday.tm_mday += 6; // Move to next Sunday
  tm_sunday.tm_hour = 12;
  tm_sunday.tm_min = 0;
  tm_sunday.tm_sec = 0;
  uint64_t sunday_noon = mktime(&tm_sunday) * 1000;

  // Monday at 3 AM
  localtime_r(&base_t, &tm_monday_night);
  tm_monday_night.tm_mday += 1; // Move to Monday
  tm_monday_night.tm_hour = 3;
  tm_monday_night.tm_min = 0;
  tm_monday_night.tm_sec = 0;
  uint64_t monday_night = mktime(&tm_monday_night) * 1000;

  // Extract time context values manually for testing
  time_t t = monday_noon / 1000;
  struct tm tmval;
  localtime_r(&t, &tmval);
  int hour_value = tmval.tm_hour;
  EXPECT_EQ(hour_value, 12);

  // Get contextual baselines
  auto monday_noon_baseline = engine->get_contextual_baseline(
      "test", entity, DynamicLearningEngine::TimeContext::HOURLY, 12);
  auto monday_night_baseline = engine->get_contextual_baseline(
      "test", entity, DynamicLearningEngine::TimeContext::HOURLY, 3);

  ASSERT_NE(monday_noon_baseline, nullptr);
  ASSERT_NE(monday_night_baseline, nullptr);

  // Verify contextual baselines have different values
  if (monday_noon_baseline->is_established &&
      monday_night_baseline->is_established) {
    double noon_mean = monday_noon_baseline->statistics.get_mean();
    double night_mean = monday_night_baseline->statistics.get_mean();
    EXPECT_GT(noon_mean, night_mean);
  }

  // Test time-based threshold calculation
  double monday_noon_threshold =
      engine->calculate_time_based_threshold("test", entity, monday_noon, 0.95);
  double sunday_noon_threshold =
      engine->calculate_time_based_threshold("test", entity, sunday_noon, 0.95);
  double monday_night_threshold = engine->calculate_time_based_threshold(
      "test", entity, monday_night, 0.95);

  // Verify thresholds reflect patterns
  EXPECT_GT(monday_noon_threshold, monday_night_threshold);
  EXPECT_GT(monday_noon_threshold, sunday_noon_threshold);
}

TEST_F(SeasonalPatternDetectionTest, GradualThresholdAdjustment) {
  std::string entity = "gradual_adjustment_test";

  // First establish a baseline with consistent values
  for (int i = 0; i < 200; ++i) {
    engine->process_event("test", entity, 100.0, base_time + i * 1000);
  }

  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);
  ASSERT_TRUE(baseline->is_established);

  // Test the apply_gradual_threshold_adjustment method directly
  double current = 100.0;
  double target = 200.0;
  double adjusted =
      engine->apply_gradual_threshold_adjustment(current, target, 0.1);

  // Should be limited to 10% change
  EXPECT_NEAR(adjusted, 110.0, 0.1);

  // Test with multiple steps
  double step1 = engine->apply_gradual_threshold_adjustment(100.0, 200.0, 0.1);
  double step2 = engine->apply_gradual_threshold_adjustment(step1, 200.0, 0.1);
  double step3 = engine->apply_gradual_threshold_adjustment(step2, 200.0, 0.1);

  EXPECT_NEAR(step1, 110.0, 0.1);
  EXPECT_NEAR(step2, 121.0, 0.1);
  EXPECT_NEAR(step3, 133.1, 0.1);
}

TEST_F(SeasonalPatternDetectionTest, PatternConfidenceScoring) {
  std::string entity = "confidence_scoring_test";

  // Create data with clear pattern
  for (int day = 0; day < 14; ++day) {
    for (int hour = 0; hour < 24; ++hour) {
      double value = 50.0 + 50.0 * sin(2.0 * M_PI * hour / 24.0);
      uint64_t timestamp = get_timestamp_for_hour(day, hour);
      engine->process_event("test", entity, value, timestamp);
    }
  }

  auto baseline = engine->get_baseline("test", entity);
  ASSERT_NE(baseline, nullptr);

  // Force update of seasonal model
  baseline->seasonal_model.update_pattern();

  // Get pattern and check confidence
  auto pattern = baseline->seasonal_model.get_current_pattern();
  EXPECT_GT(pattern.confidence_score, 0.7); // Should have high confidence

  // Check hourly confidence scores
  for (size_t i = 0; i < pattern.hourly_confidence.size(); ++i) {
    EXPECT_GT(pattern.hourly_confidence[i], 0.0);
  }

  // Check time context confidence
  uint64_t test_time = get_timestamp_for_hour(15, 12);
  double context_confidence =
      baseline->seasonal_model.get_time_context_confidence(test_time);
  EXPECT_GT(context_confidence, 0.5);

  // Now create data with random noise (no pattern)
  std::string noisy_entity = "noisy_test";
  std::uniform_real_distribution<> dist(0.0, 100.0);

  for (int i = 0; i < 500; ++i) {
    double value = dist(gen);
    uint64_t timestamp = base_time + i * 1000;
    engine->process_event("test", noisy_entity, value, timestamp);
  }

  auto noisy_baseline = engine->get_baseline("test", noisy_entity);
  ASSERT_NE(noisy_baseline, nullptr);

  // Force update of seasonal model
  noisy_baseline->seasonal_model.update_pattern();

  // Get pattern and check confidence
  auto noisy_pattern = noisy_baseline->seasonal_model.get_current_pattern();
  EXPECT_LT(noisy_pattern.confidence_score, pattern.confidence_score);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
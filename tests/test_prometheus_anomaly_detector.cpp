#include "../src/analysis/prometheus_anomaly_detector.hpp"
#include "../src/analysis/prometheus_client.hpp"

#include <gtest/gtest.h>

using analysis::PrometheusAnomalyDetector;
using analysis::PromQLRule;

TEST(PrometheusAnomalyDetector, AddAndGetRule) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9090";
  auto client = std::make_shared<PrometheusClient>(cfg);
  PrometheusAnomalyDetector detector(client);
  PromQLRule rule{"test", "up{job=\"api\"}", 1.0, ">", {}};
  EXPECT_TRUE(detector.add_rule(rule));
  auto got = detector.get_rule("test");
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->name, "test");
  EXPECT_FALSE(detector.add_rule(rule)); // duplicate
}

TEST(PrometheusAnomalyDetector, RemoveAndUpdateRule) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9090";
  auto client = std::make_shared<PrometheusClient>(cfg);
  PrometheusAnomalyDetector detector(client);
  PromQLRule rule{"test", "up{job=\"api\"}", 1.0, ">", {}};
  detector.add_rule(rule);
  EXPECT_TRUE(detector.remove_rule("test"));
  EXPECT_FALSE(detector.remove_rule("test"));
  detector.add_rule(rule);
  PromQLRule rule2 = rule;
  rule2.threshold = 2.0;
  EXPECT_TRUE(detector.update_rule(rule2));
  auto got = detector.get_rule("test");
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->threshold, 2.0);
}

TEST(PrometheusAnomalyDetector, ValidateRule) {
  PromQLRule valid{"a", "up", 1.0, ">", {}};
  PromQLRule invalid_op{"b", "up", 1.0, "BAD", {}};
  PromQLRule empty_name{"", "up", 1.0, ">", {}};
  EXPECT_TRUE(PrometheusAnomalyDetector::validate_rule(valid));
  EXPECT_FALSE(PrometheusAnomalyDetector::validate_rule(invalid_op));
  EXPECT_FALSE(PrometheusAnomalyDetector::validate_rule(empty_name));
}

#include "analysis/prometheus_anomaly_detector.hpp"
#include "analysis/prometheus_client.hpp"

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

TEST(PrometheusAnomalyDetector, TemplateSubstitution) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9090";
  auto client = std::make_shared<PrometheusClient>(cfg);
  PrometheusAnomalyDetector detector(client);

  // Single variable
  std::string templ = "sum(rate(http_requests_total{ip=\"{{ip}}\"}[5m]))";
  std::map<std::string, std::string> vars = {{"ip", "1.2.3.4"}};
  EXPECT_EQ(detector.substitute(templ, vars),
            "sum(rate(http_requests_total{ip=\"1.2.3.4\"}[5m]))");

  // Multiple variables
  templ = "foo{ip=\"{{ip}}\",path=\"{{path}}\"}";
  vars = {{"ip", "1.2.3.4"}, {"path", "/bar"}};
  EXPECT_EQ(detector.substitute(templ, vars),
            "foo{ip=\"1.2.3.4\",path=\"/bar\"}");

  // Repeated variable
  templ = "{{ip}}-{{ip}}";
  vars = {{"ip", "X"}};
  EXPECT_EQ(detector.substitute(templ, vars), "X-X");

  // Missing variable (should leave placeholder)
  templ = "foo{{missing}}bar";
  vars = {{"ip", "1.2.3.4"}};
  EXPECT_EQ(detector.substitute(templ, vars), "foo{{missing}}bar");

  // Curly braces in value
  templ = "foo{{ip}}bar";
  vars = {{"ip", "{weird}"}};
  EXPECT_EQ(detector.substitute(templ, vars), "foo{weird}bar");

  // No variables
  templ = "static_query";
  vars = {};
  EXPECT_EQ(detector.substitute(templ, vars), "static_query");
}

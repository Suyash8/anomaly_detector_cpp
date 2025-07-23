#include "analysis/prometheus_anomaly_detector.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>

using analysis::PrometheusAnomalyDetector;
using analysis::PromQLRule;

// Mock PrometheusClient for evaluation tests
class MockPrometheusClient : public PrometheusClient {
public:
  explicit MockPrometheusClient(const std::string &response,
                                bool throw_exc = false)
      : PrometheusClient(PrometheusClientConfig{"mock"}), response_(response),
        throw_exc_(throw_exc) {}
  std::string query(const std::string &) {
    if (throw_exc_)
      throw PrometheusClientError("mock error");
    return response_;
  }

private:
  std::string response_;
  bool throw_exc_;
};

TEST(PrometheusAnomalyDetector, EvaluateRuleComparisonOperators) {
  // JSON result with value 5.0
  std::string json =
      R"({"status":"success","data":{"result":[{"value":[0,"5.0"]}]}})";
  auto client = std::make_shared<MockPrometheusClient>(json);
  PrometheusAnomalyDetector detector(client);
  std::vector<std::pair<std::string, double>> ops = {{">", 4.0},  {">=", 5.0},
                                                     {"<", 6.0},  {"<=", 5.0},
                                                     {"==", 5.0}, {"!=", 4.0}};
  for (const auto &op : ops) {
    PromQLRule rule{"r", "up", op.second, op.first, {}};
    detector.add_rule(rule);
    auto res = detector.evaluate_rule("r");
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res->is_anomaly) << op.first;
    // Score should be abs(5.0 - threshold)
    EXPECT_DOUBLE_EQ(res->score, std::abs(5.0 - op.second));
    detector.remove_rule("r");
  }
  // Negative cases
  std::vector<std::pair<std::string, double>> neg_ops = {
      {">", 6.0},  {">=", 6.0}, {"<", 4.0},
      {"<=", 4.0}, {"==", 4.0}, {"!=", 5.0}};
  for (const auto &op : neg_ops) {
    PromQLRule rule{"r", "up", op.second, op.first, {}};
    detector.add_rule(rule);
    auto res = detector.evaluate_rule("r");
    ASSERT_TRUE(res.has_value());
    EXPECT_FALSE(res->is_anomaly) << op.first;
    EXPECT_DOUBLE_EQ(res->score, std::abs(5.0 - op.second));
    detector.remove_rule("r");
  }
}

TEST(PrometheusAnomalyDetector, EvaluateRuleErrors) {
  // Prometheus error
  std::string json = R"({"status":"error"})";
  auto client = std::make_shared<MockPrometheusClient>(json);
  PrometheusAnomalyDetector detector(client);
  PromQLRule rule{"r", "up", 1.0, ">", {}};
  detector.add_rule(rule);
  auto res = detector.evaluate_rule("r");
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->details, "Prometheus error");
  detector.remove_rule("r");

  // No data
  json = R"({"status":"success","data":{"result":[]}})";
  client = std::make_shared<MockPrometheusClient>(json);
  PrometheusAnomalyDetector detector2(client);
  detector2.add_rule(rule);
  res = detector2.evaluate_rule("r");
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->details, "No data");
  detector2.remove_rule("r");

  // Parse error
  json = "not a json";
  client = std::make_shared<MockPrometheusClient>(json);
  PrometheusAnomalyDetector detector3(client);
  detector3.add_rule(rule);
  res = detector3.evaluate_rule("r");
  ASSERT_TRUE(res.has_value());
  EXPECT_TRUE(res->details.find("Parse error") == 0);
  detector3.remove_rule("r");

  // Query error (exception)
  client = std::make_shared<MockPrometheusClient>("", true);
  PrometheusAnomalyDetector detector4(client);
  detector4.add_rule(rule);
  res = detector4.evaluate_rule("r");
  ASSERT_TRUE(res.has_value());
  EXPECT_TRUE(res->details.find("Query error") == 0);
  detector4.remove_rule("r");

  // Invalid operator
  PromQLRule bad_op{"bad", "up", 1.0, "BAD", {}};
  detector4.add_rule(bad_op);
  res = detector4.evaluate_rule("bad");
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(res->details, "Invalid comparison operator");
  detector4.remove_rule("bad");
}

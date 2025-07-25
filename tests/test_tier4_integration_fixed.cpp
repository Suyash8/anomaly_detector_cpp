#include "analysis/analyzed_event.hpp"
#include "analysis/prometheus_anomaly_detector.hpp"
#include "analysis/prometheus_client.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "detection/rule_engine.hpp"
#include "models/model_manager.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>

using analysis::PrometheusAnomalyDetector;
using analysis::PromQLRule;

// Enhanced Mock PrometheusClient for integration tests
class MockPrometheusClientIntegration : public PrometheusClient {
public:
  explicit MockPrometheusClientIntegration(
      const PrometheusClientConfig &config = PrometheusClientConfig{"mock"})
      : PrometheusClient(config), query_count_(0), failure_mode_(false) {}

  std::string query(const std::string &promql) override {
    query_count_++;
    last_query_ = promql;

    if (failure_mode_) {
      throw PrometheusClientError("Mock failure for testing");
    }

    // Return different responses based on query content for testing
    if (promql.find("test_metric_high") != std::string::npos) {
      // High value that should trigger anomaly
      return R"({"status":"success","data":{"result":[{"value":[0,"150.0"]}]}})";
    } else if (promql.find("test_metric_low") != std::string::npos) {
      // Low value that should not trigger anomaly
      return R"({"status":"success","data":{"result":[{"value":[0,"2.0"]}]}})";
    } else if (promql.find("test_metric_variable") != std::string::npos) {
      // Variable response based on query count (for dynamic testing)
      double value = (query_count_ % 2 == 0) ? 100.0 : 5.0;
      return R"({"status":"success","data":{"result":[{"value":[0,")" +
             std::to_string(value) + R"("]}]}})";
    } else if (promql.find("test_metric_empty") != std::string::npos) {
      // Empty result
      return R"({"status":"success","data":{"result":[]}})";
    } else {
      // Default low value
      return R"({"status":"success","data":{"result":[{"value":[0,"3.0"]}]}})";
    }
  }

  // Test helpers
  void set_failure_mode(bool enabled) { failure_mode_ = enabled; }
  int get_query_count() const { return query_count_; }
  std::string get_last_query() const { return last_query_; }
  void reset_counters() {
    query_count_ = 0;
    last_query_.clear();
  }

private:
  int query_count_;
  std::string last_query_;
  bool failure_mode_;
};

class Tier4IntegrationTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Set up base configuration

    // Enable Tier 4
    config_.tier4.enabled = true;
    config_.tier4.prometheus_url = "http://mock:9090";
    config_.tier4.query_timeout_seconds = 5;
    config_.tier4.evaluation_interval_seconds = 10;

    // Set up other required configs
    config_.alert_output_path = "/tmp/test_alerts.log";
    config_.file_dispatcher_enabled = true;

    // Create alert manager
    alert_manager_ = std::make_unique<AlertManager>();
    alert_manager_->reconfigure(config_);

    // Create model manager with config
    model_manager_ = std::make_shared<ModelManager>(config_);

    // Create rule engine
    rule_engine_ =
        std::make_unique<RuleEngine>(*alert_manager_, config_, model_manager_);
  }

  void TearDown() override {
    rule_engine_.reset();
    alert_manager_.reset();
    model_manager_.reset();
  }

  // Helper function to create test AnalyzedEvent
  AnalyzedEvent create_test_event(const std::string &ip = "192.168.1.100",
                                  const std::string &path = "/test") {
    LogEntry log_entry;
    log_entry.timestamp_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    log_entry.client_ip = ip;
    log_entry.path = path;
    log_entry.session_id = "test_session";
    log_entry.user_agent = "test_agent";
    log_entry.method = "GET";
    log_entry.status_code = 200;
    log_entry.response_bytes = 1024;
    log_entry.request_time_ms = 100;

    return AnalyzedEvent(log_entry);
  }

  Config::AppConfig config_;
  std::unique_ptr<AlertManager> alert_manager_;
  std::shared_ptr<ModelManager> model_manager_;
  std::unique_ptr<RuleEngine> rule_engine_;
};

TEST_F(Tier4IntegrationTest, Tier4DetectorInitialization) {
  // Create mock client
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();

  // Create Tier 4 detector
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);

  // Set detector on rule engine
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add some test rules
  PromQLRule rule1{"high_cpu_usage",
                   "rate(cpu_usage_total[5m])",
                   100.0,
                   ">",
                   {{"severity", "high"}}};

  PromQLRule rule2{"low_memory",
                   "memory_available_bytes",
                   1000000.0,
                   "<",
                   {{"severity", "medium"}}};

  ASSERT_TRUE(tier4_detector->add_rule(rule1));
  ASSERT_TRUE(tier4_detector->add_rule(rule2));

  // Verify rules were added
  auto rule1_result = tier4_detector->get_rule("high_cpu_usage");
  auto rule2_result = tier4_detector->get_rule("low_memory");
  EXPECT_TRUE(rule1_result.has_value());
  EXPECT_TRUE(rule2_result.has_value());
}

TEST_F(Tier4IntegrationTest, Tier4RuleEvaluationInRuleEngine) {
  // Create mock client with specific responses
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add rules that will trigger based on our mock responses
  PromQLRule high_rule{"test_high_metric",
                       "test_metric_high",
                       100.0,
                       ">",
                       {{"tier", "4"}, {"test", "high"}}};

  PromQLRule low_rule{"test_low_metric",
                      "test_metric_low",
                      10.0,
                      ">",
                      {{"tier", "4"}, {"test", "low"}}};

  ASSERT_TRUE(tier4_detector->add_rule(high_rule));
  ASSERT_TRUE(tier4_detector->add_rule(low_rule));

  // Create test analyzed event
  auto event = create_test_event();

  // Reset query counter
  mock_client->reset_counters();

  // Evaluate rules (this should trigger Tier 4 evaluation)
  rule_engine_->evaluate_rules(event);

  // Verify that Prometheus queries were made
  EXPECT_GT(mock_client->get_query_count(), 0);

  // Wait a bit for alert processing
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(Tier4IntegrationTest, Tier4GracefulDegradationOnFailure) {
  // Create mock client configured to fail
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  mock_client->set_failure_mode(true);

  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add a test rule
  PromQLRule rule{"test_rule", "test_metric", 50.0, ">", {{"tier", "4"}}};

  ASSERT_TRUE(tier4_detector->add_rule(rule));

  // Create test event
  auto event = create_test_event();

  // This should not throw an exception despite Prometheus failure
  EXPECT_NO_THROW(rule_engine_->evaluate_rules(event));

  // Verify query was attempted
  EXPECT_GT(mock_client->get_query_count(), 0);
}

TEST_F(Tier4IntegrationTest, Tier4MetricsTracking) {
  // This test would require metrics exporter, but we can test basic
  // functionality
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add rules
  PromQLRule rule1{
      "variable_metric", "test_metric_variable", 50.0, ">", {{"tier", "4"}}};

  ASSERT_TRUE(tier4_detector->add_rule(rule1));

  // Create test event
  auto event = create_test_event();

  mock_client->reset_counters();

  // Evaluate multiple times to test metrics tracking
  for (int i = 0; i < 5; ++i) {
    rule_engine_->evaluate_rules(event);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  // Verify multiple queries were made
  EXPECT_GE(mock_client->get_query_count(), 5);
}

TEST_F(Tier4IntegrationTest, Tier4DisabledConfiguration) {
  // Disable Tier 4 in configuration
  config_.tier4.enabled = false;

  // Recreate rule engine with disabled Tier 4
  rule_engine_ =
      std::make_unique<RuleEngine>(*alert_manager_, config_, model_manager_);

  // Create mock client and detector
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add rule
  PromQLRule rule{"test_rule", "test_metric", 50.0, ">", {{"tier", "4"}}};

  ASSERT_TRUE(tier4_detector->add_rule(rule));

  // Create test event
  auto event = create_test_event();

  mock_client->reset_counters();

  // Evaluate rules - should not execute Tier 4 due to disabled config
  rule_engine_->evaluate_rules(event);

  // Since Tier 4 is disabled, no Prometheus queries should be made
  EXPECT_EQ(mock_client->get_query_count(), 0);
}

TEST_F(Tier4IntegrationTest, Tier4EmptyRuleSetHandling) {
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Don't add any rules - test empty rule set

  // Create test event
  auto event = create_test_event();

  mock_client->reset_counters();

  // Should handle empty rule set gracefully
  EXPECT_NO_THROW(rule_engine_->evaluate_rules(event));

  // No queries should be made with empty rule set
  EXPECT_EQ(mock_client->get_query_count(), 0);
}

TEST_F(Tier4IntegrationTest, Tier4TemplateSubstitution) {
  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add rule with template variables
  PromQLRule rule{
      "template_rule",
      "rate(http_requests_total{ip=\"${ip}\", path=\"${path}\"}[5m])",
      10.0,
      ">",
      {{"tier", "4"}}};

  ASSERT_TRUE(tier4_detector->add_rule(rule));

  // Create test event with specific values
  auto event = create_test_event("192.168.1.200", "/api/test");

  mock_client->reset_counters();

  rule_engine_->evaluate_rules(event);

  // Verify query was made and template substitution occurred
  EXPECT_GT(mock_client->get_query_count(), 0);
  std::string last_query = mock_client->get_last_query();
  EXPECT_TRUE(last_query.find("192.168.1.200") != std::string::npos);
  EXPECT_TRUE(last_query.find("/api/test") != std::string::npos);
}

TEST_F(Tier4IntegrationTest, Tier4PerformanceTimeout) {
  // Configure shorter timeout for testing
  config_.tier4.query_timeout_seconds = 1;
  rule_engine_ =
      std::make_unique<RuleEngine>(*alert_manager_, config_, model_manager_);

  auto mock_client = std::make_shared<MockPrometheusClientIntegration>();
  auto tier4_detector =
      std::make_shared<PrometheusAnomalyDetector>(mock_client);
  rule_engine_->set_tier4_anomaly_detector(tier4_detector);

  // Add rule
  PromQLRule rule{"timeout_rule", "test_metric", 50.0, ">", {{"tier", "4"}}};

  ASSERT_TRUE(tier4_detector->add_rule(rule));

  // Create test event
  auto event = create_test_event();

  // Measure execution time
  auto start = std::chrono::high_resolution_clock::now();
  rule_engine_->evaluate_rules(event);
  auto end = std::chrono::high_resolution_clock::now();

  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  // Should complete quickly (well under timeout, which is 1 second = 1000ms)
  EXPECT_LT(duration.count(), 500); // Should be much faster than 500ms
}

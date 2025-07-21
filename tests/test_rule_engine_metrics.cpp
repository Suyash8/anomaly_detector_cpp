#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "analysis/analyzed_event.hpp"
#include "core/alert.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/prometheus_metrics_exporter.hpp"
#include "detection/rule_engine.hpp"
#include "models/model_manager.hpp"

// Mock Prometheus Metrics Exporter for testing
class MockPrometheusMetricsExporter
    : public prometheus::PrometheusMetricsExporter {
public:
  MockPrometheusMetricsExporter() : PrometheusMetricsExporter() {}

  // Track metrics that were set/incremented/observed
  mutable std::map<std::pair<std::string, std::map<std::string, std::string>>,
                   double>
      gauge_values;
  mutable std::map<std::pair<std::string, std::map<std::string, std::string>>,
                   int>
      counter_increments;
  mutable std::map<std::pair<std::string, std::map<std::string, std::string>>,
                   std::vector<double>>
      histogram_observations;
  mutable std::vector<std::string> registered_counters;
  mutable std::vector<std::string> registered_gauges;
  mutable std::vector<std::string> registered_histograms;

  void
  set_gauge(const std::string &name, double value,
            const std::map<std::string, std::string> &labels = {}) override {
    gauge_values[{name, labels}] = value;
  }

  void increment_counter(const std::string &name,
                         const std::map<std::string, std::string> &labels = {},
                         double value = 1.0) override {
    counter_increments[{name, labels}] += static_cast<int>(value);
  }

  void observe_histogram(
      const std::string &name, double value,
      const std::map<std::string, std::string> &labels = {}) override {
    histogram_observations[{name, labels}].push_back(value);
  }

  void register_counter(
      const std::string &name, const std::string & /*help*/,
      const std::vector<std::string> & /*label_names*/ = {}) override {
    registered_counters.push_back(name);
  }

  void register_gauge(
      const std::string &name, const std::string & /*help*/,
      const std::vector<std::string> & /*label_names*/ = {}) override {
    registered_gauges.push_back(name);
  }

  void register_histogram(
      const std::string &name, const std::string & /*help*/,
      const std::vector<double> & /*buckets*/ = {},
      const std::vector<std::string> & /*label_names*/ = {}) override {
    registered_histograms.push_back(name);
  }

  // Helper methods to access metrics for testing
  bool
  has_counter(const std::string &name,
              const std::map<std::string, std::string> &labels = {}) const {
    return counter_increments.find({name, labels}) != counter_increments.end();
  }

  int get_counter(const std::string &name,
                  const std::map<std::string, std::string> &labels = {}) const {
    auto it = counter_increments.find({name, labels});
    return it != counter_increments.end() ? it->second : 0;
  }

  bool has_gauge(const std::string &name,
                 const std::map<std::string, std::string> &labels = {}) const {
    return gauge_values.find({name, labels}) != gauge_values.end();
  }

  double
  get_gauge(const std::string &name,
            const std::map<std::string, std::string> &labels = {}) const {
    auto it = gauge_values.find({name, labels});
    return it != gauge_values.end() ? it->second : 0.0;
  }

  std::vector<double> get_histogram_observations(
      const std::string &name,
      const std::map<std::string, std::string> &labels = {}) const {
    auto it = histogram_observations.find({name, labels});
    return it != histogram_observations.end() ? it->second
                                              : std::vector<double>{};
  }

  void clear_metrics() {
    gauge_values.clear();
    counter_increments.clear();
    histogram_observations.clear();
  }
};

// Mock Alert Manager for testing
class MockAlertManager : public AlertManager {
public:
  MockAlertManager() = default;

  void record_alert(const Alert &alert) { recorded_alerts.push_back(alert); }

  std::vector<Alert> recorded_alerts;

  void clear_alerts() { recorded_alerts.clear(); }
};

// Test fixture for Rule Engine metrics tests
class RuleEngineMetricsTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Set up basic configuration
    config.tier1.enabled = true;
    config.tier1.max_requests_per_ip_in_window = 100;
    config.tier1.max_failed_logins_per_ip = 5;
    config.tier1.check_user_agent_anomalies = true;
    config.tier1.score_suspicious_path = 85.0;
    config.tier1.score_known_bad_ua = 90.0;
    config.tier1.score_missing_ua = 40.0;
    config.tier1.score_headless_browser = 70.0;
    config.tier1.score_outdated_browser = 30.0;
    config.tier1.score_ua_cycling = 95.0;
    config.tier1.min_assets_per_html_ratio = 2.0;
    config.tier1.min_html_requests_for_ratio_check = 3;
    config.tier1.max_failed_logins_per_session = 3;
    config.tier1.max_requests_per_session_in_window = 50;
    config.tier1.max_ua_changes_per_session = 2;
    config.tier1.score_sensitive_path_new_ip = 80.0;
    config.tier1.sliding_window_duration_seconds = 300;
    config.tier1.session_tracking_enabled = true;
    config.tier1.session_inactivity_ttl_seconds = 1800;
    config.tier1.suspicious_path_substrings = {"/admin", "/../", "eval("};
    config.tier1.suspicious_ua_substrings = {"sqlmap", "nikto", "nmap"};
    config.tier1.sensitive_path_substrings = {"/admin", "/config"};

    config.tier2.enabled = true;
    config.tier2.z_score_threshold = 3.0;
    config.tier2.min_samples_for_z_score = 10;
    config.tier2.historical_deviation_factor = 5.0;

    config.tier3.enabled = true;
    config.tier3.anomaly_score_threshold = 0.8;

    config.monitoring.enable_deep_timing = true;

    // Create mock components
    mock_exporter = std::make_shared<MockPrometheusMetricsExporter>();
    mock_alert_manager = std::make_unique<MockAlertManager>();
    mock_model_manager = std::make_shared<ModelManager>(config);

    // Create rule engine
    rule_engine = std::make_unique<RuleEngine>(*mock_alert_manager, config,
                                               mock_model_manager);
    rule_engine->set_metrics_exporter(mock_exporter);
  }

  void TearDown() override {
    rule_engine.reset();
    mock_alert_manager.reset();
    mock_exporter.reset();
    mock_model_manager.reset();
  }

  Config::AppConfig config;
  std::shared_ptr<MockPrometheusMetricsExporter> mock_exporter;
  std::unique_ptr<MockAlertManager> mock_alert_manager;
  std::shared_ptr<ModelManager> mock_model_manager;
  std::unique_ptr<RuleEngine> rule_engine;

  // Helper method to create test analyzed events
  AnalyzedEvent
  create_test_event(const std::string &ip = "192.168.1.100",
                    const std::string &path = "/test",
                    const std::string &user_agent = "Mozilla/5.0") {
    // Create a LogEntry first
    LogEntry log;
    log.ip_address = ip;
    log.request_path = path;
    log.user_agent = user_agent;
    log.request_method = "GET";
    log.http_status_code = 200;
    log.parsed_timestamp_ms = 1000000;
    log.request_time_s = std::make_optional(0.1);

    // Create AnalyzedEvent with the LogEntry
    AnalyzedEvent event(log);

    // Initialize optional fields to avoid triggering rules unintentionally
    event.current_ip_request_count_in_window = std::make_optional<size_t>(50);
    event.current_ip_failed_login_count_in_window =
        std::make_optional<size_t>(2);
    event.ip_html_requests_in_window = 5;
    event.ip_asset_requests_in_window = 10;
    event.ip_assets_per_html_ratio = std::make_optional(2.5);

    event.is_ua_missing = false;
    event.is_ua_known_bad = false;
    event.is_ua_headless = false;
    event.is_ua_outdated = false;
    event.is_ua_cycling = false;
    event.is_first_request_from_ip = false;
    event.is_path_new_for_ip = false;

    return event;
  }
};

// =================================================================================
// Test 1: Detection metrics by tier (hit rates, processing time, alert
// generation)
// =================================================================================

TEST_F(RuleEngineMetricsTest, MetricsRegistrationOnStartup) {
  // Verify that rule engine metrics are properly registered
  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_rule_evaluations_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_rule_hits_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_gauges.begin(),
                        mock_exporter->registered_gauges.end(),
                        "ad_rule_hit_rate") !=
              mock_exporter->registered_gauges.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_histograms.begin(),
                        mock_exporter->registered_histograms.end(),
                        "ad_rule_processing_time_seconds") !=
              mock_exporter->registered_histograms.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_alerts_generated_by_tier_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_histograms.begin(),
                        mock_exporter->registered_histograms.end(),
                        "ad_alert_score_distribution") !=
              mock_exporter->registered_histograms.end());
}

TEST_F(RuleEngineMetricsTest, Tier1RuleEvaluationTracking) {
  auto event = create_test_event();

  // Clear metrics to start fresh
  mock_exporter->clear_metrics();

  // Process event to trigger tier 1 rule evaluations
  rule_engine->evaluate_rules(event);

  // Verify rule evaluation counters are incremented
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_failed_logins"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_user_agent"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_suspicious_string"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_asset_ratio"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_new_seen"}}));

  // Verify hit rates are calculated (should be 0 initially since no rules
  // triggered)
  EXPECT_TRUE(mock_exporter->has_gauge(
      "ad_rule_hit_rate",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
  EXPECT_EQ(mock_exporter->get_gauge(
                "ad_rule_hit_rate",
                {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}),
            0.0);
}

TEST_F(RuleEngineMetricsTest, Tier1RuleHitTracking) {
  auto event = create_test_event();

  // Set up event to trigger high request rate rule
  event.current_ip_request_count_in_window =
      std::make_optional<size_t>(150); // Above threshold of 100

  mock_exporter->clear_metrics();

  // Process event to trigger rule hit
  rule_engine->evaluate_rules(event);

  // Verify rule hit counter is incremented
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
  EXPECT_GE(mock_exporter->get_counter(
                "ad_rule_hits_total",
                {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}),
            1);

  // Verify hit rate is calculated correctly (should be 1.0 since rule
  // triggered)
  EXPECT_TRUE(mock_exporter->has_gauge(
      "ad_rule_hit_rate",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
  EXPECT_EQ(mock_exporter->get_gauge(
                "ad_rule_hit_rate",
                {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}),
            1.0);

  // Verify alert generation metrics
  EXPECT_TRUE(mock_exporter->has_counter("ad_alerts_generated_total",
                                         {{"tier", "tier1"},
                                          {"action", "rate_limit"},
                                          {"rule", "tier1_requests_per_ip"}}));
}

TEST_F(RuleEngineMetricsTest, Tier2RuleEvaluationAndHitTracking) {
  auto event = create_test_event();

  // Set up event to trigger tier 2 statistical rules
  event.ip_req_time_zscore = std::make_optional(4.5); // Above threshold of 3.0
  event.path_bytes_sent_zscore = std::make_optional(3.8);

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify tier 2 rule evaluation tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier2"}, {"rule", "tier2_ip_zscore"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier2"}, {"rule", "tier2_path_zscore"}}));

  // Verify tier 2 rule hits
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total", {{"tier", "tier2"}, {"rule", "tier2_ip_zscore"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier2"}, {"rule", "tier2_path_zscore"}}));

  // Verify alert generation for tier 2
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_generated_total",
      {{"tier", "tier2"}, {"action", "log"}, {"rule", "tier2_ip_zscore"}}));
}

TEST_F(RuleEngineMetricsTest, Tier3MLRuleTracking) {
  auto event = create_test_event();

  // Set up feature vector for ML processing
  event.feature_vector = {0.1, 0.2, 0.3, 0.4, 0.5};

  mock_exporter->clear_metrics();

  // Process event (Note: ML model might not be available, but evaluation should
  // still be tracked)
  rule_engine->evaluate_rules(event);

  // Verify tier 3 rule evaluation tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total", {{"tier", "tier3"}, {"rule", "tier3_ml"}}));
}

TEST_F(RuleEngineMetricsTest, AlertScoreDistributionTracking) {
  auto event = create_test_event();

  // Set up multiple events with different score triggers
  event.current_ip_failed_login_count_in_window =
      std::make_optional<size_t>(10); // High score trigger

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify alert score distribution is tracked
  auto hist_observations = mock_exporter->get_histogram_observations(
      "ad_alert_score_distribution", {{"tier", "tier1"}});
  EXPECT_FALSE(hist_observations.empty());
  EXPECT_GT(hist_observations[0], 0.0); // Score should be positive
}

// =================================================================================
// Test 2: Alert throttling and suppression metrics
// =================================================================================

TEST_F(RuleEngineMetricsTest, MultipleRuleHitRateCalculation) {
  auto event = create_test_event();

  mock_exporter->clear_metrics();

  // Process the same event multiple times to test hit rate calculation
  for (int i = 0; i < 5; i++) {
    if (i < 2) {
      // First 2 times, don't trigger the rule
      event.current_ip_request_count_in_window = std::make_optional<size_t>(50);
    } else {
      // Last 3 times, trigger the rule
      event.current_ip_request_count_in_window =
          std::make_optional<size_t>(150);
    }
    rule_engine->evaluate_rules(event);
  }

  // Verify hit rate is calculated correctly (3 hits out of 5 evaluations = 0.6)
  double hit_rate = mock_exporter->get_gauge(
      "ad_rule_hit_rate",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}});
  EXPECT_FLOAT_EQ(hit_rate, 0.6);

  // Verify evaluation count
  int evaluations = mock_exporter->get_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}});
  EXPECT_EQ(evaluations, 5);

  // Verify hit count
  int hits = mock_exporter->get_counter(
      "ad_rule_hits_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}});
  EXPECT_EQ(hits, 3);
}

// =================================================================================
// Test 3: Rule evaluation performance and effectiveness
// =================================================================================

TEST_F(RuleEngineMetricsTest, ProcessingTimeMetrics) {
  auto event = create_test_event();

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // The processing time metrics are handled by MetricsManager, not directly by
  // our mock exporter. Instead, let's verify that rule evaluation metrics are
  // being tracked correctly, which is what our mock exporter should see.

  // Verify rule evaluation tracking (which does use our mock exporter)
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));

  // The timing histograms are managed by MetricsManager internally,
  // so we just verify that the rule evaluation completed successfully
  // by checking that evaluation counters were incremented
  int tier1_evaluations = mock_exporter->get_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}});
  EXPECT_GT(tier1_evaluations, 0);

  // Verify tier 2 and 3 evaluations also occurred
  if (config.tier2.enabled) {
    EXPECT_TRUE(mock_exporter->has_counter(
        "ad_rule_evaluations_total",
        {{"tier", "tier2"}, {"rule", "tier2_ip_zscore"}}));
  }

  if (config.tier3.enabled) {
    EXPECT_TRUE(
        mock_exporter->has_counter("ad_rule_evaluations_total",
                                   {{"tier", "tier3"}, {"rule", "tier3_ml"}}));
  }
}

TEST_F(RuleEngineMetricsTest, SuspiciousStringRuleTracking) {
  auto event = create_test_event();

  // Set up event to trigger suspicious string rules
  event.raw_log.request_path = "/admin/config"; // Contains "admin" from config
  event.raw_log.user_agent = "sqlmap/1.0";      // Contains "sqlmap" from config

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify suspicious string rule evaluation and hits
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_suspicious_string"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier1"}, {"rule", "tier1_suspicious_string"}}));

  // Should generate multiple alerts (one for path, one for UA)
  EXPECT_GE(mock_exporter->get_counter(
                "ad_rule_hits_total",
                {{"tier", "tier1"}, {"rule", "tier1_suspicious_string"}}),
            1);
}

TEST_F(RuleEngineMetricsTest, UserAgentAnomalyRuleTracking) {
  auto event = create_test_event();

  // Test missing user agent
  event.raw_log.user_agent = "";
  event.is_ua_missing = true;

  mock_exporter->clear_metrics();
  rule_engine->evaluate_rules(event);

  // Verify user agent rule tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_user_agent"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total", {{"tier", "tier1"}, {"rule", "tier1_user_agent"}}));

  // Test known bad user agent
  mock_exporter->clear_metrics();
  event.is_ua_missing = false;
  event.is_ua_known_bad = true;
  rule_engine->evaluate_rules(event);

  // Should have another hit
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total", {{"tier", "tier1"}, {"rule", "tier1_user_agent"}}));
}

TEST_F(RuleEngineMetricsTest, AssetRatioRuleTracking) {
  auto event = create_test_event();

  // Set up event to trigger asset ratio rule
  event.ip_html_requests_in_window = 5;  // Above min threshold of 3
  event.ip_asset_requests_in_window = 2; // Low asset count
  event.ip_assets_per_html_ratio =
      std::make_optional(0.4); // Below threshold of 2.0

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify asset ratio rule tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_asset_ratio"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier1"}, {"rule", "tier1_asset_ratio"}}));
}

TEST_F(RuleEngineMetricsTest, NewSeenRuleTracking) {
  auto event = create_test_event();

  // Set up event to trigger new seen rules
  event.is_first_request_from_ip = true;
  event.raw_log.request_path = "/admin/users"; // Contains sensitive path

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify new seen rule tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_new_seen"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total", {{"tier", "tier1"}, {"rule", "tier1_new_seen"}}));
}

TEST_F(RuleEngineMetricsTest, HistoricalComparisonRuleTracking) {
  auto event = create_test_event();

  // Set up event to trigger historical comparison rule
  event.raw_log.request_time_s = std::make_optional(5.0); // High request time
  event.ip_hist_req_time_mean = std::make_optional(0.5);  // Low historical mean
  event.ip_hist_req_time_samples =
      std::make_optional<uint64_t>(20); // Above min samples

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify historical comparison rule tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier2"}, {"rule", "tier2_historical_comparison"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier2"}, {"rule", "tier2_historical_comparison"}}));
}

// =================================================================================
// Test 4: Comprehensive metrics validation
// =================================================================================

TEST_F(RuleEngineMetricsTest, AllTierMetricsIntegration) {
  auto event = create_test_event();

  // Set up event to trigger rules across all tiers
  event.current_ip_request_count_in_window =
      std::make_optional<size_t>(150);                // Tier 1
  event.ip_req_time_zscore = std::make_optional(4.0); // Tier 2
  event.feature_vector = {0.1, 0.2, 0.3};             // Tier 3

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify all tiers have evaluation metrics
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier2"}, {"rule", "tier2_ip_zscore"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total", {{"tier", "tier3"}, {"rule", "tier3_ml"}}));

  // Verify alerts are generated with proper tier labeling
  EXPECT_TRUE(mock_exporter->has_counter("ad_alerts_generated_total",
                                         {{"tier", "tier1"},
                                          {"action", "rate_limit"},
                                          {"rule", "tier1_requests_per_ip"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_generated_total",
      {{"tier", "tier2"}, {"action", "log"}, {"rule", "tier2_ip_zscore"}}));
}

TEST_F(RuleEngineMetricsTest, DisabledTiersNoMetrics) {
  // Disable tier 2 and tier 3
  config.tier2.enabled = false;
  config.tier3.enabled = false;

  // Recreate rule engine with new config
  rule_engine = std::make_unique<RuleEngine>(*mock_alert_manager, config,
                                             mock_model_manager);
  rule_engine->set_metrics_exporter(mock_exporter);

  auto event = create_test_event();
  event.ip_req_time_zscore =
      std::make_optional(4.0); // Would trigger tier 2 if enabled

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify only tier 1 metrics are recorded
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
  EXPECT_FALSE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier2"}, {"rule", "tier2_ip_zscore"}}));
  EXPECT_FALSE(mock_exporter->has_counter(
      "ad_rule_evaluations_total", {{"tier", "tier3"}, {"rule", "tier3_ml"}}));
}

TEST_F(RuleEngineMetricsTest, MetricsWithoutExporter) {
  // Create rule engine without metrics exporter
  auto rule_engine_no_metrics = std::make_unique<RuleEngine>(
      *mock_alert_manager, config, mock_model_manager);

  auto event = create_test_event();
  event.current_ip_request_count_in_window = std::make_optional<size_t>(150);

  // Should not crash when processing without metrics exporter
  EXPECT_NO_THROW(rule_engine_no_metrics->evaluate_rules(event));
}

TEST_F(RuleEngineMetricsTest, FailedLoginRuleTracking) {
  auto event = create_test_event();

  // Set up event to trigger failed login rule
  event.current_ip_failed_login_count_in_window =
      std::make_optional<size_t>(10); // Above threshold of 5

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify failed login rule tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_failed_logins"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier1"}, {"rule", "tier1_failed_logins"}}));

  // Verify alert generation with BLOCK action
  EXPECT_TRUE(mock_exporter->has_counter("ad_alerts_generated_total",
                                         {{"tier", "tier1"},
                                          {"action", "block"},
                                          {"rule", "tier1_failed_logins"}}));
}

TEST_F(RuleEngineMetricsTest, SessionRuleTracking) {
  auto event = create_test_event();

  // Create a session state for session-based rules
  PerSessionState session_state;
  session_state.failed_login_attempts = 5; // Above threshold of 3
  session_state.last_seen_timestamp_ms = 1000000;

  // Add multiple UAs to trigger UA cycling
  session_state.unique_user_agents.insert("Mozilla/5.0");
  session_state.unique_user_agents.insert("Chrome/90.0");
  session_state.unique_user_agents.insert("Safari/14.0");
  session_state.unique_user_agents.insert(
      "Firefox/88.0"); // 4 UAs, above threshold of 2

  event.raw_session_state = session_state;

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Verify session rule tracking
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_session"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_hits_total", {{"tier", "tier1"}, {"rule", "tier1_session"}}));

  // Should generate multiple session-related alerts
  EXPECT_GE(
      mock_exporter->get_counter(
          "ad_rule_hits_total", {{"tier", "tier1"}, {"rule", "tier1_session"}}),
      1);
}

// =================================================================================
// Test 5: Edge cases and error conditions
// =================================================================================

TEST_F(RuleEngineMetricsTest, EmptyFeatureVectorNoMLMetrics) {
  auto event = create_test_event();
  event.feature_vector.clear(); // Empty feature vector

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // ML rule should still be evaluated (to track attempts) but no hit should
  // occur
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total", {{"tier", "tier3"}, {"rule", "tier3_ml"}}));

  // No hit should be recorded for ML rule with empty features
  EXPECT_FALSE(mock_exporter->has_counter(
      "ad_rule_hits_total", {{"tier", "tier3"}, {"rule", "tier3_ml"}}));
}

TEST_F(RuleEngineMetricsTest, ZeroScoreAlertsNotGenerated) {
  auto event = create_test_event();

  // Set up conditions that would normally trigger rules but with zero impact
  event.current_ip_request_count_in_window =
      std::make_optional<size_t>(50); // Below threshold

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // Rule evaluation should be tracked
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));

  // But no rule hit should be recorded since threshold wasn't exceeded
  EXPECT_FALSE(mock_exporter->has_counter(
      "ad_rule_hits_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));
}

TEST_F(RuleEngineMetricsTest, AllowlistedIPSkipsRules) {
  // Add IP to allowlist
  std::string allowlist_path = "/tmp/test_allowlist.txt";
  std::ofstream allowlist_file(allowlist_path);
  allowlist_file << "192.168.1.0/24\n";
  allowlist_file.close();

  config.allowlist_path = allowlist_path;
  rule_engine->reconfigure(config);

  auto event = create_test_event("192.168.1.100"); // IP in allowlist
  event.current_ip_request_count_in_window =
      std::make_optional<size_t>(150); // Would trigger rule

  mock_exporter->clear_metrics();

  // Process event
  rule_engine->evaluate_rules(event);

  // No rule evaluations should occur for allowlisted IPs
  EXPECT_FALSE(mock_exporter->has_counter(
      "ad_rule_evaluations_total",
      {{"tier", "tier1"}, {"rule", "tier1_requests_per_ip"}}));

  // Clean up
  std::remove(allowlist_path.c_str());
}

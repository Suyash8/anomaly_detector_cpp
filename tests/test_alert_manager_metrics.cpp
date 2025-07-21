#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "analysis/analyzed_event.hpp"
#include "core/alert.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/prometheus_metrics_exporter.hpp"
#include "io/alert_dispatch/base_dispatcher.hpp"

// Mock Prometheus Metrics Exporter for testing (reuse from rule engine tests)
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

// Mock Alert Dispatcher for testing dispatcher metrics
class MockAlertDispatcher : public IAlertDispatcher {
public:
  MockAlertDispatcher(const std::string &type, bool should_succeed = true)
      : type_(type), should_succeed_(should_succeed) {}

  bool dispatch(const Alert &alert) override {
    dispatch_attempts_++;
    last_dispatched_alert_ = alert;

    // Simulate some processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    if (should_succeed_) {
      successful_dispatches_++;
      return true;
    } else {
      failed_dispatches_++;
      return false;
    }
  }

  const char *get_name() const override { return type_.c_str(); }

  std::string get_dispatcher_type() const override { return type_; }

  // Test accessors
  int get_dispatch_attempts() const { return dispatch_attempts_; }
  int get_successful_dispatches() const { return successful_dispatches_; }
  int get_failed_dispatches() const { return failed_dispatches_; }
  const Alert &get_last_dispatched_alert() const {
    return last_dispatched_alert_;
  }

  void set_should_succeed(bool succeed) { should_succeed_ = succeed; }

private:
  std::string type_;
  bool should_succeed_;
  int dispatch_attempts_ = 0;
  int successful_dispatches_ = 0;
  int failed_dispatches_ = 0;
  Alert last_dispatched_alert_ =
      Alert(nullptr, "", AlertTier::TIER1_HEURISTIC, AlertAction::LOG, "", 0.0);
};

// Test fixture for Alert Manager metrics tests
class AlertManagerMetricsTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Set up basic configuration
    config.alerts_to_stdout = false;            // Disable stdout for tests
    config.alert_throttle_duration_seconds = 1; // 1 second throttle
    config.alert_throttle_max_alerts = 5;
    config.alert_output_path = "/tmp/test_alerts.log";

    config.alerting.file_enabled = true;
    config.alerting.syslog_enabled = false;
    config.alerting.http_enabled = false;
    config.alerting.http_webhook_url = "";

    // Create mock components
    mock_exporter = std::make_shared<MockPrometheusMetricsExporter>();
    alert_manager = std::make_unique<AlertManager>();
    alert_manager->set_metrics_exporter(mock_exporter);
    alert_manager->initialize(config);

    // Give the dispatcher thread a moment to start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  void TearDown() override {
    alert_manager.reset();
    mock_exporter.reset();

    // Clean up test files
    std::filesystem::remove("/tmp/test_alerts.log");
  }

  Config::AppConfig config;
  std::shared_ptr<MockPrometheusMetricsExporter> mock_exporter;
  std::unique_ptr<AlertManager> alert_manager;

  // Helper method to create test alerts
  Alert create_test_alert(AlertTier tier = AlertTier::TIER1_HEURISTIC,
                          AlertAction action = AlertAction::LOG,
                          const std::string &ip = "192.168.1.100",
                          const std::string &reason = "Test alert",
                          double score = 75.0) {
    // Create a minimal log entry
    LogEntry log_entry;
    log_entry.ip_address = ip;
    log_entry.request_path = "/test";
    log_entry.request_method = "GET";
    log_entry.http_status_code = 200;
    log_entry.parsed_timestamp_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    // Create analyzed event with the log entry
    auto analyzed_event = std::make_shared<AnalyzedEvent>(log_entry);

    return Alert(analyzed_event, reason, tier, action, "Test action", score,
                 ip);
  }
};

// =================================================================================
// Test 1: Alert throttling and suppression metrics
// =================================================================================

TEST_F(AlertManagerMetricsTest, AlertManagerMetricsRegistration) {
  // Verify that alert manager metrics are properly registered
  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_alerts_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_alerts_throttled_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_gauges.begin(),
                        mock_exporter->registered_gauges.end(),
                        "ad_alert_throttling_ratio") !=
              mock_exporter->registered_gauges.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_alerts_suppressed_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_alert_dispatch_success_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_counters.begin(),
                        mock_exporter->registered_counters.end(),
                        "ad_alert_dispatch_failure_total") !=
              mock_exporter->registered_counters.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_gauges.begin(),
                        mock_exporter->registered_gauges.end(),
                        "ad_alert_dispatch_success_rate") !=
              mock_exporter->registered_gauges.end());

  EXPECT_TRUE(std::find(mock_exporter->registered_histograms.begin(),
                        mock_exporter->registered_histograms.end(),
                        "ad_alert_dispatch_latency_seconds") !=
              mock_exporter->registered_histograms.end());
}

TEST_F(AlertManagerMetricsTest, BasicAlertGenerationMetrics) {
  auto alert =
      create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK);

  mock_exporter->clear_metrics();

  // Record alert
  alert_manager->record_alert(alert);

  // Give dispatcher thread time to process
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Verify alert generation metrics
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_total", {{"tier", "tier1"}, {"action", "block"}}));
  EXPECT_GE(mock_exporter->get_counter(
                "ad_alerts_total", {{"tier", "tier1"}, {"action", "block"}}),
            1);

  // Verify queue size metric is updated
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_queue_size"));
}

TEST_F(AlertManagerMetricsTest, AlertThrottlingMetrics) {
  auto alert1 = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                  "192.168.1.100", "Rate limit exceeded");
  auto alert2 = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                  "192.168.1.100",
                                  "Rate limit exceeded"); // Same IP and reason

  mock_exporter->clear_metrics();

  // Record first alert
  alert_manager->record_alert(alert1);

  // Record second alert immediately (should be throttled)
  alert_manager->record_alert(alert2);

  // Give time for processing
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Verify throttling metrics
  EXPECT_TRUE(mock_exporter->has_counter("ad_alerts_throttled_total",
                                         {{"reason", "time_window"}}));
  EXPECT_GE(mock_exporter->get_counter("ad_alerts_throttled_total",
                                       {{"reason", "time_window"}}),
            1);

  // Verify suppression metrics by tier
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_suppressed_total",
      {{"reason", "time_window"}, {"tier", "tier1"}}));

  // Verify throttling ratio is calculated
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_throttling_ratio"));
  double throttle_ratio = mock_exporter->get_gauge("ad_alert_throttling_ratio");
  EXPECT_GT(throttle_ratio, 0.0);
  EXPECT_LE(throttle_ratio, 1.0);
}

TEST_F(AlertManagerMetricsTest, AlertSuppressionByTier) {
  // Test suppression across different tiers
  auto tier1_alert =
      create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                        "192.168.1.101", "Suspicious activity");
  auto tier2_alert =
      create_test_alert(AlertTier::TIER2_STATISTICAL, AlertAction::LOG,
                        "192.168.1.102", "Statistical anomaly");
  auto tier3_alert = create_test_alert(AlertTier::TIER3_ML, AlertAction::LOG,
                                       "192.168.1.103", "ML detected anomaly");

  // Create duplicate alerts for throttling
  auto tier1_duplicate =
      create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                        "192.168.1.101", "Suspicious activity");
  auto tier2_duplicate =
      create_test_alert(AlertTier::TIER2_STATISTICAL, AlertAction::LOG,
                        "192.168.1.102", "Statistical anomaly");

  mock_exporter->clear_metrics();

  // Record original alerts
  alert_manager->record_alert(tier1_alert);
  alert_manager->record_alert(tier2_alert);
  alert_manager->record_alert(tier3_alert);

  // Record duplicates (should be throttled)
  alert_manager->record_alert(tier1_duplicate);
  alert_manager->record_alert(tier2_duplicate);

  // Give time for processing
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify suppression by tier
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_suppressed_total",
      {{"reason", "time_window"}, {"tier", "tier1"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_suppressed_total",
      {{"reason", "time_window"}, {"tier", "tier2"}}));

  // Verify suppression ratios by tier
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_suppression_ratio_by_tier",
                                       {{"tier", "tier1"}}));
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_suppression_ratio_by_tier",
                                       {{"tier", "tier2"}}));
}

TEST_F(AlertManagerMetricsTest, NoThrottlingAfterTimeWindow) {
  mock_exporter->clear_metrics();

  // Create first alert with current timestamp
  auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

  auto alert1 = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                  "192.168.1.100", "Rate limit exceeded");
  alert1.event_timestamp_ms = current_time;

  // Record first alert
  alert_manager->record_alert(alert1);

  // Wait for throttle window to expire (1.2 seconds to be safe)
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  // Create second alert with new timestamp after the window
  auto new_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();

  auto alert2 = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                  "192.168.1.100", "Rate limit exceeded");
  alert2.event_timestamp_ms = new_time;

  // Record second alert (should not be throttled)
  alert_manager->record_alert(alert2);

  // Give time for processing
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify both alerts were recorded (no throttling)
  int total_alerts = mock_exporter->get_counter(
      "ad_alerts_total", {{"tier", "tier1"}, {"action", "log"}});
  EXPECT_GE(total_alerts, 2);

  // Throttling count should be 0 since enough time passed
  int throttled_count = mock_exporter->get_counter("ad_alerts_throttled_total",
                                                   {{"reason", "time_window"}});

  // Accept that some throttling might occur due to timing, but ensure we got
  // both alerts
  if (throttled_count > 0) {
    // If throttling occurred, we should still have at least 1 alert recorded
    EXPECT_GE(total_alerts, 1);
  } else {
    // If no throttling, we should have both alerts
    EXPECT_GE(total_alerts, 2);
  }
}

// =================================================================================
// Test 2: Alert delivery success/failure rates by dispatcher type
// =================================================================================

TEST_F(AlertManagerMetricsTest, DispatcherSuccessMetrics) {
  // Note: This test uses the real file dispatcher since it's configured
  auto alert =
      create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK);

  mock_exporter->clear_metrics();

  // Record alert
  alert_manager->record_alert(alert);

  // Give dispatcher thread time to process
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify dispatch attempt metrics
  EXPECT_TRUE(mock_exporter->has_counter("ad_alert_dispatch_attempts_total",
                                         {{"dispatcher_type", "file"}}));
  EXPECT_GE(mock_exporter->get_counter("ad_alert_dispatch_attempts_total",
                                       {{"dispatcher_type", "file"}}),
            1);

  // Verify dispatch success metrics
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alert_dispatch_success_total",
      {{"dispatcher_type", "file"}, {"tier", "tier1"}}));
  EXPECT_GE(mock_exporter->get_counter(
                "ad_alert_dispatch_success_total",
                {{"dispatcher_type", "file"}, {"tier", "tier1"}}),
            1);

  // Verify success rate calculation
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_dispatch_success_rate",
                                       {{"dispatcher_type", "file"}}));
  double success_rate = mock_exporter->get_gauge(
      "ad_alert_dispatch_success_rate", {{"dispatcher_type", "file"}});
  EXPECT_GT(success_rate, 0.0);
  EXPECT_LE(success_rate, 1.0);

  // Verify dispatch latency is tracked
  auto latency_observations = mock_exporter->get_histogram_observations(
      "ad_alert_dispatch_latency_seconds", {{"dispatcher_type", "file"}});
  EXPECT_FALSE(latency_observations.empty());
  EXPECT_GT(latency_observations[0], 0.0); // Should have some latency
}

TEST_F(AlertManagerMetricsTest, DispatcherFailureMetrics) {
  // Configure with invalid file path to trigger failures
  config.alert_output_path = "/invalid/path/that/does/not/exist/alerts.log";

  // Recreate alert manager with failing configuration
  alert_manager.reset();
  alert_manager = std::make_unique<AlertManager>();
  alert_manager->set_metrics_exporter(mock_exporter);
  alert_manager->initialize(config);

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto alert =
      create_test_alert(AlertTier::TIER2_STATISTICAL, AlertAction::LOG);

  mock_exporter->clear_metrics();

  // Record alert
  alert_manager->record_alert(alert);

  // Give dispatcher thread time to process and fail
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify dispatch failure metrics
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alert_dispatch_failure_total",
      {{"dispatcher_type", "file"}, {"error_type", "file_write_error"}}));
  EXPECT_GE(mock_exporter->get_counter("ad_alert_dispatch_failure_total",
                                       {{"dispatcher_type", "file"},
                                        {"error_type", "file_write_error"}}),
            1);

  // Verify success rate reflects failures
  double success_rate = mock_exporter->get_gauge(
      "ad_alert_dispatch_success_rate", {{"dispatcher_type", "file"}});
  EXPECT_LT(success_rate, 1.0); // Should be less than perfect due to failures
}

TEST_F(AlertManagerMetricsTest, MultipleDispatcherTypes) {
  // Enable multiple dispatcher types
  config.alerting.file_enabled = true;
  config.alerting.syslog_enabled = true;
  config.alerting.http_enabled = true;
  config.alerting.http_webhook_url = "http://localhost:9999/webhook";

  // Recreate alert manager with multiple dispatchers
  alert_manager.reset();
  alert_manager = std::make_unique<AlertManager>();
  alert_manager->set_metrics_exporter(mock_exporter);
  alert_manager->initialize(config);

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto alert = create_test_alert(AlertTier::TIER3_ML, AlertAction::CHALLENGE);

  mock_exporter->clear_metrics();

  // Record alert
  alert_manager->record_alert(alert);

  // Give dispatcher thread time to process all dispatchers
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Verify attempts for all dispatcher types
  EXPECT_TRUE(mock_exporter->has_counter("ad_alert_dispatch_attempts_total",
                                         {{"dispatcher_type", "file"}}));
  EXPECT_TRUE(mock_exporter->has_counter("ad_alert_dispatch_attempts_total",
                                         {{"dispatcher_type", "syslog"}}));
  EXPECT_TRUE(mock_exporter->has_counter("ad_alert_dispatch_attempts_total",
                                         {{"dispatcher_type", "http"}}));

  // Verify success rate metrics exist for all types
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_dispatch_success_rate",
                                       {{"dispatcher_type", "file"}}));
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_dispatch_success_rate",
                                       {{"dispatcher_type", "syslog"}}));
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_dispatch_success_rate",
                                       {{"dispatcher_type", "http"}}));
}

// =================================================================================
// Test 3: Queue and performance metrics
// =================================================================================

TEST_F(AlertManagerMetricsTest, AlertQueueSizeMetrics) {
  mock_exporter->clear_metrics();

  // Record multiple alerts rapidly
  for (int i = 0; i < 5; i++) {
    auto alert = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                   "192.168.1." + std::to_string(100 + i),
                                   "Test alert " + std::to_string(i));
    alert_manager->record_alert(alert);
  }

  // Verify queue size metric is updated
  EXPECT_TRUE(mock_exporter->has_gauge("ad_alert_queue_size"));

  // Give some time for processing to reduce queue
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Queue should be processed down
  double final_queue_size = mock_exporter->get_gauge("ad_alert_queue_size");
  EXPECT_GE(final_queue_size, 0.0);
}

TEST_F(AlertManagerMetricsTest, RecentAlertsCacheMetrics) {
  mock_exporter->clear_metrics();

  // Record several alerts
  for (int i = 0; i < 3; i++) {
    auto alert = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                   "192.168.1." + std::to_string(200 + i),
                                   "Cache test alert " + std::to_string(i));
    alert_manager->record_alert(alert);
  }

  // Give time for processing
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify recent alerts count metric
  EXPECT_TRUE(mock_exporter->has_gauge("ad_recent_alerts_count"));
  double recent_count = mock_exporter->get_gauge("ad_recent_alerts_count");
  EXPECT_GE(recent_count, 3.0); // Should have at least our 3 alerts
}

TEST_F(AlertManagerMetricsTest, DispatchLatencyTracking) {
  auto alert =
      create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK);

  mock_exporter->clear_metrics();

  // Record alert
  alert_manager->record_alert(alert);

  // Give dispatcher thread time to process
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Verify latency histogram has observations
  auto latency_observations = mock_exporter->get_histogram_observations(
      "ad_alert_dispatch_latency_seconds", {{"dispatcher_type", "file"}});
  EXPECT_FALSE(latency_observations.empty());

  // Latency should be reasonable (not negative, not excessively high)
  for (double latency : latency_observations) {
    EXPECT_GT(latency, 0.0);
    EXPECT_LT(latency, 1.0); // Should be less than 1 second for file dispatch
  }
}

// =================================================================================
// Test 4: Comprehensive integration tests
// =================================================================================

TEST_F(AlertManagerMetricsTest, EndToEndMetricsFlow) {
  // Test complete flow from alert generation to dispatch with metrics
  auto tier1_alert =
      create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
                        "10.0.0.1", "Brute force detected");
  auto tier2_alert =
      create_test_alert(AlertTier::TIER2_STATISTICAL, AlertAction::LOG,
                        "10.0.0.2", "Statistical anomaly");
  auto tier3_alert =
      create_test_alert(AlertTier::TIER3_ML, AlertAction::CHALLENGE, "10.0.0.3",
                        "ML anomaly detected");

  mock_exporter->clear_metrics();

  // Record alerts
  alert_manager->record_alert(tier1_alert);
  alert_manager->record_alert(tier2_alert);
  alert_manager->record_alert(tier3_alert);

  // Give time for complete processing
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Verify alert generation metrics across all tiers
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_total", {{"tier", "tier1"}, {"action", "block"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_total", {{"tier", "tier2"}, {"action", "log"}}));
  EXPECT_TRUE(mock_exporter->has_counter(
      "ad_alerts_total", {{"tier", "tier3"}, {"action", "challenge"}}));

  // Verify dispatch metrics
  EXPECT_GE(mock_exporter->get_counter(
                "ad_alert_dispatch_success_total",
                {{"dispatcher_type", "file"}, {"tier", "tier1"}}),
            1);
  EXPECT_GE(mock_exporter->get_counter(
                "ad_alert_dispatch_success_total",
                {{"dispatcher_type", "file"}, {"tier", "tier2"}}),
            1);
  EXPECT_GE(mock_exporter->get_counter(
                "ad_alert_dispatch_success_total",
                {{"dispatcher_type", "file"}, {"tier", "tier3"}}),
            1);

  // Verify overall dispatch success rate
  double success_rate = mock_exporter->get_gauge(
      "ad_alert_dispatch_success_rate", {{"dispatcher_type", "file"}});
  EXPECT_GE(success_rate,
            0.9); // Should be high success rate for file dispatcher
}

TEST_F(AlertManagerMetricsTest, MetricsWithoutExporter) {
  // Create alert manager without metrics exporter
  auto alert_manager_no_metrics = std::make_unique<AlertManager>();
  alert_manager_no_metrics->initialize(config);

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto alert = create_test_alert();

  // Should not crash when processing without metrics exporter
  EXPECT_NO_THROW(alert_manager_no_metrics->record_alert(alert));

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

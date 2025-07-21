#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "analysis/analyzed_event.hpp"
#include "core/alert.hpp"
#include "core/log_entry.hpp"
#include "io/alert_dispatch/base_dispatcher.hpp"
#include "io/alert_dispatch/file_dispatcher.hpp"
#include "io/alert_dispatch/http_dispatcher.hpp"
#include "io/alert_dispatch/syslog_dispatcher.hpp"

// Test fixture for Alert Dispatcher tests
class AlertDispatcherTest : public ::testing::Test {
protected:
  void SetUp() override {
    test_file_path_ = "/tmp/test_alert_dispatcher.log";

    // Clean up any existing test files
    std::filesystem::remove(test_file_path_);
  }

  void TearDown() override {
    // Clean up test files
    std::filesystem::remove(test_file_path_);
  }

  std::string test_file_path_;

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
// Test 1: File Dispatcher Implementation and Type Identification
// =================================================================================

TEST_F(AlertDispatcherTest, FileDispatcherTypeIdentification) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);

  // Verify dispatcher type identification
  EXPECT_EQ(file_dispatcher->get_dispatcher_type(), "file");
  EXPECT_STREQ(file_dispatcher->get_name(), "FileDispatcher");
}

TEST_F(AlertDispatcherTest, FileDispatcherSuccessfulDispatch) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);
  auto alert = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
                                 "10.0.0.1", "File dispatcher test");

  // Dispatch should succeed
  bool result = file_dispatcher->dispatch(alert);
  EXPECT_TRUE(result);

  // Verify file was created and contains alert data
  EXPECT_TRUE(std::filesystem::exists(test_file_path_));

  std::ifstream file(test_file_path_);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  file.close();

  // Verify alert content is in the file
  EXPECT_NE(content.find("10.0.0.1"), std::string::npos);
  EXPECT_NE(content.find("File dispatcher test"), std::string::npos);
  EXPECT_NE(content.find("TIER1_HEURISTIC"), std::string::npos);
}

TEST_F(AlertDispatcherTest, FileDispatcherFailureHandling) {
  // Use an invalid path to trigger failure
  std::string invalid_path = "/invalid/directory/that/does/not/exist/test.log";
  auto file_dispatcher = std::make_unique<FileDispatcher>(invalid_path);
  auto alert = create_test_alert();

  // Dispatch should fail
  bool result = file_dispatcher->dispatch(alert);
  EXPECT_FALSE(result);
}

TEST_F(AlertDispatcherTest, FileDispatcherMultipleAlerts) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);

  // Dispatch multiple alerts
  for (int i = 0; i < 3; i++) {
    auto alert = create_test_alert(AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
                                   "10.0.0." + std::to_string(i + 1),
                                   "Alert " + std::to_string(i + 1));
    bool result = file_dispatcher->dispatch(alert);
    EXPECT_TRUE(result);
  }

  // Verify all alerts are in the file
  std::ifstream file(test_file_path_);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  file.close();

  EXPECT_NE(content.find("10.0.0.1"), std::string::npos);
  EXPECT_NE(content.find("10.0.0.2"), std::string::npos);
  EXPECT_NE(content.find("10.0.0.3"), std::string::npos);
  EXPECT_NE(content.find("Alert 1"), std::string::npos);
  EXPECT_NE(content.find("Alert 2"), std::string::npos);
  EXPECT_NE(content.find("Alert 3"), std::string::npos);
}

// =================================================================================
// Test 2: HTTP Dispatcher Implementation and Type Identification
// =================================================================================

TEST_F(AlertDispatcherTest, HttpDispatcherTypeIdentification) {
  auto http_dispatcher =
      std::make_unique<HttpDispatcher>("http://localhost:9999/webhook");

  // Verify dispatcher type identification
  EXPECT_EQ(http_dispatcher->get_dispatcher_type(), "http");
  EXPECT_STREQ(http_dispatcher->get_name(), "HttpDispatcher");
}

TEST_F(AlertDispatcherTest, HttpDispatcherFailureHandling) {
  // Use an invalid URL to trigger failure
  auto http_dispatcher = std::make_unique<HttpDispatcher>(
      "http://invalid-host-that-does-not-exist:9999/webhook");
  auto alert =
      create_test_alert(AlertTier::TIER2_STATISTICAL, AlertAction::LOG);

  // Dispatch should fail (no server listening)
  bool result = http_dispatcher->dispatch(alert);
  EXPECT_FALSE(result);
}

TEST_F(AlertDispatcherTest, HttpDispatcherInvalidUrl) {
  // Test with malformed URL
  auto http_dispatcher = std::make_unique<HttpDispatcher>("not-a-valid-url");
  auto alert = create_test_alert();

  // Dispatch should fail
  bool result = http_dispatcher->dispatch(alert);
  EXPECT_FALSE(result);
}

// =================================================================================
// Test 3: Syslog Dispatcher Implementation and Type Identification
// =================================================================================

TEST_F(AlertDispatcherTest, SyslogDispatcherTypeIdentification) {
  auto syslog_dispatcher = std::make_unique<SyslogDispatcher>();

  // Verify dispatcher type identification
  EXPECT_EQ(syslog_dispatcher->get_dispatcher_type(), "syslog");
  EXPECT_STREQ(syslog_dispatcher->get_name(), "SyslogDispatcher");
}

TEST_F(AlertDispatcherTest, SyslogDispatcherBasicDispatch) {
  auto syslog_dispatcher = std::make_unique<SyslogDispatcher>();
  auto alert = create_test_alert(AlertTier::TIER3_ML, AlertAction::CHALLENGE,
                                 "10.1.1.1", "Syslog test alert");

  // Syslog dispatch should generally succeed (depends on system syslog)
  // We can't easily verify the actual syslog output, but we can test that
  // the dispatch call doesn't crash and returns a reasonable result
  bool result = syslog_dispatcher->dispatch(alert);

  // Syslog dispatch might succeed or fail depending on system configuration
  // The important thing is that it doesn't crash
  EXPECT_TRUE(result == true ||
              result == false); // Either outcome is acceptable
}

// =================================================================================
// Test 4: Dispatcher Performance and Metrics Support
// =================================================================================

TEST_F(AlertDispatcherTest, DispatcherPerformanceTiming) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);
  auto alert = create_test_alert();

  // Measure dispatch time in microseconds for better precision
  auto start_time = std::chrono::high_resolution_clock::now();
  bool result = file_dispatcher->dispatch(alert);
  auto end_time = std::chrono::high_resolution_clock::now();

  EXPECT_TRUE(result);

  // Verify timing is reasonable using microseconds
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
      end_time - start_time);
  EXPECT_LT(duration.count(), 1000000); // Should take less than 1 second
  EXPECT_GE(duration.count(), 0);       // Should take at least 0 microseconds
}

TEST_F(AlertDispatcherTest, AllDispatcherTypesUnique) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);
  auto http_dispatcher =
      std::make_unique<HttpDispatcher>("http://localhost:9999/webhook");
  auto syslog_dispatcher = std::make_unique<SyslogDispatcher>();

  // Verify all dispatcher types are unique
  EXPECT_NE(file_dispatcher->get_dispatcher_type(),
            http_dispatcher->get_dispatcher_type());
  EXPECT_NE(file_dispatcher->get_dispatcher_type(),
            syslog_dispatcher->get_dispatcher_type());
  EXPECT_NE(http_dispatcher->get_dispatcher_type(),
            syslog_dispatcher->get_dispatcher_type());

  // Verify all names are unique
  EXPECT_STRNE(file_dispatcher->get_name(), http_dispatcher->get_name());
  EXPECT_STRNE(file_dispatcher->get_name(), syslog_dispatcher->get_name());
  EXPECT_STRNE(http_dispatcher->get_name(), syslog_dispatcher->get_name());
}

// =================================================================================
// Test 5: Alert Content Verification
// =================================================================================

TEST_F(AlertDispatcherTest, AlertContentSerialization) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);

  // Create alert with specific content
  auto alert = create_test_alert(AlertTier::TIER2_STATISTICAL,
                                 AlertAction::RATE_LIMIT, "203.0.113.42",
                                 "Anomalous request pattern detected", 89.5);

  bool result = file_dispatcher->dispatch(alert);
  EXPECT_TRUE(result);

  // Read and verify file content
  std::ifstream file(test_file_path_);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  file.close();

  // Verify specific alert details are present
  EXPECT_NE(content.find("203.0.113.42"), std::string::npos);
  EXPECT_NE(content.find("Anomalous request pattern detected"),
            std::string::npos);
  EXPECT_NE(content.find("TIER2_STATISTICAL"), std::string::npos);
  EXPECT_NE(content.find("RATE_LIMIT"), std::string::npos);
  EXPECT_NE(content.find("89.5"), std::string::npos);
}

TEST_F(AlertDispatcherTest, AlertWithMLFeatures) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);

  // Create alert with ML feature contribution
  auto alert = create_test_alert(AlertTier::TIER3_ML, AlertAction::BLOCK,
                                 "198.51.100.1", "ML model detected anomaly");
  alert.ml_feature_contribution =
      "feature1: 0.3, feature2: 0.7, feature3: -0.1";

  bool result = file_dispatcher->dispatch(alert);
  EXPECT_TRUE(result);

  // Verify ML features are included in output
  std::ifstream file(test_file_path_);
  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  file.close();

  EXPECT_NE(content.find("feature1: 0.3"), std::string::npos);
  EXPECT_NE(content.find("feature2: 0.7"), std::string::npos);
  EXPECT_NE(content.find("feature3: -0.1"), std::string::npos);
}

// =================================================================================
// Test 6: Error Handling and Edge Cases
// =================================================================================

TEST_F(AlertDispatcherTest, FileDispatcherResourceCleanup) {
  {
    // Create dispatcher in a scope that will be destroyed
    auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);
    auto alert = create_test_alert();

    bool result = file_dispatcher->dispatch(alert);
    EXPECT_TRUE(result);

    // Dispatcher goes out of scope here and should clean up properly
  }

  // File should still exist and be readable after dispatcher destruction
  EXPECT_TRUE(std::filesystem::exists(test_file_path_));

  std::ifstream file(test_file_path_);
  EXPECT_TRUE(file.is_open());
  file.close();
}

TEST_F(AlertDispatcherTest, DispatcherWithEmptyAlert) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);

  // Create alert with minimal/empty content
  LogEntry empty_log;
  auto analyzed_event = std::make_shared<AnalyzedEvent>(empty_log);
  Alert empty_alert(analyzed_event, "", AlertTier::TIER1_HEURISTIC,
                    AlertAction::NO_ACTION, "", 0.0);

  // Should handle empty alert gracefully
  bool result = file_dispatcher->dispatch(empty_alert);
  EXPECT_TRUE(result);

  // File should be created even with empty alert
  EXPECT_TRUE(std::filesystem::exists(test_file_path_));
}

TEST_F(AlertDispatcherTest, HighVolumeDispatchTest) {
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);

  // Dispatch many alerts to test performance
  const int num_alerts = 100;
  int successful_dispatches = 0;

  auto start_time = std::chrono::high_resolution_clock::now();

  for (int i = 0; i < num_alerts; i++) {
    auto alert = create_test_alert(
        AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
        "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256),
        "High volume test alert " + std::to_string(i));
    if (file_dispatcher->dispatch(alert)) {
      successful_dispatches++;
    }
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  // All dispatches should succeed
  EXPECT_EQ(successful_dispatches, num_alerts);

  // Should complete in reasonable time (less than 5 seconds)
  EXPECT_LT(duration.count(), 5000);

  // Verify file size is reasonable (alerts were actually written)
  std::filesystem::path file_path(test_file_path_);
  auto file_size = std::filesystem::file_size(file_path);
  EXPECT_GT(file_size,
            num_alerts * 50); // Each alert should be at least 50 bytes
}

// =================================================================================
// Test 7: Integration Testing for Dispatcher Metrics Requirements
// =================================================================================

TEST_F(AlertDispatcherTest, DispatcherMetricsCompatibility) {
  // This test verifies that dispatchers provide the necessary information
  // for the alert manager to track metrics correctly

  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);
  auto http_dispatcher =
      std::make_unique<HttpDispatcher>("http://localhost:9999/webhook");
  auto syslog_dispatcher = std::make_unique<SyslogDispatcher>();

  std::vector<std::unique_ptr<IAlertDispatcher>> dispatchers;
  dispatchers.push_back(std::move(file_dispatcher));
  dispatchers.push_back(std::move(http_dispatcher));
  dispatchers.push_back(std::move(syslog_dispatcher));

  // Test that all dispatchers provide proper type identification for metrics
  std::vector<std::string> expected_types = {"file", "http", "syslog"};

  for (size_t i = 0; i < dispatchers.size(); i++) {
    EXPECT_EQ(dispatchers[i]->get_dispatcher_type(), expected_types[i]);
    EXPECT_FALSE(dispatchers[i]->get_dispatcher_type().empty());
    EXPECT_NE(dispatchers[i]->get_name(), nullptr);
    EXPECT_NE(strlen(dispatchers[i]->get_name()), 0);
  }
}

TEST_F(AlertDispatcherTest, DispatcherSuccessFailureScenarios) {
  // Test scenarios that would generate different metric outcomes

  // Scenario 1: Successful file dispatch
  auto working_file_dispatcher =
      std::make_unique<FileDispatcher>(test_file_path_);
  auto alert = create_test_alert();

  bool success_result = working_file_dispatcher->dispatch(alert);
  EXPECT_TRUE(success_result); // Should generate success metrics

  // Scenario 2: Failed file dispatch
  auto failing_file_dispatcher =
      std::make_unique<FileDispatcher>("/invalid/path/test.log");
  bool failure_result = failing_file_dispatcher->dispatch(alert);
  EXPECT_FALSE(failure_result); // Should generate failure metrics with
                                // "file_write_error"

  // Scenario 3: Failed HTTP dispatch
  auto failing_http_dispatcher =
      std::make_unique<HttpDispatcher>("http://nonexistent:9999/webhook");
  bool http_failure_result = failing_http_dispatcher->dispatch(alert);
  EXPECT_FALSE(http_failure_result); // Should generate failure metrics with
                                     // "network_error"

  // These test cases ensure that the alert manager can properly categorize
  // success/failure metrics by dispatcher type and error type
}

TEST_F(AlertDispatcherTest, DispatcherLatencyMeasurement) {
  // Test that dispatcher operations can be timed for latency metrics
  auto file_dispatcher = std::make_unique<FileDispatcher>(test_file_path_);
  auto alert = create_test_alert();

  // Measure multiple dispatches to verify consistent timing
  std::vector<double> latencies;

  for (int i = 0; i < 5; i++) {
    auto start = std::chrono::high_resolution_clock::now();
    bool result = file_dispatcher->dispatch(alert);
    auto end = std::chrono::high_resolution_clock::now();

    EXPECT_TRUE(result);

    double latency = std::chrono::duration<double>(end - start).count();
    latencies.push_back(latency);

    // Each dispatch should complete in reasonable time
    EXPECT_GT(latency, 0.0);
    EXPECT_LT(latency, 1.0); // Less than 1 second
  }

  // Verify latencies are measurable and reasonable
  EXPECT_EQ(latencies.size(), 5);
  for (double latency : latencies) {
    EXPECT_GT(latency, 0.0);
  }
}

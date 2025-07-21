#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <regex>
#include <httplib.h>
#include "core/prometheus_metrics_exporter.hpp"

class PrometheusMetricsExporterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use a different port for each test to avoid conflicts
        static int port_counter = 9091;
        config_.port = port_counter++;
        exporter_ = std::make_unique<prometheus::PrometheusMetricsExporter>(config_);
    }

    void TearDown() override {
        if (exporter_) {
            exporter_->stop_server();
        }
    }

    prometheus::PrometheusMetricsExporter::Config config_;
    std::unique_ptr<prometheus::PrometheusMetricsExporter> exporter_;
};

TEST_F(PrometheusMetricsExporterTest, RegisterCounter) {
    // Test basic counter registration
    EXPECT_NO_THROW(exporter_->register_counter("test_counter", "Test counter"));
    
    // Test counter with labels
    EXPECT_NO_THROW(exporter_->register_counter("test_counter_with_labels", "Test counter with labels", {"method", "status"}));
    
    // Test duplicate registration should throw
    EXPECT_THROW(exporter_->register_counter("test_counter", "Duplicate counter"), std::invalid_argument);
}

TEST_F(PrometheusMetricsExporterTest, RegisterGauge) {
    // Test basic gauge registration
    EXPECT_NO_THROW(exporter_->register_gauge("test_gauge", "Test gauge"));
    
    // Test gauge with labels
    EXPECT_NO_THROW(exporter_->register_gauge("test_gauge_with_labels", "Test gauge with labels", {"component"}));
    
    // Test duplicate registration should throw
    EXPECT_THROW(exporter_->register_gauge("test_gauge", "Duplicate gauge"), std::invalid_argument);
}

TEST_F(PrometheusMetricsExporterTest, RegisterHistogram) {
    // Test basic histogram registration
    EXPECT_NO_THROW(exporter_->register_histogram("test_histogram", "Test histogram"));
    
    // Test histogram with custom buckets
    std::vector<double> buckets = {0.1, 0.5, 1.0, 5.0};
    EXPECT_NO_THROW(exporter_->register_histogram("test_histogram_custom", "Test histogram with custom buckets", buckets));
    
    // Test histogram with labels
    EXPECT_NO_THROW(exporter_->register_histogram("test_histogram_with_labels", "Test histogram with labels", {}, {"endpoint"}));
    
    // Test duplicate registration should throw
    EXPECT_THROW(exporter_->register_histogram("test_histogram", "Duplicate histogram"), std::invalid_argument);
}

TEST_F(PrometheusMetricsExporterTest, CounterOperations) {
    exporter_->register_counter("requests_total", "Total requests", {"method", "status"});
    
    // Test increment without labels (should fail for labeled counter)
    EXPECT_THROW(exporter_->increment_counter("requests_total"), std::invalid_argument);
    
    // Test increment with correct labels
    std::map<std::string, std::string> labels = {{"method", "GET"}, {"status", "200"}};
    EXPECT_NO_THROW(exporter_->increment_counter("requests_total", labels, 1.0));
    EXPECT_NO_THROW(exporter_->increment_counter("requests_total", labels, 5.0));
    
    // Test increment with missing labels
    std::map<std::string, std::string> incomplete_labels = {{"method", "GET"}};
    EXPECT_THROW(exporter_->increment_counter("requests_total", incomplete_labels), std::invalid_argument);
    
    // Test increment with negative value
    EXPECT_THROW(exporter_->increment_counter("requests_total", labels, -1.0), std::invalid_argument);
    
    // Test increment non-existent counter
    EXPECT_THROW(exporter_->increment_counter("non_existent", labels), std::invalid_argument);
}

TEST_F(PrometheusMetricsExporterTest, GaugeOperations) {
    exporter_->register_gauge("memory_usage_bytes", "Memory usage in bytes", {"component"});
    
    std::map<std::string, std::string> labels = {{"component", "analysis_engine"}};
    
    // Test set gauge value
    EXPECT_NO_THROW(exporter_->set_gauge("memory_usage_bytes", 1024.5, labels));
    EXPECT_NO_THROW(exporter_->set_gauge("memory_usage_bytes", 2048.0, labels));
    
    // Test set with missing labels
    std::map<std::string, std::string> incomplete_labels = {};
    EXPECT_THROW(exporter_->set_gauge("memory_usage_bytes", 1024.0, incomplete_labels), std::invalid_argument);
    
    // Test set non-existent gauge
    EXPECT_THROW(exporter_->set_gauge("non_existent", 1024.0, labels), std::invalid_argument);
}

TEST_F(PrometheusMetricsExporterTest, HistogramOperations) {
    std::vector<double> buckets = {0.1, 0.5, 1.0, 5.0};
    exporter_->register_histogram("request_duration_seconds", "Request duration", buckets, {"endpoint"});
    
    std::map<std::string, std::string> labels = {{"endpoint", "/api/v1/data"}};
    
    // Test observe values
    EXPECT_NO_THROW(exporter_->observe_histogram("request_duration_seconds", 0.05, labels));
    EXPECT_NO_THROW(exporter_->observe_histogram("request_duration_seconds", 0.3, labels));
    EXPECT_NO_THROW(exporter_->observe_histogram("request_duration_seconds", 1.5, labels));
    EXPECT_NO_THROW(exporter_->observe_histogram("request_duration_seconds", 10.0, labels));
    
    // Test observe with missing labels
    std::map<std::string, std::string> incomplete_labels = {};
    EXPECT_THROW(exporter_->observe_histogram("request_duration_seconds", 0.1, incomplete_labels), std::invalid_argument);
    
    // Test observe non-existent histogram
    EXPECT_THROW(exporter_->observe_histogram("non_existent", 0.1, labels), std::invalid_argument);
}

TEST_F(PrometheusMetricsExporterTest, MetricsOutput) {
    // Register various metrics
    exporter_->register_counter("test_counter", "Test counter");
    exporter_->register_gauge("test_gauge", "Test gauge");
    exporter_->register_histogram("test_histogram", "Test histogram");
    
    // Update metrics
    exporter_->increment_counter("test_counter", {}, 5.0);
    exporter_->set_gauge("test_gauge", 42.5, {});
    exporter_->observe_histogram("test_histogram", 0.1, {});
    exporter_->observe_histogram("test_histogram", 1.5, {});
    
    // Generate output
    std::string output = exporter_->generate_metrics_output();
    
    // Verify output contains expected content
    EXPECT_TRUE(output.find("# HELP test_counter Test counter") != std::string::npos);
    EXPECT_TRUE(output.find("# TYPE test_counter counter") != std::string::npos);
    EXPECT_TRUE(output.find("test_counter 5.000000") != std::string::npos);
    
    EXPECT_TRUE(output.find("# HELP test_gauge Test gauge") != std::string::npos);
    EXPECT_TRUE(output.find("# TYPE test_gauge gauge") != std::string::npos);
    EXPECT_TRUE(output.find("test_gauge 42.500000") != std::string::npos);
    
    EXPECT_TRUE(output.find("# HELP test_histogram Test histogram") != std::string::npos);
    EXPECT_TRUE(output.find("# TYPE test_histogram histogram") != std::string::npos);
    EXPECT_TRUE(output.find("test_histogram_bucket") != std::string::npos);
    EXPECT_TRUE(output.find("test_histogram_sum") != std::string::npos);
    EXPECT_TRUE(output.find("test_histogram_count") != std::string::npos);
}

TEST_F(PrometheusMetricsExporterTest, MetricsOutputWithLabels) {
    // Register metrics with labels
    exporter_->register_counter("http_requests_total", "Total HTTP requests", {"method", "status"});
    exporter_->register_gauge("memory_usage", "Memory usage", {"component"});
    
    // Update metrics with different label combinations
    exporter_->increment_counter("http_requests_total", {{"method", "GET"}, {"status", "200"}}, 10);
    exporter_->increment_counter("http_requests_total", {{"method", "POST"}, {"status", "201"}}, 5);
    exporter_->set_gauge("memory_usage", 1024.0, {{"component", "engine"}});
    exporter_->set_gauge("memory_usage", 512.0, {{"component", "cache"}});
    
    std::string output = exporter_->generate_metrics_output();
    
    // Verify labeled metrics are properly formatted
    EXPECT_TRUE(output.find("http_requests_total{method=\"GET\",status=\"200\"} 10.000000") != std::string::npos);
    EXPECT_TRUE(output.find("http_requests_total{method=\"POST\",status=\"201\"} 5.000000") != std::string::npos);
    EXPECT_TRUE(output.find("memory_usage{component=\"engine\"} 1024.000000") != std::string::npos);
    EXPECT_TRUE(output.find("memory_usage{component=\"cache\"} 512.000000") != std::string::npos);
}

TEST_F(PrometheusMetricsExporterTest, ServerStartStop) {
    // Test server start
    EXPECT_TRUE(exporter_->start_server());
    EXPECT_TRUE(exporter_->is_running());
    
    // Give server time to fully start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Test HTTP endpoint
    httplib::Client client("localhost", config_.port);
    client.set_connection_timeout(1, 0); // 1 second timeout
    
    auto health_res = client.Get("/health");
    EXPECT_TRUE(health_res);
    EXPECT_EQ(health_res->status, 200);
    EXPECT_EQ(health_res->body, "OK");
    
    // Test metrics endpoint
    exporter_->register_counter("test_counter", "Test counter");
    exporter_->increment_counter("test_counter", {}, 1.0);
    
    auto metrics_res = client.Get("/metrics");
    EXPECT_TRUE(metrics_res);
    EXPECT_EQ(metrics_res->status, 200);
    EXPECT_TRUE(metrics_res->body.find("test_counter 1.000000") != std::string::npos);
    
    // Test server stop
    exporter_->stop_server();
    EXPECT_FALSE(exporter_->is_running());
}

TEST_F(PrometheusMetricsExporterTest, InvalidMetricNames) {
    // Test invalid metric names
    EXPECT_THROW(exporter_->register_counter("", "Empty name"), std::invalid_argument);
    EXPECT_THROW(exporter_->register_counter("123invalid", "Starts with number"), std::invalid_argument);
    EXPECT_THROW(exporter_->register_counter("invalid-name", "Contains dash"), std::invalid_argument);
    EXPECT_THROW(exporter_->register_counter("invalid.name", "Contains dot"), std::invalid_argument);
    
    // Test valid metric names
    EXPECT_NO_THROW(exporter_->register_counter("valid_name", "Valid name"));
    EXPECT_NO_THROW(exporter_->register_counter("valid_name_123", "Valid name with numbers"));
    EXPECT_NO_THROW(exporter_->register_counter("valid:name", "Valid name with colon"));
    EXPECT_NO_THROW(exporter_->register_counter("_valid_name", "Valid name starting with underscore"));
}

TEST_F(PrometheusMetricsExporterTest, InvalidLabelNames) {
    // Test invalid label names
    EXPECT_THROW(exporter_->register_counter("test", "Test", {""}), std::invalid_argument);
    EXPECT_THROW(exporter_->register_counter("test", "Test", {"123invalid"}), std::invalid_argument);
    EXPECT_THROW(exporter_->register_counter("test", "Test", {"invalid-name"}), std::invalid_argument);
    EXPECT_THROW(exporter_->register_counter("test", "Test", {"__reserved"}), std::invalid_argument);
    
    // Test valid label names
    EXPECT_NO_THROW(exporter_->register_counter("test", "Test", {"valid_name"}));
    EXPECT_NO_THROW(exporter_->register_counter("test2", "Test", {"valid_name_123"}));
    EXPECT_NO_THROW(exporter_->register_counter("test3", "Test", {"_valid_name"}));
}

TEST_F(PrometheusMetricsExporterTest, LabelValueEscaping) {
    exporter_->register_counter("test_counter", "Test counter", {"label"});
    
    // Test label values that need escaping
    std::map<std::string, std::string> labels_with_quotes = {{"label", "value with \"quotes\""}};
    std::map<std::string, std::string> labels_with_newlines = {{"label", "value with\nnewlines"}};
    std::map<std::string, std::string> labels_with_backslashes = {{"label", "value with\\backslashes"}};
    
    EXPECT_NO_THROW(exporter_->increment_counter("test_counter", labels_with_quotes));
    EXPECT_NO_THROW(exporter_->increment_counter("test_counter", labels_with_newlines));
    EXPECT_NO_THROW(exporter_->increment_counter("test_counter", labels_with_backslashes));
    
    std::string output = exporter_->generate_metrics_output();
    
    // Verify proper escaping in output
    EXPECT_TRUE(output.find("label=\"value with \\\"quotes\\\"\"") != std::string::npos);
    EXPECT_TRUE(output.find("label=\"value with\\nnewlines\"") != std::string::npos);
    EXPECT_TRUE(output.find("label=\"value with\\\\backslashes\"") != std::string::npos);
}

TEST_F(PrometheusMetricsExporterTest, ThreadSafety) {
    exporter_->register_counter("concurrent_counter", "Concurrent counter");
    exporter_->register_gauge("concurrent_gauge", "Concurrent gauge");
    
    const int num_threads = 10;
    const int operations_per_thread = 100;
    
    std::vector<std::thread> threads;
    
    // Start multiple threads that increment counter and update gauge
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, operations_per_thread]() {
            for (int j = 0; j < operations_per_thread; ++j) {
                exporter_->increment_counter("concurrent_counter", {}, 1.0);
                exporter_->set_gauge("concurrent_gauge", static_cast<double>(j), {});
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify that all increments were recorded
    std::string output = exporter_->generate_metrics_output();
    double expected_value = static_cast<double>(num_threads * operations_per_thread);
    
    // Look for the counter name and verify the value is correct
    EXPECT_TRUE(output.find("concurrent_counter") != std::string::npos);
    
    // Extract and verify the actual counter value using regex for more robust parsing
    std::regex counter_regex(R"(concurrent_counter\s+([\d\.]+))");
    std::smatch match;
    
    ASSERT_TRUE(std::regex_search(output, match, counter_regex));
    ASSERT_EQ(match.size(), 2);
    
    std::string value_str = match[1].str();
    // Trim any whitespace
    value_str.erase(0, value_str.find_first_not_of(" \t\r\n"));
    value_str.erase(value_str.find_last_not_of(" \t\r\n") + 1);
    
    ASSERT_FALSE(value_str.empty());
    
    double actual_value;
    try {
        actual_value = std::stod(value_str);
    } catch (const std::exception& e) {
        FAIL() << "Failed to parse counter value '" << value_str << "': " << e.what();
    }
    
    EXPECT_DOUBLE_EQ(expected_value, actual_value);
}
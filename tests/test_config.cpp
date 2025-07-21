#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <memory>
#include "../src/core/config.hpp"

class ConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a temporary directory for test files
        test_dir = std::filesystem::temp_directory_path() / "config_test";
        std::filesystem::create_directories(test_dir);
    }

    void TearDown() override {
        // Clean up test files
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

    std::string createTestConfigFile(const std::string& content) {
        auto config_path = test_dir / "test_config.ini";
        std::ofstream file(config_path);
        file << content;
        file.close();
        return config_path.string();
    }

    std::filesystem::path test_dir;
};

// Test Prometheus configuration parsing
TEST_F(ConfigTest, PrometheusConfigParsing) {
    std::string config_content = R"(
[Prometheus]
enabled = true
host = 127.0.0.1
port = 9091
metrics_path = /custom/metrics
health_path = /custom/health
scrape_interval_seconds = 30
replace_web_server = true
max_metrics_age_seconds = 600
)";

    std::string config_file = createTestConfigFile(config_content);
    Config::ConfigManager manager;
    ASSERT_TRUE(manager.load_configuration(config_file));

    auto config = manager.get_config();
    EXPECT_TRUE(config->prometheus.enabled);
    EXPECT_EQ(config->prometheus.host, "127.0.0.1");
    EXPECT_EQ(config->prometheus.port, 9091);
    EXPECT_EQ(config->prometheus.metrics_path, "/custom/metrics");
    EXPECT_EQ(config->prometheus.health_path, "/custom/health");
    EXPECT_EQ(config->prometheus.scrape_interval_seconds, 30);
    EXPECT_TRUE(config->prometheus.replace_web_server);
    EXPECT_EQ(config->prometheus.max_metrics_age_seconds, 600);
}

// Test Dynamic Learning configuration parsing
TEST_F(ConfigTest, DynamicLearningConfigParsing) {
    std::string config_content = R"(
[DynamicLearning]
enabled = true
learning_window_hours = 48
confidence_threshold = 0.99
min_samples_for_learning = 200
seasonal_detection_sensitivity = 0.9
baseline_update_interval_seconds = 600
enable_manual_overrides = false
threshold_change_max_percent = 25.0
)";

    std::string config_file = createTestConfigFile(config_content);
    Config::ConfigManager manager;
    ASSERT_TRUE(manager.load_configuration(config_file));

    auto config = manager.get_config();
    EXPECT_TRUE(config->dynamic_learning.enabled);
    EXPECT_EQ(config->dynamic_learning.learning_window_hours, 48);
    EXPECT_DOUBLE_EQ(config->dynamic_learning.confidence_threshold, 0.99);
    EXPECT_EQ(config->dynamic_learning.min_samples_for_learning, 200);
    EXPECT_DOUBLE_EQ(config->dynamic_learning.seasonal_detection_sensitivity, 0.9);
    EXPECT_EQ(config->dynamic_learning.baseline_update_interval_seconds, 600);
    EXPECT_FALSE(config->dynamic_learning.enable_manual_overrides);
    EXPECT_DOUBLE_EQ(config->dynamic_learning.threshold_change_max_percent, 25.0);
}

// Test Tier4 configuration parsing
TEST_F(ConfigTest, Tier4ConfigParsing) {
    std::string config_content = R"(
[Tier4]
enabled = true
prometheus_url = http://prometheus.example.com:9090
query_timeout_seconds = 45
evaluation_interval_seconds = 120
max_concurrent_queries = 20
auth_token = test_token_123
enable_circuit_breaker = false
circuit_breaker_failure_threshold = 10
circuit_breaker_recovery_timeout_seconds = 120
)";

    std::string config_file = createTestConfigFile(config_content);
    Config::ConfigManager manager;
    ASSERT_TRUE(manager.load_configuration(config_file));

    auto config = manager.get_config();
    EXPECT_TRUE(config->tier4.enabled);
    EXPECT_EQ(config->tier4.prometheus_url, "http://prometheus.example.com:9090");
    EXPECT_EQ(config->tier4.query_timeout_seconds, 45);
    EXPECT_EQ(config->tier4.evaluation_interval_seconds, 120);
    EXPECT_EQ(config->tier4.max_concurrent_queries, 20);
    EXPECT_EQ(config->tier4.auth_token, "test_token_123");
    EXPECT_FALSE(config->tier4.enable_circuit_breaker);
    EXPECT_EQ(config->tier4.circuit_breaker_failure_threshold, 10);
    EXPECT_EQ(config->tier4.circuit_breaker_recovery_timeout_seconds, 120);
}

// Test Memory Management configuration parsing
TEST_F(ConfigTest, MemoryManagementConfigParsing) {
    std::string config_content = R"(
[MemoryManagement]
enabled = true
max_memory_usage_mb = 2048
memory_pressure_threshold_mb = 1600
enable_object_pooling = false
eviction_check_interval_seconds = 120
eviction_threshold_percent = 85.0
enable_memory_compaction = false
state_object_ttl_seconds = 7200
)";

    std::string config_file = createTestConfigFile(config_content);
    Config::ConfigManager manager;
    ASSERT_TRUE(manager.load_configuration(config_file));

    auto config = manager.get_config();
    EXPECT_TRUE(config->memory_management.enabled);
    EXPECT_EQ(config->memory_management.max_memory_usage_mb, 2048);
    EXPECT_EQ(config->memory_management.memory_pressure_threshold_mb, 1600);
    EXPECT_FALSE(config->memory_management.enable_object_pooling);
    EXPECT_EQ(config->memory_management.eviction_check_interval_seconds, 120);
    EXPECT_DOUBLE_EQ(config->memory_management.eviction_threshold_percent, 85.0);
    EXPECT_FALSE(config->memory_management.enable_memory_compaction);
    EXPECT_EQ(config->memory_management.state_object_ttl_seconds, 7200);
}

// Test configuration validation - valid Prometheus config
TEST_F(ConfigTest, PrometheusConfigValidation_Valid) {
    Config::PrometheusConfig config;
    config.enabled = true;
    config.host = "0.0.0.0";
    config.port = 9090;
    config.metrics_path = "/metrics";
    config.health_path = "/health";
    config.scrape_interval_seconds = 15;
    config.max_metrics_age_seconds = 300;

    std::vector<std::string> errors;
    EXPECT_TRUE(Config::validate_prometheus_config(config, errors));
    EXPECT_TRUE(errors.empty());
}

// Test configuration validation - invalid Prometheus config
TEST_F(ConfigTest, PrometheusConfigValidation_Invalid) {
    Config::PrometheusConfig config;
    config.port = 70000; // Invalid port
    config.scrape_interval_seconds = 0; // Invalid interval
    config.max_metrics_age_seconds = 30; // Too low
    config.metrics_path = "metrics"; // Missing leading slash
    config.health_path = ""; // Empty path

    std::vector<std::string> errors;
    EXPECT_FALSE(Config::validate_prometheus_config(config, errors));
    EXPECT_EQ(errors.size(), 5);
}

// Test configuration validation - valid Dynamic Learning config
TEST_F(ConfigTest, DynamicLearningConfigValidation_Valid) {
    Config::DynamicLearningConfig config;
    config.learning_window_hours = 24;
    config.confidence_threshold = 0.95;
    config.min_samples_for_learning = 100;
    config.seasonal_detection_sensitivity = 0.8;
    config.baseline_update_interval_seconds = 300;
    config.threshold_change_max_percent = 50.0;

    std::vector<std::string> errors;
    EXPECT_TRUE(Config::validate_dynamic_learning_config(config, errors));
    EXPECT_TRUE(errors.empty());
}

// Test configuration validation - invalid Dynamic Learning config
TEST_F(ConfigTest, DynamicLearningConfigValidation_Invalid) {
    Config::DynamicLearningConfig config;
    config.learning_window_hours = 200; // Too high
    config.confidence_threshold = 0.3; // Too low
    config.min_samples_for_learning = 5; // Too low
    config.seasonal_detection_sensitivity = 1.5; // Too high
    config.baseline_update_interval_seconds = 30; // Too low
    config.threshold_change_max_percent = 600.0; // Too high

    std::vector<std::string> errors;
    EXPECT_FALSE(Config::validate_dynamic_learning_config(config, errors));
    EXPECT_EQ(errors.size(), 6);
}

// Test configuration validation - valid Tier4 config
TEST_F(ConfigTest, Tier4ConfigValidation_Valid) {
    Config::Tier4Config config;
    config.enabled = true;
    config.prometheus_url = "http://localhost:9090";
    config.query_timeout_seconds = 30;
    config.evaluation_interval_seconds = 60;
    config.max_concurrent_queries = 10;
    config.circuit_breaker_failure_threshold = 5;
    config.circuit_breaker_recovery_timeout_seconds = 60;

    std::vector<std::string> errors;
    EXPECT_TRUE(Config::validate_tier4_config(config, errors));
    EXPECT_TRUE(errors.empty());
}

// Test configuration validation - invalid Tier4 config
TEST_F(ConfigTest, Tier4ConfigValidation_Invalid) {
    Config::Tier4Config config;
    config.enabled = true;
    config.prometheus_url = ""; // Empty URL when enabled
    config.query_timeout_seconds = 0; // Too low
    config.evaluation_interval_seconds = 5; // Too low
    config.max_concurrent_queries = 200; // Too high
    config.circuit_breaker_failure_threshold = 100; // Too high
    config.circuit_breaker_recovery_timeout_seconds = 5; // Too low

    std::vector<std::string> errors;
    EXPECT_FALSE(Config::validate_tier4_config(config, errors));
    EXPECT_EQ(errors.size(), 6);
}

// Test configuration validation - valid Memory Management config
TEST_F(ConfigTest, MemoryManagementConfigValidation_Valid) {
    Config::MemoryManagementConfig config;
    config.max_memory_usage_mb = 1024;
    config.memory_pressure_threshold_mb = 800;
    config.eviction_check_interval_seconds = 60;
    config.eviction_threshold_percent = 80.0;
    config.state_object_ttl_seconds = 3600;

    std::vector<std::string> errors;
    EXPECT_TRUE(Config::validate_memory_management_config(config, errors));
    EXPECT_TRUE(errors.empty());
}

// Test configuration validation - invalid Memory Management config
TEST_F(ConfigTest, MemoryManagementConfigValidation_Invalid) {
    Config::MemoryManagementConfig config;
    config.max_memory_usage_mb = 32; // Too low
    config.memory_pressure_threshold_mb = 2048; // Higher than max
    config.eviction_check_interval_seconds = 5; // Too low
    config.eviction_threshold_percent = 30.0; // Too low
    config.state_object_ttl_seconds = 100; // Too low

    std::vector<std::string> errors;
    EXPECT_FALSE(Config::validate_memory_management_config(config, errors));
    EXPECT_EQ(errors.size(), 5);
}

// Test cross-component validation
TEST_F(ConfigTest, CrossComponentValidation) {
    Config::AppConfig config;
    
    // Test case 1: Prometheus and monitoring using same port with replace_web_server enabled
    config.prometheus.enabled = true;
    config.prometheus.replace_web_server = true;
    config.prometheus.port = 9090;
    config.monitoring.web_server_port = 9090;

    std::vector<std::string> errors;
    EXPECT_FALSE(Config::validate_app_config(config, errors));
    EXPECT_GT(errors.size(), 0);
    
    // Fix the port conflict
    errors.clear();
    config.prometheus.port = 9091;
    
    // Test case 2: Tier4 enabled without Prometheus
    config.tier4.enabled = true;
    config.prometheus.enabled = false;
    
    EXPECT_FALSE(Config::validate_app_config(config, errors));
    EXPECT_GT(errors.size(), 0);
}

// Test default configuration values
TEST_F(ConfigTest, DefaultConfigurationValues) {
    Config::AppConfig config;
    
    // Test Prometheus defaults
    EXPECT_TRUE(config.prometheus.enabled);
    EXPECT_EQ(config.prometheus.host, "0.0.0.0");
    EXPECT_EQ(config.prometheus.port, 9090);
    EXPECT_EQ(config.prometheus.metrics_path, "/metrics");
    EXPECT_EQ(config.prometheus.health_path, "/health");
    EXPECT_EQ(config.prometheus.scrape_interval_seconds, 15);
    EXPECT_FALSE(config.prometheus.replace_web_server);
    EXPECT_EQ(config.prometheus.max_metrics_age_seconds, 300);
    
    // Test Dynamic Learning defaults
    EXPECT_TRUE(config.dynamic_learning.enabled);
    EXPECT_EQ(config.dynamic_learning.learning_window_hours, 24);
    EXPECT_DOUBLE_EQ(config.dynamic_learning.confidence_threshold, 0.95);
    EXPECT_EQ(config.dynamic_learning.min_samples_for_learning, 100);
    EXPECT_DOUBLE_EQ(config.dynamic_learning.seasonal_detection_sensitivity, 0.8);
    EXPECT_EQ(config.dynamic_learning.baseline_update_interval_seconds, 300);
    EXPECT_TRUE(config.dynamic_learning.enable_manual_overrides);
    EXPECT_DOUBLE_EQ(config.dynamic_learning.threshold_change_max_percent, 50.0);
    
    // Test Tier4 defaults
    EXPECT_FALSE(config.tier4.enabled);
    EXPECT_EQ(config.tier4.prometheus_url, "http://localhost:9090");
    EXPECT_EQ(config.tier4.query_timeout_seconds, 30);
    EXPECT_EQ(config.tier4.evaluation_interval_seconds, 60);
    EXPECT_EQ(config.tier4.max_concurrent_queries, 10);
    EXPECT_EQ(config.tier4.auth_token, "");
    EXPECT_TRUE(config.tier4.enable_circuit_breaker);
    EXPECT_EQ(config.tier4.circuit_breaker_failure_threshold, 5);
    EXPECT_EQ(config.tier4.circuit_breaker_recovery_timeout_seconds, 60);
    
    // Test Memory Management defaults
    EXPECT_TRUE(config.memory_management.enabled);
    EXPECT_EQ(config.memory_management.max_memory_usage_mb, 1024);
    EXPECT_EQ(config.memory_management.memory_pressure_threshold_mb, 800);
    EXPECT_TRUE(config.memory_management.enable_object_pooling);
    EXPECT_EQ(config.memory_management.eviction_check_interval_seconds, 60);
    EXPECT_DOUBLE_EQ(config.memory_management.eviction_threshold_percent, 80.0);
    EXPECT_TRUE(config.memory_management.enable_memory_compaction);
    EXPECT_EQ(config.memory_management.state_object_ttl_seconds, 3600);
}

// Test boolean parsing variations
TEST_F(ConfigTest, BooleanParsing) {
    std::string config_content = R"(
[Prometheus]
enabled = true
replace_web_server = 1
port = 9091

[Monitoring]
web_server_port = 9090

[DynamicLearning]
enabled = yes
enable_manual_overrides = on

[Tier4]
enabled = false
enable_circuit_breaker = 0

[MemoryManagement]
enabled = no
enable_object_pooling = off
)";

    std::string config_file = createTestConfigFile(config_content);
    Config::ConfigManager manager;
    ASSERT_TRUE(manager.load_configuration(config_file));

    auto config = manager.get_config();
    EXPECT_TRUE(config->prometheus.enabled);
    EXPECT_TRUE(config->prometheus.replace_web_server);
    EXPECT_TRUE(config->dynamic_learning.enabled);
    EXPECT_TRUE(config->dynamic_learning.enable_manual_overrides);
    EXPECT_FALSE(config->tier4.enabled);
    EXPECT_FALSE(config->tier4.enable_circuit_breaker);
    EXPECT_FALSE(config->memory_management.enabled);
    EXPECT_FALSE(config->memory_management.enable_object_pooling);
}

// Test configuration file with missing sections (should use defaults)
TEST_F(ConfigTest, MissingSections) {
    std::string config_content = R"(
# Only basic config, new sections missing
log_source_type = file
)";

    std::string config_file = createTestConfigFile(config_content);
    Config::ConfigManager manager;
    ASSERT_TRUE(manager.load_configuration(config_file));

    auto config = manager.get_config();
    
    // Should use default values for all new sections
    EXPECT_TRUE(config->prometheus.enabled);
    EXPECT_TRUE(config->dynamic_learning.enabled);
    EXPECT_FALSE(config->tier4.enabled);
    EXPECT_TRUE(config->memory_management.enabled);
}

// Test invalid configuration file
TEST_F(ConfigTest, InvalidConfigurationFile) {
    Config::ConfigManager manager;
    EXPECT_FALSE(manager.load_configuration("/nonexistent/path/config.ini"));
}
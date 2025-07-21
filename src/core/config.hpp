#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

enum class LogLevel;
enum class LogComponent;

namespace Config {

namespace Keys {

// General Settings
constexpr const char *LOG_SOURCE_TYPE = "log_source_type";
constexpr const char *LOG_INPUT_PATH = "log_input_path";
constexpr const char *READER_STATE_PATH = "reader_state_path";
constexpr const char *ALLOWLIST_PATH = "allowlist_path";
constexpr const char *ALERTS_TO_STDOUT = "alerts_to_stdout";
constexpr const char *ALERTS_TO_FILE = "alerts_to_file";
constexpr const char *ALERT_OUTPUT_PATH = "alert_output_path";
constexpr const char *ALERT_THROTTLE_DURATION_SECONDS =
    "alert_throttle_duration_seconds";
constexpr const char *ALERT_THROTTLE_MAX_ALERTS = "alert_throttle_max_alerts";
constexpr const char *STATE_PERSISTENCE_ENABLED = "state_persistence_enabled";
constexpr const char *STATE_FILE_PATH = "state_file_path";
constexpr const char *STATE_SAVE_INTERVAL_EVENTS = "state_save_interval_events";
constexpr const char *STATE_PRUNING_ENABLED = "state_pruning_enabled";
constexpr const char *STATE_TTL_SECONDS = "state_ttl_seconds";
constexpr const char *STATE_PRUNE_INTERVAL_EVENTS =
    "state_prune_interval_events";
constexpr const char *LIVE_MONITORING_ENABLED = "live_monitoring_enabled";
constexpr const char *LIVE_MONITORING_SLEEP_SECONDS =
    "live_monitoring_sleep_seconds";
constexpr const char *STATE_FILE_MAGIC = "state_file_magic";
constexpr const char *ML_DATA_COLLECTION_ENABLED = "ml_data_collection_enabled";
constexpr const char *ML_DATA_COLLECTION_PATH = "ml_data_collection_path";

// Tier1 Settings
constexpr const char *T1_ENABLED = "enabled";
constexpr const char *T1_SLIDING_WINDOW_SECONDS =
    "sliding_window_duration_seconds";
constexpr const char *T1_MAX_REQUESTS_PER_IP = "max_requests_per_ip_in_window";
constexpr const char *T1_MAX_FAILED_LOGINS_PER_IP = "max_failed_logins_per_ip";
constexpr const char *T1_FAILED_LOGIN_STATUS_CODES =
    "failed_login_status_codes";
constexpr const char *T1_CHECK_UA_ANOMALIES = "check_user_agent_anomalies";
constexpr const char *T1_HEADLESS_BROWSER_STRINGS = "headless_browser_strings";
constexpr const char *T1_MIN_CHROME_VERSION = "min_chrome_version";
constexpr const char *T1_MIN_FIREFOX_VERSION = "min_firefox_version";
constexpr const char *T1_MAX_UNIQUE_UAS_PER_IP =
    "max_unique_uas_per_ip_in_window";
constexpr const char *T1_HTML_PATH_SUFFIXES = "html_path_suffixes";
constexpr const char *T1_HTML_EXACT_PATHS = "html_exact_paths";
constexpr const char *T1_ASSET_PATH_PREFIXES = "asset_path_prefixes";
constexpr const char *T1_ASSET_PATH_SUFFIXES = "asset_path_suffixes";
constexpr const char *T1_MIN_HTML_REQUESTS_FOR_RATIO =
    "min_html_requests_for_ratio_check";
constexpr const char *T1_MIN_ASSETS_PER_HTML_RATIO =
    "min_assets_per_html_ratio";
constexpr const char *T1_SUSPICIOUS_PATH_SUBSTRINGS =
    "suspicious_path_substrings";
constexpr const char *T1_SUSPICIOUS_UA_SUBSTRINGS = "suspicious_ua_substrings";
constexpr const char *T1_SENSITIVE_PATH_SUBSTRINGS =
    "sensitive_path_substrings";
constexpr const char *T1_SESSION_TRACKING_ENABLED = "session_tracking_enabled";
constexpr const char *T1_SESSION_KEY_COMPONENTS = "session_key_components";
constexpr const char *T1_SESSION_INACTIVITY_TTL_SECONDS =
    "session_inactivity_ttl_seconds";
constexpr const char *T1_MAX_FAILED_LOGINS_PER_SESSION =
    "max_failed_logins_per_session";
constexpr const char *T1_MAX_REQUESTS_PER_SESSION_IN_WINDOW =
    "max_requests_per_session_in_window";
constexpr const char *T1_MAX_UA_CHANGES_PER_SESSION =
    "max_ua_changes_per_session";
constexpr const char *T1_MAX_UNIQUE_PATHS_STORED_PER_IP =
    "max_unique_paths_stored_per_ip";
constexpr const char *T1_SCORE_MISSING_UA = "score_missing_ua";
constexpr const char *T1_SCORE_OUTDATED_BROWSER = "score_outdated_browser";
constexpr const char *T1_SCORE_KNOWN_BAD_UA = "score_known_bad_ua";
constexpr const char *T1_SCORE_HEADLESS_BROWSER = "score_headless_browser";
constexpr const char *T1_SCORE_UA_CYCLING = "score_ua_cycling";
constexpr const char *T1_SCORE_SUSPICIOUS_PATH = "score_suspicious_path";
constexpr const char *T1_SCORE_SENSITIVE_PATH_NEW_IP =
    "score_sensitive_path_new_ip";

// Tier2 Settings
constexpr const char *T2_ENABLED = "enabled";
constexpr const char *T2_Z_SCORE_THRESHOLD = "z_score_threshold";
constexpr const char *T2_MIN_SAMPLES_FOR_Z_SCORE = "min_samples_for_z_score";
constexpr const char *T2_HISTORICAL_DEVIATION_FACTOR =
    "historical_deviation_factor";

// Tier3 Settings
constexpr const char *T3_ENABLED = "enabled";
constexpr const char *T3_MODEL_PATH = "model_path";
constexpr const char *T3_ANOMALY_SCORE_THRESHOLD = "anomaly_score_threshold";
constexpr const char *T3_MODEL_METADATA_PATH = "model_metadata_path";
constexpr const char *T3_AUTO_RETRAINING_ENABLED =
    "automated_retraining_enabled";
constexpr const char *T3_RETRAINING_INTERVAL_S = "retraining_interval_seconds";
constexpr const char *T3_TRAINING_SCRIPT_PATH = "training_script_path";

// Alerting Settings
constexpr const char *AL_FILE_ENABLED = "file_enabled";
constexpr const char *AL_SYSLOG_ENABLED = "syslog_enabled";
constexpr const char *AL_HTTP_ENABLED = "http_enabled";
constexpr const char *AL_HTTP_WEBHOOK_URL = "http_webhook_url";

// Threat Intel Settings
constexpr const char *TI_ENABLED = "enabled";
constexpr const char *TI_FEED_URLS = "feed_urls";
constexpr const char *TI_UPDATE_INTERVAL_SECONDS = "update_interval_seconds";

// Mongo Settings
constexpr const char *MO_URI = "uri";
constexpr const char *MO_DATABASE = "database";
constexpr const char *MO_COLLECTION = "collection";
constexpr const char *MO_TIMESTAMP_FIELD_NAME = "timestamp_field_name";

// Logging Settings
constexpr const char *LOGGING_DEFAULT_LEVEL = "default_level";

// Monitoring Settings
constexpr const char *MONITORING_ENABLE_DEEP_TIMING = "enable_deep_timing";
constexpr const char *MONITORING_WEB_SERVER_HOST = "web_server_host";
constexpr const char *MONITORING_WEB_SERVER_PORT = "web_server_port";

// Prometheus Settings
constexpr const char *PROMETHEUS_ENABLED = "enabled";
constexpr const char *PROMETHEUS_HOST = "host";
constexpr const char *PROMETHEUS_PORT = "port";
constexpr const char *PROMETHEUS_METRICS_PATH = "metrics_path";
constexpr const char *PROMETHEUS_HEALTH_PATH = "health_path";
constexpr const char *PROMETHEUS_SCRAPE_INTERVAL_SECONDS = "scrape_interval_seconds";
constexpr const char *PROMETHEUS_REPLACE_WEB_SERVER = "replace_web_server";
constexpr const char *PROMETHEUS_MAX_METRICS_AGE_SECONDS = "max_metrics_age_seconds";

// Dynamic Learning Settings
constexpr const char *DL_ENABLED = "enabled";
constexpr const char *DL_LEARNING_WINDOW_HOURS = "learning_window_hours";
constexpr const char *DL_CONFIDENCE_THRESHOLD = "confidence_threshold";
constexpr const char *DL_MIN_SAMPLES_FOR_LEARNING = "min_samples_for_learning";
constexpr const char *DL_SEASONAL_DETECTION_SENSITIVITY = "seasonal_detection_sensitivity";
constexpr const char *DL_BASELINE_UPDATE_INTERVAL_SECONDS = "baseline_update_interval_seconds";
constexpr const char *DL_ENABLE_MANUAL_OVERRIDES = "enable_manual_overrides";
constexpr const char *DL_THRESHOLD_CHANGE_MAX_PERCENT = "threshold_change_max_percent";

// Tier4 Settings
constexpr const char *T4_ENABLED = "enabled";
constexpr const char *T4_PROMETHEUS_URL = "prometheus_url";
constexpr const char *T4_QUERY_TIMEOUT_SECONDS = "query_timeout_seconds";
constexpr const char *T4_EVALUATION_INTERVAL_SECONDS = "evaluation_interval_seconds";
constexpr const char *T4_MAX_CONCURRENT_QUERIES = "max_concurrent_queries";
constexpr const char *T4_AUTH_TOKEN = "auth_token";
constexpr const char *T4_ENABLE_CIRCUIT_BREAKER = "enable_circuit_breaker";
constexpr const char *T4_CIRCUIT_BREAKER_FAILURE_THRESHOLD = "circuit_breaker_failure_threshold";
constexpr const char *T4_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECONDS = "circuit_breaker_recovery_timeout_seconds";

// Memory Management Settings
constexpr const char *MM_ENABLED = "enabled";
constexpr const char *MM_MAX_MEMORY_USAGE_MB = "max_memory_usage_mb";
constexpr const char *MM_MEMORY_PRESSURE_THRESHOLD_MB = "memory_pressure_threshold_mb";
constexpr const char *MM_ENABLE_OBJECT_POOLING = "enable_object_pooling";
constexpr const char *MM_EVICTION_CHECK_INTERVAL_SECONDS = "eviction_check_interval_seconds";
constexpr const char *MM_EVICTION_THRESHOLD_PERCENT = "eviction_threshold_percent";
constexpr const char *MM_ENABLE_MEMORY_COMPACTION = "enable_memory_compaction";
constexpr const char *MM_STATE_OBJECT_TTL_SECONDS = "state_object_ttl_seconds";
} // namespace Keys

struct LoggingConfig {
  std::map<LogComponent, LogLevel> log_levels;
};

struct Tier1Config {
  bool enabled = true;
  uint64_t sliding_window_duration_seconds = 60;
  size_t max_requests_per_ip_in_window = 100;
  size_t max_failed_logins_per_ip = 5;
  std::vector<short> failed_login_status_codes = {401, 403};

  bool check_user_agent_anomalies = true;
  std::vector<std::string> headless_browser_substrings = {"HeadlessChrome",
                                                          "Puppeteer"};
  int min_chrome_version = 90;
  int min_firefox_version = 85;
  size_t max_unique_uas_per_ip_in_window = 3;

  std::vector<std::string> suspicious_path_substrings;
  std::vector<std::string> suspicious_ua_substrings;
  std::vector<std::string> sensitive_path_substrings;

  bool session_tracking_enabled = true;
  // Defines what makes a session unique. Can be a combination of "ip", "ua"
  std::vector<std::string> session_key_components = {"ip", "ua"};
  uint64_t session_inactivity_ttl_seconds = 1800; // 30 minutes

  uint32_t max_failed_logins_per_session = 10;
  uint32_t max_requests_per_session_in_window = 30;
  uint32_t max_ua_changes_per_session = 2;
  size_t max_unique_paths_stored_per_ip = 2000;

  std::vector<std::string> html_path_suffixes;
  std::vector<std::string> html_exact_paths;
  std::vector<std::string> asset_path_prefixes;
  std::vector<std::string> asset_path_suffixes;
  size_t min_html_requests_for_ratio_check = 5;
  double min_assets_per_html_ratio = 10.0;

  double score_missing_ua = 5.0;
  double score_outdated_browser = 10.0;
  double score_known_bad_ua = 75.0;
  double score_headless_browser = 40.0;
  double score_ua_cycling = 85.0;
  double score_suspicious_path = 95.0;
  double score_sensitive_path_new_ip = 80.0;
};

struct Tier2Config {
  bool enabled = true;
  double z_score_threshold = 3.5;
  size_t min_samples_for_z_score = 30;
  double historical_deviation_factor = 3.0;
};

struct Tier3Config {
  bool enabled = true;
  std::string model_path = "models/isolation_forest.onnx";
  double anomaly_score_threshold = 0.6;

  std::string model_metadata_path = "src/models/isolation_forest.json";
  bool automated_retraining_enabled = false;
  uint32_t retraining_interval_seconds = 86400; // Default: 24 hours
  std::string training_script_path = "ml/train.py";
};

struct AlertingConfig {
  bool file_enabled = false;
  bool syslog_enabled = false;
  bool http_enabled = false;
  std::string http_webhook_url;
};

struct ThreatIntelConfig {
  bool enabled = false;
  std::vector<std::string> feed_urls;
  uint32_t update_interval_seconds = 3600; // Default: 1 hour
};

struct MongoLogSourceConfig {
  std::string uri = "mongodb://localhost:27017";
  std::string database = "logs";
  std::string collection = "access";
  std::string timestamp_field_name = "timestamp";
};

struct MonitoringConfig {
  bool enable_deep_timing = false;
  std::string web_server_host = "0.0.0.0";
  int web_server_port = 9090;
};

struct PrometheusConfig {
  bool enabled = true;
  std::string host = "0.0.0.0";
  int port = 9090;
  std::string metrics_path = "/metrics";
  std::string health_path = "/health";
  uint32_t scrape_interval_seconds = 15;
  bool replace_web_server = false;
  uint32_t max_metrics_age_seconds = 300;
};

struct DynamicLearningConfig {
  bool enabled = true;
  uint32_t learning_window_hours = 24;
  double confidence_threshold = 0.95;
  uint32_t min_samples_for_learning = 100;
  double seasonal_detection_sensitivity = 0.8;
  uint32_t baseline_update_interval_seconds = 300;
  bool enable_manual_overrides = true;
  double threshold_change_max_percent = 50.0;
};

struct Tier4Config {
  bool enabled = false;
  std::string prometheus_url = "http://localhost:9090";
  uint32_t query_timeout_seconds = 30;
  uint32_t evaluation_interval_seconds = 60;
  uint32_t max_concurrent_queries = 10;
  std::string auth_token = "";
  bool enable_circuit_breaker = true;
  uint32_t circuit_breaker_failure_threshold = 5;
  uint32_t circuit_breaker_recovery_timeout_seconds = 60;
};

struct MemoryManagementConfig {
  bool enabled = true;
  size_t max_memory_usage_mb = 1024;
  size_t memory_pressure_threshold_mb = 800;
  bool enable_object_pooling = true;
  uint32_t eviction_check_interval_seconds = 60;
  double eviction_threshold_percent = 80.0;
  bool enable_memory_compaction = true;
  uint32_t state_object_ttl_seconds = 3600;
};

struct AppConfig {
  std::string log_source_type = "mongodb";
  std::string log_input_path = "data/sample_log.txt";
  std::string reader_state_path = "data/reader_state.dat";
  std::string allowlist_path = "data/allowlist.txt";
  bool alerts_to_stdout = true;
  bool alerts_to_file = false;
  std::string alert_output_path = "alerts.json";
  uint64_t alert_throttle_duration_seconds = 300; // 5 minutes default
  uint64_t alert_throttle_max_alerts = 10;

  bool state_persistence_enabled = true;
  std::string state_file_path = "data/engine_state.dat";
  uint64_t state_save_interval_events = 50000;
  bool state_pruning_enabled = true;
  uint64_t state_ttl_seconds = 604800; // 7 days
  uint64_t state_prune_interval_events = 100000;

  bool live_monitoring_enabled = false;
  uint64_t live_monitoring_sleep_seconds = 5;
  uint32_t state_file_magic = 0xADE57A7E;

  Tier1Config tier1;
  Tier2Config tier2;
  Tier3Config tier3;
  AlertingConfig alerting;
  ThreatIntelConfig threat_intel;
  MongoLogSourceConfig mongo_log_source;
  LoggingConfig logging;
  MonitoringConfig monitoring;
  PrometheusConfig prometheus;
  DynamicLearningConfig dynamic_learning;
  Tier4Config tier4;
  MemoryManagementConfig memory_management;

  bool ml_data_collection_enabled = false;
  std::string ml_data_collection_path = "data/training_features.csv";

  std::unordered_map<std::string, std::string> custom_settings;

  AppConfig() = default;
};

// Validation functions for configuration parameters
bool validate_prometheus_config(const PrometheusConfig& config, std::vector<std::string>& errors);
bool validate_dynamic_learning_config(const DynamicLearningConfig& config, std::vector<std::string>& errors);
bool validate_tier4_config(const Tier4Config& config, std::vector<std::string>& errors);
bool validate_memory_management_config(const MemoryManagementConfig& config, std::vector<std::string>& errors);
bool validate_app_config(const AppConfig& config, std::vector<std::string>& errors);

class ConfigManager {
public:
  ConfigManager() = default;
  bool load_configuration(const std::string &filepath);
  std::shared_ptr<const AppConfig> get_config() const;

private:
  std::string config_filepath_;
  std::shared_ptr<const AppConfig> current_config_ =
      std::make_shared<AppConfig>();
  mutable std::mutex config_mutex_;
};

} // namespace Config

#endif // CONFIG_HPP
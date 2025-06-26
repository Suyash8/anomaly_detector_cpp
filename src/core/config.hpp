#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Config {

// Define all config keys as constants to prevent typos and improve
// maintainability.
namespace Keys {
// General Settings
constexpr const char *LOG_INPUT_PATH = "log_input_path";
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
} // namespace Keys

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
};

struct AppConfig {
  std::string log_input_path = "data/sample_log.txt";
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

  std::unordered_map<std::string, std::string> custom_settings;

  AppConfig() = default;
};

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
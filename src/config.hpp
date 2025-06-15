#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace Config {

struct Tier1Config {
  bool enabled = true;
  uint64_t sliding_window_duration_seconds = 60;
  int max_requests_per_ip_in_window = 100;
  int max_failed_logins_per_ip = 5;

  bool check_user_agent_anomalies = true;
  int min_chrome_version = 90;
  int min_firefox_version = 85;
  int max_unique_uas_per_ip_in_window = 3;

  std::vector<std::string> suspicious_path_substrings;
  std::vector<std::string> suspicious_ua_substrings;
  std::vector<std::string> sensitive_path_substrings;

  uint64_t inactive_state_ttl_seconds = 86400;

  std::vector<std::string> html_path_suffixes;
  std::vector<std::string> html_exact_paths;
  std::vector<std::string> asset_path_prefixes;
  std::vector<std::string> asset_path_suffixes;
  int min_html_requests_for_ratio_check = 5;
  double min_assets_per_html_ratio = 10.0;
};

struct Tier2Config {
  bool enabled = true;
  double z_score_threshold = 3.5;
  int min_samples_for_z_score = 30;
  double historical_deviation_factor = 3.0;
};

struct AppConfig {
  std::string log_input_path = "data/sample_log.txt";
  std::string allowlist_path = "data/allowlist.txt";
  bool alerts_to_stdout = true;
  bool alerts_to_file = false;
  std::string alert_output_path = "alerts.json";

  Tier1Config tier1;
  Tier2Config tier2;

  std::unordered_map<std::string, std::string> custom_settings;

  AppConfig() = default;
};

extern AppConfig GlobalAppConfig;

// Function to load configuration from a file into GlobalAppConfig
bool load_configuration(std::string &config_filepath);

// Function to get a const reference to the global config
const AppConfig &get_app_config();
} // namespace Config

#endif // CONFIG_HPP
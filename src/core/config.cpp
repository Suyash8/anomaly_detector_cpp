#include "config.hpp"
#include "utils/utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace Config {

AppConfig GlobalAppConfig;

// Convert string to boolean using common truthy values
bool string_to_bool(std::string &val_str_raw) {
  std::string val_str = Utils::trim_copy(val_str_raw);
  std::transform(val_str.begin(), val_str.end(), val_str.begin(), ::tolower);
  return (val_str == "true" || val_str == "1" || val_str == "yes" ||
          val_str == "on");
}

bool parse_config_into(const std::string &filepath, AppConfig &config) {
  std::cout << "Attempting to load configuration from " << filepath
            << std::endl;
  std::ifstream config_file(filepath);

  if (!config_file.is_open()) {
    std::cerr << "Warning: Could not open config file '" << filepath
              << "'. Using default configuration values." << std::endl;
    return false;
  }

  std::string line;
  std::string current_section;

  int line_num = 0;
  while (std::getline(config_file, line)) {
    line_num++;
    std::string trimmed_line = Utils::trim_copy(line);

    // Skip empty lines and comments
    if (trimmed_line.empty() || trimmed_line[0] == '#' ||
        trimmed_line[0] == ';')
      continue;

    // Section header [SectionName]
    if (trimmed_line[0] == '[' && trimmed_line.back() == ']') {
      current_section =
          Utils::trim_copy(trimmed_line.substr(1, trimmed_line.length() - 2));
      continue;
    }

    // Key-value pair parsing
    size_t delimiter_pos = trimmed_line.find('=');
    if (delimiter_pos == std::string::npos) {
      std::cerr << "Warning (Config Line " << line_num
                << "): Invalid format (missing '='): " << trimmed_line
                << std::endl;
      continue;
    }

    std::string key = Utils::trim_copy(trimmed_line.substr(0, delimiter_pos));
    std::string value =
        Utils::trim_copy(trimmed_line.substr(delimiter_pos + 1));

    if (key.empty()) {
      std::cerr << "Warning (Config Line " << line_num << "): Empty key found."
                << std::endl;
      continue;
    }

    try {
      // Global (non-section) keys
      if (current_section.empty()) {
        if (key == Keys::LOG_INPUT_PATH)
          config.log_input_path = value;
        else if (key == Keys::ALLOWLIST_PATH)
          config.allowlist_path = value;
        else if (key == Keys::ALERTS_TO_STDOUT)
          config.alerts_to_stdout = string_to_bool(value);
        else if (key == Keys::ALERTS_TO_FILE)
          config.alerts_to_file = string_to_bool(value);
        else if (key == Keys::ALERT_OUTPUT_PATH)
          config.alert_output_path = value;
        else if (key == Keys::STATE_PERSISTENCE_ENABLED)
          config.state_persistence_enabled = string_to_bool(value);
        else if (key == Keys::STATE_FILE_PATH)
          config.state_file_path = value;
        else if (key == Keys::STATE_SAVE_INTERVAL_EVENTS)
          config.state_save_interval_events =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.state_save_interval_events);
        else if (key == Keys::STATE_PRUNING_ENABLED)
          config.state_pruning_enabled = string_to_bool(value);
        else if (key == Keys::STATE_TTL_SECONDS)
          config.state_ttl_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.state_ttl_seconds);
        else if (key == Keys::STATE_PRUNE_INTERVAL_EVENTS)
          config.state_prune_interval_events =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.state_prune_interval_events);
        else if (key == Keys::LIVE_MONITORING_ENABLED)
          config.live_monitoring_enabled = string_to_bool(value);
        else if (key == Keys::LIVE_MONITORING_SLEEP_SECONDS)
          config.live_monitoring_sleep_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.live_monitoring_sleep_seconds);
        else if (key == Keys::STATE_FILE_MAGIC)
          config.state_file_magic =
              Utils::string_to_number<uint32_t>(value).value_or(
                  config.state_file_magic);
        else
          config.custom_settings[key] = value;

        // Tier 1 settings
      } else if (current_section == "Tier1") {
        if (key == Keys::T1_ENABLED)
          config.tier1.enabled = string_to_bool(value);
        else if (key == Keys::T1_SLIDING_WINDOW_SECONDS)
          config.tier1.sliding_window_duration_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  config.tier1.sliding_window_duration_seconds);
        else if (key == Keys::T1_MAX_REQUESTS_PER_IP)
          config.tier1.max_requests_per_ip_in_window =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_requests_per_ip_in_window);
        else if (key == Keys::T1_MAX_FAILED_LOGINS_PER_IP)
          config.tier1.max_failed_logins_per_ip =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_failed_logins_per_ip);
        else if (key == Keys::T1_FAILED_LOGIN_STATUS_CODES) {
          std::vector<short> codes;
          std::string code_str;
          std::istringstream stream(value);
          while (std::getline(stream, code_str, ','))
            if (auto code_opt =
                    Utils::string_to_number<short>(Utils::trim_copy(code_str)))
              codes.push_back(*code_opt);

          if (!codes.empty())
            config.tier1.failed_login_status_codes = codes;
        } else if (key == Keys::T1_CHECK_UA_ANOMALIES)
          config.tier1.check_user_agent_anomalies = string_to_bool(value);
        else if (key == Keys::T1_HEADLESS_BROWSER_STRINGS)
          config.tier1.headless_browser_substrings =
              Utils::split_string(value, ',');
        else if (key == Keys::T1_MIN_CHROME_VERSION)
          config.tier1.min_chrome_version =
              Utils::string_to_number<int>(value).value_or(
                  config.tier1.min_chrome_version);
        else if (key == Keys::T1_MIN_FIREFOX_VERSION)
          config.tier1.min_firefox_version =
              Utils::string_to_number<int>(value).value_or(
                  config.tier1.min_firefox_version);
        else if (key == Keys::T1_MAX_UNIQUE_UAS_PER_IP)
          config.tier1.max_unique_uas_per_ip_in_window =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.max_unique_uas_per_ip_in_window);
        else if (key == Keys::T1_HTML_PATH_SUFFIXES)
          config.tier1.html_path_suffixes = Utils::split_string(value, ',');
        else if (key == Keys::T1_HTML_EXACT_PATHS)
          config.tier1.html_exact_paths = Utils::split_string(value, ',');
        else if (key == Keys::T1_ASSET_PATH_PREFIXES)
          config.tier1.asset_path_prefixes = Utils::split_string(value, ',');
        else if (key == Keys::T1_ASSET_PATH_SUFFIXES)
          config.tier1.asset_path_suffixes = Utils::split_string(value, ',');
        else if (key == Keys::T1_MIN_HTML_REQUESTS_FOR_RATIO)
          config.tier1.min_html_requests_for_ratio_check =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier1.min_html_requests_for_ratio_check);
        else if (key == Keys::T1_MIN_ASSETS_PER_HTML_RATIO)
          config.tier1.min_assets_per_html_ratio =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.min_assets_per_html_ratio);

        // Suspicious path/UA/sensitive substrings
        else if (key == Keys::T1_SUSPICIOUS_PATH_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              config.tier1.suspicious_path_substrings.push_back(trimmed_substr);
          }
        } else if (key == Keys::T1_SUSPICIOUS_UA_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              config.tier1.suspicious_ua_substrings.push_back(trimmed_substr);
          }
        } else if (key == Keys::T1_SENSITIVE_PATH_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              config.tier1.sensitive_path_substrings.push_back(trimmed_substr);
          }
        } else if (key == Keys::T1_SCORE_MISSING_UA)
          config.tier1.score_missing_ua =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_missing_ua);
        else if (key == Keys::T1_SCORE_OUTDATED_BROWSER)
          config.tier1.score_outdated_browser =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_outdated_browser);
        else if (key == Keys::T1_SCORE_KNOWN_BAD_UA)
          config.tier1.score_known_bad_ua =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_known_bad_ua);
        else if (key == Keys::T1_SCORE_HEADLESS_BROWSER)
          config.tier1.score_headless_browser =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_headless_browser);
        else if (key == Keys::T1_SCORE_UA_CYCLING)
          config.tier1.score_ua_cycling =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_ua_cycling);
        else if (key == Keys::T1_SCORE_SUSPICIOUS_PATH)
          config.tier1.score_suspicious_path =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_suspicious_path);
        else if (key == Keys::T1_SCORE_SENSITIVE_PATH_NEW_IP)
          config.tier1.score_sensitive_path_new_ip =
              Utils::string_to_number<double>(value).value_or(
                  config.tier1.score_sensitive_path_new_ip);

        // Tier 2 settings
      } else if (current_section == "Tier2") {
        if (key == Keys::T2_ENABLED)
          config.tier2.enabled = string_to_bool(value);
        else if (key == Keys::T2_Z_SCORE_THRESHOLD)
          config.tier2.z_score_threshold =
              Utils::string_to_number<double>(value).value_or(
                  config.tier2.z_score_threshold);
        else if (key == Keys::T2_MIN_SAMPLES_FOR_Z_SCORE)
          config.tier2.min_samples_for_z_score =
              Utils::string_to_number<size_t>(value).value_or(
                  config.tier2.min_samples_for_z_score);
        else if (key == Keys::T2_HISTORICAL_DEVIATION_FACTOR)
          config.tier2.historical_deviation_factor =
              Utils::string_to_number<double>(value).value_or(
                  config.tier2.historical_deviation_factor);

        // Tier 3 settings
      } else if (current_section == "Tier3") {
        if (key == Keys::T3_ENABLED)
          config.tier3.enabled = string_to_bool(value);
        else if (key == Keys::T3_MODEL_PATH)
          config.tier3.model_path = value;
        else if (key == Keys::T3_ANOMALY_SCORE_THRESHOLD)
          config.tier3.anomaly_score_threshold =
              Utils::string_to_number<double>(value).value_or(
                  config.tier3.anomaly_score_threshold);
      }
    } catch (const std::invalid_argument &e) {
      std::cerr << "Warning (Config Line " << line_num
                << "): Invalid value for key '" << key << "': '" << value
                << "' - " << e.what() << std::endl;
    } catch (const std::out_of_range &e) {
      std::cerr << "Warning (Config Line " << line_num
                << "): Value out of range for key '" << key << "': '" << value
                << "' - " << e.what() << std::endl;
    }
  }

  config_file.close();
  std::cout << "Configuration loaded successfully from " << filepath
            << std::endl;
  return true;
}

bool ConfigManager::load_configuration(const std::string &filepath) {
  config_filepath_ = filepath;
  auto new_config = std::make_shared<AppConfig>();

  // Use the parsing logic to fill the new config object
  if (!parse_config_into(filepath, *new_config)) {
    std::cerr << "Failed to parse configuration file: " << filepath
              << ". Keeping existing settings." << std::endl;
    return false;
  }

  // Atomically swap the pointer
  std::lock_guard<std::mutex> lock(config_mutex_);
  current_config_ = new_config;
  std::cout << "Configuration loaded successfully from " << config_filepath_
            << std::endl;
  return true;
}

std::shared_ptr<const AppConfig> ConfigManager::get_config() const {
  std::lock_guard<std::mutex> lock(config_mutex_);
  return current_config_;
}

} // namespace Config
#include "config.hpp"
#include "utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
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

// Load configuration file into global config structure
bool load_configuration(std::string &config_filepath) {
  std::cout << "Attempting to load configuration from " << config_filepath
            << std::endl;
  std::ifstream config_file(config_filepath);

  if (!config_file.is_open()) {
    std::cerr << "Warning: Could not open config file '" << config_filepath
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
          GlobalAppConfig.log_input_path = value;
        else if (key == Keys::ALLOWLIST_PATH)
          GlobalAppConfig.allowlist_path = value;
        else if (key == Keys::ALERTS_TO_STDOUT)
          GlobalAppConfig.alerts_to_stdout = string_to_bool(value);
        else if (key == Keys::ALERTS_TO_FILE)
          GlobalAppConfig.alerts_to_file = string_to_bool(value);
        else if (key == Keys::ALERT_OUTPUT_PATH)
          GlobalAppConfig.alert_output_path = value;
        else
          GlobalAppConfig.custom_settings[key] = value;

        // Tier 1 settings
      } else if (current_section == "Tier1") {
        if (key == Keys::T1_ENABLED)
          GlobalAppConfig.tier1.enabled = string_to_bool(value);
        else if (key == Keys::T1_SLIDING_WINDOW_SECONDS)
          GlobalAppConfig.tier1.sliding_window_duration_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  GlobalAppConfig.tier1.sliding_window_duration_seconds);
        else if (key == Keys::T1_MAX_REQUESTS_PER_IP)
          GlobalAppConfig.tier1.max_requests_per_ip_in_window =
              Utils::string_to_number<size_t>(value).value_or(
                  GlobalAppConfig.tier1.max_requests_per_ip_in_window);
        else if (key == Keys::T1_MAX_FAILED_LOGINS_PER_IP)
          GlobalAppConfig.tier1.max_failed_logins_per_ip =
              Utils::string_to_number<size_t>(value).value_or(
                  GlobalAppConfig.tier1.max_failed_logins_per_ip);
        else if (key == Keys::T1_FAILED_LOGIN_STATUS_CODES) {
          std::vector<short> codes;
          std::string code_str;
          std::istringstream stream(value);
          while (std::getline(stream, code_str, ','))
            if (auto code_opt =
                    Utils::string_to_number<short>(Utils::trim_copy(code_str)))
              codes.push_back(*code_opt);

          if (!codes.empty())
            GlobalAppConfig.tier1.failed_login_status_codes = codes;
        } else if (key == Keys::T1_CHECK_UA_ANOMALIES)
          GlobalAppConfig.tier1.check_user_agent_anomalies =
              string_to_bool(value);
        else if (key == Keys::T1_MIN_CHROME_VERSION)
          GlobalAppConfig.tier1.min_chrome_version =
              Utils::string_to_number<int>(value).value_or(
                  GlobalAppConfig.tier1.min_chrome_version);
        else if (key == Keys::T1_MIN_FIREFOX_VERSION)
          GlobalAppConfig.tier1.min_firefox_version =
              Utils::string_to_number<int>(value).value_or(
                  GlobalAppConfig.tier1.min_firefox_version);
        else if (key == Keys::T1_MAX_UNIQUE_UAS_PER_IP)
          GlobalAppConfig.tier1.max_unique_uas_per_ip_in_window =
              Utils::string_to_number<size_t>(value).value_or(
                  GlobalAppConfig.tier1.max_unique_uas_per_ip_in_window);
        else if (key == Keys::T1_INACTIVE_STATE_TTL_SECONDS)
          GlobalAppConfig.tier1.inactive_state_ttl_seconds =
              Utils::string_to_number<uint64_t>(value).value_or(
                  GlobalAppConfig.tier1.inactive_state_ttl_seconds);
        else if (key == Keys::T1_HTML_PATH_SUFFIXES)
          GlobalAppConfig.tier1.html_path_suffixes =
              Utils::split_string(value, ',');
        else if (key == Keys::T1_HTML_EXACT_PATHS)
          GlobalAppConfig.tier1.html_exact_paths =
              Utils::split_string(value, ',');
        else if (key == Keys::T1_ASSET_PATH_PREFIXES)
          GlobalAppConfig.tier1.asset_path_prefixes =
              Utils::split_string(value, ',');
        else if (key == Keys::T1_ASSET_PATH_SUFFIXES)
          GlobalAppConfig.tier1.asset_path_suffixes =
              Utils::split_string(value, ',');
        else if (key == Keys::T1_MIN_HTML_REQUESTS_FOR_RATIO)
          GlobalAppConfig.tier1.min_html_requests_for_ratio_check =
              Utils::string_to_number<size_t>(value).value_or(
                  GlobalAppConfig.tier1.min_html_requests_for_ratio_check);
        else if (key == Keys::T1_MIN_ASSETS_PER_HTML_RATIO)
          GlobalAppConfig.tier1.min_assets_per_html_ratio =
              Utils::string_to_number<double>(value).value_or(
                  GlobalAppConfig.tier1.min_assets_per_html_ratio);

        // Suspicious path/UA/sensitive substrings
        else if (key == Keys::T1_SUSPICIOUS_PATH_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              GlobalAppConfig.tier1.suspicious_path_substrings.push_back(
                  trimmed_substr);
          }
        } else if (key == Keys::T1_SUSPICIOUS_UA_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              GlobalAppConfig.tier1.suspicious_ua_substrings.push_back(
                  trimmed_substr);
          }
        } else if (key == Keys::T1_SENSITIVE_PATH_SUBSTRINGS) {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              GlobalAppConfig.tier1.sensitive_path_substrings.push_back(
                  trimmed_substr);
          }
        }

        // Tier 2 settings
      } else if (current_section == "Tier2") {
        if (key == Keys::T2_ENABLED)
          GlobalAppConfig.tier2.enabled = string_to_bool(value);
        else if (key == Keys::T2_Z_SCORE_THRESHOLD)
          GlobalAppConfig.tier2.z_score_threshold =
              Utils::string_to_number<double>(value).value_or(
                  GlobalAppConfig.tier2.z_score_threshold);
        else if (key == Keys::T2_MIN_SAMPLES_FOR_Z_SCORE)
          GlobalAppConfig.tier2.min_samples_for_z_score =
              Utils::string_to_number<size_t>(value).value_or(
                  GlobalAppConfig.tier2.min_samples_for_z_score);
        else if (key == Keys::T2_HISTORICAL_DEVIATION_FACTOR)
          GlobalAppConfig.tier2.historical_deviation_factor =
              Utils::string_to_number<double>(value).value_or(
                  GlobalAppConfig.tier2.historical_deviation_factor);

        // Tier 3 settings
      } else if (current_section == "Tier3") {
        if (key == Keys::T3_ENABLED)
          GlobalAppConfig.tier3.enabled = string_to_bool(value);
        else if (key == Keys::T3_MODEL_PATH)
          GlobalAppConfig.tier3.model_path = value;
        else if (key == Keys::T3_ANOMALY_SCORE_THRESHOLD)
          GlobalAppConfig.tier3.anomaly_score_threshold =
              Utils::string_to_number<double>(value).value_or(
                  GlobalAppConfig.tier3.anomaly_score_threshold);
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
  std::cout << "Configuration loaded successfully from " << config_filepath
            << std::endl;
  return true;
}

// Accessor for global app config
const AppConfig &get_app_config() { return GlobalAppConfig; }

} // namespace Config
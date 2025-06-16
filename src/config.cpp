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

bool string_to_bool(std::string &val_str_raw) {
  std::string val_str = Utils::trim_copy(val_str_raw);
  std::transform(val_str.begin(), val_str.end(), val_str.begin(), ::tolower);
  return (val_str == "true" || val_str == "1" || val_str == "yes" ||
          val_str == "on");
}

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

    // Skip empty lines or lines starting with '#' or ';' (comments)
    if (trimmed_line.empty() || trimmed_line[0] == '#' ||
        trimmed_line[0] == ';')
      continue;

    // Lines declaring a section [Tier1]
    if (trimmed_line[0] == '[' && trimmed_line.back() == ']') {
      current_section =
          Utils::trim_copy(trimmed_line.substr(1, trimmed_line.length() - 2));
      continue;
    }

    // Find the position of the '=' delimiter
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

    // Assign values to GlobalAppConfig based on the key
    // This part will grow as more config options are added.
    // Using if-else if. A map could be used for more complex scenarios.

    try {
      if (current_section.empty()) {

        if (key == "log_input_path")
          GlobalAppConfig.log_input_path = value;
        else if (key == "allowlist_path")
          GlobalAppConfig.allowlist_path = value;
        else if (key == "alerts_to_stdout")
          GlobalAppConfig.alerts_to_stdout = string_to_bool(value);
        else if (key == "alerts_to_file")
          GlobalAppConfig.alerts_to_file = string_to_bool(value);
        else if (key == "alert_output_path")
          GlobalAppConfig.alert_output_path = value;
        else
          GlobalAppConfig.custom_settings[key] = value;
      } else if (current_section == "Tier1") {
        if (key == "enabled")
          GlobalAppConfig.tier1.enabled = string_to_bool(value);
        else if (key == "sliding_window_duration_seconds")
          GlobalAppConfig.tier1.sliding_window_duration_seconds =
              *Utils::string_to_number<uint64_t>(value);
        else if (key == "max_requests_per_ip_in_window")
          GlobalAppConfig.tier1.max_requests_per_ip_in_window =
              *Utils::string_to_number<int>(value);
        else if (key == "max_failed_logins_per_ip")
          GlobalAppConfig.tier1.max_failed_logins_per_ip =
              *Utils::string_to_number<int>(value);
        else if (key == "check_user_agent_anomalies")
          GlobalAppConfig.tier1.check_user_agent_anomalies =
              string_to_bool(value);
        else if (key == "min_chrome_version")
          GlobalAppConfig.tier1.min_chrome_version =
              *Utils::string_to_number<int>(value);
        else if (key == "min_firefox_version")
          GlobalAppConfig.tier1.min_firefox_version =
              *Utils::string_to_number<int>(value);
        else if (key == "max_unique_uas_per_ip_in_window")
          GlobalAppConfig.tier1.max_unique_uas_per_ip_in_window =
              *Utils::string_to_number<int>(value);
        else if (key == "inactive_state_ttl_seconds")
          GlobalAppConfig.tier1.inactive_state_ttl_seconds =
              *Utils::string_to_number<uint64_t>(value);
        else if (key == "html_path_suffixes")
          GlobalAppConfig.tier1.html_path_suffixes =
              Utils::split_string(value, ',');
        else if (key == "html_exact_paths")
          GlobalAppConfig.tier1.html_exact_paths =
              Utils::split_string(value, ',');
        else if (key == "asset_path_prefixes")
          GlobalAppConfig.tier1.asset_path_prefixes =
              Utils::split_string(value, ',');
        else if (key == "asset_path_suffixes")
          GlobalAppConfig.tier1.asset_path_suffixes =
              Utils::split_string(value, ',');
        else if (key == "min_html_requests_for_ratio_check")
          GlobalAppConfig.tier1.min_html_requests_for_ratio_check =
              *Utils::string_to_number<int>(value);
        else if (key == "min_assets_per_html_ratio")
          GlobalAppConfig.tier1.min_assets_per_html_ratio =
              *Utils::string_to_number<double>(value);

        else if (key == "suspicious_path_substrings") {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              GlobalAppConfig.tier1.suspicious_path_substrings.push_back(
                  trimmed_substr);
          }
        } else if (key == "suspicious_ua_substrings") {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              GlobalAppConfig.tier1.suspicious_ua_substrings.push_back(
                  trimmed_substr);
          }
        } else if (key == "sensitive_path_substrings") {
          std::string current_substr;
          std::istringstream substr_stream(value);
          while (std::getline(substr_stream, current_substr, ',')) {
            std::string trimmed_substr = Utils::trim_copy(current_substr);
            if (!trimmed_substr.empty())
              GlobalAppConfig.tier1.sensitive_path_substrings.push_back(
                  trimmed_substr);
          }
        }
      } else if (current_section == "Tier2") {
        if (key == "enabled")
          GlobalAppConfig.tier2.enabled = string_to_bool(value);
        else if (key == "z_score_threshold")
          GlobalAppConfig.tier2.z_score_threshold =
              *Utils::string_to_number<double>(value);
        else if (key == "min_samples_for_z_score")
          GlobalAppConfig.tier2.min_samples_for_z_score =
              *Utils::string_to_number<int>(value);
        else if (key == "historical_deviation_factor")
          GlobalAppConfig.tier2.historical_deviation_factor =
              *Utils::string_to_number<double>(value);
      } else if (current_section == "Tier3") {
        if (key == "enabled")
          GlobalAppConfig.tier3.enabled = string_to_bool(value);
        else if (key == "model_path")
          GlobalAppConfig.tier3.model_path = value;
        else if (key == "anomaly_score_threshold")
          GlobalAppConfig.tier3.anomaly_score_threshold =
              *Utils::string_to_number<double>(value);
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

const AppConfig &get_app_config() { return GlobalAppConfig; }

} // namespace Config
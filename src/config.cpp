#include "config.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

namespace Config {
AppConfig GlobalAppConfig;

bool string_to_bool(std::string &val_str_raw) {
  std::string val_str = Utils::trim_copy(val_str_raw);
  std::transform(val_str.begin(), val_str.end(), val_str.begin(), ::tolower);

  if (val_str == "true" || val_str == "1" || val_str == "yes" ||
      val_str == "on")
    return true;
  return false;
}

bool load_configuration(std::string &config_filepath) {
  std::cout << "Attempting to load configuration from " << config_filepath
            << std::endl;
  std::ifstream config_file(config_filepath);

  if (!config_file.is_open()) {
    std::cerr << "Warning: Could not open config file '" << config_filepath
              << "'. Using default configuration values." << std::endl;
    // GlobalAppConfig is already initialized with defaults, so we can just
    // return false.
    return false;
  }

  std::string line;
  int line_num = 0;
  while (std::getline(config_file, line)) {
    line_num++;
    std::string trimmed_line = Utils::trim_copy(line);

    // Skip empty lines or lines starting with '#' or ';' (comments)
    if (trimmed_line.empty() || trimmed_line[0] == '#' ||
        trimmed_line[0] == ';')
      continue;

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

    // std::cout << "Config: Key='" << key << "', Value='" << value << "'" <<
    // std::endl;

    // Assign values to GlobalAppConfig based on the key
    // This part will grow as more config options are added.
    // Using if-else if. A map could be used for more complex scenarios.

    try {
      if (key == "log_input_path")
        GlobalAppConfig.log_input_path = value;
      else if (key == "allowlist_path")
        GlobalAppConfig.allowlist_path = value;
      else if (key == "alerts_to_stdout")
        GlobalAppConfig.alerts_to_stdout = string_to_bool(value);
      else if (key == "tier1_enabled")
        GlobalAppConfig.tier1_enabled = string_to_bool(value);
      else if (key == "tier1_max_requests_per_ip_in_window")
        GlobalAppConfig.tier1_max_requests_per_ip_in_window =
            *Utils::string_to_number<int>(value);
      else if (key == "tier1_window_duration_seconds")
        GlobalAppConfig.tier1_window_duration_seconds =
            *Utils::string_to_number<uint64_t>(value);
      else if (key == "tier1_max_failed_logins_per_ip")
        GlobalAppConfig.tier1_max_failed_logins_per_ip =
            *Utils::string_to_number<int>(value);
      // Add more else if blocks for other settings
      else {
        // std::cout << "Info (Config): Unknown configuration key '" << key <<
        //     "'" << std::endl;
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
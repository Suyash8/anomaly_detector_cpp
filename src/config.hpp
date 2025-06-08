#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>
#include <string>
namespace Config {
struct AppConfig {
  std::string log_input_path = "data/sample_log.txt";
  std::string allowlist_path = "data/allowlist.txt";
  bool alerts_to_stdout = true;

  // Tier 1 related settings
  bool tier1_enabled = true;
  int tier1_max_requests_per_ip_in_window = 500;
  uint64_t tier1_window_duration_seconds = 60;
  int tier1_max_failed_logins_per_ip = 5;

  // More settings to be added as needed

  AppConfig() = default;
};

extern AppConfig GlobalAppConfig;

// Function to load configuration from a file into GlobalAppConfig
bool load_configuration(std::string &config_filepath);

// Function to get a const reference to the global config
const AppConfig &get_app_config();
} // namespace Config

#endif // CONFIG_HPP
#include "rule_engine.hpp"
#include "alert_manager.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "utils.hpp"

#include <fstream>
#include <iostream>
#include <string>

RuleEngine::RuleEngine(AlertManager &manager, const Config::AppConfig &cfg)
    : alert_mgr(manager), app_config(cfg) {
  std::cout << "\nRuleEngine created and initialised" << std::endl;

  if (!app_config.allowlist_path.empty()) {
    if (load_ip_allowlist(app_config.allowlist_path))
      std::cout << "IP Allowlist loaded successfully: "
                << ip_allowlist_cache.size() << " entries" << std::endl;
    else
      std::cerr << "Warning: Failed to load IP allowlist from: "
                << app_config.allowlist_path << std::endl;
  }
}

RuleEngine::~RuleEngine() {
  // std::cout << "RuleEngine destroyed." << std::endl;
  // Cleanup if needed
}

bool RuleEngine::load_ip_allowlist(const std::string &filepath) {
  std::ifstream allowlist_file(filepath);
  if (!allowlist_file.is_open())
    return false;
  std::string ip_line;
  while (std::getline(allowlist_file, ip_line)) {
    std::string trimmed_ip = Utils::trim_copy(ip_line);
    if (!trimmed_ip.empty() && trimmed_ip[0] != '#')
      ip_allowlist_cache.insert(trimmed_ip);
  }
  return true;
}

void RuleEngine::process_log_entry(const LogEntry &entry) {
  if (ip_allowlist_cache.count(entry.ip_address)) {
    // std::cout << "IP " << entry.ip_address << " is allowlisted. Skipping."
    //           << std::endl;
    return; // Do not process further for allowlisted IPs
  }

  // Apply Tier 1 rules if enabled in config
  if (app_config.tier1_enabled)
    apply_tier1_rules(entry);

  // Future: Apply Tier 2 rules
  //   if (app_config.tier2_enabled)
  //     apply_tier2_rules(entry);

  // Future: Apply Tier 3 rules
  //   if (app_config.tier3_enabled)
  //     apply_tier3_rules(entry);
}

void RuleEngine::apply_tier1_rules(const LogEntry &entry) {
  // This is where we'll implement rules like:
  // - Requests per IP in a window
  // - Failed login counts
  // - Asset scraping
  // - Header anomalies

  // For now, let's create a dummy alert to test the AlertManager
  if (entry.http_status_code && *entry.http_status_code == 403) {
    if (entry.request_path.find("lehengas") != std::string::npos) {
      Alert test_alert(
          entry.parsed_timestamp_ms.value_or(Utils::get_current_time_ms()),
          entry.ip_address, "Tier 1: Suspicious 403 on Lehengas path (DEMO)",
          AlertTier::TIER1_HEURISTIC, "Investigate IP for scraping attempts",
          entry.ip_address + ":" + entry.request_path + ":" +
              std::to_string(entry.http_status_code.value()),
          1.0, // Dummy score
          entry.original_line_number, entry.raw_log_line);
      alert_mgr.record_alert(test_alert);
    }
  }
}
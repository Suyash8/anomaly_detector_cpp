#include "rule_engine.hpp"
#include "alert_manager.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/types.h>

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

PerIpState &RuleEngine::get_or_create_ip_state(const std::string &ip,
                                               uint64_t current_timestamp_ms) {
  auto it = ip_activity_trackers.find(ip);
  if (it == ip_activity_trackers.end()) {
    // IP not found, create new state.
    // Window duration comes from config (convert seconds to ms)
    uint64_t window_duration_ms =
        app_config.tier1_window_duration_seconds * 1000;

    // Use emplace to construct PerIpState in place
    auto [inserted_it, success] = ip_activity_trackers.emplace(
        ip, PerIpState(current_timestamp_ms, window_duration_ms,
                       window_duration_ms));
    // std::cout << "New IP state created for: " << ip << std::endl;
    return inserted_it->second;
  } else {
    // IP found, update last seen and return existing state
    it->second.last_seen_timestamp_ms = current_timestamp_ms;
    return it->second;
  }
}

void RuleEngine::process_log_entry(const LogEntry &entry) {
  if (!entry.parsed_timestamp_ms)
    return;

  uint64_t current_event_ts = *entry.parsed_timestamp_ms;

  if (ip_allowlist_cache.count(entry.ip_address))
    return;

  PerIpState &current_ip_state =
      get_or_create_ip_state(entry.ip_address, current_event_ts);

  current_ip_state.request_timestamps_window.add_event(current_event_ts,
                                                       current_event_ts);

  // Conditionally add to failed login window
  if (entry.http_status_code) {
    int status = *entry.http_status_code;
    if (status == 401 || status == 403) { // Common failed auth/forbidden codes
      // Add to failed login window. Value stored could be the status code or
      // just a marker
      current_ip_state.failed_login_timestamps_window.add_event(
          current_event_ts, static_cast<uint64_t>(status));
    }
  }
  // Pruning for failed_login_timestamps_window is handled by its add_event

  // Apply Tier 1 rules if enabled in config
  if (app_config.tier1_enabled)
    apply_tier1_rules(entry, current_ip_state);

  // Future: Apply Tier 2 rules
  //   if (app_config.tier2_enabled)
  //     apply_tier2_rules(entry);

  // Future: Apply Tier 3 rules
  //   if (app_config.tier3_enabled)
  //     apply_tier3_rules(entry);
}

void RuleEngine::apply_tier1_rules(const LogEntry &entry,
                                   PerIpState &current_ip_state) {
  // Rule 1: Check requests per IP
  check_requests_per_ip_rule(entry, current_ip_state);
  check_failed_logins_rule(entry, current_ip_state);

  // Future: Add calls to other Tier 1 rules
  // check_asset_scraping_rule(entry, current_ip_state);
  // check_header_anomalies_rule(entry, current_ip_state);
}

void RuleEngine::check_requests_per_ip_rule(const LogEntry &entry,
                                            PerIpState &ip_state) {
  size_t current_request_count =
      ip_state.request_timestamps_window.get_event_count();

  if (current_request_count >
      static_cast<size_t>(app_config.tier1_max_requests_per_ip_in_window)) {
    std::string reason =
        "High request rate from IP. Count: " +
        std::to_string(current_request_count) + " in last " +
        std::to_string(app_config.tier1_window_duration_seconds) + " sec";

    Alert high_rate_alert(
        entry.parsed_timestamp_ms.value_or(Utils::get_current_time_ms()),
        entry.ip_address, reason, AlertTier::TIER1_HEURISTIC,
        "Monitor/Block IP", entry.ip_address,
        static_cast<double>(current_request_count), entry.original_line_number,
        entry.raw_log_line);
    alert_mgr.record_alert(high_rate_alert);
  }
}

void RuleEngine::check_failed_logins_rule(const LogEntry &entry,
                                          PerIpState &ip_state) {
  size_t failed_login_count =
      ip_state.failed_login_timestamps_window.get_event_count();

  if (failed_login_count >
      static_cast<size_t>(app_config.tier1_max_failed_logins_per_ip)) {
    std::string reason =
        "Multiple failed login attempts from IP. Count: " +
        std::to_string(failed_login_count) + " (401/403s) in last " +
        std::to_string(app_config.tier1_window_duration_seconds) + "s.";

    // Include target path in reason/key if available and relevant for login
    // attempts
    std::string key_identifier = entry.ip_address;
    if (!entry.request_path.empty() && entry.request_path != "/") {
      reason += " Target path (sample): " + entry.request_path.substr(0, 50);
      key_identifier += " -> " + entry.request_path.substr(0, 50);
    }

    Alert failed_login_alert(
        entry.parsed_timestamp_ms.value_or(Utils::get_current_time_ms()),
        entry.ip_address, reason, AlertTier::TIER1_HEURISTIC,
        "Investigate IP for brute-force/credential stuffing",
        key_identifier, // More specific key
        static_cast<double>(failed_login_count), entry.original_line_number,
        entry.raw_log_line);
    alert_mgr.record_alert(failed_login_alert);
  }
}
#include "rule_engine.hpp"
#include "alert_manager.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
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

RuleEngine::~RuleEngine() {}

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

void RuleEngine::evaluate_rules(const AnalyzedEvent &event) {
  const LogEntry &raw_log = event.raw_log;

  if (ip_allowlist_cache.count(raw_log.ip_address))
    return;

  if (app_config.tier1.enabled) {
    check_requests_per_ip_rule(event);
    check_failed_logins_rule(event);
    // Placeholders for other Tier 1 rules that will use AnalyzedEvent
    // check_asset_scraping_rule_placeholder(event);
    // check_header_anomalies_rule_placeholder(event);
  }

  // Future: Apply Tier 2 rules using richer data in AnalyzedEvent
  if (app_config.tier2.enabled) {
    check_ip_zscore_rules(event);
  }
}

void RuleEngine::check_ip_zscore_rules(const AnalyzedEvent &event) {
  const double threshold = app_config.tier2.z_score_threshold;
  auto check = [&](const std::optional<double> &zscore_opt,
                   const std::string &metric_name) {
    if (zscore_opt && std::abs(*zscore_opt) > threshold) {
      std::string reason = "Anomalous IP " + metric_name +
                           " (Z-score: " + std::to_string(*zscore_opt) + ")";

      Alert z_score_alert(
          event.raw_log.parsed_timestamp_ms.value_or(0),
          event.raw_log.ip_address, reason, AlertTier::TIER2_STATISTICAL,
          "Investigate IP for anomalous statistical behavior",
          event.raw_log.ip_address, std::abs(*zscore_opt),
          event.raw_log.original_line_number, event.raw_log.raw_log_line);
      alert_mgr.record_alert(z_score_alert);
    }
  };

  check(event.ip_req_time_zscore, "request time");
  check(event.ip_bytes_sent_zscore, "bytes sent");
  check(event.ip_error_event_zscore, "error rate");
  check(event.ip_req_vol_zscore, "request volume");
}

void RuleEngine::check_requests_per_ip_rule(const AnalyzedEvent &event) {
  if (event.current_ip_request_count_in_window &&
      *event.current_ip_request_count_in_window >
          static_cast<size_t>(app_config.tier1.max_requests_per_ip_in_window)) {
    std::string reason =
        "High request rate from IP. Count: " +
        std::to_string(*event.current_ip_request_count_in_window) +
        " in last " +
        std::to_string(app_config.tier1.max_requests_per_ip_in_window) + "s.";

    Alert high_rate_alert(
        event.raw_log.parsed_timestamp_ms.value_or(
            Utils::get_current_time_ms()),
        event.raw_log.ip_address, reason, AlertTier::TIER1_HEURISTIC,
        "Monitor/Block IP", event.raw_log.ip_address,
        static_cast<double>(*event.current_ip_request_count_in_window),
        event.raw_log.original_line_number, event.raw_log.raw_log_line);
    alert_mgr.record_alert(high_rate_alert);
  }
}

void RuleEngine::check_failed_logins_rule(const AnalyzedEvent &event) {
  if (event.current_ip_failed_login_count_in_window &&
      *event.current_ip_failed_login_count_in_window >
          static_cast<size_t>(app_config.tier1.max_failed_logins_per_ip)) {
    std::string reason =
        "Multiple failed login attempts from IP. Count: " +
        std::to_string(*event.current_ip_failed_login_count_in_window) +
        " (401/403s) in last " +
        std::to_string(app_config.tier1.sliding_window_duration_seconds) + "s.";

    // Include target path in reason/key if available and relevant for login
    // attempts
    std::string key_identifier = event.raw_log.ip_address;
    if (!event.raw_log.request_path.empty() &&
        event.raw_log.request_path != "/") {
      reason +=
          " Target path (sample): " + event.raw_log.request_path.substr(0, 50);
      key_identifier += " -> " + event.raw_log.request_path.substr(0, 50);
    }

    Alert failed_login_alert(
        event.raw_log.parsed_timestamp_ms.value_or(
            Utils::get_current_time_ms()),
        event.raw_log.ip_address, reason, AlertTier::TIER1_HEURISTIC,
        "Investigate IP for brute-force/credential stuffing",
        key_identifier, // More specific key
        static_cast<double>(*event.current_ip_failed_login_count_in_window),
        event.raw_log.original_line_number, event.raw_log.raw_log_line);
    alert_mgr.record_alert(failed_login_alert);
  }
}

// Placeholder for asset scraping (will be refactored)
void RuleEngine::check_asset_scraping_rule_placeholder(
    const AnalyzedEvent &event) {
  // This rule will need asset access counts per path from AnalysisEngine via
  // AnalyzedEvent
  (void)event; // Suppress unused parameter warning for now
}

// Placeholder for header anomalies (will be refactored)
void RuleEngine::check_header_anomalies_rule_placeholder(
    const AnalyzedEvent &event) {
  // This rule will need flags like 'is_ua_missing' from AnalysisEngine via
  // AnalyzedEvent
  (void)event; // Suppress unused parameter warning
}

// TODO: Refactor later
bool RuleEngine::is_path_an_asset(const std::string &request_path) const {
  if (request_path.empty())
    return false;
  //  for (const std::string& prefix : app_config.tier1_asset_path_prefixes) {
  //      if (!prefix.empty() && request_path.rfind(prefix, 0) == 0) {
  //          return true;
  //      }
  //  }
  return false;
}
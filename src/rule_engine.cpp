#include "rule_engine.hpp"
#include "alert_manager.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "ml_models/heuristic_model.hpp"
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

  if (app_config.tier3.enabled) {
    std::cout << "Tier 3 ML detection is enabled (using StubModel)."
              << std::endl;
    anomaly_model_ = std::make_unique<HeuristicModel>();
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
    check_user_agent_rules(event);
    check_suspicious_string_rules(event);
    check_asset_ratio_rule(event);
    check_new_seen_rules(event);
  }

  if (app_config.tier2.enabled) {
    check_ip_zscore_rules(event);
    check_path_zscore_rules(event);
    check_historical_comparison_rules(event);
  }

  if (app_config.tier3.enabled) {
    check_ml_rules(event);
  }
}

void RuleEngine::check_ml_rules(const AnalyzedEvent &event) {
  if (!anomaly_model_ || event.feature_vector.empty())
    return;

  auto [score, explanation] =
      anomaly_model_->score_with_explanation(event.feature_vector);

  if (score > app_config.tier3.anomaly_score_threshold) {
    std::string reason =
        "High ML Anomaly Score detected: " + std::to_string(score);

    // Create the alert but don't set the explanation yet.
    // The explanation is part of the Alert struct, not the constructor.
    Alert ml_alert(event, reason, AlertTier::TIER3_ML,
                   "Review event; flagged as anomalous by ML model.", score);

    std::string contrib_str;
    for (const auto &factor : explanation) {
      if (!contrib_str.empty())
        contrib_str += ", ";

      contrib_str += factor;
    }

    ml_alert.ml_feature_contribution = contrib_str;

    alert_mgr.record_alert(ml_alert);
  }
}

void RuleEngine::check_new_seen_rules(const AnalyzedEvent &event) {
  // A brand new IP immediately tries to access a sensitive path
  if (event.is_first_request_from_ip) {
    for (const auto &sensitive : app_config.tier1.sensitive_path_substrings) {
      if (event.raw_log.request_path.find(sensitive) != std::string::npos) {
        std::string reason =
            "Newly seen IP immediately accessed a sensitive path containing '" +
            sensitive + "'.";
        Alert new_seen_sensitive_alert(
            event, reason, AlertTier::TIER1_HEURISTIC,
            "High Priority: Investigate IP for targeted probing", 15.0);
        alert_mgr.record_alert(new_seen_sensitive_alert);
        break;
      }
    }
  }

  // An existing IP suddenly accesses a new path and generates a high rate of
  // errors
  if (event.is_path_new_for_ip && event.ip_error_event_zscore &&
      *event.ip_error_event_zscore > 2.5) {
    std::string reason = "IP began generating a high error rate (Z-score: " +
                         std::to_string(*event.ip_error_event_zscore) +
                         ") while accessing a new path for the first time";
    Alert new_path_error_alert(
        event, reason, AlertTier::TIER2_STATISTICAL,
        "Investigate for vulnerability scanning or forced browsing",
        *event.ip_error_event_zscore);
    alert_mgr.record_alert(new_path_error_alert);
  }
}

void RuleEngine::check_historical_comparison_rules(const AnalyzedEvent &event) {
  const auto &cfg = app_config.tier2;
  const long min_samples = cfg.min_samples_for_z_score;

  // Check for sudden IP request time degradation
  if (event.raw_log.request_time_s && event.ip_hist_req_time_mean &&
      event.ip_hist_req_time_samples &&
      *event.ip_hist_req_time_samples >= min_samples &&
      *event.ip_hist_req_time_mean > 0) {
    if (*event.raw_log.request_time_s >
        (*event.ip_hist_req_time_mean * cfg.historical_deviation_factor)) {
      std::string reason =
          "Sudden performance degradation for IP. Request time " +
          std::to_string(*event.raw_log.request_time_s) + "s is >" +
          std::to_string(cfg.historical_deviation_factor) +
          "x the historical average of " +
          std::to_string(*event.ip_hist_req_time_mean) + "s";

      Alert historical_comparison_alert(
          event, reason, AlertTier::TIER2_STATISTICAL,
          "Investigate IP for unusual load or targeted DoS",
          *event.raw_log.request_time_s / *event.ip_hist_req_time_mean);

      alert_mgr.record_alert(historical_comparison_alert);
    }
  }
}

void RuleEngine::check_asset_ratio_rule(const AnalyzedEvent &event) {
  const auto &cfg = app_config.tier1;

  // Only check if we have seen a minimum number of HTML requests to have a
  // meaningful sample.
  if (event.ip_html_requests_in_window < cfg.min_html_requests_for_ratio_check)
    return;

  // Check if the ratio exists AND if it is BELOW the minimum expected
  // threshold.
  if (event.ip_assets_per_html_ratio &&
      *event.ip_assets_per_html_ratio < cfg.min_assets_per_html_ratio) {
    std::string reason =
        "Low Asset-to-HTML request ratio detected. Ratio: " +
        std::to_string(*event.ip_assets_per_html_ratio) +
        " (Expected minimum: >" +
        std::to_string(cfg.min_assets_per_html_ratio) + "). " +
        "HTML: " + std::to_string(event.ip_html_requests_in_window) +
        ", Assets: " + std::to_string(event.ip_asset_requests_in_window) +
        " in window.";

    // The score is higher the further the ratio is from the expected minimum.
    double score =
        cfg.min_assets_per_html_ratio - *event.ip_assets_per_html_ratio;

    Alert ratio_alert(
        event, reason, AlertTier::TIER1_HEURISTIC,
        "High confidence of bot activity (content scraping). Investigate IP.",
        score, // Score reflects severity of the deviation
        event.raw_log.ip_address);

    alert_mgr.record_alert(ratio_alert);
  }
}

void RuleEngine::check_suspicious_string_rules(const AnalyzedEvent &event) {
  auto create_suspicious_string_alert =
      [&](const std::string &reason, const std::string action, double score) {
        Alert suspicious_string_alert(event, reason, AlertTier::TIER1_HEURISTIC,
                                      action, score, event.raw_log.ip_address);
        alert_mgr.record_alert(suspicious_string_alert);
      };

  if (event.found_suspicious_path_str)
    create_suspicious_string_alert(
        "Request path contains a suspicious pattern",
        "High Priority: Block IP and investigate for exploit attempts", 15.0);

  if (event.found_suspicious_ua_str)
    create_suspicious_string_alert("User-Agent contains a suspicious pattern",
                                   "Block IP; known scanner/bot UA pattern",
                                   10.0);
}

void RuleEngine::check_user_agent_rules(const AnalyzedEvent &event) {
  if (!app_config.tier1.check_user_agent_anomalies)
    return;

  auto create_ua_alert = [&](const std::string &reason,
                             const std::string action, double score) {
    Alert user_agent_alert(event, reason, AlertTier::TIER1_HEURISTIC, action,
                           score, event.raw_log.ip_address);
    alert_mgr.record_alert(user_agent_alert);
  };

  if (event.is_ua_missing)
    create_ua_alert("Request with missing User-Agent",
                    "Investigate IP for scripted activity", 1.0);

  if (event.is_ua_known_bad)
    create_ua_alert("Request from a known malicious User-Agent signature",
                    "Block IP; known scanner/bot", 10.0);

  if (event.is_ua_headless)
    create_ua_alert(
        "Request from a known headless browser signature",
        "High likelihood of automated activity; monitor or challenge", 5.0);

  if (event.is_ua_outdated)
    create_ua_alert(
        "Request from outdated browser: " + event.detected_browser_version,
        "Investigate IP for vulnerable client or bot activity", 2.0);

  if (event.is_ua_cycling)
    create_ua_alert("IP rapidly cycling through different User-Agents",
                    "Very high likelihood of bot; consider blocking", 20.0);

  // TODO: Maybe add more such composite rules
  // Example:
  if (event.is_ua_changed_for_ip && event.ip_error_event_zscore &&
      *event.ip_error_event_zscore > 1.0)
    create_ua_alert(
        "User-Agent changed for IP, followed by anomalous error rate",
        "Investigate for potential account takeover or compromised client",
        *event.ip_error_event_zscore);
}

void RuleEngine::check_ip_zscore_rules(const AnalyzedEvent &event) {
  const double threshold = app_config.tier2.z_score_threshold;
  auto check = [&](const std::optional<double> &zscore_opt,
                   const std::string &metric_name) {
    if (zscore_opt && std::abs(*zscore_opt) > threshold) {
      std::string reason = "Anomalous IP " + metric_name +
                           " (Z-score: " + std::to_string(*zscore_opt) + ")";

      Alert z_score_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                          "Investigate IP for anomalous statistical behavior",
                          std::abs(*zscore_opt), event.raw_log.ip_address);
      alert_mgr.record_alert(z_score_alert);
    }
  };

  check(event.ip_req_time_zscore, "request time");
  check(event.ip_bytes_sent_zscore, "bytes sent");
  check(event.ip_error_event_zscore, "error rate");
  check(event.ip_req_vol_zscore, "request volume");
}

void RuleEngine::check_path_zscore_rules(const AnalyzedEvent &event) {
  const double threshold = app_config.tier2.z_score_threshold;

  auto check = [&](const std::optional<double> &zscore_opt,
                   const std::string &metric_name) {
    if (zscore_opt && std::abs(*zscore_opt) > threshold) {
      std::string reason = "Anomalous " + metric_name + " for path '" +
                           event.raw_log.request_path +
                           "' (Z-score: " + std::to_string(*zscore_opt) + ")";

      Alert z_score_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                          "Investigate path for anomalous statistical "
                          "behaviour(e.g., performance issue, data exfil)",
                          std::abs(*zscore_opt), event.raw_log.request_path);
      alert_mgr.record_alert(z_score_alert);
    }
  };

  check(event.path_req_time_zscore, "request time");
  check(event.path_bytes_sent_zscore, "bytes sent");
  check(event.path_error_event_zscore, "error rate");
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
        event, reason, AlertTier::TIER1_HEURISTIC, "Monitor/Block IP",
        static_cast<double>(*event.current_ip_request_count_in_window),
        event.raw_log.ip_address);
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
        event, reason, AlertTier::TIER1_HEURISTIC,
        "Investigate IP for brute-force/credential stuffing",
        static_cast<double>(*event.current_ip_failed_login_count_in_window),
        key_identifier);
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
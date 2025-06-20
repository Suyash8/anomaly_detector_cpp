#include "rule_engine.hpp"
#include "aho_corasick.hpp"
#include "alert_manager.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "ml_models/random_forest_model.hpp"
#include "utils.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <sys/types.h>

// =================================================================================
// Public Interface & Constructor
// =================================================================================

RuleEngine::RuleEngine(AlertManager &manager, const Config::AppConfig &cfg)
    : alert_mgr(manager), app_config(cfg) {
  std::cout << "\nRuleEngine created and initialised" << std::endl;

  if (!app_config.allowlist_path.empty()) {
    if (load_ip_allowlist(app_config.allowlist_path))
      std::cout << "IP Allowlist loaded successfully: "
                << cidr_allowlist_cache_.size() << " entries" << std::endl;
    else
      std::cerr << "Warning: Failed to load IP allowlist from: "
                << app_config.allowlist_path << std::endl;
  }

  if (!app_config.tier1.suspicious_path_substrings.empty())
    suspicious_path_matcher_ = std::make_unique<Utils::AhoCorasick>(
        app_config.tier1.suspicious_path_substrings);
  if (!app_config.tier1.suspicious_ua_substrings.empty())
    suspicious_ua_matcher_ = std::make_unique<Utils::AhoCorasick>(
        app_config.tier1.suspicious_ua_substrings);

  if (app_config.tier3.enabled) {
    std::cout << "Tier 3 ML detection is enabled (using RandomForestModel)."
              << std::endl;
    anomaly_model_ = std::make_unique<RandomForestModel>(10);
  }
}

RuleEngine::~RuleEngine() {}

void RuleEngine::evaluate_rules(const AnalyzedEvent &event_ref) {
  uint32_t event_ip = Utils::ip_string_to_uint32(event_ref.raw_log.ip_address);
  if (event_ip != 0)
    for (const auto &block : cidr_allowlist_cache_)
      if (block.contains(event_ip))
        return;

  const auto event = std::make_shared<const AnalyzedEvent>(event_ref);

  if (app_config.tier1.enabled) {
    check_requests_per_ip_rule(*event);
    check_failed_logins_rule(*event);
    check_user_agent_rules(*event);
    check_suspicious_string_rules(*event);
    check_asset_ratio_rule(*event);
    check_new_seen_rules(*event);
  }

  if (app_config.tier2.enabled) {
    check_ip_zscore_rules(*event);
    check_path_zscore_rules(*event);
    check_historical_comparison_rules(*event);
  }

  if (app_config.tier3.enabled) {
    check_ml_rules(*event);
  }
}

bool RuleEngine::load_ip_allowlist(const std::string &filepath) {
  std::ifstream allowlist_file(filepath);
  if (!allowlist_file.is_open())
    return false;
  std::string ip_line;
  while (std::getline(allowlist_file, ip_line)) {
    std::string trimmed_line = Utils::trim_copy(ip_line);
    if (!trimmed_line.empty() && trimmed_line[0] != '#') {
      if (auto cidr_opt = Utils::parse_cidr(trimmed_line))
        cidr_allowlist_cache_.push_back(*cidr_opt);
      else
        std::cerr << "Warning: Could not parse allowlist entry: "
                  << trimmed_line << std::endl;
    }
  }
  return true;
}

// =================================================================================
// Private Helper Functions
// =================================================================================

void RuleEngine::create_and_record_alert(
    const AnalyzedEvent &event, const std::string &reason, AlertTier tier,
    const std::string &action, double score, const std::string &key_id) {
  alert_mgr.record_alert(Alert(std::make_shared<AnalyzedEvent>(event), reason,
                               tier, action, score, key_id));
}

// =================================================================================
// Tier 1: Heuristic Rules
// =================================================================================

void RuleEngine::check_requests_per_ip_rule(const AnalyzedEvent &event) {
  if (event.current_ip_request_count_in_window &&
      *event.current_ip_request_count_in_window >
          app_config.tier1.max_requests_per_ip_in_window) {
    std::string reason =
        "High request rate from IP. Count: " +
        std::to_string(*event.current_ip_request_count_in_window) +
        " in last " +
        std::to_string(app_config.tier1.sliding_window_duration_seconds) + "s.";

    create_and_record_alert(
        event, reason, AlertTier::TIER1_HEURISTIC, "Monitor/Block IP",
        static_cast<double>(*event.current_ip_request_count_in_window),
        event.raw_log.ip_address);
  }
}

void RuleEngine::check_failed_logins_rule(const AnalyzedEvent &event) {
  if (event.current_ip_failed_login_count_in_window &&
      *event.current_ip_failed_login_count_in_window >
          app_config.tier1.max_failed_logins_per_ip) {
    std::string reason =
        "Multiple failed login attempts from IP. Count: " +
        std::to_string(*event.current_ip_failed_login_count_in_window) +
        " in last " +
        std::to_string(app_config.tier1.sliding_window_duration_seconds) + "s.";

    std::string key_identifier = event.raw_log.ip_address;
    if (!event.raw_log.request_path.empty() &&
        event.raw_log.request_path != "/") {
      reason +=
          " Target path (sample): " + event.raw_log.request_path.substr(0, 50);
      key_identifier += " -> " + event.raw_log.request_path.substr(0, 50);
    }

    create_and_record_alert(
        event, reason, AlertTier::TIER1_HEURISTIC,
        "Investigate IP for brute-force/credential stuffing",
        static_cast<double>(*event.current_ip_failed_login_count_in_window),
        key_identifier);
  }
}

void RuleEngine::check_suspicious_string_rules(const AnalyzedEvent &event) {
  if (suspicious_path_matcher_ &&
      !suspicious_path_matcher_->find_all(event.raw_log.request_path).empty()) {
    create_and_record_alert(
        event, "Request path contains a suspicious pattern",
        AlertTier::TIER1_HEURISTIC,
        "High Priority: Block IP and investigate for exploit attempts", 15.0,
        event.raw_log.ip_address);
  }

  if (suspicious_ua_matcher_ &&
      !suspicious_ua_matcher_->find_all(event.raw_log.user_agent).empty()) {
    create_and_record_alert(event, "User-Agent contains a suspicious pattern",
                            AlertTier::TIER1_HEURISTIC,
                            "Block IP; known scanner/bot UA pattern", 10.0,
                            event.raw_log.ip_address);
  }
}

void RuleEngine::check_user_agent_rules(const AnalyzedEvent &event) {
  if (!app_config.tier1.check_user_agent_anomalies)
    return;

  if (event.is_ua_missing) {
    create_and_record_alert(
        event, "Request with missing User-Agent", AlertTier::TIER1_HEURISTIC,
        "Investigate IP for scripted activity", 1.0, event.raw_log.ip_address);
  }
  if (event.is_ua_known_bad) {
    create_and_record_alert(
        event, "Request from a known malicious User-Agent signature",
        AlertTier::TIER1_HEURISTIC, "Block IP; known scanner/bot", 10.0,
        event.raw_log.ip_address);
  }
  if (event.is_ua_headless) {
    create_and_record_alert(
        event, "Request from a known headless browser signature",
        AlertTier::TIER1_HEURISTIC,
        "High likelihood of automated activity; monitor or challenge", 5.0,
        event.raw_log.ip_address);
  }
  if (event.is_ua_outdated) {
    create_and_record_alert(
        event,
        "Request from outdated browser: " + event.detected_browser_version,
        AlertTier::TIER1_HEURISTIC,
        "Investigate IP for vulnerable client or bot activity", 2.0,
        event.raw_log.ip_address);
  }
  if (event.is_ua_cycling) {
    create_and_record_alert(event,
                            "IP rapidly cycling through different User-Agents",
                            AlertTier::TIER1_HEURISTIC,
                            "Very high likelihood of bot; consider blocking",
                            20.0, event.raw_log.ip_address);
  }
}

void RuleEngine::check_asset_ratio_rule(const AnalyzedEvent &event) {
  const auto &cfg = app_config.tier1;
  if (static_cast<size_t>(event.ip_html_requests_in_window) <
      cfg.min_html_requests_for_ratio_check) {
    return;
  }
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
    double score =
        cfg.min_assets_per_html_ratio - *event.ip_assets_per_html_ratio;
    create_and_record_alert(
        event, reason, AlertTier::TIER1_HEURISTIC,
        "High confidence of bot activity (content scraping). Investigate IP.",
        score, event.raw_log.ip_address);
  }
}

// =================================================================================
// Tier 2: Statistical & Contextual Rules
// =================================================================================

void RuleEngine::check_ip_zscore_rules(const AnalyzedEvent &event) {
  const double threshold = app_config.tier2.z_score_threshold;
  auto check = [&](const std::optional<double> &zscore_opt,
                   const std::string &metric_name) {
    if (zscore_opt && std::abs(*zscore_opt) > threshold) {
      std::string reason = "Anomalous IP " + metric_name +
                           " (Z-score: " + std::to_string(*zscore_opt) + ")";
      create_and_record_alert(
          event, reason, AlertTier::TIER2_STATISTICAL,
          "Investigate IP for anomalous statistical behavior",
          std::abs(*zscore_opt), event.raw_log.ip_address);
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
      create_and_record_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                              "Investigate path for anomalous statistical "
                              "behaviour(e.g., performance issue, data exfil)",
                              std::abs(*zscore_opt),
                              event.raw_log.request_path);
    }
  };
  check(event.path_req_time_zscore, "request time");
  check(event.path_bytes_sent_zscore, "bytes sent");
  check(event.path_error_event_zscore, "error rate");
}

void RuleEngine::check_new_seen_rules(const AnalyzedEvent &event) {
  if (event.is_first_request_from_ip) {
    for (const auto &sensitive : app_config.tier1.sensitive_path_substrings) {
      if (event.raw_log.request_path.find(sensitive) != std::string::npos) {
        std::string reason =
            "Newly seen IP immediately accessed a sensitive path containing '" +
            sensitive + "'.";
        create_and_record_alert(
            event, reason, AlertTier::TIER1_HEURISTIC,
            "High Priority: Investigate IP for targeted probing", 15.0);
        break; // Alert once per event
      }
    }
  }

  if (event.is_path_new_for_ip && event.ip_error_event_zscore &&
      *event.ip_error_event_zscore > 2.5) {
    std::string reason = "IP began generating a high error rate (Z-score: " +
                         std::to_string(*event.ip_error_event_zscore) +
                         ") while accessing a new path for the first time";
    create_and_record_alert(
        event, reason, AlertTier::TIER2_STATISTICAL,
        "Investigate for vulnerability scanning or forced browsing",
        *event.ip_error_event_zscore);
  }
}

void RuleEngine::check_historical_comparison_rules(const AnalyzedEvent &event) {
  const auto &cfg = app_config.tier2;
  const size_t min_samples = cfg.min_samples_for_z_score;

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
      create_and_record_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                              "Investigate IP for unusual load or targeted DoS",
                              *event.raw_log.request_time_s /
                                  *event.ip_hist_req_time_mean);
    }
  }
}

// =================================================================================
// Tier 3: Machine Learning Rules
// =================================================================================

void RuleEngine::check_ml_rules(const AnalyzedEvent &event) {
  if (event.feature_vector.empty())
    return;

  auto [score, explanation] =
      anomaly_model_->score_with_explanation(event.feature_vector);

  if (score > app_config.tier3.anomaly_score_threshold) {
    std::string reason =
        "High ML Anomaly Score detected: " + std::to_string(score);

    // Create the alert using the helper. The helper takes care of the
    // shared_ptr.
    Alert ml_alert(std::make_shared<const AnalyzedEvent>(event), reason,
                   AlertTier::TIER3_ML,
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
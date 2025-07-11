#include "rule_engine.hpp"
#include "analysis/analyzed_event.hpp"
#include "core/alert.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "io/threat_intel/intel_manager.hpp"
#include "models/model_manager.hpp"
#include "rules/scoring.hpp"
#include "utils/aho_corasick.hpp"
#include "utils/scoped_timer.hpp"
#include "utils/sliding_window.hpp"
#include "utils/utils.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <sys/types.h>

// =================================================================================
// Public Interface & Constructor
// =================================================================================

RuleEngine::RuleEngine(AlertManager &manager, const Config::AppConfig &cfg,
                       std::shared_ptr<ModelManager> model_manager)
    : alert_mgr(manager), app_config(cfg), model_manager_(model_manager) {
  LOG(LogLevel::INFO, LogComponent::RULES_EVAL,
      "RuleEngine created and initialised.");

  if (!app_config.allowlist_path.empty()) {
    if (load_ip_allowlist(app_config.allowlist_path))
      LOG(LogLevel::INFO, LogComponent::RULES_EVAL,
          "IP Allowlist loaded successfully: " << cidr_allowlist_cache_.size()
                                               << " entries.");
    else
      LOG(LogLevel::ERROR, LogComponent::RULES_EVAL,
          "Failed to load IP allowlist from: " << app_config.allowlist_path);
  }

  if (!app_config.tier1.suspicious_path_substrings.empty()) {
    suspicious_path_matcher_ = std::make_unique<Utils::AhoCorasick>(
        app_config.tier1.suspicious_path_substrings);
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Initialized suspicious path matcher with "
            << app_config.tier1.suspicious_path_substrings.size()
            << " patterns.");
  }
  if (!app_config.tier1.suspicious_ua_substrings.empty()) {
    suspicious_ua_matcher_ = std::make_unique<Utils::AhoCorasick>(
        app_config.tier1.suspicious_ua_substrings);
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Initialized suspicious UA matcher with "
            << app_config.tier1.suspicious_ua_substrings.size()
            << " patterns.");
  }

  if (app_config.threat_intel.enabled)
    intel_manager_ = std::make_shared<IntelManager>(
        app_config.threat_intel.feed_urls,
        app_config.threat_intel.update_interval_seconds);
}

RuleEngine::~RuleEngine() {}

void RuleEngine::evaluate_rules(const AnalyzedEvent &event_ref) {
  static Histogram *evaluation_timer =
      MetricsManager::instance().register_histogram(
          "ad_rule_engine_evaluation_duration_seconds",
          "Latency of the entire RuleEngine::evaluate_rules function.");
  ScopedTimer timer(*evaluation_timer);

  LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
      "Entering evaluate_rules for IP: " << event_ref.raw_log.ip_address);

  // --- Pre-checks: Threat Intel and Allowlist ---
  uint32_t event_ip_u32 =
      Utils::ip_string_to_uint32(event_ref.raw_log.ip_address);
  if (event_ip_u32 != 0)
    if (intel_manager_ && intel_manager_->is_blacklisted(event_ip_u32)) {
      LOG(LogLevel::DEBUG, LogComponent::IO_THREATINTEL,
          "IP " << event_ref.raw_log.ip_address
                << " found on threat intelligence blacklist. Creating alert "
                   "and stopping further evaluation.");
      create_and_record_alert(
          event_ref, "IP is on external threat intelligence blacklist",
          AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
          "Block IP immediately; listed on external threat feed.", 100.0,
          event_ref.raw_log.ip_address);
      return;
    }

  for (const auto &block : cidr_allowlist_cache_) {
    if (block.contains(event_ip_u32)) {
      LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
          "IP " << event_ref.raw_log.ip_address
                << " is on the allowlist. Skipping all rule evaluation.");
      return;
    }
  }

  const auto event = std::make_shared<const AnalyzedEvent>(event_ref);

  if (app_config.tier1.enabled) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Evaluating Tier 1 rules for IP: " << event->raw_log.ip_address);
    check_requests_per_ip_rule(*event);
    check_failed_logins_rule(*event);
    check_user_agent_rules(*event);
    check_suspicious_string_rules(*event);
    check_asset_ratio_rule(*event);
    check_new_seen_rules(*event);
    check_session_rules(*event);
  } else
    LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
        "Tier 1 rules are disabled.");

  if (app_config.tier2.enabled) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Evaluating Tier 2 rules for IP: " << event->raw_log.ip_address);
    check_ip_zscore_rules(*event);
    check_path_zscore_rules(*event);
    check_historical_comparison_rules(*event);
  } else
    LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
        "Tier 2 rules are disabled.");

  if (app_config.tier3.enabled) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Evaluating Tier 3 rules for IP: " << event->raw_log.ip_address);
    check_ml_rules(*event);
  } else
    LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
        "Tier 3 rules are disabled.");

  LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
      "Exiting evaluate_rules for IP: " << event_ref.raw_log.ip_address);
}

bool RuleEngine::load_ip_allowlist(const std::string &filepath) {
  LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
      "Loading IP allowlist from: " << filepath);
  std::ifstream allowlist_file(filepath);
  if (!allowlist_file.is_open()) {
    LOG(LogLevel::ERROR, LogComponent::RULES_EVAL,
        "Could not open allowlist file: " << filepath);
    return false;
  }
  std::string ip_line;
  while (std::getline(allowlist_file, ip_line)) {
    std::string trimmed_line = Utils::trim_copy(ip_line);
    if (!trimmed_line.empty() && trimmed_line[0] != '#') {
      if (auto cidr_opt = Utils::parse_cidr(trimmed_line)) {
        cidr_allowlist_cache_.push_back(*cidr_opt);
        LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
            "Added CIDR to allowlist: " << trimmed_line);
      } else
        LOG(LogLevel::WARN, LogComponent::RULES_EVAL,
            "Could not parse allowlist entry: " << trimmed_line);
    }
  }
  return true;
}

void RuleEngine::reconfigure(const Config::AppConfig &new_config) {
  LOG(LogLevel::INFO, LogComponent::RULES_EVAL,
      "RuleEngine is being reconfigured.");
  app_config = new_config;

  cidr_allowlist_cache_.clear();
  if (!app_config.allowlist_path.empty())
    load_ip_allowlist(app_config.allowlist_path);

  // Re-build the Aho-Corasick matchers
  if (!app_config.tier1.suspicious_path_substrings.empty()) {
    suspicious_path_matcher_ = std::make_unique<Utils::AhoCorasick>(
        app_config.tier1.suspicious_path_substrings);
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Re-initialized suspicious path matcher.");
  } else {
    suspicious_path_matcher_.reset();
  }

  if (!app_config.tier1.suspicious_ua_substrings.empty()) {
    suspicious_ua_matcher_ = std::make_unique<Utils::AhoCorasick>(
        app_config.tier1.suspicious_ua_substrings);
    LOG(LogLevel::DEBUG, LogComponent::RULES_EVAL,
        "Re-initialized suspicious UA matcher.");
  } else
    suspicious_ua_matcher_.reset();

  if (new_config.threat_intel.enabled) {
    intel_manager_ = std::make_shared<IntelManager>(
        new_config.threat_intel.feed_urls,
        new_config.threat_intel.update_interval_seconds);
  } else
    intel_manager_.reset();

  LOG(LogLevel::INFO, LogComponent::RULES_EVAL,
      "RuleEngine has been reconfigured successfully.");
}

// =================================================================================
// Private Helper Functions
// =================================================================================

void RuleEngine::create_and_record_alert(const AnalyzedEvent &event,
                                         std::string_view reason,
                                         AlertTier tier, AlertAction action,
                                         std::string_view action_str,
                                         double score,
                                         std::string_view key_id) {
  if (score <= 0.0) {
    LOG(LogLevel::TRACE, LogComponent::RULES_EVAL,
        "Score is <= 0.0, not creating alert for reason: " << reason);
    return;
  }
  LOG(LogLevel::INFO, LogComponent::RULES_EVAL,
      "Creating alert for IP " << event.raw_log.ip_address << " with score "
                               << score << ". Reason: " << reason);
  alert_mgr.record_alert(Alert(std::make_shared<const AnalyzedEvent>(event),
                               reason, tier, action, action_str, score,
                               key_id));
}

// =================================================================================
// Tier 1: Heuristic Rules
// =================================================================================

void RuleEngine::check_requests_per_ip_rule(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'requests_per_ip' rule...");
  if (event.current_ip_request_count_in_window &&
      *event.current_ip_request_count_in_window >
          app_config.tier1.max_requests_per_ip_in_window) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'requests_per_ip' TRIGGERED for IP "
            << event.raw_log.ip_address << ". Count: "
            << *event.current_ip_request_count_in_window << " > Threshold: "
            << app_config.tier1.max_requests_per_ip_in_window);
    double current_val = *event.current_ip_request_count_in_window;
    double threshold = app_config.tier1.max_requests_per_ip_in_window;
    double dangerous_val = threshold * 10;
    double score =
        Scoring::from_threshold(current_val, threshold, dangerous_val, 60.0);

    std::string reason =
        "High request rate from IP. Count: " +
        std::to_string(*event.current_ip_request_count_in_window) +
        " in last " +
        std::to_string(app_config.tier1.sliding_window_duration_seconds) + "s.";
    std::string action_str = "Consider rate-limiting IP; traffic volume "
                             "exceeds configured threshold.";

    create_and_record_alert(event, reason, AlertTier::TIER1_HEURISTIC,
                            AlertAction::RATE_LIMIT, action_str, score,
                            event.raw_log.ip_address);
  }
}

void RuleEngine::check_failed_logins_rule(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'failed_logins' rule...");
  if (event.current_ip_failed_login_count_in_window &&
      *event.current_ip_failed_login_count_in_window >
          app_config.tier1.max_failed_logins_per_ip) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'failed_logins' TRIGGERED for IP "
            << event.raw_log.ip_address
            << ". Count: " << *event.current_ip_failed_login_count_in_window
            << " > Threshold: " << app_config.tier1.max_failed_logins_per_ip);
    double current_val = *event.current_ip_failed_login_count_in_window;
    double threshold = app_config.tier1.max_failed_logins_per_ip;
    double dangerous_val = threshold * 5;
    double score = Scoring::from_threshold(current_val, threshold,
                                           dangerous_val, 70.0, 99.0);

    std::string reason =
        "Multiple failed login attempts from IP. Count: " +
        std::to_string(*event.current_ip_failed_login_count_in_window) +
        " in last " +
        std::to_string(app_config.tier1.sliding_window_duration_seconds) + "s.";
    std::string action_str = "Investigate IP for brute-force/credential "
                             "stuffing; consider blocking.";

    create_and_record_alert(event, reason, AlertTier::TIER1_HEURISTIC,
                            AlertAction::BLOCK, action_str, score,
                            event.raw_log.ip_address);
  }
}

void RuleEngine::check_suspicious_string_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'suspicious_string' rules...");
  if (suspicious_path_matcher_) {
    auto matches =
        suspicious_path_matcher_->find_all(event.raw_log.request_path);
    if (!matches.empty()) {
      LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
          "'suspicious_path' TRIGGERED for IP "
              << event.raw_log.ip_address
              << ". Path: " << event.raw_log.request_path
              << " matched pattern: " << matches[0]);
      create_and_record_alert(
          event, "Request path contains a suspicious pattern: " + matches[0],
          AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
          "High Priority: Block IP and investigate for exploit attempts",
          app_config.tier1.score_suspicious_path, event.raw_log.ip_address);
    }
  }

  if (suspicious_ua_matcher_) {
    auto matches = suspicious_ua_matcher_->find_all(event.raw_log.user_agent);
    if (!matches.empty()) {
      LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
          "'suspicious_ua' TRIGGERED for IP "
              << event.raw_log.ip_address
              << ". UA matched pattern: " << matches[0]);
      create_and_record_alert(
          event, "User-Agent contains a suspicious pattern: " + matches[0],
          AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
          "Block IP; known scanner/bot UA pattern",
          app_config.tier1.score_known_bad_ua, event.raw_log.ip_address);
    }
  }
}

void RuleEngine::check_user_agent_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'user_agent' rules...");
  if (!app_config.tier1.check_user_agent_anomalies)
    return;

  if (event.is_ua_missing) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'ua_missing' TRIGGERED for IP " << event.raw_log.ip_address);
    create_and_record_alert(
        event, "Request with missing User-Agent", AlertTier::TIER1_HEURISTIC,
        AlertAction::LOG, "Investigate IP for scripted activity",
        app_config.tier1.score_missing_ua, event.raw_log.ip_address);
  }

  if (event.is_ua_known_bad) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'ua_known_bad' TRIGGERED for IP " << event.raw_log.ip_address);
    create_and_record_alert(
        event, "Request from a known malicious User-Agent signature",
        AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
        "Block IP; known scanner/bot", app_config.tier1.score_known_bad_ua,
        event.raw_log.ip_address);
  }

  if (event.is_ua_headless) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'ua_headless' TRIGGERED for IP " << event.raw_log.ip_address);
    create_and_record_alert(
        event, "Request from a known headless browser signature",
        AlertTier::TIER1_HEURISTIC, AlertAction::CHALLENGE,
        "High likelihood of automated activity; monitor or challenge",
        app_config.tier1.score_headless_browser, event.raw_log.ip_address);
  }

  if (event.is_ua_outdated) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'ua_outdated' TRIGGERED for IP " << event.raw_log.ip_address);
    create_and_record_alert(
        event,
        "Request from outdated browser: " + event.detected_browser_version,
        AlertTier::TIER1_HEURISTIC, AlertAction::LOG,
        "Investigate IP for vulnerable client or bot activity",
        app_config.tier1.score_outdated_browser, event.raw_log.ip_address);
  }

  if (event.is_ua_cycling) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'ua_cycling' TRIGGERED for IP " << event.raw_log.ip_address);
    create_and_record_alert(
        event, "IP rapidly cycling through different User-Agents",
        AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
        "Very high likelihood of bot; consider blocking",
        app_config.tier1.score_ua_cycling, event.raw_log.ip_address);
  }
}

void RuleEngine::check_asset_ratio_rule(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'asset_ratio' rule...");
  const auto &cfg = app_config.tier1;

  if (static_cast<size_t>(event.ip_html_requests_in_window) <
      cfg.min_html_requests_for_ratio_check) {
    LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
        "Skipping asset_ratio check, not enough HTML requests ("
            << event.ip_html_requests_in_window << "/"
            << cfg.min_html_requests_for_ratio_check << ").");
    return;
  }

  if (event.ip_assets_per_html_ratio &&
      *event.ip_assets_per_html_ratio < cfg.min_assets_per_html_ratio) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'asset_ratio' TRIGGERED for IP "
            << event.raw_log.ip_address
            << ". Ratio: " << *event.ip_assets_per_html_ratio
            << " < Threshold: " << cfg.min_assets_per_html_ratio);
    double score = Scoring::from_threshold(cfg.min_assets_per_html_ratio,
                                           *event.ip_assets_per_html_ratio, 0.1,
                                           50.0, 95.0);
    std::string reason =
        "Low Asset-to-HTML request ratio detected. Ratio: " +
        std::to_string(*event.ip_assets_per_html_ratio) +
        " (Expected minimum: >" +
        std::to_string(cfg.min_assets_per_html_ratio) + "). " +
        "HTML: " + std::to_string(event.ip_html_requests_in_window) +
        ", Assets: " + std::to_string(event.ip_asset_requests_in_window) +
        " in window.";
    std::string action_str =
        "High confidence of bot activity (content scraping). Investigate IP.";
    create_and_record_alert(event, reason, AlertTier::TIER1_HEURISTIC,
                            AlertAction::CHALLENGE, action_str, score,
                            event.raw_log.ip_address);
  }
}

void RuleEngine::check_session_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'session' rules...");
  if (!event.raw_session_state)
    return;

  const auto &session = *event.raw_session_state;

  // Rule: High number of failed logins in a single session
  if (session.failed_login_attempts >
      app_config.tier1.max_failed_logins_per_session) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'session_failed_logins' TRIGGERED for session. Count: "
            << session.failed_login_attempts << " > Threshold: "
            << app_config.tier1.max_failed_logins_per_session);
    create_and_record_alert(
        event,
        "High number of failed logins within a single session: " +
            std::to_string(session.failed_login_attempts),
        AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
        "Block session/IP; high confidence of credential stuffing.", 85.0,
        event.raw_log.ip_address);
  }

  // Rule: Impossibly fast navigation within the sliding window
  auto &temp_window =
      const_cast<SlidingWindow<uint64_t> &>(session.request_timestamps_window);
  temp_window.prune_old_events(session.last_seen_timestamp_ms);
  if (temp_window.get_event_count() >
      app_config.tier1.max_requests_per_session_in_window) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'session_request_rate' TRIGGERED for session. Count: "
            << temp_window.get_event_count() << " > Threshold: "
            << app_config.tier1.max_requests_per_session_in_window);
    create_and_record_alert(
        event,
        "Anomalously high request rate within a single session: " +
            std::to_string(temp_window.get_event_count()) + " reqs in window.",
        AlertTier::TIER1_HEURISTIC, AlertAction::CHALLENGE,
        "High confidence of bot activity (scraping/probing).", 70.0,
        event.raw_log.ip_address);
  }

  // Rule: User-Agent cycling within a session
  if (session.unique_user_agents.size() >
      app_config.tier1.max_ua_changes_per_session) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
        "'session_ua_cycling' TRIGGERED for session. Count: "
            << session.unique_user_agents.size()
            << " > Threshold: " << app_config.tier1.max_ua_changes_per_session);
    create_and_record_alert(
        event,
        "User-Agent changed " +
            std::to_string(session.unique_user_agents.size()) +
            " times within a single session.",
        AlertTier::TIER1_HEURISTIC, AlertAction::BLOCK,
        "Very high confidence of sophisticated bot or attacker.", 90.0,
        event.raw_log.ip_address);
  }
}

// =================================================================================
// Tier 2: Statistical & Contextual Rules
// =================================================================================

void RuleEngine::check_ip_zscore_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T2_STATISTICAL,
      "Checking 'ip_zscore' rules...");
  const double threshold = app_config.tier2.z_score_threshold;
  std::string action_str = "Investigate IP for anomalous statistical behavior.";

  auto check = [&](const std::optional<double> &zscore_opt,
                   const std::string &metric_name) {
    if (zscore_opt && std::abs(*zscore_opt) > threshold) {
      LOG(LogLevel::DEBUG, LogComponent::RULES_T2_STATISTICAL,
          "'ip_zscore_" << metric_name << "' TRIGGERED for IP "
                        << event.raw_log.ip_address << ". Z-Score: "
                        << *zscore_opt << " > Threshold: " << threshold);
      double score = Scoring::from_z_score(*zscore_opt, threshold);
      std::string reason = "Anomalous IP " + metric_name +
                           " (Z-score: " + std::to_string(*zscore_opt) + ")";
      create_and_record_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                              AlertAction::LOG, action_str, score,
                              event.raw_log.ip_address);
    }
  };
  check(event.ip_req_time_zscore, "request_time");
  check(event.ip_bytes_sent_zscore, "bytes_sent");
  check(event.ip_error_event_zscore, "error_rate");
  check(event.ip_req_vol_zscore, "request_volume");
}

void RuleEngine::check_path_zscore_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T2_STATISTICAL,
      "Checking 'path_zscore' rules...");
  const double threshold = app_config.tier2.z_score_threshold;
  std::string action_str = "Investigate path for anomalous statistical "
                           "behaviour (e.g., performance issue, data exfil).";

  auto check = [&](const std::optional<double> &zscore_opt,
                   const std::string &metric_name) {
    if (zscore_opt && std::abs(*zscore_opt) > threshold) {
      LOG(LogLevel::DEBUG, LogComponent::RULES_T2_STATISTICAL,
          "'path_zscore_" << metric_name << "' TRIGGERED for path "
                          << event.raw_log.request_path << ". Z-Score: "
                          << *zscore_opt << " > Threshold: " << threshold);
      double score = Scoring::from_z_score(*zscore_opt, threshold);
      std::string reason = "Anomalous " + metric_name + " for path '" +
                           event.raw_log.request_path +
                           "' (Z-score: " + std::to_string(*zscore_opt) + ")";
      create_and_record_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                              AlertAction::LOG, action_str, score,
                              event.raw_log.request_path);
    }
  };
  check(event.path_req_time_zscore, "request_time");
  check(event.path_bytes_sent_zscore, "bytes_sent");
  check(event.path_error_event_zscore, "error_rate");
}

void RuleEngine::check_new_seen_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T1_HEURISTIC,
      "Checking 'new_seen' rules...");
  if (event.is_first_request_from_ip) {
    for (const auto &sensitive : app_config.tier1.sensitive_path_substrings) {
      if (event.raw_log.request_path.find(sensitive) != std::string::npos) {
        LOG(LogLevel::DEBUG, LogComponent::RULES_T1_HEURISTIC,
            "'new_ip_sensitive_path' TRIGGERED for IP "
                << event.raw_log.ip_address << " accessing "
                << event.raw_log.request_path);
        std::string reason =
            "Newly seen IP immediately accessed a sensitive path containing '" +
            sensitive + "'.";
        std::string alert_str =
            "High Priority: Investigate IP for targeted probing.";
        create_and_record_alert(event, reason, AlertTier::TIER1_HEURISTIC,
                                AlertAction::BLOCK, alert_str,
                                app_config.tier1.score_sensitive_path_new_ip,
                                event.raw_log.ip_address);
        break;
      }
    }
  }

  if (event.is_path_new_for_ip && event.ip_error_event_zscore &&
      *event.ip_error_event_zscore > 2.5) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T2_STATISTICAL,
        "'new_path_high_error' TRIGGERED for IP "
            << event.raw_log.ip_address << " accessing "
            << event.raw_log.request_path);
    double score =
        Scoring::from_z_score(*event.ip_error_event_zscore, 2.5, 70.0);
    std::string reason = "IP began generating a high error rate (Z-score: " +
                         std::to_string(*event.ip_error_event_zscore) +
                         ") while accessing a new path for the first time";
    std::string action_str =
        "Investigate for vulnerability scanning or forced browsing.";
    create_and_record_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                            AlertAction::CHALLENGE, action_str, score,
                            event.raw_log.ip_address);
  }
}

void RuleEngine::check_historical_comparison_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T2_STATISTICAL,
      "Checking 'historical_comparison' rules...");
  const auto &cfg = app_config.tier2;
  const size_t min_samples = cfg.min_samples_for_z_score;

  if (event.raw_log.request_time_s && event.ip_hist_req_time_mean &&
      event.ip_hist_req_time_samples &&
      *event.ip_hist_req_time_samples >= min_samples &&
      *event.ip_hist_req_time_mean > 0) {
    if (*event.raw_log.request_time_s >
        (*event.ip_hist_req_time_mean * cfg.historical_deviation_factor)) {
      LOG(LogLevel::DEBUG, LogComponent::RULES_T2_STATISTICAL,
          "'historical_deviation_req_time' TRIGGERED for IP "
              << event.raw_log.ip_address
              << ". Current: " << *event.raw_log.request_time_s << " > "
              << cfg.historical_deviation_factor
              << "x Mean: " << *event.ip_hist_req_time_mean);
      double score = Scoring::from_threshold(
          *event.raw_log.request_time_s,
          *event.ip_hist_req_time_mean * cfg.historical_deviation_factor,
          *event.ip_hist_req_time_mean * cfg.historical_deviation_factor * 5,
          50.0);
      std::string reason =
          "Sudden performance degradation for IP. Request time " +
          std::to_string(*event.raw_log.request_time_s) + "s is >" +
          std::to_string(cfg.historical_deviation_factor) +
          "x the historical average of " +
          std::to_string(*event.ip_hist_req_time_mean) + "s";
      std::string action_str =
          "Investigate IP for unusual load or targeted DoS.";
      create_and_record_alert(event, reason, AlertTier::TIER2_STATISTICAL,
                              AlertAction::LOG, action_str, score,
                              event.raw_log.ip_address);
    }
  }
}

// =================================================================================
// Tier 3: Machine Learning Rules
// =================================================================================

void RuleEngine::check_ml_rules(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::RULES_T3_ML, "Checking 'ml' rules...");
  if (event.feature_vector.empty()) {
    LOG(LogLevel::TRACE, LogComponent::RULES_T3_ML,
        "Skipping ML check, feature vector is empty.");
    return;
  }

  auto model = model_manager_->get_active_model();
  if (!model) {
    LOG(LogLevel::WARN, LogComponent::RULES_T3_ML,
        "Skipping ML check, no active model loaded.");
    return;
  }

  auto [score, explanation_vec] =
      model->score_with_explanation(event.feature_vector);
  LOG(LogLevel::DEBUG, LogComponent::ML_INFERENCE,
      "ML model scored event for IP " << event.raw_log.ip_address
                                      << " with a score of: " << score);

  if (score > app_config.tier3.anomaly_score_threshold) {
    LOG(LogLevel::DEBUG, LogComponent::RULES_T3_ML,
        "'ml_anomaly' TRIGGERED for IP "
            << event.raw_log.ip_address << ". Score: " << score
            << " > Threshold: " << app_config.tier3.anomaly_score_threshold);
    std::string reason =
        "High ML Anomaly Score detected: " + std::to_string(score);
    std::string action_str = "Review event; flagged as anomalous by ML model.";

    auto ml_alert = Alert(std::make_shared<const AnalyzedEvent>(event), reason,
                          AlertTier::TIER3_ML, AlertAction::BLOCK, action_str,
                          score, event.raw_log.ip_address);

    std::string contrib_str;
    for (size_t i = 0; i < explanation_vec.size(); ++i) {
      contrib_str += explanation_vec[i];
      if (i < explanation_vec.size() - 1)
        contrib_str += ", ";
    }
    ml_alert.ml_feature_contribution = contrib_str;

    alert_mgr.record_alert(ml_alert);
  }
}
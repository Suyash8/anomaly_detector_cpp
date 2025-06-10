#include "analysis_engine.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "ua_parser.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>

AnalysisEngine::AnalysisEngine(const Config::AppConfig &cfg) : app_config(cfg) {
  std::cout << "AnalysisEngine created." << std::endl;
}

AnalysisEngine::~AnalysisEngine() {}

PerIpState &
AnalysisEngine::get_or_create_ip_state(const std::string &ip,
                                       uint64_t current_timestamp_ms) {
  auto it = ip_activity_trackers.find(ip);
  if (it == ip_activity_trackers.end()) {
    uint64_t window_duration_ms =
        app_config.tier1.sliding_window_duration_seconds * 1000;

    // Assuming failed login window uses the same duration for now
    auto [inserted_it, success] = ip_activity_trackers.emplace(
        ip, PerIpState(current_timestamp_ms, window_duration_ms,
                       window_duration_ms));

    return inserted_it->second;
  } else {
    it->second.last_seen_timestamp_ms = current_timestamp_ms;
    return it->second;
  }
}

void perform_advanced_ua_analysis(const std::string &ua,
                                  const Config::Tier1Config &cfg,
                                  PerIpState &ip_state, AnalyzedEvent &event,
                                  uint64_t ts) {
  if (!cfg.check_user_agent_anomalies)
    return;

  // 1. Missing UA
  if (ua.empty() || ua == "-") {
    event.is_ua_missing = true;
    return;
  }

  // 2. Headless/Known Bad Bot detection
  if (ua.find("HeadlessChrome") != std::string::npos ||
      ua.find("Puppeteer") != std::string::npos) {
    event.is_ua_headless = true;
  }
  if (ua.find("sqlmap") != std::string::npos ||
      ua.find("Nmap") != std::string::npos) {
    event.is_ua_known_bad = true;
  }

  // 3. Version Check
  if (auto ver = UAParser::get_major_version(ua, "Chrome/");
      ver && *ver < cfg.min_chrome_version) {
    event.is_ua_outdated = true;
    event.detected_browser_version = "Chrome/" + std::to_string(*ver);
  } else if (auto ver = UAParser::get_major_version(ua, "Firefox/");
             ver && *ver < cfg.min_firefox_version) {
    event.is_ua_outdated = true;
    event.detected_browser_version = "Firefox/" + std::to_string(*ver);
  }

  // 4. Platform Inconsistency
  bool has_desktop = ua.find("Windows") != std::string::npos ||
                     ua.find("Macintosh") != std::string::npos ||
                     ua.find("Linux") != std::string::npos;
  bool has_mobile = ua.find("iPhone") != std::string::npos ||
                    ua.find("Android") != std::string::npos;
  if (has_desktop && has_mobile) {
    event.is_ua_inconsistent = true;
  }

  // 5. UA changed and cycling check
  // Prune the cycling window first
  ip_state.recent_unique_ua_window.prune_old_events(ts);

  // Check if UA changed since last request
  if (!ip_state.last_known_user_agent.empty() &&
      ip_state.last_known_user_agent != ua)
    event.is_ua_changed_for_ip = true;
  ip_state.last_known_user_agent = ua;

  // Add to cycling window only if it is a new UA for the window
  bool found_in_window = false;
  for (const auto &pair :
       ip_state.recent_unique_ua_window.get_raw_window_data()) {
    if (pair.second == ua) {
      found_in_window = true;
      break;
    }
  }

  if (!found_in_window)
    ip_state.recent_unique_ua_window.add_event(ts, ua);
  if (ip_state.recent_unique_ua_window.get_event_count() >
      static_cast<size_t>(cfg.max_unique_uas_per_ip_in_window))
    event.is_ua_cycling = true;
}

AnalyzedEvent AnalysisEngine::process_and_analyze(const LogEntry &raw_log) {
  AnalyzedEvent event(raw_log);

  if (!raw_log.parsed_timestamp_ms)
    return event;
  uint64_t current_event_ts = *raw_log.parsed_timestamp_ms;

  PerIpState &current_ip_state =
      get_or_create_ip_state(raw_log.ip_address, current_event_ts);

  // --- Tier 1 window updates ---
  // Update IP's request timestamp window
  current_ip_state.request_timestamps_window.add_event(current_event_ts,
                                                       current_event_ts);
  event.current_ip_request_count_in_window =
      current_ip_state.request_timestamps_window.get_event_count();

  // Update IP's failed login window if applicable
  if (raw_log.http_status_code) {
    int status = *raw_log.http_status_code;
    if (status == 401 || status == 403)
      current_ip_state.failed_login_timestamps_window.add_event(
          current_event_ts, static_cast<uint64_t>(status));
  }

  event.current_ip_failed_login_count_in_window =
      current_ip_state.failed_login_timestamps_window.get_event_count();

  // --- Tier 2 historical stats updates ---
  if (raw_log.request_time_s)
    current_ip_state.request_time_tracker.update(*raw_log.request_time_s);
  if (raw_log.bytes_sent)
    current_ip_state.bytes_sent_tracker.update(*raw_log.bytes_sent);

  bool is_error =
      (raw_log.http_status_code && *raw_log.http_status_code > 400 &&
       *raw_log.http_status_code < 600);
  current_ip_state.error_rate_tracker.update(is_error ? 1.0 : 0.0);

  double current_requests_in_gen_window = static_cast<double>(
      current_ip_state.request_timestamps_window.get_event_count());
  current_ip_state.requests_in_window_count_tracker.update(
      current_requests_in_gen_window);

  // --- Populate AnalyzedEvent with raw historical stats ---
  event.ip_hist_req_time_mean =
      current_ip_state.request_time_tracker.get_mean();
  event.ip_hist_req_time_stddev =
      current_ip_state.request_time_tracker.get_stddev();
  event.ip_hist_req_time_samples =
      current_ip_state.request_time_tracker.get_count();

  event.ip_hist_bytes_mean = current_ip_state.bytes_sent_tracker.get_mean();
  event.ip_hist_bytes_stddev = current_ip_state.bytes_sent_tracker.get_stddev();
  event.ip_hist_bytes_samples = current_ip_state.bytes_sent_tracker.get_count();

  event.ip_hist_error_rate_mean =
      current_ip_state.error_rate_tracker.get_mean();
  event.ip_hist_error_rate_stddev =
      current_ip_state.error_rate_tracker.get_stddev();
  event.ip_hist_error_rate_samples =
      current_ip_state.error_rate_tracker.get_count();

  event.ip_hist_req_vol_mean =
      current_ip_state.requests_in_window_count_tracker.get_mean();
  event.ip_hist_req_vol_stddev =
      current_ip_state.requests_in_window_count_tracker.get_stddev();
  event.ip_hist_req_vol_samples =
      current_ip_state.requests_in_window_count_tracker.get_count();

  // --- Z-Score calculation logic ---
  const auto &tier2_cfg = app_config.tier2;
  long min_samples = tier2_cfg.min_samples_for_z_score;

  // Req Time Z-score
  if (raw_log.request_time_s &&
      current_ip_state.request_time_tracker.get_count() >= min_samples) {
    double stddev = current_ip_state.request_time_tracker.get_stddev();
    if (stddev > 1e-6) // Avoid division by zero
      event.ip_req_time_zscore =
          (*raw_log.request_time_s -
           current_ip_state.request_time_tracker.get_mean()) /
          stddev;
  }

  // Bytes Sent Z-score
  if (raw_log.bytes_sent &&
      current_ip_state.bytes_sent_tracker.get_count() >= min_samples) {
    double stddev = current_ip_state.bytes_sent_tracker.get_stddev();
    if (stddev > 1.0) // Require at least 1 byte of stddev to be meaningful
      event.ip_bytes_sent_zscore =
          (static_cast<double>(*raw_log.bytes_sent) -
           current_ip_state.bytes_sent_tracker.get_mean()) /
          stddev;
  }

  // Error Event Z-score
  if (current_ip_state.error_rate_tracker.get_count() >= min_samples) {
    double current_error_val =
        (raw_log.http_status_code && *raw_log.http_status_code >= 400) ? 1.0
                                                                       : 0.0;
    double stddev = current_ip_state.error_rate_tracker.get_stddev();

    if (stddev > 0.01) // Require some variability
      event.ip_error_event_zscore =
          (current_error_val - current_ip_state.error_rate_tracker.get_mean()) /
          stddev;
  }

  // Request Volume Z-score
  if (current_ip_state.requests_in_window_count_tracker.get_count() >=
      min_samples) {
    double current_req_vol = static_cast<double>(
        current_ip_state.request_timestamps_window.get_event_count());
    double stddev =
        current_ip_state.requests_in_window_count_tracker.get_stddev();

    if (stddev > 0.5) // Require some variabilitu
      event.ip_req_vol_zscore =
          (current_req_vol -
           current_ip_state.requests_in_window_count_tracker.get_mean()) /
          stddev;
  }

  // --- User-Agent analysis logic ---
  perform_advanced_ua_analysis(raw_log.user_agent, app_config.tier1,
                               current_ip_state, event, current_event_ts);

  // --- Suspicious string scaning ---
  for (const auto &substr : app_config.tier1.suspicious_path_substrings) {
    if (raw_log.request_path.find(substr) != std::string::npos) {
      event.found_suspicious_path_str = true;
      break;
    }
  }

  for (const auto &substr : app_config.tier1.suspicious_ua_substrings) {
    if (raw_log.user_agent.find(substr) != std::string::npos) {
      event.found_suspicious_ua_str = true;
      break;
    }
  }

  return event;
}
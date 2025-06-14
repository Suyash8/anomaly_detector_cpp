#include "analysis_engine.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "ua_parser.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

enum class RequestType { HTML, ASSET, OTHER };

RequestType get_request_type(const std::string &path,
                             const Config::Tier1Config &cfg) {
  for (const auto &exact : cfg.html_exact_paths) {
    if (path == exact)
      return RequestType::HTML;
  }

  for (const auto &prefix : cfg.asset_path_prefixes) {
    if (path.rfind(prefix, 0) == 0)
      return RequestType::ASSET;
  }

  size_t last_dot = path.rfind('.');
  if (last_dot != std::string::npos) {
    std::string suffix = path.substr(last_dot);

    for (const auto &s : cfg.html_path_suffixes) {
      if (suffix == s)
        return RequestType::HTML;
    }

    for (const auto &s : cfg.asset_path_suffixes) {
      if (suffix == s)
        return RequestType::ASSET;
    }
  }

  return RequestType::OTHER;
}

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

PerPathState &
AnalysisEngine::get_or_create_path_state(const std::string &path,
                                         uint64_t current_timestamp_ms) {
  auto it = path_activity_trackers.find(path);
  if (it == path_activity_trackers.end()) {
    auto [inserted_it, success] = path_activity_trackers.emplace(
        path, PerPathState(current_timestamp_ms));
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

void ::AnalysisEngine::prune_inactive_states(uint64_t current_timestamp_ms) {
  const uint64_t ttl_ms = app_config.tier1.inactive_state_ttl_seconds * 1000;
  if (ttl_ms == 0)
    return;

  for (auto it = ip_activity_trackers.begin();
       it != ip_activity_trackers.end();) {
    if ((current_timestamp_ms - it->second.last_seen_timestamp_ms) > ttl_ms)
      it = ip_activity_trackers.erase(it);
    else
      ++it;
  }

  for (auto it = path_activity_trackers.begin();
       it != path_activity_trackers.end();) {
    if ((current_timestamp_ms - it->second.last_seen_timestamp_ms) > ttl_ms)
      it = path_activity_trackers.erase(it);
    else
      ++it;
  }
}

AnalyzedEvent AnalysisEngine::process_and_analyze(const LogEntry &raw_log) {
  AnalyzedEvent event(raw_log);

  if (!raw_log.parsed_timestamp_ms)
    return event;
  uint64_t current_event_ts = *raw_log.parsed_timestamp_ms;

  // --- Periodic Pruning ---
  events_processed_since_last_prune_++;
  if (events_processed_since_last_prune_ >= PRUNE_CHECK_INTERNVAL) {
    prune_inactive_states(current_event_ts);
    events_processed_since_last_prune_ = 0;
  }

  PerIpState &current_ip_state =
      get_or_create_ip_state(raw_log.ip_address, current_event_ts);
  PerPathState &current_path_state =
      get_or_create_path_state(raw_log.request_path, current_event_ts);

  // --- "New Seen" Tracking Logic ---
  if (current_ip_state.ip_first_seen_timestamp_ms == 0) {
    current_ip_state.ip_first_seen_timestamp_ms = current_event_ts;
    event.is_first_request_from_ip = true;
  }

  if (current_ip_state.paths_seen_by_ip.find(raw_log.request_path) ==
      current_ip_state.paths_seen_by_ip.end()) {
    event.is_path_new_for_ip = true;
    current_ip_state.paths_seen_by_ip.insert(raw_log.request_path);
  }

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

  // HTML/Asset request tracking
  RequestType type = get_request_type(raw_log.request_path, app_config.tier1);
  if (type == RequestType::HTML)
    current_ip_state.html_request_timestamps.add_event(current_event_ts, 1);
  else if (type == RequestType::ASSET)
    current_ip_state.asset_request_timestamps.add_event(current_event_ts, 1);

  event.ip_html_requests_in_window =
      current_ip_state.html_request_timestamps.get_event_count();
  event.ip_asset_requests_in_window =
      current_ip_state.asset_request_timestamps.get_event_count();

  if (event.ip_html_requests_in_window > 0)
    event.ip_assets_per_html_ratio =
        static_cast<double>(event.ip_asset_requests_in_window) /
        static_cast<double>(event.ip_html_requests_in_window);

  // --- Tier 2 historical stats updates ---
  if (raw_log.request_time_s) {
    current_ip_state.request_time_tracker.update(*raw_log.request_time_s);
    current_path_state.request_time_tracker.update(*raw_log.request_time_s);
  }
  if (raw_log.bytes_sent) {
    current_ip_state.bytes_sent_tracker.update(
        static_cast<double>(*raw_log.bytes_sent));
    current_path_state.bytes_sent_tracker.update(
        static_cast<double>(*raw_log.bytes_sent));
  }
  bool is_error =
      (raw_log.http_status_code && *raw_log.http_status_code > 400 &&
       *raw_log.http_status_code < 600);
  current_ip_state.error_rate_tracker.update(is_error ? 1.0 : 0.0);
  current_path_state.error_rate_tracker.update(is_error ? 1.0 : 0.0);

  current_path_state.request_volume_tracker.update(1.0);

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

  event.path_hist_req_time_mean =
      current_path_state.request_time_tracker.get_mean();
  event.path_hist_req_time_stddev =
      current_path_state.request_time_tracker.get_stddev();

  event.path_hist_bytes_mean = current_path_state.bytes_sent_tracker.get_mean();
  event.path_hist_bytes_stddev =
      current_path_state.bytes_sent_tracker.get_stddev();

  event.path_hist_error_rate_mean =
      current_path_state.error_rate_tracker.get_mean();
  event.path_hist_error_rate_stddev =
      current_path_state.error_rate_tracker.get_stddev();

  // --- Z-Score calculation logic ---
  const auto &tier2_cfg = app_config.tier2;
  long min_samples = tier2_cfg.min_samples_for_z_score;

  // Path Req Time Z-score
  if (raw_log.request_time_s &&
      current_path_state.request_time_tracker.get_count() >= min_samples) {
    double stddev = *event.path_hist_req_time_stddev;
    if (stddev > 1e-6)
      event.path_req_time_zscore =
          (*raw_log.request_time_s - *event.path_hist_req_time_mean) / stddev;
  }

  // Path Bytes Sent Z-score
  if (raw_log.bytes_sent &&
      current_path_state.bytes_sent_tracker.get_count() >= min_samples) {
    double stddev = *event.path_hist_bytes_stddev;
    if (stddev > 1.0)
      event.path_bytes_sent_zscore = (static_cast<double>(*raw_log.bytes_sent) -
                                      *event.path_hist_bytes_mean) /
                                     stddev;
  }

  // Path Error Event Z-score
  if (current_path_state.error_rate_tracker.get_count() >= min_samples) {
    double current_error_val =
        (raw_log.http_status_code && *raw_log.http_status_code >= 400) ? 1.0
                                                                       : 0.0;
    double stddev = *event.path_hist_error_rate_stddev;
    if (stddev > 0.01)
      event.path_error_event_zscore =
          (current_error_val - *event.path_hist_error_rate_mean) / stddev;
  }

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
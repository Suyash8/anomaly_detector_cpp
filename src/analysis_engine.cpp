#include "analysis_engine.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
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
  const std::string &current_ua = raw_log.user_agent;

  // 1. Check if UA is missing
  if (current_ua.empty() || current_ua == "-")
    event.is_ua_missing = true;

  // 2. Check if UA has changed for this IP
  if (!event.is_ua_missing) {
    if (current_ip_state.historical_user_agents.empty())
      current_ip_state.last_known_user_agent = current_ua;
    else if (current_ip_state.last_known_user_agent != current_ua) {
      event.is_ua_changed_for_ip = true;
      current_ip_state.last_known_user_agent = current_ua;
    }

    // Add to historical set
    // TODO: Maybe try making it a queue or something?
    if (current_ip_state.historical_user_agents.size() < 20)
      current_ip_state.historical_user_agents.insert(current_ua);

    // 3. Basic check for known bad UA (example)
    // TODO: Bring this list from config
    if (current_ua.find("sqlmap") != std::string::npos ||
        current_ua.find("Nmap") != std::string::npos)
      event.is_ua_known_bad = true;
  }

  return event;
}
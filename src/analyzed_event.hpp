#ifndef ANALYZED_EVENT_HPP
#define ANALYZED_EVENT_HPP

#include "log_entry.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

struct AnalyzedEvent {
  LogEntry raw_log;

  // ----------------------------
  // Request behaviour statistics
  // ----------------------------

  // Window-based IP request stats
  std::optional<size_t> current_ip_request_count_in_window;
  std::optional<size_t> current_ip_failed_login_count_in_window;

  // Historical stats for IP request time
  std::optional<double> ip_hist_req_time_mean;
  std::optional<double> ip_hist_req_time_stddev;
  std::optional<uint64_t> ip_hist_req_time_samples;

  // Historical stats for bytes sent by IP
  std::optional<double> ip_hist_bytes_mean;
  std::optional<double> ip_hist_bytes_stddev;
  std::optional<uint64_t> ip_hist_bytes_samples;

  // Historical stats for error rate from IP
  std::optional<double> ip_hist_error_rate_mean;
  std::optional<double> ip_hist_error_rate_stddev;
  std::optional<uint64_t> ip_hist_error_rate_samples;

  // Historical stats for request volume from IP
  std::optional<double> ip_hist_req_vol_mean;
  std::optional<double> ip_hist_req_vol_stddev;
  std::optional<uint64_t> ip_hist_req_vol_samples;

  // Z-scores for IP behaviour deviation
  std::optional<double> ip_req_time_zscore;
  std::optional<double> ip_bytes_sent_zscore;
  std::optional<double> ip_error_event_zscore;
  std::optional<double> ip_req_vol_zscore;

  // Historical stats for path request time
  std::optional<double> path_hist_req_time_mean;
  std::optional<double> path_hist_req_time_stddev;
  std::optional<double> path_req_time_zscore;

  // Historical stats for path bytes sent
  std::optional<double> path_hist_bytes_mean;
  std::optional<double> path_hist_bytes_stddev;
  std::optional<double> path_bytes_sent_zscore;

  // Historical stats for path error rate
  std::optional<double> path_hist_error_rate_mean;
  std::optional<double> path_hist_error_rate_stddev;
  std::optional<double> path_error_event_zscore;

  //----------------------
  // Binary analysis flags
  // ---------------------

  // Contextual request flags
  bool is_first_request_from_ip = false;
  bool is_path_new_for_ip = false;

  // UA analysis flags
  bool is_ua_missing = false;
  bool is_ua_changed_for_ip = false;
  bool is_ua_known_bad = false;
  bool is_ua_outdated = false;
  bool is_ua_headless = false;
  bool is_ua_inconsistent = false;
  bool is_ua_cycling = false;
  std::string detected_browser_version;

  // Suspicious string flags
  bool found_suspicious_path_str = false;
  bool found_suspicious_ua_str = false;

  // ---------------------------
  // Request type categorization
  // ---------------------------

  int ip_html_requests_in_window = 0;
  int ip_asset_requests_in_window = 0;
  std::optional<double> ip_assets_per_html_ratio;

  // ----------------------
  // Machine learning input
  // ----------------------

  std::vector<double> feature_vector;

  // -------------------
  // --- Constructor ---
  // -------------------

  AnalyzedEvent(const LogEntry &log)
      : raw_log(log), is_first_request_from_ip(false),
        is_path_new_for_ip(false), is_ua_missing(false),
        is_ua_changed_for_ip(false), is_ua_known_bad(false),
        is_ua_outdated(false), is_ua_headless(false), is_ua_inconsistent(false),
        is_ua_cycling(false), found_suspicious_path_str(false),
        found_suspicious_ua_str(false), ip_html_requests_in_window(0),
        ip_asset_requests_in_window(0) {}
};

#endif // ANALYZED_EVENT_HPP
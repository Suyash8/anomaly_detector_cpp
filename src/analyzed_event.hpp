#ifndef ANALYZED_EVENT_HPP
#define ANALYZED_EVENT_HPP

#include "log_entry.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

struct AnalyzedEvent {
  LogEntry raw_log; // Keep the original log entry

  // Fields to be populated by AnalysisEngine
  // Initial Tier 1 related analysis results (previously calculated in
  // RuleEngine)
  std::optional<size_t> current_ip_request_count_in_window;
  std::optional<size_t> current_ip_failed_login_count_in_window;

  // Raw historical stats for IP
  std::optional<double> ip_hist_req_time_mean;
  std::optional<double> ip_hist_req_time_stddev;
  std::optional<uint64_t> ip_hist_req_time_samples;

  std::optional<double> ip_hist_bytes_mean;
  std::optional<double> ip_hist_bytes_stddev;
  std::optional<uint64_t> ip_hist_bytes_samples;

  std::optional<double> ip_hist_error_rate_mean;
  std::optional<double> ip_hist_error_rate_stddev;
  std::optional<uint64_t> ip_hist_error_rate_samples;

  std::optional<double> ip_hist_req_vol_mean;
  std::optional<double> ip_hist_req_vol_stddev;
  std::optional<uint64_t> ip_hist_req_vol_samples;

  std::optional<double> ip_req_time_zscore;
  std::optional<double> ip_bytes_sent_zscore;
  std::optional<double> ip_error_event_zscore;
  std::optional<double> ip_req_vol_zscore;

  std::optional<double> path_hist_req_time_mean;
  std::optional<double> path_hist_req_time_stddev;
  std::optional<double> path_req_time_zscore;

  std::optional<double> path_hist_bytes_mean;
  std::optional<double> path_hist_bytes_stddev;
  std::optional<double> path_bytes_sent_zscore;

  std::optional<double> path_hist_error_rate_mean;
  std::optional<double> path_hist_error_rate_stddev;
  std::optional<double> path_error_event_zscore;

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

  int ip_html_requests_in_window = 0;
  int ip_asset_requests_in_window = 0;
  std::optional<double> ip_assets_per_html_ratio;

  // Default constructor
  AnalyzedEvent(const LogEntry &log) : raw_log(log) {}
};

#endif // ANALYZED_EVENT_HPP
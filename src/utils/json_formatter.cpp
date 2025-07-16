#include "json_formatter.hpp"

#include <sstream>
#include <string_view>

std::string JsonFormatter::escape_json_value(std::string_view input) {
  std::ostringstream o;
  for (char c : input)
    switch (c) {
    case '"':
      o << "\\\"";
      break;
    case '\\':
      o << "\\\\";
      break;
    case '\b':
      o << "\\b";
      break;
    case '\f':
      o << "\\f";
      break;
    case '\n':
      o << "\\n";
      break;
    case '\r':
      o << "\\r";
      break;
    case '\t':
      o << "\\t";
      break;
    default:
      // if (('\x00' <= c && c <= '\x1f') || (c >= '\x80' && c <= '\xff'))
      //   o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
      //     << static_cast<int>(static_cast<unsigned char>(c));
      // else
      //   o << c;
      if (c >= 32 && c <= 126)
        o << c;
    }
  return o.str();
}

nlohmann::json JsonFormatter::alert_to_json_object(const Alert &alert_data) {
  nlohmann::json j;
  const auto &analysis_context = *alert_data.event_context;
  const auto &log_context = analysis_context.raw_log;

  // Helper to handle optional values cleanly
  auto get_opt = [](const auto &opt, auto default_val) {
    return opt.value_or(default_val);
  };

  // === Core Alert Info ===

  // All string values are escaped for JSON safety
  j["timestamp_ms"] = alert_data.event_timestamp_ms;
  j["alert_reason"] = escape_json_value(alert_data.alert_reason);
  j["detection_tier"] =
      alert_tier_to_string_representation(alert_data.detection_tier);
  j["suggested_action"] = escape_json_value(alert_data.suggested_action);
  j["action_code"] = alert_action_to_string(alert_data.action_code);
  j["anomaly_score"] = alert_data.normalized_score;
  j["offending_key"] = escape_json_value(alert_data.offending_key_identifier);
  j["ml_contributing_factors"] = alert_data.ml_feature_contribution;

  // === Log Context (The Raw Log Fields) ===
  nlohmann::json j_log;
  j_log["source_ip"] = escape_json_value(log_context.ip_address);
  j_log["line_number"] = log_context.original_line_number;
  j_log["host"] = escape_json_value(log_context.host);
  j_log["timestamp_str"] = escape_json_value(log_context.timestamp_str);
  j_log["request_method"] = escape_json_value(log_context.request_method);
  j_log["request_path"] = escape_json_value(log_context.request_path);
  j_log["request_protocol"] = escape_json_value(log_context.request_protocol);
  j_log["status_code"] = get_opt(log_context.http_status_code, 0);
  j_log["bytes_sent"] = get_opt(log_context.bytes_sent, (uint64_t)0);
  j_log["request_time_s"] = get_opt(log_context.request_time_s, 0.0);
  j_log["user_agent"] = escape_json_value(log_context.user_agent);
  j_log["referer"] = escape_json_value(log_context.referer);
  j_log["country_code"] = escape_json_value(log_context.country_code);
  j_log["x_request_id"] = escape_json_value(log_context.x_request_id);
  j["log_context"] = j_log;

  // === Analysis Context (The Rich, Calculated Data) ===
  nlohmann::json j_analysis;

  // Binary Flags
  j_analysis["flags"] = {
      {"is_first_request_from_ip", analysis_context.is_first_request_from_ip},
      {"is_path_new_for_ip", analysis_context.is_path_new_for_ip},
      {"is_ua_missing", analysis_context.is_ua_missing},
      {"is_ua_changed_for_ip", analysis_context.is_ua_changed_for_ip},
      {"is_ua_known_bad", analysis_context.is_ua_known_bad},
      {"is_ua_outdated", analysis_context.is_ua_outdated},
      {"is_ua_headless", analysis_context.is_ua_headless},
      {"is_ua_inconsistent", analysis_context.is_ua_inconsistent},
      {"is_ua_cycling", analysis_context.is_ua_cycling},
      {"found_suspicious_path_str", analysis_context.found_suspicious_path_str},
      {"found_suspicious_ua_str", analysis_context.found_suspicious_ua_str}};

  // Windowed Stats
  j_analysis["windowed_stats"] = {
      {"ip_request_count",
       get_opt(analysis_context.current_ip_request_count_in_window, (size_t)0)},
      {"ip_failed_login_count",
       get_opt(analysis_context.current_ip_failed_login_count_in_window,
               (size_t)0)},
      {"ip_html_requests", analysis_context.ip_html_requests_in_window},
      {"ip_asset_requests", analysis_context.ip_asset_requests_in_window},
      {"ip_assets_per_html_ratio",
       get_opt(analysis_context.ip_assets_per_html_ratio, 0.0)}};

  // Z-Scores
  j_analysis["z_scores"] = {
      {"ip_req_time", get_opt(analysis_context.ip_req_time_zscore, 0.0)},
      {"ip_bytes_sent", get_opt(analysis_context.ip_bytes_sent_zscore, 0.0)},
      {"ip_error_event", get_opt(analysis_context.ip_error_event_zscore, 0.0)},
      {"ip_req_volume", get_opt(analysis_context.ip_req_vol_zscore, 0.0)},
      {"path_req_time", get_opt(analysis_context.path_req_time_zscore, 0.0)},
      {"path_bytes_sent",
       get_opt(analysis_context.path_bytes_sent_zscore, 0.0)},
      {"path_error_event",
       get_opt(analysis_context.path_error_event_zscore, 0.0)}};

  // Session Features (if they exist)
  if (analysis_context.raw_session_state.has_value()) {
    const auto &session = analysis_context.raw_session_state.value();
    const auto &derived =
        analysis_context.derived_session_features.value_or(SessionFeatures{});
    j_analysis["session_context"] = {
        {"start_time_ms", session.session_start_timestamp_ms},
        {"last_seen_ms", session.last_seen_timestamp_ms},
        {"request_count", session.request_count},
        {"unique_paths", session.unique_paths_visited.size()},
        {"unique_uas", session.unique_user_agents.size()},
        {"failed_logins", session.failed_login_attempts},
        {"errors_4xx", session.error_4xx_count},
        {"errors_5xx", session.error_5xx_count},
        {"avg_time_between_reqs_s", derived.avg_time_between_request_s},
        {"post_to_get_ratio", derived.post_to_get_ratio}};
  } else {
    j_analysis["session_context"] = nullptr;
  }

  j["analysis_context"] = j_analysis;

  // Add the raw log line itself for full context
  j["raw_log_line"] = escape_json_value(log_context.raw_log_line);

  return j;
}

std::string JsonFormatter::format_alert_to_json(const Alert &alert_data) {
  return alert_to_json_object(alert_data).dump();
}
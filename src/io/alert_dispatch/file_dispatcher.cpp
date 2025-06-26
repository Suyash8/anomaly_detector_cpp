#include "file_dispatcher.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

FileDispatcher::FileDispatcher(const std::string &file_path)
    : alert_file_output_path_(file_path) {
  if (!alert_file_output_path_.empty()) {
    alert_file_stream_.open(alert_file_output_path_, std::ios::app);
    if (!alert_file_stream_.is_open())
      std::cerr << "Error: FileDispatcher could not open alert output file: "
                << alert_file_output_path_ << std::endl;
  }
}

std::string
FileDispatcher::format_alert_to_json(const Alert &alert_data) const {
  const auto &log_context = alert_data.event_context->raw_log;
  const auto &analysis_context = *alert_data.event_context;

  std::ostringstream ss;
  ss << "{ ";
  ss << "\"timestamp_ms\": " << alert_data.event_timestamp_ms << ", ";

  // ISO 8601 timestamp for human readability in other tools
  auto time_in_seconds =
      static_cast<std::time_t>(alert_data.event_timestamp_ms / 1000);
  char time_buffer[100];

  std::tm tm_buf;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  std::tm *tm_info = gmtime_r(&time_in_seconds, &tm_buf);
#elif defined(_MSC_VER)
  errno_t err = gmtime_s(&tm_buf, &time_in_seconds);
  std::tm *tm_info = (err == 0) ? &tm_buf : nullptr;
#else
  std::tm *tm_info = std::gmtime(&time_in_seconds);
#endif

  if (tm_info) {
    std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%dT%H:%M:%S",
                  tm_info);
    ss << "\"timestamp_utc\":\"" << time_buffer << "." << std::setw(3)
       << std::setfill('0') << (alert_data.event_timestamp_ms % 1000) << "Z\",";
  }

  // Core Alert Info
  ss << "\"alert_reason\":\"" << escape_json_value(alert_data.alert_reason)
     << "\",";
  ss << "\"detection_tier\":\""
     << alert_tier_to_string_representation(alert_data.detection_tier) << "\",";
  ss << "\"suggested_action\":\""
     << escape_json_value(alert_data.suggested_action) << "\",";
  ss << "\"action\":\""
     << escape_json_value(alert_action_to_string(alert_data.action_code));
  ss << "\"anomaly_score\":" << alert_data.normalized_score << ",";
  ss << "\"offending_key\":\""
     << escape_json_value(alert_data.offending_key_identifier) << "\",";
  ss << "\"ml_contributing_factors\":\""
     << escape_json_value(alert_data.ml_feature_contribution) << "\",";

  // Log Context (all the important fields from the log that triggered the
  // alert)
  ss << "\"log_context\":{";
  ss << "\"source_ip\":\"" << escape_json_value(alert_data.source_ip) << "\",";
  ss << "\"log_line_number\":" << alert_data.associated_log_line << ",";
  ss << "\"host\":\"" << escape_json_value(log_context.host) << "\",";
  ss << "\"request_method\":\"" << escape_json_value(log_context.request_method)
     << "\",";
  ss << "\"request_path\":\"" << escape_json_value(log_context.request_path)
     << "\",";
  ss << "\"status_code\":" << log_context.http_status_code.value_or(0) << ",";
  ss << "\"bytes_sent\":" << log_context.bytes_sent.value_or(0) << ",";
  ss << "\"request_time_s\":" << log_context.request_time_s.value_or(0.0)
     << ",";
  ss << "\"user_agent\":\"" << escape_json_value(log_context.user_agent)
     << "\",";
  ss << "\"referer\":\"" << escape_json_value(log_context.referer) << "\",";
  ss << "\"country_code\":\"" << escape_json_value(log_context.country_code)
     << "\"";
  ss << "}";

  // Analysis Context (all the rich data from AnalyzedEvent)
  ss << ",\"analysis_context\":{";
  // Tier 1 flags
  ss << "\"is_ua_missing\":"
     << (analysis_context.is_ua_missing ? "true" : "false") << ",";
  ss << "\"is_ua_outdated\":"
     << (analysis_context.is_ua_outdated ? "true" : "false") << ",";
  ss << "\"is_ua_headless\":"
     << (analysis_context.is_ua_headless ? "true" : "false") << ",";
  ss << "\"is_ua_cycling\":"
     << (analysis_context.is_ua_cycling ? "true" : "false") << ",";
  ss << "\"found_suspicious_path_str\":"
     << (analysis_context.found_suspicious_path_str ? "true" : "false") << ",";
  ss << "\"found_suspicious_ua_str\":"
     << (analysis_context.found_suspicious_ua_str ? "true" : "false") << ",";
  // Tier 2 Z-scores
  ss << "\"ip_req_time_zscore\":"
     << analysis_context.ip_req_time_zscore.value_or(0.0) << ",";
  ss << "\"ip_bytes_sent_zscore\":"
     << analysis_context.ip_bytes_sent_zscore.value_or(0.0) << ",";
  ss << "\"ip_error_event_zscore\":"
     << analysis_context.ip_error_event_zscore.value_or(0.0) << ",";
  ss << "\"ip_req_vol_zscore\":"
     << analysis_context.ip_req_vol_zscore.value_or(0.0);
  // Add more analysis fields here as they are created
  ss << "}";

  ss << ",\"raw_log\":\""
     << escape_json_value(alert_data.raw_log_trigger_sample) << "\"";

  ss << "}";
  return ss.str();
}

std::string FileDispatcher::escape_json_value(const std::string &input) const {
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
      if ('\x00' <= c && c <= '\x1f')
        o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
          << static_cast<int>(static_cast<unsigned char>(c));
      else
        o << c;
    }
  return o.str();
}
#include "alert_manager.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include <string>

Alert::Alert(const AnalyzedEvent &event, const std::string &reason,
             AlertTier tier, const std::string &action, double score,
             const std::string &key_id)
    : event_timestamp_ms(event.raw_log.parsed_timestamp_ms.value_or(0)),
      source_ip(event.raw_log.ip_address), alert_reason(reason),
      detection_tier(tier), suggested_action(action),
      offending_key_identifier(key_id.empty() ? event.raw_log.ip_address
                                              : key_id),
      anomaly_score(score),
      associated_log_line(event.raw_log.original_line_number),
      raw_log_trigger_sample(event.raw_log.raw_log_line),
      ml_feature_contribution(""), log_context(event.raw_log),
      analysis_context(event) {}

std::string alert_tier_to_string_representation(AlertTier tier) {
  switch (tier) {
  case AlertTier::TIER1_HEURISTIC:
    return "TIER1_HEURISTIC";
  case AlertTier::TIER2_STATISTICAL:
    return "TIER2_STATISTICAL";
  case AlertTier::TIER3_ML:
    return "TIER3_ML";
  default:
    return "UNKNOWN_TIER";
  }
}

AlertManager::AlertManager()
    : output_alerts_to_stdout(true), output_alerts_to_file(false) {
  std::cout << "AlertManager created" << std::endl;
}

AlertManager::~AlertManager() {
  if (alert_file_stream.is_open()) {
    alert_file_stream.flush();
    alert_file_stream.close();
  }
}

void AlertManager::initialize(const Config::AppConfig &app_config) {
  output_alerts_to_stdout = app_config.alerts_to_stdout;
  output_alerts_to_file = app_config.alerts_to_file;
  alert_file_output_path = app_config.alert_output_path;
  // For now, keep file output simple or disable it until JSON formatting is
  // more robust output_alerts_to_file = app_config.alerts_to_file;
  // alert_file_output_path = app_config.alert_output_path;

  // A very simple approach for file output if enabled:
  if (output_alerts_to_file && !alert_file_output_path.empty()) {
    alert_file_stream.open(alert_file_output_path,
                           std::ios::app); // Append mode
    if (!alert_file_stream.is_open()) {
      std::cerr << "Error: AlertManager could not open alert output file: "
                << alert_file_output_path << std::endl;
      output_alerts_to_file = false; // Disable file output if open failed
    } else {
      std::cout << "Alerts will be logged to: " << alert_file_output_path
                << std::endl;
    }
  }
  std::cout << "AlertManager initialized. Stdout alerts: "
            << (output_alerts_to_stdout ? "Enabled" : "Disabled") << std::endl;
}

std::string AlertManager::escape_json_value(const std::string &input) const {
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
      if ('\x00' >= c && c < '\x1f')
        o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
          << static_cast<int>(static_cast<unsigned char>(c));
      else
        o << c;
    }
  return o.str();
}

std::string
AlertManager::format_alert_to_human_readable(const Alert &alert_data) const {
  // Naive string concatenation for now. std::ostringstream is better for
  // complex formatting.
  std::string formatted_alert = "ALERT DETECTED:\n";

  auto time_in_seconds =
      static_cast<std::time_t>(alert_data.event_timestamp_ms / 1000);
  char time_buffer[100];

  // Use std::strftime for POSIX-compliant systems. For Windows, localtime_s is
  // preferred. For simplicity, let's use std::localtime (note: not thread-safe
  // without care).
  std::tm *tm_info = std::localtime(&time_in_seconds);
  if (tm_info) {
    std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S",
                  tm_info);
  } else {
    std::snprintf(time_buffer, sizeof(time_buffer), "%llu",
                  (unsigned long long)alert_data.event_timestamp_ms);
  }

  formatted_alert += "  Timestamp: " + std::string(time_buffer) + "." +
                     std::to_string(alert_data.event_timestamp_ms % 1000) +
                     "\n";
  formatted_alert +=
      "  Tier:      " +
      alert_tier_to_string_representation(alert_data.detection_tier) + "\n";
  formatted_alert += "  Source IP: " + alert_data.source_ip + "\n";
  formatted_alert += "  Reason:    " + alert_data.alert_reason + "\n";

  if (!alert_data.offending_key_identifier.empty() &&
      alert_data.offending_key_identifier != alert_data.source_ip)
    formatted_alert +=
        "  Key ID:    " + alert_data.offending_key_identifier + "\n";

  if (alert_data.anomaly_score != 0)
    formatted_alert +=
        "  Score:     " + std::to_string(alert_data.anomaly_score) + "\n";

  formatted_alert += "  Action:    " + alert_data.suggested_action + "\n";

  if (!alert_data.ml_feature_contribution.empty())
    formatted_alert +=
        "  Factors:   " + alert_data.ml_feature_contribution + "\n";

  if (alert_data.associated_log_line > 0)
    formatted_alert +=
        "  Log Line:  " + std::to_string(alert_data.associated_log_line) + "\n";

  if (!alert_data.raw_log_trigger_sample.empty())
    formatted_alert +=
        "  Sample:    " + alert_data.raw_log_trigger_sample.substr(0, 100) +
        (alert_data.raw_log_trigger_sample.length() > 100 ? "..." : "") + "\n";

  formatted_alert += "----------------------------------------";
  return formatted_alert;
}

std::string AlertManager::format_alert_to_json(const Alert &alert_data) const {
  // Placeholder for JSON formatting - this is a more involved task for later
  // For now, could just return a simplified string or the human-readable one
  std::ostringstream ss;
  ss << "{ ";
  ss << "\"timestamp_ms\": " << alert_data.event_timestamp_ms << ", ";

  // ISO 8601 timestamp for human readability in other tools
  auto time_in_seconds =
      static_cast<std::time_t>(alert_data.event_timestamp_ms / 1000);
  char time_buffer[100];

  // std::gmtime is better for consistent UTC time format
  std::tm *tm_info = std::gmtime(&time_in_seconds);
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
  ss << "\"anomaly_score\":" << alert_data.anomaly_score << ",";
  ss << "\"offending_key\":\""
     << escape_json_value(alert_data.offending_key_identifier) << "\",";
  ss << "\"ml_contributing_factors\":\""
     << escape_json_value(alert_data.ml_feature_contribution) << "\",";

  // Log Context (all the important fields from the log that triggered the
  // alert)
  ss << "\"log_context\":{";
  ss << "\"source_ip\":\"" << escape_json_value(alert_data.source_ip) << "\",";
  ss << "\"log_line_number\":" << alert_data.associated_log_line << ",";
  ss << "\"host\":\"" << escape_json_value(alert_data.log_context.host)
     << "\",";
  ss << "\"request_method\":\""
     << escape_json_value(alert_data.log_context.request_method) << "\",";
  ss << "\"request_path\":\""
     << escape_json_value(alert_data.log_context.request_path) << "\",";
  ss << "\"status_code\":"
     << alert_data.log_context.http_status_code.value_or(0) << ",";
  ss << "\"bytes_sent\":" << alert_data.log_context.bytes_sent.value_or(0)
     << ",";
  ss << "\"request_time_s\":"
     << alert_data.log_context.request_time_s.value_or(0.0) << ",";
  ss << "\"user_agent\":\""
     << escape_json_value(alert_data.log_context.user_agent) << "\",";
  ss << "\"referer\":\"" << escape_json_value(alert_data.log_context.referer)
     << "\",";
  ss << "\"country_code\":\""
     << escape_json_value(alert_data.log_context.country_code) << "\"";
  ss << "},";

  // Analysis Context (all the rich data from AnalyzedEvent)
  ss << "\"analysis_context\":{";
  // Tier 1 flags
  ss << "\"is_ua_missing\":"
     << (alert_data.analysis_context.is_ua_missing ? "true" : "false") << ",";
  ss << "\"is_ua_outdated\":"
     << (alert_data.analysis_context.is_ua_outdated ? "true" : "false") << ",";
  ss << "\"is_ua_headless\":"
     << (alert_data.analysis_context.is_ua_headless ? "true" : "false") << ",";
  ss << "\"is_ua_cycling\":"
     << (alert_data.analysis_context.is_ua_cycling ? "true" : "false") << ",";
  ss << "\"found_suspicious_path_str\":"
     << (alert_data.analysis_context.found_suspicious_path_str ? "true"
                                                               : "false")
     << ",";
  ss << "\"found_suspicious_ua_str\":"
     << (alert_data.analysis_context.found_suspicious_ua_str ? "true" : "false")
     << ",";
  // Tier 2 Z-scores
  ss << "\"ip_req_time_zscore\":"
     << alert_data.analysis_context.ip_req_time_zscore.value_or(0.0) << ",";
  ss << "\"ip_bytes_sent_zscore\":"
     << alert_data.analysis_context.ip_bytes_sent_zscore.value_or(0.0) << ",";
  ss << "\"ip_error_event_zscore\":"
     << alert_data.analysis_context.ip_error_event_zscore.value_or(0.0) << ",";
  ss << "\"ip_req_vol_zscore\":"
     << alert_data.analysis_context.ip_req_vol_zscore.value_or(0.0);
  // Add more analysis fields here as they are created
  ss << "},";

  ss << "\"raw_log\":\"" << escape_json_value(alert_data.raw_log_trigger_sample)
     << "\"";

  ss << "}";
  return ss.str();
}

void AlertManager::record_alert(const Alert &new_alert) {
  if (output_alerts_to_stdout) {
    std::cout << format_alert_to_human_readable(new_alert) << std::endl;
  }

  if (output_alerts_to_file && alert_file_stream.is_open()) {
    alert_file_stream << format_alert_to_json(new_alert)
                      << std::endl; // Use JSON for file
  }
  // If buffering: buffered_alerts.push_back(new_alert);
}

void AlertManager::flush_all_alerts() {
  // If buffering was implemented, this is where you'd write them out.
  if (output_alerts_to_file && alert_file_stream.is_open()) {
    alert_file_stream.flush();
  }
  // std::cout << "AlertManager: flush_all_alerts() called." << std::endl;
}
#include "alert_manager.hpp"
#include "config.hpp"
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>

Alert::Alert(uint64_t ts, const std::string &ip, const std::string &reason,
             AlertTier tier, const std::string &action,
             const std::string &key_id, double score, uint64_t log_line_num,
             const std::string &log_sample)
    : event_timestamp_ms(ts), source_ip(ip), alert_reason(reason),
      detection_tier(tier), suggested_action(action),
      offending_key_identifier(key_id.empty() ? ip : key_id),
      anomaly_score(score), associated_log_line(log_line_num),
      raw_log_trigger_sample(log_sample) {}

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
    : output_alerts_to_file(false), output_alerts_to_stdout(true) {
  std::cout << "AlertManager created" << std::endl;
}

AlertManager::~AlertManager() {
  if (alert_file_stream.is_open()) {
    alert_file_stream.flush();
    alert_file_stream.close();
    // std::cout << "Alert output file stream closed." << std::endl;
  }
}

void AlertManager::initialize(const Config::AppConfig &app_config) {
  output_alerts_to_stdout = app_config.alerts_to_stdout;
  // For now, keep file output simple or disable it until JSON formatting is
  // more robust output_alerts_to_file = app_config.alerts_to_file;
  // alert_file_output_path = app_config.alert_output_path;

  // A very simple approach for file output if enabled:
  // if (output_alerts_to_file && !alert_file_output_path.empty()) {
  //     alert_file_stream.open(alert_file_output_path, std::ios::app); //
  //     Append mode if (!alert_file_stream.is_open()) {
  //         std::cerr << "Error: AlertManager could not open alert output file:
  //         " << alert_file_output_path << std::endl; output_alerts_to_file =
  //         false; // Disable file output if open failed
  //     } else {
  //         std::cout << "Alerts will be logged to: " << alert_file_output_path
  //         << std::endl;
  //     }
  // }
  std::cout << "AlertManager initialized. Stdout alerts: "
            << (output_alerts_to_stdout ? "Enabled" : "Disabled") << std::endl;
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
  // Placeholder for JSON formatting - this is a more involved task for later.
  // For now, could just return a simplified string or the human-readable one.
  std::ostringstream ss;
  ss << "{ ";
  ss << "\"timestamp_ms\": " << alert_data.event_timestamp_ms << ", ";
  ss << "\"ip\": \"" << alert_data.source_ip
     << "\", "; // Basic escaping might be needed for real JSON
  ss << "\"reason\": \"" << alert_data.alert_reason << "\", ";
  ss << "\"tier\": \""
     << alert_tier_to_string_representation(alert_data.detection_tier) << "\"";
  // Add other fields similarly
  ss << " }";
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
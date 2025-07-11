#include "json_formatter.hpp"

nlohmann::json JsonFormatter::alert_to_json_object(const Alert &alert_data) {
  nlohmann::json j;
  const auto &log_context = alert_data.event_context->raw_log;

  j["timestamp_ms"] = alert_data.event_timestamp_ms;
  j["alert_reason"] = alert_data.alert_reason;
  j["detection_tier"] =
      alert_tier_to_string_representation(alert_data.detection_tier);
  j["suggested_action"] = alert_data.suggested_action;
  j["anomaly_score"] = alert_data.normalized_score;
  j["offending_key"] = alert_data.offending_key_identifier;

  nlohmann::json j_log;
  j_log["source_ip"] = log_context.ip_address;
  j_log["host"] = log_context.host;
  j_log["request_path"] = log_context.request_path;
  j_log["status_code"] = log_context.http_status_code.value_or(0);
  j_log["user_agent"] = log_context.user_agent;
  j["log_context"] = j_log;

  return j;
}

std::string JsonFormatter::format_alert_to_json(const Alert &alert_data) {
  // This maintains compatibility with the existing FileDispatcher
  // But we use the new object-based method internally
  nlohmann::json j = alert_to_json_object(alert_data);

  // Add back fields that were in the original string version if needed
  j["raw_log"] = alert_data.raw_log_trigger_sample;

  return j.dump(); // dump without indent
}
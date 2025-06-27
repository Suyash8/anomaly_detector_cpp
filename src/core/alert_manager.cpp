#include "alert_manager.hpp"
#include "alert.hpp"
#include "config.hpp"
#include "io/alert_dispatch/file_dispatcher.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>

AlertManager::AlertManager() : output_alerts_to_stdout(true) {
  std::cout << "AlertManager created" << std::endl;
}

AlertManager::~AlertManager() { flush_all_alerts(); }

void AlertManager::initialize(const Config::AppConfig &app_config) {
  reconfigure(app_config);
}

void AlertManager::reconfigure(const Config::AppConfig &new_config) {
  output_alerts_to_stdout = new_config.alerts_to_stdout;
  throttle_duration_ms_ = new_config.alert_throttle_duration_seconds * 1000;
  alert_throttle_max_intervening_alerts_ = new_config.alert_throttle_max_alerts;

  dispatchers_.clear();

  if (new_config.alerts_to_file && !new_config.alert_output_path.empty()) {
    dispatchers_.push_back(
        std::make_unique<FileDispatcher>(new_config.alert_output_path));
  }

  std::cout << "AlertManager has been reconfigured. Active dispatchers: "
            << dispatchers_.size() << std::endl;
}

void AlertManager::record_alert(const Alert &new_alert) {
  if (throttle_duration_ms_ > 0) {
    std::string throttle_key =
        new_alert.source_ip + ":" + new_alert.alert_reason;
    auto it = recent_alert_timestamps_.find(throttle_key);

    if (it != recent_alert_timestamps_.end()) {
      auto &throttle_info = it->second;
      uint64_t last_alert_time = throttle_info.first;
      size_t last_alert_global_count = throttle_info.second;

      size_t intervening_alerts =
          total_alerts_recorded_ - last_alert_global_count;

      bool is_in_time_window = new_alert.event_timestamp_ms <
                               (last_alert_time + throttle_duration_ms_);
      bool has_exceeded_intervening_limit =
          (alert_throttle_max_intervening_alerts_ > 0) &&
          (intervening_alerts >= alert_throttle_max_intervening_alerts_);

      if (is_in_time_window && !has_exceeded_intervening_limit) {
        return; // Suppress the alert
      }
    }

    // If we are here, the alert will be recorded
    total_alerts_recorded_++;
    recent_alert_timestamps_[throttle_key] = {new_alert.event_timestamp_ms,
                                              total_alerts_recorded_};
  }

  if (output_alerts_to_stdout)
    std::cout << format_alert_to_human_readable(new_alert) << std::endl;

  for (const auto &dispatcher : dispatchers_)
    dispatcher->dispatch(new_alert);
}

void AlertManager::flush_all_alerts() {}

std::string
AlertManager::format_alert_to_human_readable(const Alert &alert_data) const {
  std::string formatted_alert = "ALERT DETECTED:\n";

  auto time_in_seconds =
      static_cast<std::time_t>(alert_data.event_timestamp_ms / 1000);
  char time_buffer[100];

  std::tm tm_buf;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  std::tm *tm_info = localtime_r(&time_in_seconds, &tm_buf);
#elif defined(_MSC_VER)
  errno_t err = localtime_s(&tm_buf, &time_in_seconds);
  std::tm *tm_info = (err == 0) ? &tm_buf : nullptr;
#else
  std::tm *tm_info = std::localtime(&time_in_seconds);
#endif

  if (tm_info)
    std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S",
                  tm_info);
  else
    std::snprintf(time_buffer, sizeof(time_buffer), "%llu",
                  (unsigned long long)alert_data.event_timestamp_ms);

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

  formatted_alert +=
      "  Score:     " + std::to_string(alert_data.normalized_score) + "\n";

  formatted_alert += "  Action Str:" + alert_data.suggested_action + "\n";

  formatted_alert +=
      "  Action:    " + alert_action_to_string(alert_data.action_code) + "\n";

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

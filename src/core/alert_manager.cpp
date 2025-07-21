#include "alert_manager.hpp"
#include "alert.hpp"
#include "config.hpp"
#include "io/alert_dispatch/file_dispatcher.hpp"
#include "io/alert_dispatch/http_dispatcher.hpp"
#include "io/alert_dispatch/syslog_dispatcher.hpp"
#include "prometheus_metrics_exporter.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

AlertManager::AlertManager() : output_alerts_to_stdout(true) {
  std::cout << "AlertManager created" << std::endl;
}

AlertManager::~AlertManager() {
  shutdown_flag_ = true;
  alert_queue_.shutdown();
  if (dispatcher_thread_.joinable())
    dispatcher_thread_.join();
  flush_all_alerts();
}

void AlertManager::initialize(const Config::AppConfig &app_config) {
  reconfigure(app_config);
  dispatcher_thread_ = std::thread(&AlertManager::dispatcher_loop, this);
}

void AlertManager::reconfigure(const Config::AppConfig &new_config) {
  output_alerts_to_stdout = new_config.alerts_to_stdout;
  throttle_duration_ms_ = new_config.alert_throttle_duration_seconds * 1000;
  alert_throttle_max_intervening_alerts_ = new_config.alert_throttle_max_alerts;

  dispatchers_.clear();
  const auto &alert_cfg = new_config.alerting;

  if (alert_cfg.file_enabled && !new_config.alert_output_path.empty()) {
    dispatchers_.push_back(
        std::make_unique<FileDispatcher>(new_config.alert_output_path));
    std::cout << "AlertManager: FileDispatcher enabled, outputting to "
              << new_config.alert_output_path << std::endl;
  }

  if (alert_cfg.syslog_enabled) {
    dispatchers_.push_back(std::make_unique<SyslogDispatcher>());
    std::cout << "AlertManager: SyslogDispatcher enabled." << std::endl;
  }

  if (alert_cfg.http_enabled && !alert_cfg.http_webhook_url.empty()) {
    dispatchers_.push_back(
        std::make_unique<HttpDispatcher>(alert_cfg.http_webhook_url));
    std::cout << "AlertManager: HttpDispatcher enabled for URL: "
              << alert_cfg.http_webhook_url << std::endl;
  }

  std::cout << "AlertManager has been reconfigured. Active dispatchers: "
            << dispatchers_.size() << std::endl;
}

void AlertManager::record_alert(const Alert &new_alert) {
  alerts_processed_++;

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
        // Track throttled alerts
        alerts_throttled_++;

        // Update metrics
        if (metrics_exporter_) {
          // Track throttled alerts with reason
          std::string throttle_reason = is_in_time_window ? "time_window" : "intervening_limit";
          metrics_exporter_->increment_counter("ad_alerts_throttled_total", 
                                              {{"reason", throttle_reason}});

          // Track suppressed alerts by tier
          std::string tier_str;
          switch (new_alert.detection_tier) {
          case AlertTier::TIER1_HEURISTIC:
            tier_str = "tier1";
            break;
          case AlertTier::TIER2_STATISTICAL:
            tier_str = "tier2";
            break;
          case AlertTier::TIER3_ML:
            tier_str = "tier3";
            break;
          default:
            tier_str = "unknown";
          }
          
          metrics_exporter_->increment_counter("ad_alerts_suppressed_total", 
                                              {{"reason", throttle_reason}, 
                                               {"tier", tier_str}});

          // Update throttling ratio
          double throttle_ratio =
              static_cast<double>(alerts_throttled_.load()) /
              static_cast<double>(alerts_processed_.load());
          metrics_exporter_->set_gauge("ad_alert_throttling_ratio",
                                       throttle_ratio);
                                       
          // Update suppression ratio by tier
          // We need to calculate this based on tier-specific counts
          // For now, we'll use the overall ratio as an approximation
          metrics_exporter_->set_gauge("ad_alert_suppression_ratio_by_tier",
                                      throttle_ratio,
                                      {{"tier", tier_str}});
        }

        return; // Suppress the alert
      }
    }

    // If we are here, the alert will be recorded
    total_alerts_recorded_++;
    recent_alert_timestamps_[throttle_key] = {new_alert.event_timestamp_ms,
                                              total_alerts_recorded_};
  }

  {
    std::lock_guard<std::mutex> lock(recent_alerts_mutex_);
    recent_alerts_.push_front(new_alert);
    if (recent_alerts_.size() > MAX_RECENT_ALERTS)
      recent_alerts_.pop_back();

    // Update recent alerts count metric
    if (metrics_exporter_) {
      metrics_exporter_->set_gauge("ad_recent_alerts_count",
                                   static_cast<double>(recent_alerts_.size()));
    }
  }

  // Track alert metrics by tier and action
  if (metrics_exporter_) {
    std::string tier_str;
    switch (new_alert.detection_tier) {
    case AlertTier::TIER1_HEURISTIC:
      tier_str = "tier1";
      break;
    case AlertTier::TIER2_STATISTICAL:
      tier_str = "tier2";
      break;
    case AlertTier::TIER3_ML:
      tier_str = "tier3";
      break;
    default:
      tier_str = "unknown";
    }

    std::string action_str;
    switch (new_alert.action_code) {
    case AlertAction::NO_ACTION:
      action_str = "no_action";
      break;
    case AlertAction::LOG:
      action_str = "log";
      break;
    case AlertAction::CHALLENGE:
      action_str = "challenge";
      break;
    case AlertAction::RATE_LIMIT:
      action_str = "rate_limit";
      break;
    case AlertAction::BLOCK:
      action_str = "block";
      break;
    default:
      action_str = "unknown";
    }

    metrics_exporter_->increment_counter(
        "ad_alerts_total", {{"tier", tier_str}, {"action", action_str}});
  }

  alert_queue_.push(new_alert);

  // Update queue size metric
  if (metrics_exporter_) {
    metrics_exporter_->set_gauge("ad_alert_queue_size",
                                 static_cast<double>(alert_queue_.size()));
  }
}

std::vector<Alert> AlertManager::get_recent_alerts(size_t limit) const {
  std::lock_guard<std::mutex> lock(recent_alerts_mutex_);
  std::vector<Alert> alerts_copy;
  size_t count = 0;
  for (const auto &alert : recent_alerts_) {
    if (count++ >= limit)
      break;
    alerts_copy.push_back(alert);
  }
  return alerts_copy;
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

void AlertManager::dispatcher_loop() {
  while (!shutdown_flag_) {
    std::optional<Alert> alert_opt = alert_queue_.wait_and_pop();

    if (!alert_opt) {
      if (shutdown_flag_)
        break;
      continue;
    }

    const Alert &alert_to_dispatch = *alert_opt;

    if (output_alerts_to_stdout)
      std::cout << format_alert_to_human_readable(alert_to_dispatch)
                << std::endl;

    for (const auto &dispatcher : dispatchers_) {
      if (dispatcher) {
        std::string dispatcher_type = dispatcher->get_dispatcher_type();

        // Track dispatch attempt
        if (metrics_exporter_) {
          metrics_exporter_->increment_counter(
              "ad_alert_dispatch_attempts_total",
              {{"dispatcher_type", dispatcher_type}});
        }

        // Get tier string for metrics
        std::string tier_str;
        switch (alert_to_dispatch.detection_tier) {
        case AlertTier::TIER1_HEURISTIC:
          tier_str = "tier1";
          break;
        case AlertTier::TIER2_STATISTICAL:
          tier_str = "tier2";
          break;
        case AlertTier::TIER3_ML:
          tier_str = "tier3";
          break;
        default:
          tier_str = "unknown";
        }

        // Measure dispatch latency
        auto start_time = std::chrono::high_resolution_clock::now();
        bool success = dispatcher->dispatch(alert_to_dispatch);
        auto end_time = std::chrono::high_resolution_clock::now();
        
        // Calculate latency in seconds
        double latency_seconds = std::chrono::duration<double>(end_time - start_time).count();

        // Track dispatch success/failure
        if (metrics_exporter_) {
          if (success) {
            metrics_exporter_->increment_counter(
                "ad_alert_dispatch_success_total",
                {{"dispatcher_type", dispatcher_type}, {"tier", tier_str}});
            dispatcher_success_counts_[dispatcher_type]++;
            
            // Track dispatch latency on success
            metrics_exporter_->observe_histogram(
                "ad_alert_dispatch_latency_seconds",
                latency_seconds,
                {{"dispatcher_type", dispatcher_type}});
          } else {
            // Determine error type based on dispatcher type
            std::string error_type = "unknown";
            if (dispatcher_type == "http") {
              error_type = "network_error"; // Default error type for HTTP
            } else if (dispatcher_type == "file") {
              error_type = "file_write_error"; // Default error type for file
            } else if (dispatcher_type == "syslog") {
              error_type = "syslog_error"; // Default error type for syslog
            }
            
            metrics_exporter_->increment_counter(
                "ad_alert_dispatch_failure_total",
                {{"dispatcher_type", dispatcher_type}, {"error_type", error_type}});
            dispatcher_failure_counts_[dispatcher_type]++;
          }

          // Calculate and update success rate
          size_t success_count =
              dispatcher_success_counts_[dispatcher_type].load();
          size_t failure_count =
              dispatcher_failure_counts_[dispatcher_type].load();
          size_t total_count = success_count + failure_count;

          double success_rate = (total_count > 0)
                                    ? static_cast<double>(success_count) /
                                          static_cast<double>(total_count)
                                    : 1.0;

          metrics_exporter_->set_gauge("ad_alert_dispatch_success_rate",
                                       success_rate,
                                       {{"dispatcher_type", dispatcher_type}});
        }
      }
    }

    // Update queue size metric after processing
    if (metrics_exporter_) {
      metrics_exporter_->set_gauge("ad_alert_queue_size",
                                   static_cast<double>(alert_queue_.size()));
    }
  }
}
void AlertManager::set_metrics_exporter(
    std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter) {
  metrics_exporter_ = exporter;
  if (metrics_exporter_) {
    register_alert_manager_metrics();
  }
}

void AlertManager::register_alert_manager_metrics() {
  if (!metrics_exporter_)
    return;

  // Register alert generation metrics
  metrics_exporter_->register_counter("ad_alerts_total",
                                      "Total number of alerts generated",
                                      {"tier", "action"});

  // Register alert throttling metrics
  metrics_exporter_->register_counter(
      "ad_alerts_throttled_total",
      "Total number of alerts suppressed by throttling",
      {"reason"});

  metrics_exporter_->register_gauge(
      "ad_alert_throttling_ratio", "Ratio of throttled alerts to total alerts");
      
  // Register alert suppression metrics by type
  metrics_exporter_->register_counter(
      "ad_alerts_suppressed_total",
      "Total number of alerts suppressed",
      {"reason", "tier"});
      
  metrics_exporter_->register_gauge(
      "ad_alert_suppression_ratio_by_tier",
      "Ratio of suppressed alerts to total alerts by tier",
      {"tier"});

  // Register alert dispatcher metrics
  metrics_exporter_->register_counter("ad_alert_dispatch_attempts_total",
                                      "Total number of alert dispatch attempts",
                                      {"dispatcher_type"});

  metrics_exporter_->register_counter(
      "ad_alert_dispatch_success_total",
      "Total number of successful alert dispatches", 
      {"dispatcher_type", "tier"});

  metrics_exporter_->register_counter("ad_alert_dispatch_failure_total",
                                      "Total number of failed alert dispatches", 
                                      {"dispatcher_type", "error_type"});

  metrics_exporter_->register_gauge(
      "ad_alert_dispatch_success_rate",
      "Success rate for alert dispatches (0.0-1.0)", 
      {"dispatcher_type"});
      
  metrics_exporter_->register_histogram(
      "ad_alert_dispatch_latency_seconds",
      "Time taken to dispatch alerts",
      {0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
      {"dispatcher_type"});

  // Register queue metrics
  metrics_exporter_->register_gauge("ad_alert_queue_size",
                                    "Current size of the alert queue");

  metrics_exporter_->register_gauge(
      "ad_recent_alerts_count", "Number of alerts in the recent alerts cache");
}
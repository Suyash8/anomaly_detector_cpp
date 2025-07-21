#include "dynamic_learning_engine.hpp"
#include "../analysis/analyzed_event.hpp"
#include "../core/logger.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <mutex>
#include <shared_mutex>

namespace learning {

DynamicLearningEngine::DynamicLearningEngine() {
  // Initialize with default configuration
  config_ = Config::DynamicLearningConfig();
}

DynamicLearningEngine::DynamicLearningEngine(
    const Config::DynamicLearningConfig &config)
    : config_(config) {}

std::string
DynamicLearningEngine::make_key(const std::string &entity_type,
                                const std::string &entity_id) const {
  return entity_type + ":" + entity_id;
}

void DynamicLearningEngine::process_event(const std::string &entity_type,
                                          const std::string &entity_id,
                                          double value, uint64_t timestamp_ms) {
  update_baseline(entity_type, entity_id, value, timestamp_ms);
}

std::shared_ptr<LearningBaseline>
DynamicLearningEngine::get_baseline(const std::string &entity_type,
                                    const std::string &entity_id) {
  std::shared_lock<std::shared_mutex> lock(baselines_mutex_);
  auto key = make_key(entity_type, entity_id);
  auto it = baselines_.find(key);
  if (it != baselines_.end())
    return it->second;
  lock.unlock();
  // Create new baseline if not found
  std::unique_lock<std::shared_mutex> ulock(baselines_mutex_);
  auto baseline = std::make_shared<LearningBaseline>();
  baseline->entity_type = entity_type;
  baseline->entity_id = entity_id;
  baseline->created_at = baseline->last_updated = 0;
  baseline->is_established = false;
  baselines_[key] = baseline;
  return baseline;
}

void DynamicLearningEngine::update_baseline(const std::string &entity_type,
                                            const std::string &entity_id,
                                            double value,
                                            uint64_t timestamp_ms) {
  auto baseline = get_baseline(entity_type, entity_id);
  // Capture old threshold for audit
  double old_threshold = std::numeric_limits<double>::quiet_NaN();
  if (baseline->is_established) {
    old_threshold = baseline->statistics.get_percentile(0.95);
  }

  baseline->statistics.add_value(value, timestamp_ms);
  baseline->seasonal_model.add_observation(value, timestamp_ms);
  baseline->last_updated = timestamp_ms;

  if (!baseline->is_established && baseline->statistics.is_established()) {
    baseline->is_established = true;
    LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
        "Baseline established for [" << entity_type << ":" << entity_id << "]");
  }

  if (!baseline->is_established)
    return;

  // Calculate new threshold
  double new_threshold = baseline->statistics.get_percentile(0.95);

  // Check if threshold change is acceptable (especially for security-critical
  // entities)
  if (!std::isnan(old_threshold) &&
      !is_threshold_change_acceptable(*baseline, old_threshold,
                                      new_threshold)) {
    LOG(LogLevel::WARN, LogComponent::ANALYSIS_STATS,
        "Large threshold change detected for ["
            << entity_type << ":" << entity_id << "] "
            << "old: " << old_threshold << ", new: " << new_threshold
            << " (change: "
            << std::abs(new_threshold - old_threshold) /
                   std::abs(old_threshold) * 100.0
            << "%, "
            << "max allowed: " << baseline->max_threshold_change_percent
            << "%)");
  }

  // Audit: log threshold change if significant
  if (!std::isnan(old_threshold) &&
      std::abs(new_threshold - old_threshold) >
          0.01 * std::max(std::abs(old_threshold), 1.0)) {

    add_threshold_audit_entry(*baseline, old_threshold, new_threshold, 0.95,
                              timestamp_ms, "Baseline update", "");

    // Invalidate threshold cache
    baseline->cached_thresholds.clear();
    baseline->threshold_cache_timestamp = 0;

    LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
        "Threshold change for [" << entity_type << ":" << entity_id << "] "
                                 << "old: " << old_threshold << ", new: "
                                 << new_threshold << ", ts: " << timestamp_ms);
  }
}

bool DynamicLearningEngine::is_anomalous(const std::string &entity_type,
                                         const std::string &entity_id,
                                         double value,
                                         double &anomaly_score) const {
  std::shared_lock<std::shared_mutex> lock(baselines_mutex_);
  auto key = make_key(entity_type, entity_id);
  auto it = baselines_.find(key);
  if (it == baselines_.end())
    return false;
  const auto &baseline = it->second;
  if (!baseline->is_established)
    return false;
  double mean = baseline->statistics.get_mean();
  double stddev = baseline->statistics.get_standard_deviation();
  if (stddev < 1e-6)
    stddev = 1.0; // avoid div by zero
  anomaly_score = std::abs(value - mean) / stddev;
  return anomaly_score > 3.0; // 3-sigma rule
}

double DynamicLearningEngine::calculate_dynamic_threshold(
    const LearningBaseline &baseline, uint64_t /* timestamp_ms */,
    double percentile) const {
  if (baseline.manual_override_active) {
    return baseline.manual_override_threshold;
  }
  // Use rolling statistics percentile with seasonal adjustment if available
  double base_threshold = baseline.statistics.get_percentile(percentile);

  // Apply seasonal factor if pattern is established
  if (baseline.seasonal_model.is_pattern_established()) {
    // Note: timestamp_ms could be used here for seasonal adjustment
    // For now, just return the base threshold
    return base_threshold;
  }

  return base_threshold;
}

double
DynamicLearningEngine::get_entity_threshold(const std::string &entity_type,
                                            const std::string &entity_id,
                                            double percentile) const {
  return calculate_percentile_threshold(entity_type, entity_id, percentile,
                                        true);
}

size_t DynamicLearningEngine::get_baseline_count() const {
  std::shared_lock<std::shared_mutex> lock(baselines_mutex_);
  return baselines_.size();
}

void DynamicLearningEngine::cleanup_expired_baselines(uint64_t now_ms,
                                                      uint64_t ttl_ms) {
  std::unique_lock<std::shared_mutex> lock(baselines_mutex_);
  for (auto it = baselines_.begin(); it != baselines_.end();) {
    if (now_ms - it->second->last_updated > ttl_ms) {
      it = baselines_.erase(it);
    } else {
      ++it;
    }
  }
}

void DynamicLearningEngine::process_analyzed_event(const AnalyzedEvent &event) {
  // Use parsed_timestamp_ms if available, else skip
  if (!event.raw_log.parsed_timestamp_ms.has_value())
    return;
  uint64_t ts = event.raw_log.parsed_timestamp_ms.value();

  // --- Per-IP baseline updates ---
  if (!event.raw_log.ip_address.empty()) {
    // Request time processing
    if (event.raw_log.request_time_s.has_value()) {
      update_baseline("ip_request_time", std::string(event.raw_log.ip_address),
                      event.raw_log.request_time_s.value(), ts);
    }

    // Bytes sent processing
    if (event.raw_log.bytes_sent.has_value()) {
      update_baseline("ip_bytes", std::string(event.raw_log.ip_address),
                      static_cast<double>(event.raw_log.bytes_sent.value()),
                      ts);
    }

    // Error rate processing (from historical analysis)
    if (event.ip_hist_error_rate_mean.has_value()) {
      update_baseline("ip_error_rate", std::string(event.raw_log.ip_address),
                      event.ip_hist_error_rate_mean.value(), ts);
    }

    // Request volume processing
    if (event.ip_hist_req_vol_mean.has_value()) {
      update_baseline("ip_request_volume",
                      std::string(event.raw_log.ip_address),
                      event.ip_hist_req_vol_mean.value(), ts);
    }

    // Request count in window
    if (event.current_ip_request_count_in_window.has_value()) {
      update_baseline(
          "ip_request_count", std::string(event.raw_log.ip_address),
          static_cast<double>(event.current_ip_request_count_in_window.value()),
          ts);
    }

    // Failed login count
    if (event.current_ip_failed_login_count_in_window.has_value()) {
      update_baseline(
          "ip_failed_logins", std::string(event.raw_log.ip_address),
          static_cast<double>(
              event.current_ip_failed_login_count_in_window.value()),
          ts);
    }
  }

  // --- Per-Path baseline updates ---
  if (!event.raw_log.request_path.empty()) {
    // Path request time
    if (event.path_hist_req_time_mean.has_value()) {
      update_baseline("path_request_time", event.raw_log.request_path,
                      event.path_hist_req_time_mean.value(), ts);
    }

    // Path bytes sent
    if (event.path_hist_bytes_mean.has_value()) {
      update_baseline("path_bytes", event.raw_log.request_path,
                      event.path_hist_bytes_mean.value(), ts);
    }

    // Path error rate
    if (event.path_hist_error_rate_mean.has_value()) {
      update_baseline("path_error_rate", event.raw_log.request_path,
                      event.path_hist_error_rate_mean.value(), ts);
    }
  }

  // --- Per-Session baseline updates ---
  if (event.raw_session_state.has_value()) {
    const auto &session_state = event.raw_session_state.value();

    // Use IP address as session identifier since session_id is not available
    std::string session_key = std::string(event.raw_log.ip_address);

    if (!session_key.empty()) {
      // Session request count
      if (session_state.request_count > 0) {
        update_baseline("session_request_count", session_key,
                        static_cast<double>(session_state.request_count), ts);
      }

      // Session unique paths count
      update_baseline(
          "session_unique_paths", session_key,
          static_cast<double>(session_state.get_unique_paths_count()), ts);

      // Session error rates
      double total_requests = static_cast<double>(session_state.request_count);
      if (total_requests > 0) {
        double error_rate =
            (session_state.error_4xx_count + session_state.error_5xx_count) /
            total_requests;
        update_baseline("session_error_rate", session_key, error_rate, ts);
      }

      // Session failed login attempts
      if (session_state.failed_login_attempts > 0) {
        update_baseline(
            "session_failed_logins", session_key,
            static_cast<double>(session_state.failed_login_attempts), ts);
      }

      // Session request frequency (requests per time window)
      size_t request_freq = session_state.get_request_timestamps_count();
      if (request_freq > 0) {
        update_baseline("session_request_frequency", session_key,
                        static_cast<double>(request_freq), ts);
      }
    }
  }

  // --- Security-critical entity marking (based on configuration) ---
  if (config_.auto_mark_login_paths_critical &&
      !event.raw_log.request_path.empty()) {
    std::string path = event.raw_log.request_path;
    if (path.find("/login") != std::string::npos ||
        path.find("/auth") != std::string::npos ||
        (config_.auto_mark_admin_paths_critical &&
         (path.find("/admin") != std::string::npos ||
          path.find("/api/auth") != std::string::npos))) {

      mark_entity_as_security_critical(
          "path_request_time", path,
          config_.security_critical_max_change_percent);
      mark_entity_as_security_critical(
          "path_error_rate", path,
          config_.security_critical_max_change_percent / 2.0);
    }
  }

  // Mark IPs with high failed login counts as security critical (based on
  // configuration)
  if (config_.auto_mark_high_failed_login_ips_critical &&
      event.current_ip_failed_login_count_in_window.has_value() &&
      event.current_ip_failed_login_count_in_window.value() >=
          config_.failed_login_threshold_for_critical) {

    mark_entity_as_security_critical(
        "ip_failed_logins", std::string(event.raw_log.ip_address),
        config_.security_critical_max_change_percent);
    mark_entity_as_security_critical(
        "ip_request_count", std::string(event.raw_log.ip_address),
        config_.security_critical_max_change_percent * 2.0);
  }
}

void DynamicLearningEngine::set_manual_override(const std::string &entity_type,
                                                const std::string &entity_id,
                                                double threshold) {
  auto baseline = get_baseline(entity_type, entity_id);
  double old_threshold = std::numeric_limits<double>::quiet_NaN();
  if (baseline->is_established) {
    old_threshold = baseline->statistics.get_percentile(0.95);
  }

  baseline->manual_override_threshold = threshold;
  baseline->manual_override_active = true;
  baseline->override_timestamp_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  // Add audit entry
  add_threshold_audit_entry(*baseline, old_threshold, threshold, 0.95,
                            baseline->override_timestamp_ms, "Manual override",
                            "system");

  // Invalidate cache
  invalidate_threshold_cache(entity_type, entity_id);

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
      "Manual override set for [" << entity_type << ":" << entity_id << "] to "
                                  << threshold);
}

void DynamicLearningEngine::clear_manual_override(
    const std::string &entity_type, const std::string &entity_id) {
  auto baseline = get_baseline(entity_type, entity_id);
  double old_threshold = baseline->manual_override_threshold;

  baseline->manual_override_active = false;
  baseline->manual_override_threshold =
      std::numeric_limits<double>::quiet_NaN();
  baseline->override_operator_id.clear();
  baseline->override_timestamp_ms = 0;

  // Add audit entry
  double new_threshold = std::numeric_limits<double>::quiet_NaN();
  if (baseline->is_established) {
    new_threshold = baseline->statistics.get_percentile(0.95);
  }

  add_threshold_audit_entry(
      *baseline, old_threshold, new_threshold, 0.95,
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count(),
      "Manual override cleared", "system");

  // Invalidate cache
  invalidate_threshold_cache(entity_type, entity_id);

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
      "Manual override cleared for [" << entity_type << ":" << entity_id
                                      << "]");
}

// Enhanced threshold management implementations

bool DynamicLearningEngine::update_baseline_with_threshold_check(
    const std::string &entity_type, const std::string &entity_id, double value,
    uint64_t timestamp_ms, double /* max_change_percent */) {

  auto baseline = get_baseline(entity_type, entity_id);
  if (!baseline)
    return false;

  // Get old threshold for comparison
  double old_threshold = std::numeric_limits<double>::quiet_NaN();
  if (baseline->is_established) {
    old_threshold = baseline->statistics.get_percentile(0.95);
  }

  // Update the baseline
  baseline->statistics.add_value(value, timestamp_ms);
  baseline->seasonal_model.add_observation(value, timestamp_ms);
  baseline->last_updated = timestamp_ms;

  if (!baseline->is_established && baseline->statistics.is_established()) {
    baseline->is_established = true;
    LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
        "Baseline established for [" << entity_type << ":" << entity_id << "]");
  }

  if (!baseline->is_established)
    return true;

  // Calculate new threshold
  double new_threshold = baseline->statistics.get_percentile(0.95);

  // Check if threshold change is acceptable
  if (!std::isnan(old_threshold) &&
      !is_threshold_change_acceptable(*baseline, old_threshold,
                                      new_threshold)) {
    LOG(LogLevel::WARN, LogComponent::ANALYSIS_STATS,
        "Threshold change rejected for ["
            << entity_type << ":" << entity_id << "] "
            << "old: " << old_threshold << ", new: " << new_threshold
            << " (exceeds max change: "
            << baseline->max_threshold_change_percent << "%)");
    return false;
  }

  // Log significant threshold changes
  if (!std::isnan(old_threshold) &&
      std::abs(new_threshold - old_threshold) >
          0.01 * std::max(std::abs(old_threshold), 1.0)) {

    add_threshold_audit_entry(*baseline, old_threshold, new_threshold, 0.95,
                              timestamp_ms, "Baseline update", "");

    // Invalidate threshold cache
    baseline->cached_thresholds.clear();
    baseline->threshold_cache_timestamp = 0;

    LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
        "Threshold change for [" << entity_type << ":" << entity_id << "] "
                                 << "old: " << old_threshold << ", new: "
                                 << new_threshold << ", ts: " << timestamp_ms);
  }

  return true;
}

double DynamicLearningEngine::calculate_percentile_threshold(
    const std::string &entity_type, const std::string &entity_id,
    double percentile, bool use_cache) const {

  std::shared_lock<std::shared_mutex> lock(baselines_mutex_);
  auto key = make_key(entity_type, entity_id);
  auto it = baselines_.find(key);
  if (it == baselines_.end() || !it->second->is_established) {
    return std::numeric_limits<double>::quiet_NaN();
  }

  auto &baseline = *it->second;
  uint64_t current_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  // Check cache first if enabled
  if (use_cache) {
    double cached_value =
        get_cached_threshold(baseline, percentile, current_time);
    if (!std::isnan(cached_value)) {
      return cached_value;
    }
  }

  // Calculate new threshold
  double threshold;
  if (baseline.manual_override_active) {
    threshold = baseline.manual_override_threshold;
  } else {
    threshold = baseline.statistics.get_percentile(percentile);

    // Apply seasonal adjustment if available
    if (baseline.seasonal_model.is_pattern_established()) {
      // Apply seasonal factor (implementation would depend on seasonal model
      // specifics)
      threshold = baseline.statistics.get_percentile(percentile);
    }
  }

  // Update cache
  if (use_cache) {
    // This requires a const_cast since we need to modify the cache in a const
    // method
    const_cast<LearningBaseline &>(baseline).cached_thresholds[percentile] =
        threshold;
    const_cast<LearningBaseline &>(baseline).threshold_cache_timestamp =
        current_time;
  }

  return threshold;
}

void DynamicLearningEngine::mark_entity_as_security_critical(
    const std::string &entity_type, const std::string &entity_id,
    double max_change_percent) {

  auto baseline = get_baseline(entity_type, entity_id);
  baseline->is_security_critical = true;
  baseline->max_threshold_change_percent = max_change_percent;

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
      "Entity marked as security critical ["
          << entity_type << ":" << entity_id << "] "
          << "max change: " << max_change_percent << "%");
}

void DynamicLearningEngine::unmark_entity_as_security_critical(
    const std::string &entity_type, const std::string &entity_id) {

  auto baseline = get_baseline(entity_type, entity_id);
  baseline->is_security_critical = false;
  baseline->max_threshold_change_percent = 50.0; // Reset to default

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
      "Entity unmarked as security critical [" << entity_type << ":"
                                               << entity_id << "]");
}

bool DynamicLearningEngine::is_entity_security_critical(
    const std::string &entity_type, const std::string &entity_id) const {

  std::shared_lock<std::shared_mutex> lock(baselines_mutex_);
  auto key = make_key(entity_type, entity_id);
  auto it = baselines_.find(key);
  return it != baselines_.end() && it->second->is_security_critical;
}

bool DynamicLearningEngine::set_manual_override_with_validation(
    const std::string &entity_type, const std::string &entity_id,
    double threshold, const std::string &operator_id,
    const std::string &reason) {

  if (threshold <= 0) {
    LOG(LogLevel::ERROR, LogComponent::ANALYSIS_STATS,
        "Invalid threshold value for manual override: " << threshold);
    return false;
  }

  if (operator_id.empty()) {
    LOG(LogLevel::ERROR, LogComponent::ANALYSIS_STATS,
        "Operator ID required for manual override");
    return false;
  }

  auto baseline = get_baseline(entity_type, entity_id);
  double old_threshold = std::numeric_limits<double>::quiet_NaN();
  if (baseline->is_established) {
    old_threshold = baseline->statistics.get_percentile(0.95);
  }

  // Additional validation for security-critical entities
  if (baseline->is_security_critical && !std::isnan(old_threshold)) {
    double change_percent =
        std::abs(threshold - old_threshold) / old_threshold * 100.0;
    if (change_percent > baseline->max_threshold_change_percent) {
      LOG(LogLevel::WARN, LogComponent::ANALYSIS_STATS,
          "Manual override rejected for security-critical entity ["
              << entity_type << ":" << entity_id
              << "] - change too large: " << change_percent
              << "% (max: " << baseline->max_threshold_change_percent << "%)");
      return false;
    }
  }

  baseline->manual_override_threshold = threshold;
  baseline->manual_override_active = true;
  baseline->override_operator_id = operator_id;
  baseline->override_timestamp_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  // Add audit entry
  std::string audit_reason = reason.empty() ? "Manual override" : reason;
  add_threshold_audit_entry(*baseline, old_threshold, threshold, 0.95,
                            baseline->override_timestamp_ms, audit_reason,
                            operator_id);

  // Invalidate cache
  invalidate_threshold_cache(entity_type, entity_id);

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
      "Manual override set for [" << entity_type << ":" << entity_id << "] to "
                                  << threshold << " by " << operator_id << " - "
                                  << audit_reason);

  return true;
}

std::vector<ThresholdAuditEntry> DynamicLearningEngine::get_threshold_audit_log(
    const std::string &entity_type, const std::string &entity_id,
    uint64_t since_timestamp_ms) const {

  std::shared_lock<std::shared_mutex> lock(baselines_mutex_);
  auto key = make_key(entity_type, entity_id);
  auto it = baselines_.find(key);
  if (it == baselines_.end()) {
    return {};
  }

  std::vector<ThresholdAuditEntry> result;
  for (const auto &entry : it->second->threshold_audit_log) {
    if (entry.timestamp_ms >= since_timestamp_ms) {
      result.push_back(entry);
    }
  }

  return result;
}

void DynamicLearningEngine::clear_threshold_audit_log(
    const std::string &entity_type, const std::string &entity_id) {

  auto baseline = get_baseline(entity_type, entity_id);
  baseline->threshold_audit_log.clear();

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_STATS,
      "Threshold audit log cleared for [" << entity_type << ":" << entity_id
                                          << "]");
}

void DynamicLearningEngine::invalidate_threshold_cache(
    const std::string &entity_type, const std::string &entity_id) {

  auto baseline = get_baseline(entity_type, entity_id);
  baseline->cached_thresholds.clear();
  baseline->threshold_cache_timestamp = 0;
}

void DynamicLearningEngine::invalidate_all_threshold_caches() {
  std::unique_lock<std::shared_mutex> lock(baselines_mutex_);
  for (auto &[key, baseline] : baselines_) {
    baseline->cached_thresholds.clear();
    baseline->threshold_cache_timestamp = 0;
  }
}

// Private helper methods

void DynamicLearningEngine::add_threshold_audit_entry(
    LearningBaseline &baseline, double old_threshold, double new_threshold,
    double percentile, uint64_t timestamp_ms, const std::string &reason,
    const std::string &operator_id) {

  ThresholdAuditEntry entry;
  entry.timestamp_ms = timestamp_ms;
  entry.old_threshold = old_threshold;
  entry.new_threshold = new_threshold;
  entry.percentile = percentile;
  entry.reason = reason;
  entry.operator_id = operator_id;

  baseline.threshold_audit_log.push_back(entry);

  // Maintain maximum audit log size based on configuration
  size_t max_entries = config_.max_audit_entries_per_entity;
  while (baseline.threshold_audit_log.size() > max_entries) {
    baseline.threshold_audit_log.pop_front();
  }
}

bool DynamicLearningEngine::is_threshold_change_acceptable(
    const LearningBaseline &baseline, double old_threshold,
    double new_threshold) const {

  if (std::isnan(old_threshold) || std::isnan(new_threshold)) {
    return true; // Can't compare NaN values
  }

  if (old_threshold == 0.0) {
    return true; // Avoid division by zero
  }

  double change_percent =
      std::abs(new_threshold - old_threshold) / std::abs(old_threshold) * 100.0;
  return change_percent <= baseline.max_threshold_change_percent;
}

void DynamicLearningEngine::update_threshold_cache(
    LearningBaseline &baseline, double percentile, double threshold,
    uint64_t timestamp_ms) const {

  baseline.cached_thresholds[percentile] = threshold;
  baseline.threshold_cache_timestamp = timestamp_ms;
}

double
DynamicLearningEngine::get_cached_threshold(const LearningBaseline &baseline,
                                            double percentile,
                                            uint64_t current_time_ms) const {

  // Use configuration for cache TTL
  uint64_t cache_ttl_ms = config_.threshold_cache_ttl_seconds * 1000;

  // Check if cache is still valid
  if (current_time_ms - baseline.threshold_cache_timestamp > cache_ttl_ms) {
    return std::numeric_limits<double>::quiet_NaN();
  }

  auto it = baseline.cached_thresholds.find(percentile);
  if (it != baseline.cached_thresholds.end()) {
    return it->second;
  }

  return std::numeric_limits<double>::quiet_NaN();
}

} // namespace learning

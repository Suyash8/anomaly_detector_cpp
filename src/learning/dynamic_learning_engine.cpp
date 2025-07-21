#include "dynamic_learning_engine.hpp"
#include "../analysis/analyzed_event.hpp"

#include <cmath>
#include <mutex>
#include <shared_mutex>

namespace learning {

DynamicLearningEngine::DynamicLearningEngine() {}

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
  baseline->statistics.add_value(value, timestamp_ms);
  baseline->seasonal_model.add_observation(value, timestamp_ms);
  baseline->last_updated = timestamp_ms;
  if (!baseline->is_established && baseline->statistics.is_established()) {
    baseline->is_established = true;
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

  // --- Per-IP ---
  if (!event.raw_log.ip_address.empty() &&
      event.raw_log.request_time_s.has_value()) {
    process_event("ip", std::string(event.raw_log.ip_address),
                  event.raw_log.request_time_s.value(), ts);
  }
  // Optionally, update with bytes sent
  if (!event.raw_log.ip_address.empty() &&
      event.raw_log.bytes_sent.has_value()) {
    process_event("ip_bytes", std::string(event.raw_log.ip_address),
                  static_cast<double>(event.raw_log.bytes_sent.value()), ts);
  }
  // Optionally, update with error rate if available
  if (!event.raw_log.ip_address.empty() &&
      event.ip_hist_error_rate_mean.has_value()) {
    process_event("ip_error_rate", std::string(event.raw_log.ip_address),
                  event.ip_hist_error_rate_mean.value(), ts);
  }

  // --- Per-Path ---
  if (!event.raw_log.request_path.empty() &&
      event.path_hist_req_time_mean.has_value()) {
    process_event("path", event.raw_log.request_path,
                  event.path_hist_req_time_mean.value(), ts);
  }
  if (!event.raw_log.request_path.empty() &&
      event.path_hist_bytes_mean.has_value()) {
    process_event("path_bytes", event.raw_log.request_path,
                  event.path_hist_bytes_mean.value(), ts);
  }
  if (!event.raw_log.request_path.empty() &&
      event.path_hist_error_rate_mean.has_value()) {
    process_event("path_error_rate", event.raw_log.request_path,
                  event.path_hist_error_rate_mean.value(), ts);
  }

  // --- Per-Session (skipped: no session_id available) ---
}

} // namespace learning

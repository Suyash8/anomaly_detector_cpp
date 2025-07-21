#ifndef DYNAMIC_LEARNING_ENGINE_HPP
#define DYNAMIC_LEARNING_ENGINE_HPP

#include "../analysis/analyzed_event.hpp"
#include "rolling_statistics.hpp"
#include "seasonal_model.hpp"

#include <cstdint>
#include <limits>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace learning {

struct LearningBaseline {
  RollingStatistics statistics;
  SeasonalModel seasonal_model;
  std::string entity_type;
  std::string entity_id;
  uint64_t created_at;
  uint64_t last_updated;
  bool is_established;

  // Manual override for threshold (optional, NaN if not set)
  double manual_override_threshold = std::numeric_limits<double>::quiet_NaN();
  bool manual_override_active = false;
};

class DynamicLearningEngine {
public:
  explicit DynamicLearningEngine();
  void process_event(const std::string &entity_type,
                     const std::string &entity_id, double value,
                     uint64_t timestamp_ms);
  void process_analyzed_event(const struct AnalyzedEvent &event);
  bool is_anomalous(const std::string &entity_type,
                    const std::string &entity_id, double value,
                    double &anomaly_score) const;
  std::shared_ptr<LearningBaseline> get_baseline(const std::string &entity_type,
                                                 const std::string &entity_id);
  void update_baseline(const std::string &entity_type,
                       const std::string &entity_id, double value,
                       uint64_t timestamp_ms);
  double calculate_dynamic_threshold(const LearningBaseline &baseline,
                                     uint64_t timestamp_ms,
                                     double percentile = 0.95) const;
  size_t get_baseline_count() const;
  void cleanup_expired_baselines(uint64_t now_ms,
                                 uint64_t ttl_ms = 72 * 3600 * 1000);
  double get_entity_threshold(const std::string &entity_type,
                              const std::string &entity_id,
                              double percentile = 0.95) const;

  // Manual override API
  void set_manual_override(const std::string &entity_type,
                           const std::string &entity_id, double threshold);
  void clear_manual_override(const std::string &entity_type,
                             const std::string &entity_id);

private:
  mutable std::shared_mutex baselines_mutex_;
  std::unordered_map<std::string, std::shared_ptr<LearningBaseline>> baselines_;
  std::string make_key(const std::string &entity_type,
                       const std::string &entity_id) const;
};

} // namespace learning

#endif // DYNAMIC_LEARNING_ENGINE_HPP

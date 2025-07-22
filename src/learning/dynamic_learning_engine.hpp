#ifndef DYNAMIC_LEARNING_ENGINE_HPP
#define DYNAMIC_LEARNING_ENGINE_HPP

#include "../analysis/analyzed_event.hpp"
#include "../core/config.hpp"
#include "rolling_statistics.hpp"
#include "seasonal_model.hpp"

#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace learning {

struct ThresholdAuditEntry {
  uint64_t timestamp_ms;
  double old_threshold;
  double new_threshold;
  double percentile;
  std::string reason;
  std::string operator_id; // For manual overrides
};

struct LearningBaseline {
  RollingStatistics statistics;
  SeasonalModel seasonal_model;
  std::string entity_type;
  std::string entity_id;
  uint64_t created_at;
  uint64_t last_updated;
  bool is_established;

  // Cached thresholds for different percentiles
  std::unordered_map<double, double> cached_thresholds;
  uint64_t threshold_cache_timestamp = 0;

  // Manual override for threshold (optional, NaN if not set)
  double manual_override_threshold = std::numeric_limits<double>::quiet_NaN();
  bool manual_override_active = false;
  std::string override_operator_id;
  uint64_t override_timestamp_ms = 0;

  // Audit trail for threshold changes
  std::deque<ThresholdAuditEntry> threshold_audit_log;

  // Security-critical threshold flags
  bool is_security_critical = false;
  double max_threshold_change_percent =
      50.0; // Maximum allowed threshold change
};

class DynamicLearningEngine {
public:
  explicit DynamicLearningEngine();
  explicit DynamicLearningEngine(
      const struct Config::DynamicLearningConfig &config);
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

  // Enhanced threshold management methods
  bool update_baseline_with_threshold_check(const std::string &entity_type,
                                            const std::string &entity_id,
                                            double value, uint64_t timestamp_ms,
                                            double max_change_percent = 50.0);

  // Percentile-based threshold calculations
  double calculate_percentile_threshold(const std::string &entity_type,
                                        const std::string &entity_id,
                                        double percentile,
                                        bool use_cache = true) const;

  // Entity-specific threshold management
  void mark_entity_as_security_critical(const std::string &entity_type,
                                        const std::string &entity_id,
                                        double max_change_percent = 10.0);
  void unmark_entity_as_security_critical(const std::string &entity_type,
                                          const std::string &entity_id);
  bool is_entity_security_critical(const std::string &entity_type,
                                   const std::string &entity_id) const;

  // Enhanced manual override capabilities
  bool set_manual_override_with_validation(const std::string &entity_type,
                                           const std::string &entity_id,
                                           double threshold,
                                           const std::string &operator_id,
                                           const std::string &reason = "");

  // Audit trail management
  std::vector<ThresholdAuditEntry>
  get_threshold_audit_log(const std::string &entity_type,
                          const std::string &entity_id,
                          uint64_t since_timestamp_ms = 0) const;

  void clear_threshold_audit_log(const std::string &entity_type,
                                 const std::string &entity_id);

  // Threshold cache management
  void invalidate_threshold_cache(const std::string &entity_type,
                                  const std::string &entity_id);
  void invalidate_all_threshold_caches();

  // Manual override API (enhanced)
  void set_manual_override(const std::string &entity_type,
                           const std::string &entity_id, double threshold);
  void clear_manual_override(const std::string &entity_type,
                             const std::string &entity_id);

public:
  enum class TimeContext { NONE, HOURLY, DAILY, WEEKLY };
  std::shared_ptr<LearningBaseline>
  get_contextual_baseline(const std::string &entity_type,
                          const std::string &entity_id, TimeContext context,
                          int context_value);

private:
  mutable std::shared_mutex baselines_mutex_;
  std::unordered_map<std::string, std::shared_ptr<LearningBaseline>> baselines_;
  Config::DynamicLearningConfig config_;

  // Time-contextual baseline support
  struct ContextualKey {
    std::string entity_type;
    std::string entity_id;
    TimeContext context;
    int context_value; // hour (0-23), day (0-6), week (0-3)
    bool operator==(const ContextualKey &other) const {
      return entity_type == other.entity_type && entity_id == other.entity_id &&
             context == other.context && context_value == other.context_value;
    }
  };
  struct ContextualKeyHash {
    std::size_t operator()(const ContextualKey &k) const {
      return std::hash<std::string>()(k.entity_type) ^
             std::hash<std::string>()(k.entity_id) ^
             std::hash<int>()(static_cast<int>(k.context)) ^
             std::hash<int>()(k.context_value);
    }
  };

  // Contextual baselines: key is ContextualKey
  std::unordered_map<ContextualKey, std::shared_ptr<LearningBaseline>,
                     ContextualKeyHash>
      contextual_baselines_;

  // Gradual threshold adjustment config
  double max_gradual_threshold_step_ = 0.1; // 10% per update

  std::string make_key(const std::string &entity_type,
                       const std::string &entity_id) const;

  // Private helper methods for threshold management
  void add_threshold_audit_entry(LearningBaseline &baseline,
                                 double old_threshold, double new_threshold,
                                 double percentile, uint64_t timestamp_ms,
                                 const std::string &reason,
                                 const std::string &operator_id = "");

  bool is_threshold_change_acceptable(const LearningBaseline &baseline,
                                      double old_threshold,
                                      double new_threshold) const;

  void update_threshold_cache(LearningBaseline &baseline, double percentile,
                              double threshold, uint64_t timestamp_ms) const;

  double get_cached_threshold(const LearningBaseline &baseline,
                              double percentile,
                              uint64_t current_time_ms) const;

  // Helper for time context
  static TimeContext get_time_context(uint64_t timestamp_ms,
                                      int &context_value);
};

} // namespace learning

#endif // DYNAMIC_LEARNING_ENGINE_HPP

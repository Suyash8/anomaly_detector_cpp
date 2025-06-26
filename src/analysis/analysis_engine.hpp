#ifndef ANALYSIS_ENGINE_HPP
#define ANALYSIS_ENGINE_HPP

#include "../core/config.hpp"
#include "../core/log_entry.hpp"
#include "../models/feature_manager.hpp"
#include "analyzed_event.hpp"
#include "per_ip_state.hpp"
#include "per_path_state.hpp"

#include <cstdint>
#include <string>

class AnalysisEngine {
public:
  AnalysisEngine(const Config::AppConfig &cfg);
  ~AnalysisEngine();

  AnalyzedEvent process_and_analyze(const LogEntry &raw_log);

  bool save_state(const std::string &path) const;
  bool load_state(const std::string &path);

  void run_pruning(uint64_t current_timestamp_ms);
  uint64_t get_max_timestamp_seen() const;

  void reconfigure(const Config::AppConfig &new_config);
  void reset_in_memory_state();

private:
  Config::AppConfig app_config;
  std::unordered_map<std::string, PerIpState> ip_activity_trackers;
  std::unordered_map<std::string, PerPathState> path_activity_trackers;

  FeatureManager feature_manager_;

  // Track the highest seen timestamp to correctly handle out-of-order logs
  uint64_t max_timestamp_seen_ = 0;

  PerIpState &get_or_create_ip_state(const std::string &ip,
                                     uint64_t current_timestamp_ms);
  PerPathState &get_or_create_path_state(const std::string &path,
                                         uint64_t current_timestamp_ms);
};

#endif // ANALYSIS_ENGINE_HPP
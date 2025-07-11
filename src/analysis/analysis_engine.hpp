#ifndef ANALYSIS_ENGINE_HPP
#define ANALYSIS_ENGINE_HPP

#include "analysis/per_session_state.hpp"
#include "analyzed_event.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "models/feature_manager.hpp"
#include "models/model_data_collector.hpp"
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

  size_t get_ip_state_count() const { return ip_activity_trackers.size(); }
  size_t get_path_state_count() const { return path_activity_trackers.size(); }
  size_t get_session_state_count() const { return session_trackers.size(); }

private:
  Config::AppConfig app_config;
  std::unordered_map<std::string, PerIpState> ip_activity_trackers;
  std::unordered_map<std::string, PerPathState> path_activity_trackers;
  std::unordered_map<std::string, PerSessionState> session_trackers;

  std::unique_ptr<ModelDataCollector> data_collector_;

  FeatureManager feature_manager_;
  uint64_t max_timestamp_seen_ = 0;

  std::string build_session_key(const LogEntry &raw_log) const;

  PerIpState &get_or_create_ip_state(const std::string &ip,
                                     uint64_t current_timestamp_ms);
  PerPathState &get_or_create_path_state(const std::string &path,
                                         uint64_t current_timestamp_ms);
};

#endif // ANALYSIS_ENGINE_HPP
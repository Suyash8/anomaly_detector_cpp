#ifndef ANALYSIS_ENGINE_HPP
#define ANALYSIS_ENGINE_HPP

#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "ml_models/feature_manager.hpp"
#include "sliding_window.hpp"
#include "stats_tracker.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct PerPathState {
  StatsTracker request_time_tracker;
  StatsTracker bytes_sent_tracker;
  StatsTracker error_rate_tracker;
  StatsTracker request_volume_tracker;

  uint64_t last_seen_timestamp_ms;

  PerPathState(uint64_t current_timestamp_ms)
      : last_seen_timestamp_ms(current_timestamp_ms) {}

  PerPathState() : last_seen_timestamp_ms(0) {}

  void save(std::ofstream &out) const;
  void load(std::ifstream &in);
};

struct PerIpState {
  // Tier 1 Windows
  SlidingWindow<uint64_t> request_timestamps_window;
  SlidingWindow<uint64_t> failed_login_timestamps_window;
  SlidingWindow<uint64_t> html_request_timestamps;
  SlidingWindow<uint64_t> asset_request_timestamps;

  // std::unordered_map<std::string, SlidingWindow<uint64_t>>
  // asset_path_access_window; //Will re add later
  uint64_t last_seen_timestamp_ms; // To help with pruning inactive IPs later
  uint64_t ip_first_seen_timestamp_ms = 0;
  std::unordered_set<std::string> paths_seen_by_ip;

  std::string last_known_user_agent;
  std::unordered_set<std::string> historical_user_agents;
  SlidingWindow<std::string> recent_unique_ua_window;

  // Tier 2 Historical Trackers
  StatsTracker request_time_tracker;
  StatsTracker bytes_sent_tracker;
  StatsTracker error_rate_tracker;
  StatsTracker requests_in_window_count_tracker;

  PerIpState(uint64_t current_timestamp_ms, uint64_t general_window_duration_ms,
             uint64_t login_window_duration_ms)
      : request_timestamps_window(general_window_duration_ms, 0),
        failed_login_timestamps_window(login_window_duration_ms, 0),
        html_request_timestamps(general_window_duration_ms, 0),
        asset_request_timestamps(general_window_duration_ms, 0),
        recent_unique_ua_window(general_window_duration_ms, 0),
        last_seen_timestamp_ms(current_timestamp_ms) {}

  PerIpState()
      : request_timestamps_window(0, 0), failed_login_timestamps_window(0, 0),
        html_request_timestamps(0, 0), asset_request_timestamps(0, 0),
        recent_unique_ua_window(0, 0), last_seen_timestamp_ms(0) {}

  void save(std::ofstream &out) const;
  void load(std::ifstream &in);
};

class AnalysisEngine {
public:
  AnalysisEngine(const Config::AppConfig &cfg);
  ~AnalysisEngine();

  AnalyzedEvent process_and_analyze(const LogEntry &raw_log);

  bool save_state(const std::string &path) const;
  bool load_state(const std::string &path);

  void run_pruning(uint64_t current_timestamp_ms);
  uint64_t get_max_timestamp_seen() const;

private:
  const Config::AppConfig &app_config;
  std::unordered_map<std::string, PerIpState> ip_activity_trackers;
  std::unordered_map<std::string, PerPathState> path_activity_trackers;

  FeatureManager feature_manager_;

  // Track the highest seen timestamp to correctly handle out-of-order logs
  uint64_t max_timestamp_seen_ = 0;

  PerIpState &get_or_create_ip_state(const std::string &ip,
                                     uint64_t current_timestamp_ms);
  PerPathState &get_or_create_path_state(const std::string &path,
                                         uint64_t current_timestamp_ms);

  void prune_inactive_states(uint64_t current_timestamp_ms);

  // Helper to check if a path is an asset path - might be needed here if asset
  // analysis moves
  // bool is_path_an_asset(const std::string &request_path) const;
};

#endif // ANALYSIS_ENGINE_HPP
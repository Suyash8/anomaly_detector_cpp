#ifndef ANALYSIS_ENGINE_HPP
#define ANALYSIS_ENGINE_HPP

#include "analyzed_event.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "sliding_window.hpp"
#include "stats_tracker.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct PerIpState {
  // Tier 1 Windows
  SlidingWindow<uint64_t> request_timestamps_window;
  SlidingWindow<uint64_t> failed_login_timestamps_window;
  // std::unordered_map<std::string, SlidingWindow<uint64_t>>
  // asset_path_access_window; //Will re add later
  uint64_t last_seen_timestamp_ms; // To help with pruning inactive IPs later

  std::string last_known_user_agent;
  std::unordered_set<std::string> historical_user_agents;

  // Tier 2 Historical Trackers
  StatsTracker request_time_tracker;
  StatsTracker bytes_sent_tracker;
  StatsTracker error_rate_tracker;
  StatsTracker requests_in_window_count_tracker;

  PerIpState(uint64_t current_timestamp_ms, uint64_t general_window_duration_ms,
             uint64_t login_window_duration_ms)
      : request_timestamps_window(general_window_duration_ms, 0),
        failed_login_timestamps_window(login_window_duration_ms, 0),
        last_seen_timestamp_ms(current_timestamp_ms) {}

  PerIpState()
      : request_timestamps_window(0, 0), failed_login_timestamps_window(0, 0),
        last_seen_timestamp_ms(0) {}
};

class AnalysisEngine {
public:
  AnalysisEngine(const Config::AppConfig &cfg);
  ~AnalysisEngine();

  AnalyzedEvent process_and_analyze(const LogEntry &raw_log);

private:
  const Config::AppConfig &app_config;
  std::unordered_map<std::string, PerIpState> ip_activity_trackers;

  //   std::unordered_map<std::string, PerPathState>
  //       path_activity_trackers; // For later

  PerIpState &get_or_create_ip_state(const std::string &ip,
                                     uint64_t current_timestamp_ms);

  // Helper to check if a path is an asset path - might be needed here if asset
  // analysis moves
  // bool is_path_an_asset(const std::string &request_path) const;
};

#endif // ANALYSIS_ENGINE_HPP
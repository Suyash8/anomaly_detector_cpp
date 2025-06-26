#ifndef PER_IP_STATE_HPP
#define PER_IP_STATE_HPP

#include "../utils/sliding_window.hpp"
#include "../utils/stats_tracker.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_set>

struct PerIpState {
  // Tier 1 Windows
  SlidingWindow<uint64_t> request_timestamps_window;
  SlidingWindow<uint64_t> failed_login_timestamps_window;
  SlidingWindow<uint64_t> html_request_timestamps;
  SlidingWindow<uint64_t> asset_request_timestamps;
  SlidingWindow<std::string> recent_unique_ua_window;

  // std::unordered_map<std::string, SlidingWindow<uint64_t>>
  // asset_path_access_window; //Will re add later
  uint64_t last_seen_timestamp_ms; // To help with pruning inactive IPs later
  uint64_t ip_first_seen_timestamp_ms = 0;
  std::unordered_set<std::string> paths_seen_by_ip;

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

#endif // PER_IP_STATE_HPP
#ifndef PER_IP_STATE_HPP
#define PER_IP_STATE_HPP

#include "utils/sliding_window.hpp"
#include "utils/stats_tracker.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_set>

struct PerIpState {
  int default_elements_limit = 200;
  int default_duration_ms = 60000; // 60 seconds

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

  size_t get_request_timestamps_count() const {
    return request_timestamps_window.get_event_count();
  }
  size_t get_failed_login_timestamps_count() const {
    return failed_login_timestamps_window.get_event_count();
  }
  size_t get_html_request_timestamps_count() const {
    return html_request_timestamps.get_event_count();
  }
  size_t get_asset_request_timestamps_count() const {
    return asset_request_timestamps.get_event_count();
  }
  size_t get_recent_unique_ua_count() const {
    return recent_unique_ua_window.get_event_count();
  }
  size_t get_paths_seen_count() const { return paths_seen_by_ip.size(); }
  size_t get_historical_user_agents_count() const {
    return historical_user_agents.size();
  }

  // Memory footprint calculation
  size_t calculate_memory_footprint() const {
    size_t total = sizeof(PerIpState);

    // Sliding windows memory
    total += request_timestamps_window.get_event_count() * sizeof(uint64_t);
    total +=
        failed_login_timestamps_window.get_event_count() * sizeof(uint64_t);
    total += html_request_timestamps.get_event_count() * sizeof(uint64_t);
    total += asset_request_timestamps.get_event_count() * sizeof(uint64_t);

    // UA window memory (strings are more complex)
    for (const auto &pair : recent_unique_ua_window.get_raw_window_data()) {
      total += pair.second.size() + sizeof(std::string);
    }

    // Paths seen memory
    for (const auto &path : paths_seen_by_ip) {
      total += path.size() + sizeof(std::string);
    }

    // Historical user agents memory
    for (const auto &ua : historical_user_agents) {
      total += ua.size() + sizeof(std::string);
    }

    // Last known user agent
    total += last_known_user_agent.size();

    return total;
  }

  PerIpState(uint64_t current_timestamp_ms, uint64_t general_window_duration_ms,
             uint64_t login_window_duration_ms)
      : request_timestamps_window(general_window_duration_ms,
                                  default_elements_limit),
        failed_login_timestamps_window(login_window_duration_ms,
                                       default_elements_limit),
        html_request_timestamps(general_window_duration_ms,
                                default_elements_limit),
        asset_request_timestamps(general_window_duration_ms,
                                 default_elements_limit),
        recent_unique_ua_window(general_window_duration_ms,
                                default_elements_limit),
        last_seen_timestamp_ms(current_timestamp_ms) {}

  PerIpState()
      : request_timestamps_window(default_duration_ms, default_elements_limit),
        failed_login_timestamps_window(default_duration_ms,
                                       default_elements_limit),
        html_request_timestamps(default_duration_ms, default_elements_limit),
        asset_request_timestamps(default_duration_ms, default_elements_limit),
        recent_unique_ua_window(default_duration_ms, default_elements_limit),
        last_seen_timestamp_ms(0) {}

  void save(std::ofstream &out) const;
  void load(std::ifstream &in);
};

#endif // PER_IP_STATE_HPP
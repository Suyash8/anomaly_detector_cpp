#ifndef PER_SESSION_STATE_HPP
#define PER_SESSION_STATE_HPP

#include "utils/sliding_window.hpp"
#include "utils/stats_tracker.hpp"

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <unordered_set>

struct PerSessionState {
  uint64_t session_start_timestamp_ms = 0;
  uint64_t last_seen_timestamp_ms = 0;

  // Track the sequence of requests for path analysis
  std::deque<std::pair<uint64_t, std::string>> request_history;

  // --- Core Stats ---
  uint64_t request_count = 0;
  std::unordered_set<std::string> unique_paths_visited;
  std::unordered_set<std::string> unique_user_agents;

  // --- HTTP Method & Status Tracking ---
  std::map<std::string, int> http_method_counts;
  uint32_t failed_login_attempts = 0;
  uint32_t error_4xx_count = 0;
  uint32_t error_5xx_count = 0;

  // --- Per-Session Performance Tracking ---
  StatsTracker request_time_tracker;
  StatsTracker bytes_sent_tracker;

  // --- Window for High-Frequency Activity Detection ---
  SlidingWindow<uint64_t> request_timestamps_window;

  PerSessionState()
      : session_start_timestamp_ms(0), last_seen_timestamp_ms(0),
        failed_login_attempts(0), error_4xx_count(0), error_5xx_count(0),
        request_time_tracker(), bytes_sent_tracker(),
        request_timestamps_window(0, 0) {}

  // Constructor to initialize with the first event and window duration
  PerSessionState(uint64_t timestamp_ms, uint64_t window_duration_ms)
      : session_start_timestamp_ms(timestamp_ms),
        last_seen_timestamp_ms(timestamp_ms),
        request_timestamps_window(window_duration_ms, 0) {}
};

#endif // PER_SESSION_STATE_HPP
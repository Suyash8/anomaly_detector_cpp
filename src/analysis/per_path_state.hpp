#ifndef PER_PATH_STATE_HPP
#define PER_PATH_STATE_HPP

#include "utils/stats_tracker.hpp"

#include <cstdint>
#include <fstream>

struct PerPathState {
  StatsTracker request_time_tracker;
  StatsTracker bytes_sent_tracker;
  StatsTracker error_rate_tracker;
  StatsTracker request_volume_tracker;

  uint64_t last_seen_timestamp_ms;

  // Memory footprint calculation
  size_t calculate_memory_footprint() const {
    size_t total = sizeof(PerPathState);

    // StatsTracker objects contain internal data structures
    // Each StatsTracker typically stores a running count, sum, sum_of_squares
    // which are basic numeric types, so minimal additional memory
    total += sizeof(double) * 3 * 4; // 4 StatsTrackers with ~3 doubles each

    return total;
  }

  PerPathState(uint64_t current_timestamp_ms)
      : last_seen_timestamp_ms(current_timestamp_ms) {}

  PerPathState() : last_seen_timestamp_ms(0) {}

  void save(std::ofstream &out) const;
  void load(std::ifstream &in);
};

#endif // PER_PATH_STATE_HPP
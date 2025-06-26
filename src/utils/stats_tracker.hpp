#ifndef STATS_TRACKER_HPP
#define STATS_TRACKER_HPP

#include <cstdint>
#include <fstream>

class StatsTracker {
public:
  StatsTracker();

  // Add a new data point to the stream
  void update(double new_value);

  // Getters for the current statistical state
  int64_t get_count() const;
  double get_mean() const;
  double get_variance() const;
  double get_stddev() const;

  void save(std::ofstream &out) const;
  void load(std::ifstream &in);

private:
  int64_t count_;
  double mean_;
  // M2 is the sum of squares of differences from the current mean
  double m2_;
};

#endif // STATS_TRACKER_HPP
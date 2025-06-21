#ifndef STATS_TRACKER_HPP
#define STATS_TRACKER_HPP

#include <cstdint>

namespace StateSerializer {
class Accessor;
}

class StatsTracker {
public:
  StatsTracker();

  void update(double new_value);

  int64_t get_count() const;
  double get_mean() const;
  double get_variance() const;
  double get_stddev() const;

private:
  friend class StateSerializer::Accessor;

  int64_t count_;
  double mean_;
  // M2 is the sum of squares of differences from the current mean
  double m2_;
};

#endif // STATS_TRACKER_HPP
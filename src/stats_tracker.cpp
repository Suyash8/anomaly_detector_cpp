#include "stats_tracker.hpp"
#include <cmath>
#include <cstdint>

StatsTracker::StatsTracker() : count_(0), mean_(0), m2_(0) {}

void StatsTracker::update(double new_value) {
  count_++;
  double delta = new_value - mean_;
  mean_ += delta / count_;
  double delta2 = new_value - mean_;
  m2_ += delta * delta2;
}

int64_t StatsTracker::get_count() const { return count_; }

double StatsTracker::get_mean() const { return count_ > 0 ? mean_ : 0.0; }

double StatsTracker::get_variance() const {
  // For variance to be meaningful, at least 2 samples are needed
  if (count_ < 2) {
    return 0.0;
  }
  // Population variance is M2 / n
  // Sample variance would be M2 / (n - 1)
  return m2_ / count_;
}

double StatsTracker::get_stddev() const { return std::sqrt(get_variance()); }
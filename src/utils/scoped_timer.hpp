#ifndef SCOPED_TIMER_HPP
#define SCOPED_TIMER_HPP

#include "core/metrics_manager.hpp"
#include <chrono>

class ScopedTimer {
public:
  explicit ScopedTimer(Histogram &histogram_metric)
      : metric_(histogram_metric),
        start_time_(std::chrono::high_resolution_clock::now()) {}

  ~ScopedTimer() {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::duration<double>>(
        end_time - start_time_);
    metric_.observe(duration.count());
  }

private:
  Histogram &metric_;
  std::chrono::time_point<std::chrono::high_resolution_clock> start_time_;
};

#endif // SCOPED_TIMER_HPP
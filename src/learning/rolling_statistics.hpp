#ifndef ROLLING_STATISTICS_HPP
#define ROLLING_STATISTICS_HPP

#include <cstdint>
#include <deque>
#include <shared_mutex>
#include <vector>

namespace learning {

/**
 * Thread-safe rolling statistics calculator using Exponentially Weighted Moving
 * Average (EWMA) Provides confidence intervals using Bayesian updating and
 * efficient percentile calculations
 */
class RollingStatistics {
public:
  /**
   * Constructor
   * @param alpha Decay factor for EWMA (0 < alpha <= 1, smaller = more stable)
   * @param window_size Maximum number of samples to keep in memory
   */
  explicit RollingStatistics(double alpha = 0.1, size_t window_size = 1000);

  /**
   * Add a new value to the rolling statistics
   * @param value The value to add
   * @param timestamp_ms Timestamp in milliseconds
   */
  void add_value(double value, uint64_t timestamp_ms);

  /**
   * Get the current EWMA mean
   */
  double get_mean() const;

  /**
   * Get the current EWMA variance
   */
  double get_variance() const;

  /**
   * Get the current standard deviation
   */
  double get_standard_deviation() const;

  /**
   * Get a specific percentile from recent samples
   * @param percentile Value between 0.0 and 1.0
   */
  double get_percentile(double percentile) const;

  /**
   * Get confidence interval using Bayesian updating
   * @param confidence Confidence level (e.g., 0.95 for 95%)
   * @return Pair of (lower_bound, upper_bound)
   */
  std::pair<double, double>
  get_confidence_interval(double confidence = 0.95) const;

  /**
   * Get the number of samples processed
   */
  size_t get_sample_count() const;

  /**
   * Get the timestamp of the last update
   */
  uint64_t get_last_update_time() const;

  /**
   * Reset all statistics
   */
  void reset();

  /**
   * Get approximate memory usage in bytes
   */
  size_t get_memory_usage() const;

  /**
   * Check if enough samples have been collected for reliable statistics
   */
  bool is_established(size_t min_samples = 30) const;

private:
  mutable std::shared_mutex mutex_;

  // EWMA parameters
  double alpha_;         // Decay factor
  double ewma_mean_;     // Current EWMA mean
  double ewma_variance_; // Current EWMA variance

  // Sample storage for percentile calculations
  std::deque<std::pair<double, uint64_t>> samples_;
  size_t max_window_size_;

  // Metadata
  uint64_t last_update_time_;
  size_t total_sample_count_;

  // Helper methods
  double calculate_t_critical(double confidence,
                              size_t degrees_of_freedom) const;
  double calculate_normal_critical(double confidence) const;
  std::vector<double> get_sorted_values() const;
};

} // namespace learning

#endif // ROLLING_STATISTICS_HPP

#ifndef SEASONAL_MODEL_HPP
#define SEASONAL_MODEL_HPP

#include <cstdint>
#include <mutex>
#include <vector>

namespace learning {

/**
 * Seasonal pattern detection and modeling using Fourier analysis
 * Detects patterns in hourly, daily, and weekly cycles using DFT coefficients
 */
class SeasonalModel {
public:
  struct FourierCoefficients {
    std::vector<double> real;      // Real components
    std::vector<double> imaginary; // Imaginary components
    std::vector<double> magnitude; // Magnitude (power spectrum)
    std::vector<double> phase;     // Phase angles
  };

  struct SeasonalPattern {
    std::vector<double> hourly_pattern; // 24 values (one per hour)
    std::vector<double> daily_pattern;  // 7 values (one per day of week)
    std::vector<double> weekly_pattern; // 4 values (one per week of month)

    // Fourier analysis results
    FourierCoefficients hourly_fourier;
    FourierCoefficients daily_fourier;

    double confidence_score;  // Overall pattern confidence [0.0, 1.0]
    uint64_t last_updated;    // Timestamp when pattern was last updated
    size_t observation_count; // Number of observations used for this pattern

    // Dominant frequency components
    std::vector<int> dominant_hourly_frequencies;
    std::vector<int> dominant_daily_frequencies;
  };

  /**
   * Constructor
   * @param min_samples Minimum number of samples required before pattern
   * detection begins
   */
  explicit SeasonalModel(size_t min_samples = 1000);

  /**
   * Add a new observation for pattern learning
   * @param value The observed value
   * @param timestamp_ms Timestamp in milliseconds since epoch
   */
  void add_observation(double value, uint64_t timestamp_ms);

  /**
   * Get the expected value based on seasonal patterns with Fourier
   * reconstruction
   * @param timestamp_ms Timestamp for which to get expected value
   * @return Expected value based on learned patterns
   */
  double get_expected_value(uint64_t timestamp_ms) const;

  /**
   * Get the seasonal adjustment factor for a given timestamp using Fourier
   * analysis
   * @param timestamp_ms Timestamp for which to get seasonal factor
   * @return Multiplier factor (1.0 = no adjustment, >1.0 = higher than average,
   * <1.0 = lower)
   */
  double get_seasonal_factor(uint64_t timestamp_ms) const;

  /**
   * Get the current seasonal pattern
   */
  SeasonalPattern get_current_pattern() const;

  /**
   * Check if a reliable pattern has been established
   */
  bool is_pattern_established() const;

  /**
   * Force an update of the seasonal pattern (normally done automatically)
   */
  void update_pattern();

  /**
   * Reset all learned patterns
   */
  void reset();

  /**
   * Get approximate memory usage in bytes
   */
  size_t get_memory_usage() const;

private:
  mutable std::recursive_mutex mutex_;

  // Configuration
  size_t min_samples_for_pattern_;

  // Observation storage
  std::vector<std::pair<double, uint64_t>> observations_;

  // Current pattern
  SeasonalPattern current_pattern_;

  // Pattern update tracking
  uint64_t last_pattern_update_;
  static const uint64_t PATTERN_UPDATE_INTERVAL_MS = 3600000; // 1 hour

  // Helper methods
  void compute_hourly_pattern();
  void compute_daily_pattern();
  void compute_weekly_pattern();
  double calculate_pattern_confidence() const;

  // Fourier analysis methods
  void compute_fourier_transform(const std::vector<double> &data,
                                 FourierCoefficients &coeffs) const;
  double reconstruct_from_fourier(const FourierCoefficients &coeffs,
                                  double normalized_time) const;
  std::vector<int> find_dominant_frequencies(const FourierCoefficients &coeffs,
                                             size_t max_components = 3) const;

  // Time utility methods
  int get_hour_of_day(uint64_t timestamp_ms) const;
  int get_day_of_week(uint64_t timestamp_ms) const;
  int get_week_of_month(uint64_t timestamp_ms) const;

  // Statistical helpers
  std::vector<double> compute_moving_average(const std::vector<double> &data,
                                             size_t window_size) const;
  double compute_autocorrelation(const std::vector<double> &data,
                                 size_t lag) const;
  std::vector<double> extract_values_for_time_bucket(int bucket_type,
                                                     int bucket_value) const;
};

} // namespace learning

#endif // SEASONAL_MODEL_HPP

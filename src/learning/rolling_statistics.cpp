#include "rolling_statistics.hpp"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <stdexcept>

namespace learning {

RollingStatistics::RollingStatistics(double alpha, size_t window_size)
    : alpha_(alpha), ewma_mean_(0.0), ewma_variance_(0.0),
      max_window_size_(window_size), last_update_time_(0),
      total_sample_count_(0) {
  if (alpha <= 0.0 || alpha > 1.0) {
    throw std::invalid_argument("Alpha must be between 0 and 1");
  }
  if (window_size == 0) {
    throw std::invalid_argument("Window size must be greater than 0");
  }
}

void RollingStatistics::add_value(double value, uint64_t timestamp_ms) {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  if (total_sample_count_ == 0) {
    // Initialize with first value
    ewma_mean_ = value;
    ewma_variance_ = 0.0;
  } else {
    // Update EWMA mean
    double delta = value - ewma_mean_;
    ewma_mean_ += alpha_ * delta;

    // Update EWMA variance using Welford's online algorithm with EWMA
    ewma_variance_ = (1.0 - alpha_) * ewma_variance_ + alpha_ * delta * delta;
  }

  // Add to sample buffer for percentile calculations
  samples_.emplace_back(value, timestamp_ms);
  if (samples_.size() > max_window_size_) {
    samples_.pop_front();
  }

  last_update_time_ = timestamp_ms;
  total_sample_count_++;
}

double RollingStatistics::get_mean() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return ewma_mean_;
}

double RollingStatistics::get_variance() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return ewma_variance_;
}

double RollingStatistics::get_standard_deviation() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return std::sqrt(ewma_variance_);
}

double RollingStatistics::get_percentile(double percentile) const {
  if (percentile < 0.0 || percentile > 1.0) {
    throw std::invalid_argument("Percentile must be between 0.0 and 1.0");
  }

  std::shared_lock<std::shared_mutex> lock(mutex_);

  if (samples_.empty()) {
    return ewma_mean_;
  }

  auto sorted_values = get_sorted_values();
  if (sorted_values.size() == 1) {
    return sorted_values[0];
  }

  // Linear interpolation for percentile calculation
  double index = percentile * (sorted_values.size() - 1);
  size_t lower_index = static_cast<size_t>(std::floor(index));
  size_t upper_index = static_cast<size_t>(std::ceil(index));

  if (lower_index == upper_index) {
    return sorted_values[lower_index];
  }

  double weight = index - lower_index;
  return sorted_values[lower_index] * (1.0 - weight) +
         sorted_values[upper_index] * weight;
}

std::pair<double, double>
RollingStatistics::get_confidence_interval(double confidence) const {
  if (confidence < 0.0 || confidence > 1.0) {
    throw std::invalid_argument("Confidence must be between 0.0 and 1.0");
  }

  std::shared_lock<std::shared_mutex> lock(mutex_);

  if (total_sample_count_ < 3) {
    // Not enough samples for reliable confidence interval
    double margin = get_standard_deviation() * 3.0;
    return {ewma_mean_ - margin, ewma_mean_ + margin};
  }

  // Calculate standard error
  double standard_error = get_standard_deviation() /
                          std::sqrt(static_cast<double>(samples_.size()));

  // Choose critical value based on sample size
  double critical_value;
  if (samples_.size() > 30) {
    // Use normal distribution for large samples
    critical_value = calculate_normal_critical(confidence);
  } else {
    // Use t-distribution for small samples
    critical_value = calculate_t_critical(confidence, samples_.size() - 1);
  }

  double margin = critical_value * standard_error;
  return {ewma_mean_ - margin, ewma_mean_ + margin};
}

size_t RollingStatistics::get_sample_count() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return total_sample_count_;
}

uint64_t RollingStatistics::get_last_update_time() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return last_update_time_;
}

void RollingStatistics::reset() {
  std::unique_lock<std::shared_mutex> lock(mutex_);
  ewma_mean_ = 0.0;
  ewma_variance_ = 0.0;
  samples_.clear();
  last_update_time_ = 0;
  total_sample_count_ = 0;
}

size_t RollingStatistics::get_memory_usage() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return sizeof(*this) + samples_.size() * sizeof(std::pair<double, uint64_t>);
}

bool RollingStatistics::is_established(size_t min_samples) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return total_sample_count_ >= min_samples;
}

double
RollingStatistics::calculate_t_critical(double confidence,
                                        size_t degrees_of_freedom) const {
  // Simplified t-distribution critical values for common confidence levels
  // This is a basic approximation - for production, consider using a proper
  // statistical library

  if (confidence >= 0.95) {
    if (degrees_of_freedom <= 10)
      return 2.228;
    if (degrees_of_freedom <= 20)
      return 2.086;
    if (degrees_of_freedom <= 30)
      return 2.042;
    return 1.96; // Approaches normal distribution
  } else if (confidence >= 0.90) {
    if (degrees_of_freedom <= 10)
      return 1.812;
    if (degrees_of_freedom <= 20)
      return 1.725;
    if (degrees_of_freedom <= 30)
      return 1.697;
    return 1.645;
  } else {
    // Default to 68% confidence (1 std dev)
    return 1.0;
  }
}

double RollingStatistics::calculate_normal_critical(double confidence) const {
  // Standard normal distribution critical values
  if (confidence >= 0.99)
    return 2.576;
  if (confidence >= 0.95)
    return 1.96;
  if (confidence >= 0.90)
    return 1.645;
  if (confidence >= 0.80)
    return 1.282;
  return 1.0; // Default to 68% confidence
}

std::vector<double> RollingStatistics::get_sorted_values() const {
  std::vector<double> values;
  values.reserve(samples_.size());

  for (const auto &sample : samples_) {
    values.push_back(sample.first);
  }

  std::sort(values.begin(), values.end());
  return values;
}

} // namespace learning

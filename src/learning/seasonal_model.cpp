#include "seasonal_model.hpp"
#include <algorithm>
#include <cmath>
#include <ctime>
#include <mutex>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace learning {

SeasonalModel::SeasonalModel(size_t min_samples)
    : min_samples_for_pattern_(min_samples), last_pattern_update_(0) {
  current_pattern_.hourly_pattern.resize(24, 1.0); // Initialize to neutral
  current_pattern_.daily_pattern.resize(7, 1.0);
  current_pattern_.weekly_pattern.resize(4, 1.0);
  current_pattern_.confidence_score = 0.0;
  current_pattern_.last_updated = 0;
  current_pattern_.observation_count = 0;

  // Initialize Fourier coefficient storage
  current_pattern_.hourly_fourier.real.resize(24, 0.0);
  current_pattern_.hourly_fourier.imaginary.resize(24, 0.0);
  current_pattern_.hourly_fourier.magnitude.resize(24, 0.0);
  current_pattern_.hourly_fourier.phase.resize(24, 0.0);

  current_pattern_.daily_fourier.real.resize(7, 0.0);
  current_pattern_.daily_fourier.imaginary.resize(7, 0.0);
  current_pattern_.daily_fourier.magnitude.resize(7, 0.0);
  current_pattern_.daily_fourier.phase.resize(7, 0.0);
}

void SeasonalModel::add_observation(double value, uint64_t timestamp_ms) {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  observations_.emplace_back(value, timestamp_ms);
  if (observations_.size() > min_samples_for_pattern_ * 2) {
    observations_.erase(observations_.begin());
  }
  // Optionally update pattern periodically
  if (timestamp_ms - last_pattern_update_ > PATTERN_UPDATE_INTERVAL_MS) {
    update_pattern();
    last_pattern_update_ = timestamp_ms;
  }
}

double SeasonalModel::get_expected_value(uint64_t timestamp_ms) const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (!is_pattern_established()) {
    return 1.0; // Neutral value when no pattern established
  }

  // Use Fourier reconstruction for more accurate prediction
  int hour = get_hour_of_day(timestamp_ms);
  double normalized_hour = static_cast<double>(hour) / 24.0;

  // Reconstruct using dominant frequency components
  return reconstruct_from_fourier(current_pattern_.hourly_fourier,
                                  normalized_hour);
}

double SeasonalModel::get_seasonal_factor(uint64_t timestamp_ms) const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (!is_pattern_established()) {
    return 1.0; // No adjustment when pattern not established
  }

  int hour = get_hour_of_day(timestamp_ms);
  int day = get_day_of_week(timestamp_ms);
  int week = get_week_of_month(timestamp_ms);

  double hourly_factor = 1.0;
  double daily_factor = 1.0;
  double weekly_factor = 1.0;

  // Use Fourier reconstruction for hourly pattern
  if (hour >= 0 && hour < 24) {
    double normalized_hour = static_cast<double>(hour) / 24.0;
    hourly_factor = reconstruct_from_fourier(current_pattern_.hourly_fourier,
                                             normalized_hour);
  }

  // Use simple averaging for daily pattern (could be enhanced with Fourier)
  if (day >= 0 && day < 7) {
    daily_factor = current_pattern_.daily_pattern[day];
  }

  if (week >= 0 && week < 4) {
    weekly_factor = current_pattern_.weekly_pattern[week];
  }

  // Combine factors (geometric mean for multiplicative model)
  return std::pow(hourly_factor * daily_factor * weekly_factor, 1.0 / 3.0);
}

learning::SeasonalModel::SeasonalPattern
SeasonalModel::get_current_pattern() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return current_pattern_;
}

bool SeasonalModel::is_pattern_established() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return observations_.size() >= min_samples_for_pattern_;
}

void SeasonalModel::update_pattern() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  if (observations_.size() < min_samples_for_pattern_)
    return;
  compute_hourly_pattern();
  compute_daily_pattern();
  compute_weekly_pattern();
  current_pattern_.confidence_score = calculate_pattern_confidence();
  current_pattern_.last_updated = observations_.back().second;
  current_pattern_.observation_count = observations_.size();
}

void SeasonalModel::reset() {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  observations_.clear();
  current_pattern_ = SeasonalPattern();
}

size_t SeasonalModel::get_memory_usage() const {
  std::lock_guard<std::recursive_mutex> lock(mutex_);
  return sizeof(*this) +
         observations_.size() * sizeof(std::pair<double, uint64_t>);
}

void SeasonalModel::compute_hourly_pattern() {
  std::vector<double> hourly_sum(24, 0.0);
  std::vector<size_t> hourly_count(24, 0);

  // Aggregate values by hour
  for (const auto &obs : observations_) {
    int hour = get_hour_of_day(obs.second);
    if (hour >= 0 && hour < 24) {
      hourly_sum[hour] += obs.first;
      hourly_count[hour]++;
    }
  }

  // Calculate averages
  for (int i = 0; i < 24; ++i) {
    current_pattern_.hourly_pattern[i] =
        (hourly_count[i] > 0) ? (hourly_sum[i] / hourly_count[i]) : 1.0;
  }

  // Perform Fourier analysis on the hourly pattern
  compute_fourier_transform(current_pattern_.hourly_pattern,
                            current_pattern_.hourly_fourier);
  current_pattern_.dominant_hourly_frequencies =
      find_dominant_frequencies(current_pattern_.hourly_fourier, 3);
}

void SeasonalModel::compute_daily_pattern() {
  std::vector<double> daily_sum(7, 0.0);
  std::vector<size_t> daily_count(7, 0);

  for (const auto &obs : observations_) {
    int day = get_day_of_week(obs.second);
    if (day >= 0 && day < 7) {
      daily_sum[day] += obs.first;
      daily_count[day]++;
    }
  }

  for (int i = 0; i < 7; ++i) {
    current_pattern_.daily_pattern[i] =
        (daily_count[i] > 0) ? (daily_sum[i] / daily_count[i]) : 1.0;
  }

  // Perform Fourier analysis on the daily pattern
  compute_fourier_transform(current_pattern_.daily_pattern,
                            current_pattern_.daily_fourier);
  current_pattern_.dominant_daily_frequencies =
      find_dominant_frequencies(current_pattern_.daily_fourier, 2);
}

void SeasonalModel::compute_weekly_pattern() {
  std::vector<double> weekly_sum(4, 0.0);
  std::vector<size_t> weekly_count(4, 0);

  for (const auto &obs : observations_) {
    int week = get_week_of_month(obs.second);
    if (week >= 0 && week < 4) {
      weekly_sum[week] += obs.first;
      weekly_count[week]++;
    }
  }

  for (int i = 0; i < 4; ++i) {
    current_pattern_.weekly_pattern[i] =
        (weekly_count[i] > 0) ? (weekly_sum[i] / weekly_count[i]) : 1.0;
  }
}

double SeasonalModel::calculate_pattern_confidence() const {
  if (observations_.size() < min_samples_for_pattern_) {
    return 0.0;
  }

  // Base confidence on pattern establishment
  double base_confidence =
      std::min(1.0, static_cast<double>(observations_.size()) /
                        (min_samples_for_pattern_ * 2));

  // Adjust based on Fourier analysis - higher magnitude of dominant frequencies
  // indicates stronger patterns
  double fourier_confidence = 0.0;
  if (!current_pattern_.hourly_fourier.magnitude.empty()) {
    double total_power = 0.0;
    double dominant_power = 0.0;

    for (size_t i = 0; i < current_pattern_.hourly_fourier.magnitude.size();
         ++i) {
      total_power += current_pattern_.hourly_fourier.magnitude[i];
    }

    for (int freq : current_pattern_.dominant_hourly_frequencies) {
      if (freq <
          static_cast<int>(current_pattern_.hourly_fourier.magnitude.size())) {
        dominant_power += current_pattern_.hourly_fourier.magnitude[freq];
      }
    }

    fourier_confidence =
        (total_power > 0) ? (dominant_power / total_power) : 0.0;
  }

  // Combine base confidence with Fourier confidence
  return base_confidence * (0.7 + 0.3 * fourier_confidence);
}

int SeasonalModel::get_hour_of_day(uint64_t timestamp_ms) const {
  time_t t = timestamp_ms / 1000;
  struct tm tmval;
  localtime_r(&t, &tmval);
  return tmval.tm_hour;
}

int SeasonalModel::get_day_of_week(uint64_t timestamp_ms) const {
  time_t t = timestamp_ms / 1000;
  struct tm tmval;
  localtime_r(&t, &tmval);
  return tmval.tm_wday;
}

int SeasonalModel::get_week_of_month(uint64_t timestamp_ms) const {
  time_t t = timestamp_ms / 1000;
  struct tm tmval;
  localtime_r(&t, &tmval);
  return tmval.tm_mday / 7;
}

void SeasonalModel::compute_fourier_transform(
    const std::vector<double> &data, FourierCoefficients &coeffs) const {
  size_t N = data.size();
  coeffs.real.assign(N, 0.0);
  coeffs.imaginary.assign(N, 0.0);
  coeffs.magnitude.assign(N, 0.0);
  coeffs.phase.assign(N, 0.0);

  // Discrete Fourier Transform
  for (size_t k = 0; k < N; ++k) {
    double real_sum = 0.0;
    double imag_sum = 0.0;

    for (size_t n = 0; n < N; ++n) {
      double angle = -2.0 * M_PI * k * n / N;
      real_sum += data[n] * std::cos(angle);
      imag_sum += data[n] * std::sin(angle);
    }

    coeffs.real[k] = real_sum / N;
    coeffs.imaginary[k] = imag_sum / N;
    coeffs.magnitude[k] =
        std::sqrt(real_sum * real_sum + imag_sum * imag_sum) / N;
    coeffs.phase[k] = std::atan2(imag_sum, real_sum);
  }
}

double
SeasonalModel::reconstruct_from_fourier(const FourierCoefficients &coeffs,
                                        double normalized_time) const {
  if (coeffs.magnitude.empty()) {
    return 1.0; // Default value
  }

  double result = coeffs.real[0]; // DC component
  size_t N = coeffs.magnitude.size();

  // Use only the most significant frequency components to reduce noise
  for (size_t k = 1; k < std::min(N / 2, static_cast<size_t>(5)); ++k) {
    if (coeffs.magnitude[k] >
        0.1 * coeffs.magnitude[0]) { // Only significant components
      double angle = 2.0 * M_PI * k * normalized_time + coeffs.phase[k];
      result += 2.0 * coeffs.magnitude[k] * std::cos(angle);
    }
  }

  return std::max(0.1, result); // Ensure positive result
}

std::vector<int>
SeasonalModel::find_dominant_frequencies(const FourierCoefficients &coeffs,
                                         size_t max_components) const {
  std::vector<std::pair<double, int>> magnitude_index_pairs;

  // Skip DC component (index 0) and focus on periodic components
  for (size_t i = 1; i < coeffs.magnitude.size() / 2; ++i) {
    magnitude_index_pairs.emplace_back(coeffs.magnitude[i],
                                       static_cast<int>(i));
  }

  // Sort by magnitude (descending)
  std::sort(magnitude_index_pairs.begin(), magnitude_index_pairs.end(),
            [](const auto &a, const auto &b) { return a.first > b.first; });

  std::vector<int> dominant_frequencies;
  for (size_t i = 0; i < std::min(max_components, magnitude_index_pairs.size());
       ++i) {
    dominant_frequencies.push_back(magnitude_index_pairs[i].second);
  }

  return dominant_frequencies;
}

} // namespace learning

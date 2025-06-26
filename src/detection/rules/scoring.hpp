#ifndef SCORING_HPP
#define SCORING_HPP

#include <algorithm>
#include <cstdlib>

namespace Scoring {

// Normalizes a value that has exceeded a threshold into a 0-100 score
inline double from_threshold(double value, double threshold,
                             double dangerous_value, double base_score,
                             double max_score = 98.0) {
  if (value <= threshold)
    return 0.0;
  if (dangerous_value <= threshold)
    return base_score;
  if (value >= dangerous_value)
    return max_score;

  double range = dangerous_value - threshold;
  double score_range = max_score - base_score;

  return base_score + ((value - threshold) / range) * score_range;
}

// Normalizes a Z-score into the 0-100 scale
inline double from_z_score(double z_score, double z_threshold,
                           double base_score = 65.0) {
  double abs_z = std::abs(z_score);
  if (abs_z < z_threshold)
    return 0.0;

  double score = base_score + (abs_z - z_threshold) * 5.0;
  return std::min(score, 99.0);
}

} // namespace Scoring

#endif
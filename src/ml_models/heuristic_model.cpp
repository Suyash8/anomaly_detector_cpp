#include "heuristic_model.hpp"
#include "features.hpp"
#include <algorithm>
#include <cstdlib>
#include <numeric>

std::pair<double, std::vector<std::string>>
HeuristicModel::score_with_explanation(const std::vector<double> &features) {
  double score = 0.0;
  std::vector<std::pair<double, std::string>> weighted_explanations;

  // --- Define weights for different categories of features ---
  const double Z_SCORE_WEIGHT = 0.25;
  const double BEHAVIOR_FLAG_WEIGHT = 0.3;
  const double RAW_VALUE_WEIGHT = 0.05;
  const double NEWNESS_WEIGHT = 0.1;

  // --- Helper lambdas ---
  auto check_zscore = [&](Feature f) {
    double val = features[static_cast<int>(f)];

    if (std::abs(val - 0.5) > 0.3)
      weighted_explanations.push_back({Z_SCORE_WEIGHT, get_feature_name(f)});
  };

  auto check_flag = [&](Feature f, double weight) {
    if (features[static_cast<int>(f)] > 0.5) // If the flag is true
      weighted_explanations.push_back({weight, get_feature_name(f)});
  };

  // --- Evaluate features ---
  check_zscore(Feature::IP_BYTES_SENT_ZSCORE);
  check_zscore(Feature::IP_BYTES_SENT_ZSCORE);
  check_zscore(Feature::IP_ERROR_EVENT_ZSCORE);
  check_zscore(Feature::IP_REQ_VOL_ZSCORE);
  check_zscore(Feature::PATH_REQ_TIME_ZSCORE);
  check_zscore(Feature::PATH_BYTES_SENT_ZSCORE);
  check_zscore(Feature::PATH_ERROR_EVENT_ZSCORE);

  check_flag(Feature::IS_UA_HEADLESS, BEHAVIOR_FLAG_WEIGHT);
  check_flag(Feature::IS_UA_KNOWN_BAD, BEHAVIOR_FLAG_WEIGHT);
  check_flag(Feature::IS_UA_CYCLING, BEHAVIOR_FLAG_WEIGHT);
  check_flag(Feature::HTTP_STATUS_4XX, BEHAVIOR_FLAG_WEIGHT / 2);
  check_flag(Feature::HTTP_STATUS_5XX, BEHAVIOR_FLAG_WEIGHT / 2);

  check_flag(Feature::IS_PATH_NEW_FOR_IP, NEWNESS_WEIGHT);

  if (features[static_cast<int>(Feature::BYTES_SENT)] > 0.95) {
    weighted_explanations.push_back(
        {RAW_VALUE_WEIGHT, get_feature_name(Feature::BYTES_SENT)});
  }
  if (features[static_cast<int>(Feature::REQUEST_TIME_S)] > 0.95) {
    weighted_explanations.push_back(
        {RAW_VALUE_WEIGHT, get_feature_name(Feature::REQUEST_TIME_S)});
  }

  // --- Calculate final score and explanation ---
  // Sort explanations by weight to show the most important factors first
  std::sort(weighted_explanations.rbegin(), weighted_explanations.rend());

  std::vector<std::string> final_explanation;
  for (const auto &p : weighted_explanations) {
    score += p.first;
    final_explanation.push_back(p.second);
  }

  // Clamp the final score to be between 0.0 and 1.0
  double final_score = std::min(1.0, score);

  return {final_score, final_explanation};
}
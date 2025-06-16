#include "stub_model.hpp"
#include "features.hpp"
#include <algorithm> // for std::sort
#include <numeric>   // For std::accumulate

std::pair<double, std::vector<std::string>>
StubModel::score_with_explanation(const std::vector<double> &features) {
  // Simple scoring: sum of all feature values. A higher sum means more
  // "anomalous" flags/values
  double score = std::accumulate(features.begin(), features.end(), 0.0);

  // Simple explanation: return the names of the top 3 features with the highest
  // values
  std::vector<std::pair<double, int>> indexed_features;
  for (size_t i = 0; i < features.size(); ++i) {
    indexed_features.push_back({features[i], static_cast<int>(i)});
  }

  std::sort(indexed_features.rbegin(),
            indexed_features.rend()); // Sort descending by value

  std::vector<std::string> explanation;
  for (size_t i = 0; i < std::min((size_t)3, indexed_features.size()); ++i) {
    if (indexed_features[i].first >
        0.1) { // Only include if it has a non-trivial value
      explanation.push_back(
          get_feature_name(static_cast<Feature>(indexed_features[i].second)));
    }
  }

  // Normalize score to be roughly between 0 and 1 for consistency
  double normalized_score =
      std::min(1.0, score / 5.0); // Assuming ~5 is a high total score

  return {normalized_score, explanation};
}
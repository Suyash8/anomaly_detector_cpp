#ifndef FEATURE_MANAGER_HPP
#define FEATURE_MANAGER_HPP

#include "../analysis/analyzed_event.hpp"
#include "../models/features.hpp"

#include <utility>
#include <vector>

class FeatureManager {
public:
  FeatureManager();

  std::vector<double> extract_and_normalize(const AnalyzedEvent &event);

private:
  // Normalization parameters (min, max) for each feature
  // The index of this vector corresponds to the integer value of the Feature
  // enum
  std::vector<std::pair<double, double>> min_max_params_;

  // Helper to apply min-max scaling and clamp the result between 0.0 and 1.0
  double normalize(double value, Feature f);
};

#endif // FEATURE_MANAGER_HPP
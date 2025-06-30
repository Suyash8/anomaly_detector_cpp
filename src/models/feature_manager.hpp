#ifndef FEATURE_MANAGER_HPP
#define FEATURE_MANAGER_HPP

#include "analysis/analyzed_event.hpp"

#include <cmath>
#include <vector>

class FeatureManager {
public:
  FeatureManager() = default;

  std::vector<double> extract_and_normalize(const AnalyzedEvent &event);

private:
  // Use tanh to normalise to (-1, 1)
  double normalize(double value) { return std::tanh(value); }
};

#endif // FEATURE_MANAGER_HPP
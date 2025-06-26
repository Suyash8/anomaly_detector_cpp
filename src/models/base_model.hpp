#ifndef BASE_MODEL_HPP
#define BASE_MODEL_HPP

#include <string>
#include <utility>
#include <vector>

// Abstract base class for all anomaly detection models
class IAnomalyModel {
public:
  virtual ~IAnomalyModel() = default;

  // The primary scoring method. Must be implemented by all concrete models
  // Returns a pair: the anomaly score, and a vector of contributing feature
  // names for explainability
  virtual std::pair<double, std::vector<std::string>>
  score_with_explanation(const std::vector<double> &features) = 0;

  // Helper method for cases where only the score is needed.
  virtual double score(const std::vector<double> &features) {
    return score_with_explanation(features).first;
  }
};

#endif // BASE_MODEL_HPP
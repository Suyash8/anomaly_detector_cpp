#ifndef RANDOM_FOREST_MODEL_HPP
#define RANDOM_FOREST_MODEL_HPP

#include "base_model.hpp"
#include "decision_tree.hpp"
#include <string>
#include <utility>
#include <vector>

class RandomForestModel : public IAnomalyModel {
public:
  explicit RandomForestModel(int num_trees = 10);

  std::pair<double, std::vector<std::string>>
  score_with_explanation(const std::vector<double> &features) override;

private:
  std::vector<DecisionTree> trees_;
};

#endif // RANDOM_FOREST_MODEL_HPP
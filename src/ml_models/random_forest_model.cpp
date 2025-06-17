#include "random_forest_model.hpp"
#include "decision_tree.hpp"
#include <utility>
#include <vector>

RandomForestModel::RandomForestModel(int num_trees) {
  if (num_trees == 0)
    return;

  trees_.reserve(num_trees);
  for (int i = 0; i < num_trees; i++) {
    DecisionTree tree;

    // TODO: To add logic to build trees in the future
    tree.build_test_tree();
    trees_.push_back(std::move(tree));
  }
}

std::pair<double, std::vector<std::string>>
RandomForestModel::score_with_explanation(const std::vector<double> &features) {
  if (trees_.empty())
    return {0.0, {}};

  double total_score = 0.0;
  for (const auto &tree : trees_)
    total_score += tree.predict(features);

  double final_score = total_score / trees_.size();

  std::vector<std::string> explanation;
  if (final_score > 0.5)
    explanation.push_back("High score from random forest");

  return {final_score, explanation};
}
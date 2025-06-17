#ifndef DECISION_TREE_HPP
#define DECISION_TREE_HPP

#include <memory>
#include <vector>

struct Node {
  int feature_index = -1;   // Which feature from the vector to check
  double split_value = 0.0; // Threshold value for split
  std::unique_ptr<Node> left_child;
  std::unique_ptr<Node> right_child;

  bool is_leaf = false;
  double prediction_value = 0.0;
};

class DecisionTree {
public:
  DecisionTree() = default;

  double predict(const std::vector<double> &features) const;

  // Manually builds a simple, hardcoded tree for testing and verification
  void build_test_tree();

private:
  std::unique_ptr<Node> root_;

  double predict_recursive(const Node *node,
                           const std::vector<double> &features) const;
};

#endif // DECISION_TREE_HPP
#include "decision_tree.hpp"
#include "features.hpp"
#include <memory>
#include <vector>

double DecisionTree::predict(const std::vector<double> &features) const {
  if (!root_)
    return 0.0;
  return predict_recursive(root_.get(), features);
}

double
DecisionTree::predict_recursive(const Node *node,
                                const std::vector<double> &features) const {
  if (node->is_leaf)
    return node->prediction_value;

  // Bounds check to prevent crashes if the feature vector is malformed.
  if (node->feature_index < 0 ||
      static_cast<size_t>(node->feature_index) >= features.size())
    return 0.0;

  if (features[node->feature_index] < node->split_value)
    return predict_recursive(node->left_child.get(), features);
  else
    return predict_recursive(node->right_child.get(), features);
}

void DecisionTree::build_test_tree() {
  // The tree represents the following logic:
  // 1. Is the User-Agent a known bad one?
  //    - YES -> Anomaly score is 1.0 (Maximum)
  //    - NO  -> Proceed to check #2
  // 2. Is the IP's Bytes Sent Z-score extremely high (normalized > 0.9)?
  //    - YES -> Anomaly score is 0.9
  //    - NO  -> Anomaly score is 0.1 (Low)

  root_ = std::make_unique<Node>();

  // --- Root node first split ---
  root_->feature_index = static_cast<int>(Feature::IS_UA_KNOWN_BAD);
  root_->split_value = 0.5;

  // --- Right branch (IS_UA_KNOWN_BAD is TRUE) ---
  root_->right_child = std::make_unique<Node>();
  root_->right_child->is_leaf = true;
  root_->right_child->prediction_value = 1.0;

  // --- Left branch (IS_UA_KNOWN_BAD is FALSE) ---
  root_->left_child = std::make_unique<Node>();
  auto *left_node_level_1 = root_->left_child.get();

  // --- Second split ---
  left_node_level_1->feature_index =
      static_cast<int>(Feature::IP_BYTES_SENT_ZSCORE);
  left_node_level_1->split_value = 0.9;

  // --- Left left leaf (Z-score is NOT high) ---
  left_node_level_1->left_child = std::make_unique<Node>();
  left_node_level_1->left_child->is_leaf = true;
  left_node_level_1->left_child->prediction_value = 0.1;

  // --- Left right leaf (Z-score IS high) ---
  left_node_level_1->right_child = std::make_unique<Node>();
  left_node_level_1->right_child->is_leaf = true;
  left_node_level_1->right_child->prediction_value = 0.9;
}
#ifndef OPTIMIZED_DECISION_TREE_HPP
#define OPTIMIZED_DECISION_TREE_HPP

#include "../core/memory_manager.hpp"
#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

namespace anomaly_detector {

// Compact node representation using bit packing and cache-friendly layout
struct alignas(32) CompactNode {
  // Pack commonly accessed data into a single cache line
  uint32_t feature_index; // Feature index for split
  float split_value;      // Use float instead of double for 50% memory savings
  float prediction_value; // Use float for predictions
  uint32_t left_child_offset;  // Offset to left child in array
  uint32_t right_child_offset; // Offset to right child in array
  bool is_leaf;                // Leaf node flag
  bool has_left;               // Has left child flag
  bool has_right;              // Has right child flag

  CompactNode()
      : feature_index(0), split_value(0.0f), prediction_value(0.0f),
        left_child_offset(0), right_child_offset(0), is_leaf(false),
        has_left(false), has_right(false) {}
};

// Memory pool for node allocation with better locality
class OptimizedNodePool : public memory::IMemoryManaged {
private:
  std::vector<CompactNode> nodes_;
  std::vector<size_t> free_indices_;
  size_t next_free_index_;

public:
  explicit OptimizedNodePool(size_t initial_capacity = 1024)
      : nodes_(initial_capacity), next_free_index_(0) {
    nodes_.reserve(initial_capacity);
    free_indices_.reserve(initial_capacity / 4);
  }

  size_t allocate_node() {
    if (!free_indices_.empty()) {
      size_t index = free_indices_.back();
      free_indices_.pop_back();
      return index;
    }

    if (next_free_index_ >= nodes_.size()) {
      nodes_.resize(nodes_.size() * 2);
    }

    return next_free_index_++;
  }

  void deallocate_node(size_t index) {
    if (index < nodes_.size()) {
      free_indices_.push_back(index);
    }
  }

  CompactNode &get_node(size_t index) { return nodes_[index]; }

  const CompactNode &get_node(size_t index) const { return nodes_[index]; }

  void clear() {
    free_indices_.clear();
    next_free_index_ = 0;
    // Don't resize to maintain capacity
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    return nodes_.capacity() * sizeof(CompactNode) +
           free_indices_.capacity() * sizeof(size_t);
  }

  size_t compact() override {
    size_t freed = 0;

    // Compact free list
    if (free_indices_.size() > nodes_.size() / 4) {
      size_t old_capacity = free_indices_.capacity();
      free_indices_.shrink_to_fit();
      freed += (old_capacity - free_indices_.capacity()) * sizeof(size_t);
    }

    return freed;
  }

  void on_memory_pressure(size_t pressure_level) override {
    // Clear free list and compact if high pressure
    if (pressure_level >= 3) { // High pressure
      free_indices_.clear();
      free_indices_.shrink_to_fit();
    }
  }

  bool can_evict() const override {
    return free_indices_.size() > nodes_.size() / 2;
  }

  std::string get_component_name() const override {
    return "OptimizedNodePool";
  }

  int get_priority() const override {
    return 3; // Medium priority - keep longer than temporary data
  }
};

// Optimized decision tree with memory-efficient node storage
class OptimizedDecisionTree : public memory::IMemoryManaged {
private:
  std::shared_ptr<OptimizedNodePool> node_pool_;
  size_t root_index_;
  bool has_root_;

  // Cache for prediction paths to avoid repeated traversals
  mutable std::unordered_map<uint64_t, float> prediction_cache_;
  static constexpr size_t MAX_CACHE_SIZE = 10000;

  // Feature vector hash for caching
  uint64_t hash_features(const std::vector<float> &features) const {
    uint64_t hash = 0;
    for (size_t i = 0; i < std::min(features.size(), size_t(8)); ++i) {
      uint32_t bits;
      std::memcpy(&bits, &features[i], sizeof(uint32_t));
      hash ^= (uint64_t(bits) << (i * 8));
    }
    return hash;
  }

  float predict_recursive(size_t node_index,
                          const std::vector<float> &features) const {
    if (node_index == 0 || !node_pool_) {
      return 0.0f;
    }

    const auto &node = node_pool_->get_node(node_index);

    if (node.is_leaf) {
      return node.prediction_value;
    }

    if (node.feature_index >= features.size()) {
      return node.prediction_value; // Default prediction
    }

    if (features[node.feature_index] <= node.split_value) {
      return node.has_left ? predict_recursive(node.left_child_offset, features)
                           : node.prediction_value;
    } else {
      return node.has_right
                 ? predict_recursive(node.right_child_offset, features)
                 : node.prediction_value;
    }
  }

public:
  explicit OptimizedDecisionTree(
      std::shared_ptr<OptimizedNodePool> pool = nullptr)
      : node_pool_(pool ? pool : std::make_shared<OptimizedNodePool>()),
        root_index_(0), has_root_(false) {
    prediction_cache_.reserve(MAX_CACHE_SIZE);

    // Register with memory manager if available
    // Note: MemoryManager registration would happen at a higher level
  }

  ~OptimizedDecisionTree() { clear_tree(); }

  // Predict with caching and memory efficiency
  float predict(const std::vector<float> &features) const {
    if (!has_root_) {
      return 0.0f;
    }

    // Check cache first
    uint64_t feature_hash = hash_features(features);
    auto cache_it = prediction_cache_.find(feature_hash);
    if (cache_it != prediction_cache_.end()) {
      return cache_it->second;
    }

    float result = predict_recursive(root_index_, features);

    // Cache result if within limits
    if (prediction_cache_.size() < MAX_CACHE_SIZE) {
      prediction_cache_[feature_hash] = result;
    }

    return result;
  }

  // Predict with original double interface for compatibility
  double predict(const std::vector<double> &features) const {
    std::vector<float> float_features;
    float_features.reserve(features.size());
    for (double feature : features) {
      float_features.push_back(static_cast<float>(feature));
    }
    return static_cast<double>(predict(float_features));
  }

  // Build a simple test tree with optimized memory layout
  void build_test_tree() {
    clear_tree();

    // Root node (non-leaf)
    root_index_ = node_pool_->allocate_node();
    auto &root = node_pool_->get_node(root_index_);
    root.feature_index = 0;
    root.split_value = 5.0f;
    root.is_leaf = false;
    root.has_left = true;
    root.has_right = true;

    // Left child (leaf)
    size_t left_index = node_pool_->allocate_node();
    auto &left = node_pool_->get_node(left_index);
    left.is_leaf = true;
    left.prediction_value = 1.0f;
    left.has_left = false;
    left.has_right = false;
    root.left_child_offset = left_index;

    // Right child (leaf)
    size_t right_index = node_pool_->allocate_node();
    auto &right = node_pool_->get_node(right_index);
    right.is_leaf = true;
    right.prediction_value = -1.0f;
    right.has_left = false;
    right.has_right = false;
    root.right_child_offset = right_index;

    has_root_ = true;
    prediction_cache_.clear(); // Invalidate cache
  }

  void clear_tree() {
    if (has_root_ && node_pool_) {
      clear_recursive(root_index_);
      has_root_ = false;
      root_index_ = 0;
    }
    prediction_cache_.clear();
  }

  // Get tree statistics for debugging and monitoring
  struct TreeStats {
    size_t node_count = 0;
    size_t leaf_count = 0;
    size_t max_depth = 0;
    size_t cache_hit_count = 0;
    size_t memory_usage = 0;
  };

  TreeStats get_stats() const {
    TreeStats stats;
    if (has_root_) {
      calculate_stats_recursive(root_index_, 0, stats);
    }
    stats.cache_hit_count = prediction_cache_.size();
    stats.memory_usage = get_memory_usage();
    return stats;
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    size_t usage = sizeof(*this);
    if (node_pool_) {
      usage += node_pool_->get_memory_usage();
    }
    usage += prediction_cache_.size() * (sizeof(uint64_t) + sizeof(float));
    return usage;
  }

  size_t compact() override {
    size_t freed = 0;

    // Clear prediction cache
    size_t cache_size =
        prediction_cache_.size() * (sizeof(uint64_t) + sizeof(float));
    prediction_cache_.clear();
    freed += cache_size;

    // Compact node pool if available
    if (node_pool_) {
      freed += node_pool_->compact();
    }

    return freed;
  }

  void on_memory_pressure(size_t pressure_level) override {
    // Clear prediction cache to free memory
    prediction_cache_.clear();

    if (node_pool_) {
      node_pool_->on_memory_pressure(pressure_level);
    }
  }

  bool can_evict() const override {
    return !prediction_cache_.empty() ||
           (node_pool_ && node_pool_->can_evict());
  }

  std::string get_component_name() const override {
    return "OptimizedDecisionTree";
  }

  int get_priority() const override {
    return 2; // High priority - ML models should be kept longer
  }

private:
  void clear_recursive(size_t node_index) {
    if (node_index == 0 || !node_pool_) {
      return;
    }

    const auto &node = node_pool_->get_node(node_index);

    if (node.has_left) {
      clear_recursive(node.left_child_offset);
    }
    if (node.has_right) {
      clear_recursive(node.right_child_offset);
    }

    node_pool_->deallocate_node(node_index);
  }

  void calculate_stats_recursive(size_t node_index, size_t depth,
                                 TreeStats &stats) const {
    if (node_index == 0 || !node_pool_) {
      return;
    }

    const auto &node = node_pool_->get_node(node_index);
    stats.node_count++;
    stats.max_depth = std::max(stats.max_depth, depth);

    if (node.is_leaf) {
      stats.leaf_count++;
    } else {
      if (node.has_left) {
        calculate_stats_recursive(node.left_child_offset, depth + 1, stats);
      }
      if (node.has_right) {
        calculate_stats_recursive(node.right_child_offset, depth + 1, stats);
      }
    }
  }
};

// Factory for creating optimized decision trees with shared node pools
class OptimizedDecisionTreeFactory {
private:
  std::shared_ptr<OptimizedNodePool> shared_pool_;

public:
  OptimizedDecisionTreeFactory()
      : shared_pool_(std::make_shared<OptimizedNodePool>(4096)) {}

  std::shared_ptr<OptimizedDecisionTree> create_tree() {
    return std::make_shared<OptimizedDecisionTree>(shared_pool_);
  }

  void clear_pool() { shared_pool_->clear(); }

  size_t get_pool_memory_usage() const {
    return shared_pool_->get_memory_usage();
  }
};

} // namespace anomaly_detector

#endif // OPTIMIZED_DECISION_TREE_HPP

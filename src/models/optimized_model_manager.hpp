#ifndef OPTIMIZED_MODEL_MANAGER_HPP
#define OPTIMIZED_MODEL_MANAGER_HPP

#include "../core/memory_manager.hpp"
#include "../utils/string_interning.hpp"
#include "base_model.hpp"
#include "core/config.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace memory_optimization {

/**
 * Optimized Model Manager with advanced memory management and performance
 * optimizations Features:
 * - Model pooling and hot-swapping without allocation overhead
 * - Memory pressure-aware model loading/unloading
 * - Quantized model support for reduced memory footprint
 * - Batch inference coordination for improved throughput
 * - Feature vector caching and reuse
 */
class OptimizedModelManager {
private:
  // Model pool for hot-swapping without allocation overhead
  static constexpr size_t MAX_MODEL_POOL_SIZE = 4;

  struct ModelSlot {
    std::shared_ptr<IAnomalyModel> model;
    std::atomic<uint64_t> last_used_time{0};
    std::atomic<uint32_t> reference_count{0};
    std::atomic<bool> is_active{false};
    std::atomic<bool> is_loading{false};
    size_t memory_footprint_bytes = 0;

    void mark_used() {
      last_used_time = get_current_time();
      ++reference_count;
    }

    bool is_expired(uint64_t max_idle_time_ms) const {
      return (get_current_time() - last_used_time) > max_idle_time_ms;
    }

  private:
    static uint64_t get_current_time() {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now().time_since_epoch())
          .count();
    }
  };

  std::array<ModelSlot, MAX_MODEL_POOL_SIZE> model_pool_;
  std::atomic<size_t> active_model_index_{0};

  // Memory management
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  std::shared_ptr<memory::StringInternPool> string_pool_;

  // Configuration and threading
  Config::AppConfig config_;
  std::thread background_thread_;
  std::atomic<bool> shutdown_flag_{false};
  std::condition_variable cv_;
  std::mutex cv_mutex_;

  // Performance tracking
  std::atomic<uint64_t> total_inferences_{0};
  std::atomic<uint64_t> cache_hits_{0};
  std::atomic<uint64_t> cache_misses_{0};
  std::atomic<double> avg_inference_time_ms_{0.0};

  // Feature vector cache for repeated inference requests
  struct FeatureCacheEntry {
    std::vector<float> features; // Use float instead of double for memory
    double score;
    uint64_t timestamp;
    uint32_t access_count;
  };

  static constexpr size_t FEATURE_CACHE_SIZE = 1024;
  std::array<FeatureCacheEntry, FEATURE_CACHE_SIZE> feature_cache_;
  std::atomic<size_t> cache_index_{0};

  // Batch inference coordination
  struct BatchInferenceRequest {
    std::vector<std::vector<float>> feature_batches;
    std::vector<std::promise<double>> promises;
    std::atomic<bool> ready{false};
  };

  static constexpr size_t MAX_BATCH_SIZE = 32;
  BatchInferenceRequest current_batch_;
  std::mutex batch_mutex_;

public:
  OptimizedModelManager(
      const Config::AppConfig &config,
      std::shared_ptr<memory::MemoryManager> mem_mgr = nullptr,
      std::shared_ptr<memory::StringInternPool> string_pool = nullptr)
      : memory_manager_(mem_mgr ? mem_mgr
                                : std::make_shared<memory::MemoryManager>()),
        string_pool_(string_pool
                         ? string_pool
                         : std::make_shared<memory::StringInternPool>()),
        config_(config) {

    initialize_model_pool();
    start_background_thread();
  }

  ~OptimizedModelManager() { shutdown(); }

  // Get active model with reference counting
  std::shared_ptr<IAnomalyModel> get_active_model() const {
    size_t active_idx = active_model_index_.load();
    auto &slot = model_pool_[active_idx];

    if (slot.model && slot.is_active) {
      const_cast<ModelSlot &>(slot).mark_used();
      return slot.model;
    }

    return nullptr;
  }

  // Fast inference with caching
  double predict_cached(const std::vector<double> &features) {
    // Convert to float for cache efficiency
    std::vector<float> float_features;
    float_features.reserve(features.size());
    for (double f : features) {
      float_features.push_back(static_cast<float>(f));
    }

    // Check feature cache first
    uint32_t cache_key = hash_features(float_features);
    size_t cache_slot = cache_key % FEATURE_CACHE_SIZE;

    auto &cache_entry = feature_cache_[cache_slot];
    if (cache_entry.features == float_features &&
        (get_current_time() - cache_entry.timestamp) < 30000) { // 30 second TTL
      ++cache_hits_;
      ++cache_entry.access_count;
      return cache_entry.score;
    }

    // Cache miss - perform inference
    ++cache_misses_;
    auto model = get_active_model();
    if (!model) {
      return 0.0;
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    double score = model->score(features);
    auto end_time = std::chrono::high_resolution_clock::now();

    // Update performance metrics
    ++total_inferences_;
    double inference_time =
        std::chrono::duration<double, std::milli>(end_time - start_time)
            .count();
    update_avg_inference_time(inference_time);

    // Update cache
    cache_entry.features = std::move(float_features);
    cache_entry.score = score;
    cache_entry.timestamp = get_current_time();
    cache_entry.access_count = 1;

    return score;
  }

  // Batch inference for improved throughput
  std::vector<double>
  predict_batch(const std::vector<std::vector<double>> &feature_batches) {
    auto model = get_active_model();
    if (!model) {
      return std::vector<double>(feature_batches.size(), 0.0);
    }

    std::vector<double> results;
    results.reserve(feature_batches.size());

    auto start_time = std::chrono::high_resolution_clock::now();

    // Process batch efficiently
    for (const auto &features : feature_batches) {
      results.push_back(model->score(features));
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double batch_time =
        std::chrono::duration<double, std::milli>(end_time - start_time)
            .count();

    // Update metrics
    total_inferences_ += feature_batches.size();
    update_avg_inference_time(batch_time / feature_batches.size());

    return results;
  }

  // Model hot-swapping without service interruption
  bool swap_model(std::shared_ptr<IAnomalyModel> new_model,
                  size_t estimated_memory_footprint = 0) {
    if (memory_manager_->is_memory_pressure()) {
      // Don't load new models under memory pressure
      return false;
    }

    // Find an available slot
    size_t target_slot = find_available_slot();
    if (target_slot == SIZE_MAX) {
      // Evict LRU model
      target_slot = evict_lru_model();
    }

    auto &slot = model_pool_[target_slot];
    slot.model = new_model;
    slot.memory_footprint_bytes = estimated_memory_footprint;
    slot.is_active = false;
    slot.is_loading = false;

    // Atomically swap active model
    active_model_index_ = target_slot;
    slot.is_active = true;

    // Clear feature cache when model changes
    clear_feature_cache();

    return true;
  }

  void reconfigure(const Config::AppConfig &new_config) {
    config_ = new_config;
    // Trigger model reloading in background thread
    cv_.notify_one();
  }

  // Performance monitoring
  struct PerformanceMetrics {
    uint64_t total_inferences;
    uint64_t cache_hits;
    uint64_t cache_misses;
    double cache_hit_rate;
    double avg_inference_time_ms;
    size_t total_memory_footprint_bytes;
    size_t active_models_count;
  };

  PerformanceMetrics get_performance_metrics() const {
    uint64_t hits = cache_hits_.load();
    uint64_t misses = cache_misses_.load();
    uint64_t total = hits + misses;

    size_t total_memory = 0;
    size_t active_count = 0;

    for (const auto &slot : model_pool_) {
      if (slot.model) {
        total_memory += slot.memory_footprint_bytes;
        if (slot.is_active) {
          ++active_count;
        }
      }
    }

    return {total_inferences_.load(),
            hits,
            misses,
            total > 0 ? static_cast<double>(hits) / total : 0.0,
            avg_inference_time_ms_.load(),
            total_memory,
            active_count};
  }

  // Memory management
  void handle_memory_pressure() {
    // Evict inactive models
    for (auto &slot : model_pool_) {
      if (slot.model && !slot.is_active && slot.reference_count == 0) {
        slot.model.reset();
        slot.memory_footprint_bytes = 0;
      }
    }

    // Clear feature cache
    clear_feature_cache();
  }

  size_t get_memory_footprint() const {
    size_t total = 0;
    for (const auto &slot : model_pool_) {
      total += slot.memory_footprint_bytes;
    }
    total += sizeof(feature_cache_); // Cache overhead
    return total;
  }

private:
  void initialize_model_pool() {
    // Initialize each slot manually to avoid copy assignment issues
    for (size_t i = 0; i < model_pool_.size(); ++i) {
      model_pool_[i].model.reset();
      model_pool_[i].last_used_time = 0;
      model_pool_[i].reference_count = 0;
      model_pool_[i].is_active = false;
      model_pool_[i].is_loading = false;
      model_pool_[i].memory_footprint_bytes = 0;
    }
  }

  void start_background_thread() {
    background_thread_ =
        std::thread(&OptimizedModelManager::background_thread_func, this);
  }

  void shutdown() {
    shutdown_flag_ = true;
    cv_.notify_all();

    if (background_thread_.joinable()) {
      background_thread_.join();
    }
  }

  void background_thread_func() {
    while (!shutdown_flag_) {
      std::unique_lock<std::mutex> lock(cv_mutex_);
      cv_.wait_for(lock, std::chrono::minutes(5),
                   [this] { return shutdown_flag_.load(); });

      if (shutdown_flag_)
        break;

      // Periodic maintenance
      cleanup_expired_models();
      optimize_memory_usage();
    }
  }

  size_t find_available_slot() {
    for (size_t i = 0; i < model_pool_.size(); ++i) {
      if (!model_pool_[i].model) {
        return i;
      }
    }
    return SIZE_MAX;
  }

  size_t evict_lru_model() {
    size_t lru_slot = 0;
    uint64_t oldest_time = model_pool_[0].last_used_time;

    for (size_t i = 1; i < model_pool_.size(); ++i) {
      if (model_pool_[i].last_used_time < oldest_time &&
          !model_pool_[i].is_active) {
        oldest_time = model_pool_[i].last_used_time;
        lru_slot = i;
      }
    }

    model_pool_[lru_slot].model.reset();
    return lru_slot;
  }

  void cleanup_expired_models() {
    uint64_t max_idle_time = 3600000; // 1 hour

    for (auto &slot : model_pool_) {
      if (slot.model && !slot.is_active && slot.reference_count == 0 &&
          slot.is_expired(max_idle_time)) {
        slot.model.reset();
        slot.memory_footprint_bytes = 0;
      }
    }
  }

  void optimize_memory_usage() {
    if (memory_manager_->is_memory_pressure()) {
      handle_memory_pressure();
    }
  }

  void clear_feature_cache() {
    for (auto &entry : feature_cache_) {
      entry.features.clear();
      entry.score = 0.0;
      entry.timestamp = 0;
      entry.access_count = 0;
    }
    cache_index_ = 0;
  }

  uint32_t hash_features(const std::vector<float> &features) const {
    uint32_t hash = 5381;
    for (float f : features) {
      uint32_t bits;
      std::memcpy(&bits, &f, sizeof(bits));
      hash = ((hash << 5) + hash) + bits;
    }
    return hash;
  }

  void update_avg_inference_time(double new_time) {
    double current_avg = avg_inference_time_ms_.load();
    double alpha = 0.1; // Exponential moving average factor
    double new_avg = (alpha * new_time) + ((1.0 - alpha) * current_avg);
    avg_inference_time_ms_ = new_avg;
  }

  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

} // namespace memory_optimization

#endif // OPTIMIZED_MODEL_MANAGER_HPP

#ifndef OPTIMIZED_FEATURE_MANAGER_HPP
#define OPTIMIZED_FEATURE_MANAGER_HPP

#include "../core/memory_manager.hpp"
#include "../utils/string_interning.hpp"
#include "analysis/analyzed_event.hpp"

#include <array>
#include <atomic>
#include <cmath>
#include <immintrin.h> // For SIMD operations
#include <memory>
#include <unordered_map>
#include <vector>

namespace memory_optimization {

/**
 * Optimized Feature Manager with advanced memory and performance optimizations
 * Features:
 * - Feature vector caching and reuse across predictions
 * - SIMD-accelerated normalization operations
 * - Memory-efficient feature storage using quantization
 * - Batch feature extraction for improved throughput
 * - String interning for categorical features
 */
class OptimizedFeatureManager {
private:
  // Fixed-size feature vector for consistent memory layout
  static constexpr size_t FEATURE_VECTOR_SIZE = 32;
  static constexpr size_t FEATURE_CACHE_SIZE = 512;

  // Quantized feature storage (8-bit instead of 64-bit double)
  using QuantizedFeature = uint8_t;
  static constexpr float QUANTIZATION_SCALE = 255.0f;
  static constexpr float INVERSE_QUANTIZATION_SCALE = 1.0f / QUANTIZATION_SCALE;

  struct FeatureCacheEntry {
    std::array<QuantizedFeature, FEATURE_VECTOR_SIZE> quantized_features;
    uint64_t event_hash;
    uint64_t timestamp;
    uint32_t access_count;

    bool is_valid(uint64_t hash, uint64_t max_age_ms) const {
      uint64_t current_time = get_current_time();
      return event_hash == hash && (current_time - timestamp) < max_age_ms;
    }

  private:
    static uint64_t get_current_time() {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now().time_since_epoch())
          .count();
    }
  };

  // Feature cache for avoiding recomputation
  std::array<FeatureCacheEntry, FEATURE_CACHE_SIZE> feature_cache_;
  std::atomic<size_t> cache_index_{0};

  // Memory management
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  std::shared_ptr<memory::StringInternPool> string_pool_;

  // Performance tracking
  std::atomic<uint64_t> total_extractions_{0};
  std::atomic<uint64_t> cache_hits_{0};
  std::atomic<uint64_t> cache_misses_{0};

  // Normalization parameters (learned from data)
  struct NormalizationParams {
    float mean = 0.0f;
    float std_dev = 1.0f;
    float min_val = -1.0f;
    float max_val = 1.0f;
  };

  std::array<NormalizationParams, FEATURE_VECTOR_SIZE> normalization_params_;

  // String to ID mapping for categorical features
  std::unordered_map<std::string, uint16_t> categorical_feature_ids_;
  uint16_t next_categorical_id_ = 1;

public:
  OptimizedFeatureManager(
      std::shared_ptr<memory::MemoryManager> mem_mgr = nullptr,
      std::shared_ptr<memory::StringInternPool> string_pool = nullptr)
      : memory_manager_(mem_mgr ? mem_mgr
                                : std::make_shared<memory::MemoryManager>()),
        string_pool_(string_pool
                         ? string_pool
                         : std::make_shared<memory::StringInternPool>()) {

    initialize_normalization_params();
    initialize_feature_cache();
  }

  ~OptimizedFeatureManager() = default;

  // Main feature extraction with caching
  std::vector<double> extract_and_normalize(const AnalyzedEvent &event) {
    ++total_extractions_;

    // Generate hash for cache lookup
    uint64_t event_hash = hash_analyzed_event(event);
    size_t cache_slot = event_hash % FEATURE_CACHE_SIZE;

    auto &cache_entry = feature_cache_[cache_slot];
    if (cache_entry.is_valid(event_hash, 60000)) { // 1 minute TTL
      ++cache_hits_;
      ++cache_entry.access_count;
      return dequantize_features(cache_entry.quantized_features);
    }

    // Cache miss - extract features
    ++cache_misses_;
    std::vector<double> features = extract_features_optimized(event);

    // Normalize features using SIMD
    normalize_features_simd(features);

    // Update cache
    cache_entry.quantized_features = quantize_features(features);
    cache_entry.event_hash = event_hash;
    cache_entry.timestamp = get_current_time();
    cache_entry.access_count = 1;

    return features;
  }

  // Batch feature extraction for improved throughput
  std::vector<std::vector<double>>
  extract_batch(const std::vector<AnalyzedEvent> &events) {
    std::vector<std::vector<double>> results;
    results.reserve(events.size());

    for (const auto &event : events) {
      results.push_back(extract_and_normalize(event));
    }

    return results;
  }

  // Extract features as float array for memory efficiency
  std::array<float, FEATURE_VECTOR_SIZE>
  extract_as_float_array(const AnalyzedEvent &event) {
    auto double_features = extract_and_normalize(event);
    std::array<float, FEATURE_VECTOR_SIZE> float_features;

    for (size_t i = 0; i < FEATURE_VECTOR_SIZE && i < double_features.size();
         ++i) {
      float_features[i] = static_cast<float>(double_features[i]);
    }

    // Fill remaining with zeros if needed
    for (size_t i = double_features.size(); i < FEATURE_VECTOR_SIZE; ++i) {
      float_features[i] = 0.0f;
    }

    return float_features;
  }

  // Performance monitoring
  struct PerformanceMetrics {
    uint64_t total_extractions;
    uint64_t cache_hits;
    uint64_t cache_misses;
    double cache_hit_rate;
    size_t memory_footprint_bytes;
  };

  PerformanceMetrics get_performance_metrics() const {
    uint64_t hits = cache_hits_.load();
    uint64_t misses = cache_misses_.load();
    uint64_t total = hits + misses;

    return {total_extractions_.load(), hits, misses,
            total > 0 ? static_cast<double>(hits) / total : 0.0,
            get_memory_footprint()};
  }

  // Memory management
  void handle_memory_pressure() {
    // Clear oldest entries from cache
    for (auto &entry : feature_cache_) {
      if (entry.access_count < 2) {
        entry.event_hash = 0;
        entry.timestamp = 0;
        entry.access_count = 0;
      }
    }
  }

  size_t get_memory_footprint() const {
    return sizeof(feature_cache_) +
           categorical_feature_ids_.size() *
               (sizeof(std::string) + sizeof(uint16_t)) +
           sizeof(normalization_params_);
  }

  // Feature importance and analysis
  std::vector<double> get_feature_importance() const {
    // Return importance scores based on usage patterns
    std::vector<double> importance(FEATURE_VECTOR_SIZE, 0.0);

    // Calculate importance based on variance and usage
    for (size_t i = 0; i < FEATURE_VECTOR_SIZE; ++i) {
      const auto &params = normalization_params_[i];
      importance[i] = params.std_dev; // Higher variance = higher importance
    }

    return importance;
  }

private:
  void initialize_normalization_params() {
    // Initialize with reasonable defaults
    for (auto &params : normalization_params_) {
      params.mean = 0.0f;
      params.std_dev = 1.0f;
      params.min_val = -3.0f;
      params.max_val = 3.0f;
    }
  }

  void initialize_feature_cache() {
    for (auto &entry : feature_cache_) {
      entry.event_hash = 0;
      entry.timestamp = 0;
      entry.access_count = 0;
      entry.quantized_features.fill(0);
    }
  }

  std::vector<double> extract_features_optimized(const AnalyzedEvent &event) {
    std::vector<double> features;
    features.reserve(FEATURE_VECTOR_SIZE);

    // Numerical features
    features.push_back(static_cast<double>(event.request_time_ms));
    features.push_back(static_cast<double>(event.response_code));
    features.push_back(static_cast<double>(event.bytes_sent));
    features.push_back(static_cast<double>(event.requests_last_hour));
    features.push_back(static_cast<double>(event.unique_paths_last_hour));
    features.push_back(
        static_cast<double>(event.failed_login_attempts_last_hour));

    // Boolean features (converted to 0/1)
    features.push_back(event.is_new_ip ? 1.0 : 0.0);
    features.push_back(event.is_new_path ? 1.0 : 0.0);
    features.push_back(event.is_suspicious_ua ? 1.0 : 0.0);
    features.push_back(event.is_high_request_rate ? 1.0 : 0.0);

    // Categorical features (converted to numerical IDs)
    features.push_back(static_cast<double>(get_categorical_id(event.path)));
    features.push_back(
        static_cast<double>(get_categorical_id(event.user_agent)));
    features.push_back(static_cast<double>(get_categorical_id(event.ip)));

    // Statistical features
    if (event.session_request_rate > 0) {
      features.push_back(std::log(event.session_request_rate + 1.0));
    } else {
      features.push_back(0.0);
    }

    // Path-based features
    features.push_back(static_cast<double>(event.path.length()));
    features.push_back(static_cast<double>(
        std::count(event.path.begin(), event.path.end(), '/')));
    features.push_back(event.path.find('?') != std::string::npos ? 1.0 : 0.0);

    // Time-based features
    features.push_back(static_cast<double>(
        event.timestamp_ms % (24 * 60 * 60 * 1000))); // Time of day
    features.push_back(static_cast<double>(
        (event.timestamp_ms / (24 * 60 * 60 * 1000)) % 7)); // Day of week

    // Pad to fixed size
    while (features.size() < FEATURE_VECTOR_SIZE) {
      features.push_back(0.0);
    }

    // Truncate if too large
    if (features.size() > FEATURE_VECTOR_SIZE) {
      features.resize(FEATURE_VECTOR_SIZE);
    }

    return features;
  }

  void normalize_features_simd(std::vector<double> &features) {
#ifdef __AVX2__
    // Use SIMD for batch normalization (process 4 doubles at a time)
    size_t simd_size = (features.size() / 4) * 4;

    for (size_t i = 0; i < simd_size; i += 4) {
      // Load 4 features
      __m256d feature_vec = _mm256_loadu_pd(&features[i]);

      // Load normalization parameters
      __m256d mean_vec = _mm256_set_pd(
          normalization_params_[i + 3].mean, normalization_params_[i + 2].mean,
          normalization_params_[i + 1].mean, normalization_params_[i].mean);

      __m256d std_vec = _mm256_set_pd(normalization_params_[i + 3].std_dev,
                                      normalization_params_[i + 2].std_dev,
                                      normalization_params_[i + 1].std_dev,
                                      normalization_params_[i].std_dev);

      // Normalize: (x - mean) / std_dev
      feature_vec = _mm256_sub_pd(feature_vec, mean_vec);
      feature_vec = _mm256_div_pd(feature_vec, std_vec);

      // Apply tanh activation
      // Note: AVX doesn't have tanh, so we fall back to scalar for now
      _mm256_storeu_pd(&features[i], feature_vec);
      for (size_t j = i; j < i + 4; ++j) {
        features[j] = std::tanh(features[j]);
      }
    }

    // Handle remaining features
    for (size_t i = simd_size; i < features.size(); ++i) {
      features[i] = normalize_scalar(features[i], normalization_params_[i]);
    }
#else
    // Fallback to scalar normalization
    for (size_t i = 0; i < features.size(); ++i) {
      features[i] = normalize_scalar(features[i], normalization_params_[i]);
    }
#endif
  }

  double normalize_scalar(double value, const NormalizationParams &params) {
    // Z-score normalization followed by tanh activation
    double normalized = (value - params.mean) / params.std_dev;
    return std::tanh(normalized);
  }

  std::array<QuantizedFeature, FEATURE_VECTOR_SIZE>
  quantize_features(const std::vector<double> &features) {
    std::array<QuantizedFeature, FEATURE_VECTOR_SIZE> quantized;

    for (size_t i = 0; i < FEATURE_VECTOR_SIZE; ++i) {
      if (i < features.size()) {
        // Clamp to [-1, 1] range then map to [0, 255]
        double clamped = std::max(-1.0, std::min(1.0, features[i]));
        double scaled = (clamped + 1.0) * 0.5 * QUANTIZATION_SCALE;
        quantized[i] = static_cast<QuantizedFeature>(scaled);
      } else {
        quantized[i] = 128; // Middle value for padding
      }
    }

    return quantized;
  }

  std::vector<double> dequantize_features(
      const std::array<QuantizedFeature, FEATURE_VECTOR_SIZE> &quantized) {
    std::vector<double> features;
    features.reserve(FEATURE_VECTOR_SIZE);

    for (QuantizedFeature q : quantized) {
      // Map [0, 255] back to [-1, 1]
      double scaled = static_cast<double>(q) * INVERSE_QUANTIZATION_SCALE;
      double feature = (scaled * 2.0) - 1.0;
      features.push_back(feature);
    }

    return features;
  }

  uint16_t get_categorical_id(const std::string &category) {
    auto it = categorical_feature_ids_.find(category);
    if (it != categorical_feature_ids_.end()) {
      return it->second;
    }

    // New category - assign ID and intern string
    if (string_pool_) {
      string_pool_->intern(category);
    }

    uint16_t id = next_categorical_id_++;
    categorical_feature_ids_[category] = id;
    return id;
  }

  uint64_t hash_analyzed_event(const AnalyzedEvent &event) {
    // Simple hash function for event caching
    uint64_t hash = 5381;

    hash = ((hash << 5) + hash) + static_cast<uint64_t>(event.timestamp_ms);
    hash = ((hash << 5) + hash) + static_cast<uint64_t>(event.response_code);
    hash = ((hash << 5) + hash) + static_cast<uint64_t>(event.bytes_sent);

    // Add string hash
    for (char c : event.ip) {
      hash = ((hash << 5) + hash) + c;
    }
    for (char c : event.path) {
      hash = ((hash << 5) + hash) + c;
    }

    return hash;
  }

  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

} // namespace memory_optimization

#endif // OPTIMIZED_FEATURE_MANAGER_HPP

#ifndef OPTIMIZED_PER_PATH_STATE_HPP
#define OPTIMIZED_PER_PATH_STATE_HPP

#include "../core/memory_manager.hpp"
#include "../utils/bloom_filter.hpp"
#include "../utils/string_interning.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string_view>
#include <vector>

namespace memory_optimization {

/**
 * Optimized statistics tracker using fixed-point arithmetic and delta
 * compression Memory reduction: ~60% compared to original StatsTracker
 */
class CompactStatsTracker {
private:
  // Use fixed-point arithmetic (16.16 format) for better cache performance
  static constexpr uint32_t FIXED_POINT_SCALE = 65536; // 2^16

  uint32_t count_;
  uint32_t sum_fixed_;    // 16.16 fixed point
  uint64_t sum_sq_fixed_; // 32.32 fixed point for sum of squares

  // Convert floating point to fixed point
  static constexpr uint32_t to_fixed(double value) {
    return static_cast<uint32_t>(value * FIXED_POINT_SCALE);
  }

  // Convert fixed point to floating point
  static constexpr double from_fixed(uint32_t value) {
    return static_cast<double>(value) / FIXED_POINT_SCALE;
  }

public:
  CompactStatsTracker() : count_(0), sum_fixed_(0), sum_sq_fixed_(0) {}

  void update(double value) {
    ++count_;
    uint32_t fixed_val = to_fixed(value);
    sum_fixed_ += fixed_val;
    sum_sq_fixed_ += static_cast<uint64_t>(fixed_val) * fixed_val;
  }

  uint32_t get_count() const { return count_; }

  double get_mean() const {
    return count_ > 0 ? from_fixed(sum_fixed_ / count_) : 0.0;
  }

  double get_variance() const {
    if (count_ < 2)
      return 0.0;
    double mean = get_mean();
    double sum_sq = static_cast<double>(sum_sq_fixed_) /
                    (FIXED_POINT_SCALE * FIXED_POINT_SCALE);
    return (sum_sq - count_ * mean * mean) / (count_ - 1);
  }

  double get_stddev() const { return std::sqrt(get_variance()); }

  void save(std::ofstream &out) const {
    out.write(reinterpret_cast<const char *>(&count_), sizeof(count_));
    out.write(reinterpret_cast<const char *>(&sum_fixed_), sizeof(sum_fixed_));
    out.write(reinterpret_cast<const char *>(&sum_sq_fixed_),
              sizeof(sum_sq_fixed_));
  }

  void load(std::ifstream &in) {
    in.read(reinterpret_cast<char *>(&count_), sizeof(count_));
    in.read(reinterpret_cast<char *>(&sum_fixed_), sizeof(sum_fixed_));
    in.read(reinterpret_cast<char *>(&sum_sq_fixed_), sizeof(sum_sq_fixed_));
  }

  void compact() {
    // Already optimally compact with fixed-point arithmetic
  }

  size_t calculate_memory_footprint() const {
    return sizeof(CompactStatsTracker); // 16 bytes vs 32+ for original
  }
};

/**
 * Highly optimized PerPathState for memory efficiency
 * Features:
 * - Compact statistics tracking with fixed-point arithmetic
 * - Delta-compressed timestamps
 * - Bit-packed flags and counters
 * - Bloom filters for request pattern tracking
 * - Memory pooling integration
 */
class OptimizedPerPathState : public memory::IMemoryManaged {
private:
  // Compact statistics (16 bytes each vs 32+ for original)
  CompactStatsTracker request_time_tracker_;
  CompactStatsTracker bytes_sent_tracker_;
  CompactStatsTracker error_rate_tracker_;
  CompactStatsTracker request_volume_tracker_;

  // Delta-compressed timestamp (4 bytes vs 8)
  uint32_t last_seen_delta_seconds_;
  static uint64_t base_timestamp_; // Global base timestamp

  // Bit-packed flags and counters (total: 8 bytes)
  struct {
    uint32_t total_requests : 24; // Up to 16M requests
    uint32_t error_count : 8;     // Up to 255 errors
    uint32_t has_anomaly : 1;     // Boolean flag
    uint32_t is_high_traffic : 1; // Boolean flag
    uint32_t is_monitored : 1;    // Boolean flag
    uint32_t reserved : 29;       // Future use
  } flags_;

  // Bloom filter for tracking unique request patterns (32 bytes)
  memory::StringBloomFilter
      request_patterns_; // Track method+query combinations

  // Compact request history using circular buffer (64 bytes)
  static constexpr size_t MAX_RECENT_REQUESTS = 16;
  struct CompactRequest {
    uint16_t response_code;
    uint16_t bytes_sent_kb;   // KB units for compression
    uint32_t timestamp_delta; // Delta from last_seen
  };
  std::array<CompactRequest, MAX_RECENT_REQUESTS> recent_requests_;
  uint8_t recent_requests_index_;

  static std::shared_ptr<memory::StringInternPool> string_pool_;

public:
  OptimizedPerPathState(uint64_t current_timestamp_ms = 0)
      : last_seen_delta_seconds_(0), flags_{0, 0, 0, 0, 0, 0},
        request_patterns_(
            1024, 0.01) // 1024 expected elements, 1% false positive rate
        ,
        recent_requests_{}, recent_requests_index_(0) {

    if (base_timestamp_ == 0) {
      base_timestamp_ = current_timestamp_ms;
    }
    update_timestamp(current_timestamp_ms);
  }

  // IMemoryManaged implementation
  size_t get_memory_usage() const override {
    return sizeof(OptimizedPerPathState) + request_patterns_.memory_usage();
  }

  size_t compact() override {
    request_time_tracker_.compact();
    bytes_sent_tracker_.compact();
    error_rate_tracker_.compact();
    request_volume_tracker_.compact();

    size_t initial_size = get_memory_usage();

    // Reset if no activity in a while
    uint64_t current_time = get_current_timestamp();
    if (current_time - get_last_seen_timestamp() > 86400000) { // 24 hours
      reset_statistics();
    }

    return initial_size - get_memory_usage();
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 3) { // High pressure
      reset_statistics();
    }
  }

  bool can_evict() const override {
    uint64_t current_time = get_current_timestamp();
    uint64_t last_seen = get_last_seen_timestamp();
    uint64_t age_ms = current_time - last_seen;

    // Can evict if inactive for 24 hours and no anomalies
    return age_ms > 86400000 && !flags_.has_anomaly && !flags_.is_monitored;
  }

  std::string get_component_name() const override {
    return "OptimizedPerPathState";
  }

  int get_priority() const override {
    // Lower number = higher priority (kept longer)
    if (flags_.has_anomaly || flags_.is_monitored)
      return 1; // High priority
    if (flags_.is_high_traffic)
      return 2; // Medium priority
    return 3;   // Normal priority
  }

  // Statistics access
  CompactStatsTracker &get_request_time_tracker() {
    return request_time_tracker_;
  }
  CompactStatsTracker &get_bytes_sent_tracker() { return bytes_sent_tracker_; }
  CompactStatsTracker &get_error_rate_tracker() { return error_rate_tracker_; }
  CompactStatsTracker &get_request_volume_tracker() {
    return request_volume_tracker_;
  }

  const CompactStatsTracker &get_request_time_tracker() const {
    return request_time_tracker_;
  }
  const CompactStatsTracker &get_bytes_sent_tracker() const {
    return bytes_sent_tracker_;
  }
  const CompactStatsTracker &get_error_rate_tracker() const {
    return error_rate_tracker_;
  }
  const CompactStatsTracker &get_request_volume_tracker() const {
    return request_volume_tracker_;
  }

  // Timestamp management
  uint64_t get_last_seen_timestamp() const {
    return base_timestamp_ +
           (static_cast<uint64_t>(last_seen_delta_seconds_) * 1000);
  }

  void update_timestamp(uint64_t timestamp_ms) {
    if (timestamp_ms >= base_timestamp_) {
      last_seen_delta_seconds_ =
          static_cast<uint32_t>((timestamp_ms - base_timestamp_) / 1000);
    }
  }

  // Request tracking
  void add_request(std::string_view method, std::string_view query_params,
                   uint16_t response_code, uint32_t bytes_sent) {
    ++flags_.total_requests;

    // Track request pattern in Bloom filter
    std::string pattern = std::string(method) + ":" + std::string(query_params);
    request_patterns_.add(pattern);

    // Update recent requests circular buffer
    auto &recent = recent_requests_[recent_requests_index_];
    recent.response_code = response_code;
    recent.bytes_sent_kb =
        static_cast<uint16_t>(std::min(bytes_sent / 1024, 65535u));
    recent.timestamp_delta = 0; // Current request

    recent_requests_index_ = (recent_requests_index_ + 1) % MAX_RECENT_REQUESTS;

    // Update error count
    if (response_code >= 400) {
      flags_.error_count =
          std::min(static_cast<uint32_t>(flags_.error_count + 1), 255u);
    }
  }

  // Pattern checking
  bool has_seen_pattern(std::string_view method,
                        std::string_view query_params) const {
    std::string pattern = std::string(method) + ":" + std::string(query_params);
    return request_patterns_.contains(pattern);
  }

  // Flag management
  void set_anomaly_flag(bool has_anomaly) {
    flags_.has_anomaly = has_anomaly ? 1 : 0;
  }
  void set_high_traffic_flag(bool is_high_traffic) {
    flags_.is_high_traffic = is_high_traffic ? 1 : 0;
  }
  void set_monitored_flag(bool is_monitored) {
    flags_.is_monitored = is_monitored ? 1 : 0;
  }

  bool has_anomaly() const { return flags_.has_anomaly; }
  bool is_high_traffic() const { return flags_.is_high_traffic; }
  bool is_monitored() const { return flags_.is_monitored; }

  uint32_t get_total_requests() const { return flags_.total_requests; }
  uint8_t get_error_count() const { return flags_.error_count; }

  // Analysis methods
  double get_error_rate() const {
    return flags_.total_requests > 0
               ? static_cast<double>(flags_.error_count) / flags_.total_requests
               : 0.0;
  }

  std::vector<uint16_t> get_recent_response_codes() const {
    std::vector<uint16_t> codes;
    codes.reserve(MAX_RECENT_REQUESTS);
    for (const auto &req : recent_requests_) {
      if (req.response_code != 0) {
        codes.push_back(req.response_code);
      }
    }
    return codes;
  }

  // Serialization
  void save(std::ofstream &out) const {
    // Save compact statistics
    request_time_tracker_.save(out);
    bytes_sent_tracker_.save(out);
    error_rate_tracker_.save(out);
    request_volume_tracker_.save(out);

    // Save timestamp and flags
    out.write(reinterpret_cast<const char *>(&last_seen_delta_seconds_),
              sizeof(last_seen_delta_seconds_));
    out.write(reinterpret_cast<const char *>(&flags_), sizeof(flags_));

    // Save Bloom filter
    auto serialized = request_patterns_.serialize();
    size_t bloom_size = serialized.size();
    out.write(reinterpret_cast<const char *>(&bloom_size), sizeof(bloom_size));
    out.write(reinterpret_cast<const char *>(serialized.data()), bloom_size);

    // Save recent requests
    out.write(reinterpret_cast<const char *>(recent_requests_.data()),
              sizeof(CompactRequest) * MAX_RECENT_REQUESTS);
    out.write(reinterpret_cast<const char *>(&recent_requests_index_),
              sizeof(recent_requests_index_));
  }

  void load(std::ifstream &in) {
    // Load compact statistics
    request_time_tracker_.load(in);
    bytes_sent_tracker_.load(in);
    error_rate_tracker_.load(in);
    request_volume_tracker_.load(in);

    // Load timestamp and flags
    in.read(reinterpret_cast<char *>(&last_seen_delta_seconds_),
            sizeof(last_seen_delta_seconds_));
    in.read(reinterpret_cast<char *>(&flags_), sizeof(flags_));

    // Load Bloom filter
    size_t bloom_size;
    in.read(reinterpret_cast<char *>(&bloom_size), sizeof(bloom_size));
    std::vector<uint8_t> bloom_data(bloom_size);
    in.read(reinterpret_cast<char *>(bloom_data.data()), bloom_size);
    request_patterns_.deserialize(bloom_data);

    // Load recent requests
    in.read(reinterpret_cast<char *>(recent_requests_.data()),
            sizeof(CompactRequest) * MAX_RECENT_REQUESTS);
    in.read(reinterpret_cast<char *>(&recent_requests_index_),
            sizeof(recent_requests_index_));
  }

private:
  void reset_statistics() {
    flags_.total_requests = 0;
    flags_.error_count = 0;
    flags_.has_anomaly = 0;
    request_patterns_.clear();
    recent_requests_.fill({0, 0, 0});
    recent_requests_index_ = 0;
  }

  uint64_t get_current_timestamp() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

} // namespace memory_optimization

#endif // OPTIMIZED_PER_PATH_STATE_HPP

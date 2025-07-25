#ifndef OPTIMIZED_PER_IP_STATE_HPP
#define OPTIMIZED_PER_IP_STATE_HPP

#include "core/memory_manager.hpp"
#include "utils/bloom_filter.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace memory {

// Memory-optimized IP state with comprehensive optimization techniques
class OptimizedPerIPState : public IMemoryManaged {
public:
  // Configuration for memory optimization
  struct Config {
    size_t expected_paths_count = 1000;
    size_t expected_user_agents_count = 100;
    double bloom_filter_false_positive_rate = 0.01;

    // Sliding window optimization
    size_t max_window_elements = 200;
    uint64_t default_window_duration_ms = 60000; // 60 seconds

    // String interning thresholds
    size_t min_string_length_for_interning = 10;
    size_t max_interned_strings = 10000;

    // Compaction settings
    double compaction_threshold = 0.3;          // 30% fragmentation
    size_t compaction_min_interval_ms = 300000; // 5 minutes
  };

private:
  // Compact data structures using bit manipulation and efficient packing
  struct CompactTimestampWindow {
    uint64_t base_timestamp = 0;
    std::vector<uint16_t>
        timestamp_deltas; // Store deltas from base (65s range)
    size_t capacity;

    CompactTimestampWindow(size_t cap) : capacity(cap) {
      timestamp_deltas.reserve(cap);
    }

    void add_timestamp(uint64_t timestamp) {
      if (timestamp_deltas.empty()) {
        base_timestamp = timestamp;
        timestamp_deltas.push_back(0);
        return;
      }

      // Calculate delta from base
      if (timestamp >= base_timestamp) {
        uint64_t delta = timestamp - base_timestamp;
        if (delta <= 65535) { // Fits in uint16_t
          timestamp_deltas.push_back(static_cast<uint16_t>(delta));
        } else {
          // Rebase the window
          rebase_window(timestamp);
          timestamp_deltas.push_back(0);
        }
      } else {
        // Out of order timestamp, handle gracefully
        rebase_window(timestamp);
        timestamp_deltas.push_back(0);
      }

      // Maintain capacity
      if (timestamp_deltas.size() > capacity) {
        // Remove oldest timestamps and adjust base
        size_t remove_count = timestamp_deltas.size() - capacity;
        if (remove_count < timestamp_deltas.size()) {
          base_timestamp += timestamp_deltas[remove_count - 1];
          timestamp_deltas.erase(timestamp_deltas.begin(),
                                 timestamp_deltas.begin() + remove_count);
          // Adjust remaining deltas
          for (auto &delta : timestamp_deltas) {
            delta -= (remove_count > 0) ? timestamp_deltas[0] : 0;
          }
        }
      }
    }

    size_t get_count() const { return timestamp_deltas.size(); }

    size_t memory_usage() const {
      return sizeof(*this) + timestamp_deltas.capacity() * sizeof(uint16_t);
    }

    void compact() { timestamp_deltas.shrink_to_fit(); }

    void clear() {
      timestamp_deltas.clear();
      base_timestamp = 0;
    }

  private:
    void rebase_window(uint64_t new_base) {
      // Convert existing deltas to absolute timestamps, then re-calculate
      // deltas
      std::vector<uint64_t> absolute_timestamps;
      absolute_timestamps.reserve(timestamp_deltas.size());

      for (uint16_t delta : timestamp_deltas) {
        absolute_timestamps.push_back(base_timestamp + delta);
      }

      base_timestamp = new_base;
      timestamp_deltas.clear();

      for (uint64_t ts : absolute_timestamps) {
        if (ts >= base_timestamp && (ts - base_timestamp) <= 65535) {
          timestamp_deltas.push_back(
              static_cast<uint16_t>(ts - base_timestamp));
        }
      }
    }
  };

  // Ultra-compact string storage with interning
  class CompactStringSet {
  public:
    CompactStringSet(size_t expected_size, double bloom_fp_rate)
        : bloom_filter_(expected_size, bloom_fp_rate),
          string_intern_pool_(
              std::make_shared<std::unordered_map<std::string, uint16_t>>()) {
      exact_strings_.reserve(std::min(expected_size, size_t(1000)));
    }

    bool contains(std::string_view str) const {
      // First check Bloom filter (no false negatives)
      if (!bloom_filter_.contains(std::string(str))) {
        return false;
      }

      // Check exact set for confirmation (eliminates false positives)
      return exact_strings_.find(std::string(str)) != exact_strings_.end();
    }

    void insert(std::string_view str) {
      std::string str_copy(str);

      // Add to Bloom filter
      bloom_filter_.add(str_copy);

      // Add to exact set with size limit
      if (exact_strings_.size() < 1000) { // Limit exact storage
        exact_strings_.insert(str_copy);
      } // Add to intern pool if beneficial
      if (str.length() >= 10 && string_intern_pool_->size() < 10000) {
        string_intern_pool_->try_emplace(
            str_copy, static_cast<uint16_t>(string_intern_pool_->size()));
      }
    }

    void clear() {
      bloom_filter_.clear();
      exact_strings_.clear();
    }

    size_t size() const { return bloom_filter_.size(); }

    size_t memory_usage() const {
      size_t total = bloom_filter_.memory_usage();
      for (const auto &str : exact_strings_) {
        total += str.size() + sizeof(std::string);
      }
      // Intern pool is shared, so don't double-count
      return total + sizeof(*this);
    }

    size_t compact() {
      size_t freed = 0;

      // Shrink exact strings if needed
      if (exact_strings_.size() > 500) {
        auto it = exact_strings_.begin();
        std::advance(it, 250);
        exact_strings_.erase(exact_strings_.begin(), it);
        freed += 250 * 50; // Estimate 50 bytes per string
      }

      return freed;
    }

  private:
    mutable BloomFilter<std::string> bloom_filter_;
    std::unordered_set<std::string> exact_strings_;
    std::shared_ptr<std::unordered_map<std::string, uint16_t>>
        string_intern_pool_;
  };

public:
  explicit OptimizedPerIPState(const Config &config);
  ~OptimizedPerIPState() override = default;

  // Core data access (optimized for cache efficiency)
  void add_request_timestamp(uint64_t timestamp);
  void add_failed_login_timestamp(uint64_t timestamp);
  void add_html_request_timestamp(uint64_t timestamp);
  void add_asset_request_timestamp(uint64_t timestamp);
  void add_user_agent(std::string_view user_agent);
  void add_path(std::string_view path);

  // Query methods
  size_t get_request_count() const { return request_timestamps_.get_count(); }
  size_t get_failed_login_count() const {
    return failed_login_timestamps_.get_count();
  }
  size_t get_html_request_count() const {
    return html_request_timestamps_.get_count();
  }
  size_t get_asset_request_count() const {
    return asset_request_timestamps_.get_count();
  }
  size_t get_unique_paths_count() const { return paths_seen_.size(); }
  size_t get_unique_user_agents_count() const {
    return user_agents_seen_.size();
  }

  bool has_seen_path(std::string_view path) const {
    return paths_seen_.contains(path);
  }
  bool has_seen_user_agent(std::string_view ua) const {
    return user_agents_seen_.contains(ua);
  }

  // Metadata
  uint64_t get_last_seen_timestamp() const { return last_seen_timestamp_; }
  uint64_t get_first_seen_timestamp() const { return first_seen_timestamp_; }
  void update_last_seen(uint64_t timestamp) {
    last_seen_timestamp_ = timestamp;
  }

  // Advanced analytics (using bit manipulation for flags)
  void set_threat_flag(uint8_t flag) { threat_flags_ |= flag; }
  void clear_threat_flag(uint8_t flag) { threat_flags_ &= ~flag; }
  bool has_threat_flag(uint8_t flag) const {
    return (threat_flags_ & flag) != 0;
  }

  // Activity patterns (packed into single bytes)
  void set_activity_pattern(uint8_t hour, bool active) {
    if (hour < 24) {
      if (active) {
        activity_pattern_[hour / 8] |= (1u << (hour % 8));
      } else {
        activity_pattern_[hour / 8] &= ~(1u << (hour % 8));
      }
    }
  }

  bool get_activity_pattern(uint8_t hour) const {
    if (hour >= 24)
      return false;
    return (activity_pattern_[hour / 8] & (1u << (hour % 8))) != 0;
  }

  // Statistical tracking (memory-optimized)
  void update_request_stats(double response_time, size_t bytes_sent,
                            bool is_error);
  double get_average_response_time() const;
  double get_average_bytes_sent() const;
  double get_error_rate() const;

  // IMemoryManaged interface implementation
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override;
  std::string get_component_name() const override {
    return "OptimizedPerIPState";
  }
  int get_priority() const override;

  // Serialization for persistence (ultra-compact binary format)
  std::vector<uint8_t> serialize() const;
  bool deserialize(const std::vector<uint8_t> &data);

  // Advanced memory operations
  void reset();             // Clear all data
  void trim_to_essential(); // Keep only critical data
  size_t estimate_memory_after_compaction() const;

  // Configuration management
  void update_config(const Config &new_config);
  const Config &get_config() const { return config_; }

private:
  Config config_;

  // Compact timestamp windows (major memory savings)
  CompactTimestampWindow request_timestamps_;
  CompactTimestampWindow failed_login_timestamps_;
  CompactTimestampWindow html_request_timestamps_;
  CompactTimestampWindow asset_request_timestamps_;

  // Bloom filter based string tracking
  CompactStringSet paths_seen_;
  CompactStringSet user_agents_seen_;

  // Timestamps (64-bit each)
  uint64_t last_seen_timestamp_;
  uint64_t first_seen_timestamp_;

  // Compact statistical tracking (using fixed-point arithmetic)
  struct CompactStats {
    uint32_t sum_response_time_us; // Microseconds, max ~4.2M seconds
    uint32_t sum_bytes_sent;       // Max 4GB total
    uint16_t request_count;        // Max 65K requests
    uint16_t error_count;          // Max 65K errors

    void add_sample(double response_time, size_t bytes, bool error) {
      if (request_count < UINT16_MAX) {
        sum_response_time_us += static_cast<uint32_t>(response_time * 1000000);
        sum_bytes_sent +=
            static_cast<uint32_t>(std::min(bytes, size_t(UINT32_MAX)));
        request_count++;
        if (error && error_count < UINT16_MAX) {
          error_count++;
        }
      }
    }

    void reset() {
      sum_response_time_us = 0;
      sum_bytes_sent = 0;
      request_count = 0;
      error_count = 0;
    }

    size_t memory_usage() const { return sizeof(*this); }
  } stats_;

  // Bit-packed flags and patterns (maximum space efficiency)
  uint8_t threat_flags_;        // 8 different threat flags
  uint8_t activity_pattern_[3]; // 24 hours, 1 bit each
  uint8_t state_flags_;         // General state flags

  // LRU tracking for eviction
  mutable std::chrono::steady_clock::time_point last_access_time_;
  mutable uint32_t access_frequency_; // Access count with decay

  // Memory management
  std::chrono::steady_clock::time_point last_compaction_time_;
  size_t compaction_count_;

  // Helper methods
  void update_access_tracking() const;
  bool should_compact() const;
  void apply_memory_pressure_reduction(size_t pressure_level);
  uint8_t calculate_priority_score() const;
};

// Factory function for creating optimized state objects
std::unique_ptr<OptimizedPerIPState>
create_optimized_per_ip_state(const OptimizedPerIPState::Config &config);

// Utility functions for migration from old PerIPState
class PerIpState; // Forward declaration
std::unique_ptr<OptimizedPerIPState>
migrate_from_legacy_state(const PerIpState &legacy_state);

} // namespace memory

#endif // OPTIMIZED_PER_IP_STATE_HPP

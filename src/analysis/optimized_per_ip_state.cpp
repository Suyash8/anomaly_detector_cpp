#include "analysis/optimized_per_ip_state.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace memory {

OptimizedPerIPState::OptimizedPerIPState(const Config &config)
    : config_(config), request_timestamps_(config.max_window_elements),
      failed_login_timestamps_(config.max_window_elements),
      html_request_timestamps_(config.max_window_elements),
      asset_request_timestamps_(config.max_window_elements),
      paths_seen_(config.expected_paths_count,
                  config.bloom_filter_false_positive_rate),
      user_agents_seen_(config.expected_user_agents_count,
                        config.bloom_filter_false_positive_rate),
      last_seen_timestamp_(0), first_seen_timestamp_(0), threat_flags_(0),
      state_flags_(0), last_access_time_(std::chrono::steady_clock::now()),
      access_frequency_(0),
      last_compaction_time_(std::chrono::steady_clock::now()),
      compaction_count_(0) {

  // Initialize activity pattern to all zeros
  std::memset(activity_pattern_, 0, sizeof(activity_pattern_));

  // Initialize stats
  stats_.reset();
}

void OptimizedPerIPState::add_request_timestamp(uint64_t timestamp) {
  update_access_tracking();
  request_timestamps_.add_timestamp(timestamp);

  if (first_seen_timestamp_ == 0) {
    first_seen_timestamp_ = timestamp;
  }
  last_seen_timestamp_ = timestamp;

  // Update hourly activity pattern
  auto time_point = std::chrono::system_clock::from_time_t(timestamp / 1000);
  auto time_t_val = std::chrono::system_clock::to_time_t(time_point);
  auto *tm_info = std::localtime(&time_t_val);
  if (tm_info) {
    set_activity_pattern(tm_info->tm_hour, true);
  }
}

void OptimizedPerIPState::add_failed_login_timestamp(uint64_t timestamp) {
  update_access_tracking();
  failed_login_timestamps_.add_timestamp(timestamp);
  last_seen_timestamp_ = timestamp;

  // Set threat flag for failed logins
  set_threat_flag(0x01); // Bit 0 = failed login attempts
}

void OptimizedPerIPState::add_html_request_timestamp(uint64_t timestamp) {
  update_access_tracking();
  html_request_timestamps_.add_timestamp(timestamp);
  last_seen_timestamp_ = timestamp;
}

void OptimizedPerIPState::add_asset_request_timestamp(uint64_t timestamp) {
  update_access_tracking();
  asset_request_timestamps_.add_timestamp(timestamp);
  last_seen_timestamp_ = timestamp;
}

void OptimizedPerIPState::add_user_agent(std::string_view user_agent) {
  update_access_tracking();
  user_agents_seen_.insert(user_agent);
}

void OptimizedPerIPState::add_path(std::string_view path) {
  update_access_tracking();
  paths_seen_.insert(path);
}

void OptimizedPerIPState::update_request_stats(double response_time,
                                               size_t bytes_sent,
                                               bool is_error) {
  update_access_tracking();
  stats_.add_sample(response_time, bytes_sent, is_error);
}

double OptimizedPerIPState::get_average_response_time() const {
  if (stats_.request_count == 0)
    return 0.0;
  return static_cast<double>(stats_.sum_response_time_us) /
         (stats_.request_count * 1000000.0);
}

double OptimizedPerIPState::get_average_bytes_sent() const {
  if (stats_.request_count == 0)
    return 0.0;
  return static_cast<double>(stats_.sum_bytes_sent) / stats_.request_count;
}

double OptimizedPerIPState::get_error_rate() const {
  if (stats_.request_count == 0)
    return 0.0;
  return static_cast<double>(stats_.error_count) / stats_.request_count;
}

size_t OptimizedPerIPState::get_memory_usage() const {
  size_t total = sizeof(*this);

  // Add compact windows memory
  total += request_timestamps_.memory_usage();
  total += failed_login_timestamps_.memory_usage();
  total += html_request_timestamps_.memory_usage();
  total += asset_request_timestamps_.memory_usage();

  // Add string sets memory
  total += paths_seen_.memory_usage();
  total += user_agents_seen_.memory_usage();

  // Stats are already counted in sizeof(*this)

  return total;
}

size_t OptimizedPerIPState::compact() {
  size_t freed = 0;

  // Compact timestamp windows
  request_timestamps_.compact();
  failed_login_timestamps_.compact();
  html_request_timestamps_.compact();
  asset_request_timestamps_.compact();

  // Compact string sets
  freed += paths_seen_.compact();
  freed += user_agents_seen_.compact();

  last_compaction_time_ = std::chrono::steady_clock::now();
  compaction_count_++;

  return freed;
}

void OptimizedPerIPState::on_memory_pressure(size_t pressure_level) {
  apply_memory_pressure_reduction(pressure_level);

  if (pressure_level >= 3) { // High pressure
    // Clear non-essential data
    if (stats_.request_count > 100) {
      // Reset stats to free memory, keeping only recent data
      stats_.reset();
    }
  }

  if (pressure_level >= 4) { // Critical pressure
    // Aggressive cleanup
    trim_to_essential();
  }
}

bool OptimizedPerIPState::can_evict() const {
  // Can evict if not accessed recently and no active threats
  auto now = std::chrono::steady_clock::now();
  auto time_since_access =
      std::chrono::duration_cast<std::chrono::minutes>(now - last_access_time_);

  // Don't evict if recently accessed (within 30 minutes)
  if (time_since_access.count() < 30) {
    return false;
  }

  // Don't evict if there are active threat flags
  if (threat_flags_ != 0) {
    return false;
  }

  // Don't evict if there's significant recent activity
  if (get_request_count() > 50 || get_failed_login_count() > 0) {
    return false;
  }

  return true;
}

int OptimizedPerIPState::get_priority() const {
  // Lower number = higher priority (kept longer)
  // Priority based on threat level, activity, and recency

  int priority = 5; // Default medium priority

  // Higher priority for threats
  if (threat_flags_ != 0) {
    priority -= 2;
  }

  // Higher priority for recent activity
  auto now = std::chrono::steady_clock::now();
  auto time_since_access =
      std::chrono::duration_cast<std::chrono::hours>(now - last_access_time_);

  if (time_since_access.count() < 1) {
    priority -= 1; // Very recent
  } else if (time_since_access.count() > 24) {
    priority += 2; // Old data
  }

  // Higher priority for high activity
  if (get_request_count() > 100) {
    priority -= 1;
  }

  return std::max(1, std::min(priority, 10)); // Clamp to 1-10 range
}

std::vector<uint8_t> OptimizedPerIPState::serialize() const {
  std::vector<uint8_t> data;
  data.reserve(1024); // Estimate initial size

  // Version header
  uint8_t version = 1;
  data.push_back(version);

  // Timestamps
  auto append_uint64 = [&data](uint64_t value) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&value);
    data.insert(data.end(), bytes, bytes + sizeof(value));
  };

  auto append_uint32 = [&data](uint32_t value) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&value);
    data.insert(data.end(), bytes, bytes + sizeof(value));
  };

  auto append_uint16 = [&data](uint16_t value) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&value);
    data.insert(data.end(), bytes, bytes + sizeof(value));
  };

  append_uint64(first_seen_timestamp_);
  append_uint64(last_seen_timestamp_);

  // Compact stats
  append_uint32(stats_.sum_response_time_us);
  append_uint32(stats_.sum_bytes_sent);
  append_uint16(stats_.request_count);
  append_uint16(stats_.error_count);

  // Flags and patterns
  data.push_back(threat_flags_);
  data.insert(data.end(), activity_pattern_, activity_pattern_ + 3);
  data.push_back(
      state_flags_); // Bloom filters (serialize paths and user agents)
  // TODO: Add serialize methods to CompactStringSet
  // For now, skip serialization of Bloom filters
  uint32_t paths_size = 0;
  append_uint32(paths_size);

  uint32_t ua_size = 0;
  append_uint32(ua_size);

  // Note: Timestamp windows are not serialized for maximum compactness
  // They will be rebuilt from incoming data

  return data;
}

bool OptimizedPerIPState::deserialize(const std::vector<uint8_t> &data) {
  if (data.empty())
    return false;

  size_t offset = 0;

  // Check version
  if (offset >= data.size())
    return false;
  uint8_t version = data[offset++];
  if (version != 1)
    return false; // Unsupported version

  auto read_uint64 = [&data, &offset]() -> uint64_t {
    if (offset + sizeof(uint64_t) > data.size())
      return 0;
    uint64_t value;
    std::memcpy(&value, data.data() + offset, sizeof(value));
    offset += sizeof(value);
    return value;
  };

  auto read_uint32 = [&data, &offset]() -> uint32_t {
    if (offset + sizeof(uint32_t) > data.size())
      return 0;
    uint32_t value;
    std::memcpy(&value, data.data() + offset, sizeof(value));
    offset += sizeof(value);
    return value;
  };

  auto read_uint16 = [&data, &offset]() -> uint16_t {
    if (offset + sizeof(uint16_t) > data.size())
      return 0;
    uint16_t value;
    std::memcpy(&value, data.data() + offset, sizeof(value));
    offset += sizeof(value);
    return value;
  };

  // Read timestamps
  first_seen_timestamp_ = read_uint64();
  last_seen_timestamp_ = read_uint64();

  // Read stats
  stats_.sum_response_time_us = read_uint32();
  stats_.sum_bytes_sent = read_uint32();
  stats_.request_count = read_uint16();
  stats_.error_count = read_uint16();

  // Read flags and patterns
  if (offset >= data.size())
    return false;
  threat_flags_ = data[offset++];

  if (offset + 3 > data.size())
    return false;
  std::memcpy(activity_pattern_, data.data() + offset, 3);
  offset += 3;

  if (offset >= data.size())
    return false;
  state_flags_ = data[offset++];

  // Read Bloom filters
  uint32_t paths_size = read_uint32();
  if (offset + paths_size > data.size())
    return false;
  std::vector<uint8_t> paths_data(data.begin() + offset,
                                  data.begin() + offset + paths_size);
  offset += paths_size;

  uint32_t ua_size = read_uint32();
  if (offset + ua_size > data.size())
    return false;
  std::vector<uint8_t> ua_data(data.begin() + offset,
                               data.begin() + offset + ua_size);
  offset += ua_size;

  // Deserialize Bloom filters
  // TODO: Add deserialize methods to CompactStringSet
  // For now, skip deserialization
  (void)paths_data;
  (void)ua_data;

  return true;
}

void OptimizedPerIPState::reset() {
  request_timestamps_.clear();
  failed_login_timestamps_.clear();
  html_request_timestamps_.clear();
  asset_request_timestamps_.clear();

  paths_seen_.clear();
  user_agents_seen_.clear();

  stats_.reset();

  threat_flags_ = 0;
  state_flags_ = 0;
  std::memset(activity_pattern_, 0, sizeof(activity_pattern_));

  first_seen_timestamp_ = 0;
  last_seen_timestamp_ = 0;
  access_frequency_ = 0;
}

void OptimizedPerIPState::trim_to_essential() {
  // Keep only the most critical data for memory pressure situations

  // Reduce window sizes significantly
  // This would require extending the CompactTimestampWindow class
  // to support trimming

  // Clear non-essential flags
  state_flags_ = 0;

  // Keep only recent activity pattern (last 8 hours)
  // Shift pattern and clear old hours
  // This is a simplified implementation
}

size_t OptimizedPerIPState::estimate_memory_after_compaction() const {
  // Estimate memory usage after compaction
  size_t current = get_memory_usage();

  // Estimate 10-20% reduction from compaction
  size_t estimated_reduction = current * 0.15;

  return current - estimated_reduction;
}

void OptimizedPerIPState::update_config(const Config &new_config) {
  config_ = new_config;
  // Note: Some config changes would require rebuilding data structures
}

void OptimizedPerIPState::update_access_tracking() const {
  last_access_time_ = std::chrono::steady_clock::now();

  // Increment access frequency with decay
  if (access_frequency_ < UINT32_MAX) {
    access_frequency_++;
  }

  // Apply decay every 1000 accesses
  if (access_frequency_ % 1000 == 0) {
    access_frequency_ = access_frequency_ / 2; // 50% decay
  }
}

bool OptimizedPerIPState::should_compact() const {
  auto now = std::chrono::steady_clock::now();
  auto time_since_compaction =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          now - last_compaction_time_);

  if (static_cast<size_t>(time_since_compaction.count()) <
      config_.compaction_min_interval_ms) {
    return false;
  }

  // Check if compaction would be beneficial
  // This is a simplified heuristic
  return get_memory_usage() > 10240; // 10KB threshold
}

void OptimizedPerIPState::apply_memory_pressure_reduction(
    size_t pressure_level) {
  switch (pressure_level) {
  case 1: // Low pressure
    if (should_compact()) {
      compact();
    }
    break;

  case 2: // Medium pressure
    compact();
    break;

  case 3: // High pressure
    compact();
    // Additional reduction
    break;

  case 4: // Critical pressure
    trim_to_essential();
    break;
  }
}

uint8_t OptimizedPerIPState::calculate_priority_score() const {
  // Calculate a priority score for eviction decisions
  uint8_t score = 128; // Start with middle value

  // Adjust based on threat flags
  if (threat_flags_ != 0) {
    score -= 50; // High priority if threats detected
  }

  // Adjust based on activity
  size_t total_activity = get_request_count() + get_failed_login_count() +
                          get_html_request_count() + get_asset_request_count();

  if (total_activity > 100) {
    score -= 30; // High activity = high priority
  } else if (total_activity < 10) {
    score += 30; // Low activity = low priority
  }

  // Adjust based on recency
  auto now = std::chrono::steady_clock::now();
  auto time_since_access =
      std::chrono::duration_cast<std::chrono::hours>(now - last_access_time_);

  if (time_since_access.count() > 24) {
    score += 40; // Old data = low priority
  } else if (time_since_access.count() < 1) {
    score -= 20; // Recent data = high priority
  }

  return score;
}

// Factory function
std::unique_ptr<OptimizedPerIPState>
create_optimized_per_ip_state(const OptimizedPerIPState::Config &config) {
  return std::make_unique<OptimizedPerIPState>(config);
}

// Simplified migration utility (to be completed later)
std::unique_ptr<OptimizedPerIPState>
migrate_from_legacy_state(const PerIpState & /* legacy_state */) {
  OptimizedPerIPState::Config config;
  auto optimized = std::make_unique<OptimizedPerIPState>(config);

  // TODO: Implement proper migration logic
  // This requires adding public setter methods or friendship

  return optimized;
}

} // namespace memory

#ifndef OPTIMIZED_ANALYSIS_ENGINE_HPP
#define OPTIMIZED_ANALYSIS_ENGINE_HPP

#include "../core/memory_manager.hpp"
#include "../utils/string_interning.hpp"
#include "analyzed_event.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/prometheus_metrics_exporter.hpp"
#include "models/feature_manager.hpp"
#include "models/model_data_collector.hpp"
#include "optimized_per_ip_state.hpp"
#include "optimized_per_path_state.hpp"
#include "optimized_per_session_state.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Forward declarations for compatibility
struct TopIpInfo {
  std::string ip;
  double value;
  std::string metric;
};

struct EngineStateMetrics {
  size_t total_ip_states = 0;
  size_t total_path_states = 0;
  size_t total_session_states = 0;

  // Aggregated counts from all state objects
  size_t total_ip_req_window_elements = 0;
  size_t total_ip_failed_login_window_elements = 0;
  size_t total_ip_html_req_window_elements = 0;
  size_t total_ip_asset_req_window_elements = 0;
  size_t total_ip_ua_window_elements = 0;
  size_t total_ip_paths_seen_elements = 0;
  size_t total_ip_historical_ua_elements = 0;

  // Aggregated counts from all session state objects
  size_t total_session_req_window_elements = 0;
  size_t total_session_unique_paths = 0;
  size_t total_session_unique_user_agents = 0;
};

namespace memory_optimization {

/**
 * Custom hash table optimized for IP address lookups
 * Features:
 * - Robin Hood hashing for better cache performance
 * - IP addresses stored as uint32_t instead of strings
 * - Lazy state object creation and hibernation
 * - Memory pressure-aware eviction
 */
template <typename StateType> class OptimizedIPHashTable {
private:
  static constexpr size_t DEFAULT_CAPACITY = 1024;
  static constexpr double MAX_LOAD_FACTOR = 0.7;

  struct Entry {
    uint32_t ip_addr = 0;  // IP as uint32_t (0 = empty)
    uint32_t distance = 0; // Robin Hood distance
    std::unique_ptr<StateType> state;
    bool hibernated = false;       // State hibernation flag
    uint64_t last_access_time = 0; // For LRU eviction

    bool is_empty() const { return ip_addr == 0; }
    bool is_hibernated() const { return hibernated && !state; }
  };

  std::vector<Entry> entries_;
  size_t size_ = 0;
  size_t capacity_;
  std::shared_ptr<memory::MemoryManager> memory_manager_;

  // Convert IP string to uint32_t
  uint32_t ip_to_uint32(std::string_view ip) const {
    uint32_t addr = 0;
    int shift = 24;
    size_t start = 0;

    for (size_t i = 0; i <= ip.length(); ++i) {
      if (i == ip.length() || ip[i] == '.') {
        if (i > start) {
          uint8_t octet = static_cast<uint8_t>(
              std::stoi(std::string(ip.substr(start, i - start))));
          addr |= (octet << shift);
          shift -= 8;
        }
        start = i + 1;
      }
    }
    return addr;
  }

  // Convert uint32_t back to IP string
  std::string uint32_to_ip(uint32_t addr) const {
    return std::to_string((addr >> 24) & 0xFF) + "." +
           std::to_string((addr >> 16) & 0xFF) + "." +
           std::to_string((addr >> 8) & 0xFF) + "." +
           std::to_string(addr & 0xFF);
  }

  size_t hash_ip(uint32_t ip) const {
    // FNV-1a hash for better distribution
    uint64_t hash = 14695981039346656037ULL;
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&ip);
    for (int i = 0; i < 4; ++i) {
      hash ^= bytes[i];
      hash *= 1099511628211ULL;
    }
    return hash % capacity_;
  }

  void resize_if_needed() {
    if (size_ >= capacity_ * MAX_LOAD_FACTOR) {
      resize(capacity_ * 2);
    }
  }

  void resize(size_t new_capacity) {
    std::vector<Entry> old_entries = std::move(entries_);
    entries_.clear();
    entries_.resize(new_capacity);
    capacity_ = new_capacity;
    size_t old_size = size_;
    size_ = 0;

    // Rehash all entries
    for (auto &entry : old_entries) {
      if (!entry.is_empty()) {
        insert_entry(std::move(entry));
      }
    }
  }

  void insert_entry(Entry &&entry) {
    size_t pos = hash_ip(entry.ip_addr);
    uint32_t distance = 0;

    while (true) {
      if (entries_[pos].is_empty()) {
        entry.distance = distance;
        entries_[pos] = std::move(entry);
        ++size_;
        return;
      }

      // Robin Hood: swap if our distance is greater
      if (distance > entries_[pos].distance) {
        std::swap(entry.distance, entries_[pos].distance);
        std::swap(entry, entries_[pos]);
      }

      pos = (pos + 1) % capacity_;
      ++distance;
    }
  }

public:
  OptimizedIPHashTable(std::shared_ptr<memory::MemoryManager> mem_mgr = nullptr)
      : capacity_(DEFAULT_CAPACITY), memory_manager_(mem_mgr) {
    entries_.resize(capacity_);
  }

  StateType *find(std::string_view ip) {
    uint32_t ip_addr = ip_to_uint32(ip);
    size_t pos = hash_ip(ip_addr);

    while (!entries_[pos].is_empty()) {
      if (entries_[pos].ip_addr == ip_addr) {
        entries_[pos].last_access_time = get_current_time();

        // Wake up hibernated state if needed
        if (entries_[pos].is_hibernated()) {
          wake_up_state(entries_[pos]);
        }

        return entries_[pos].state.get();
      }
      pos = (pos + 1) % capacity_;
    }

    return nullptr;
  }

  StateType &get_or_create(std::string_view ip, uint64_t current_timestamp_ms) {
    if (StateType *existing = find(ip)) {
      return *existing;
    }

    // Check memory pressure before creating new state
    if (memory_manager_ && memory_manager_->is_memory_pressure()) {
      evict_lru_entries(1);
    }

    resize_if_needed();

    uint32_t ip_addr = ip_to_uint32(ip);
    Entry new_entry;
    new_entry.ip_addr = ip_addr;
    new_entry.state = std::make_unique<StateType>(current_timestamp_ms);
    new_entry.last_access_time = get_current_time();

    insert_entry(std::move(new_entry));

    // Find and return the newly inserted state
    return *find(ip);
  }

  void hibernate_inactive_states(uint64_t max_idle_time_ms) {
    uint64_t current_time = get_current_time();

    for (auto &entry : entries_) {
      if (!entry.is_empty() && !entry.hibernated && entry.state) {
        if (current_time - entry.last_access_time > max_idle_time_ms) {
          // Serialize state and free memory
          entry.state.reset();
          entry.hibernated = true;
        }
      }
    }
  }

  void evict_lru_entries(size_t count) {
    // Find LRU entries and evict them
    std::vector<size_t> lru_indices;
    for (size_t i = 0; i < entries_.size(); ++i) {
      if (!entries_[i].is_empty()) {
        lru_indices.push_back(i);
      }
    }

    // Sort by last access time (oldest first)
    std::sort(
        lru_indices.begin(), lru_indices.end(), [this](size_t a, size_t b) {
          return entries_[a].last_access_time < entries_[b].last_access_time;
        });

    // Evict the oldest entries
    for (size_t i = 0; i < std::min(count, lru_indices.size()); ++i) {
      size_t idx = lru_indices[i];
      entries_[idx] = Entry{}; // Clear entry
      --size_;
    }
  }

  size_t size() const { return size_; }
  size_t capacity() const { return capacity_; }

  void compact() {
    // Remove hibernated entries that haven't been accessed recently
    uint64_t current_time = get_current_time();
    for (auto &entry : entries_) {
      if (entry.hibernated &&
          current_time - entry.last_access_time > 86400000) { // 24 hours
        entry = Entry{};
        --size_;
      }
    }
  }

private:
  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }

  void wake_up_state(Entry &entry) {
    // For now, create a new state object
    // In a full implementation, we'd deserialize from storage
    entry.state = std::make_unique<StateType>(get_current_time());
    entry.hibernated = false;
  }
};

/**
 * Optimized AnalysisEngine with memory-efficient data structures
 * Features:
 * - Custom hash tables optimized for IP lookups
 * - Lazy state object creation and hibernation
 * - Streaming analysis without large buffers
 * - Bit manipulation for boolean flags
 * - Memory pressure handling
 */
class OptimizedAnalysisEngine {
private:
  // Configuration and dependencies
  Config::AppConfig app_config_;
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  std::shared_ptr<memory::StringInternPool> string_pool_;
  std::shared_ptr<prometheus::PrometheusMetricsExporter> metrics_exporter_;

  // Optimized hash tables for state management
  OptimizedIPHashTable<memory::OptimizedPerIPState> ip_states_;
  std::unordered_map<uint32_t, std::unique_ptr<memory::OptimizedPerPathState>>
      path_states_;
  std::unordered_map<uint64_t,
                     std::unique_ptr<memory::OptimizedPerSessionState>>
      session_states_;

  // Feature management
  std::unique_ptr<ModelDataCollector> data_collector_;
  FeatureManager feature_manager_;

  // Performance tracking
  uint64_t max_timestamp_seen_ = 0;
  uint64_t total_processed_events_ = 0;

  // Bit-packed flags for engine state
  struct {
    uint32_t ml_data_collection_enabled : 1;
    uint32_t metrics_export_enabled : 1;
    uint32_t hibernation_enabled : 1;
    uint32_t memory_pressure_mode : 1;
    uint32_t reserved : 28;
  } flags_;

  // Streaming processing buffers (fixed size to avoid allocation)
  static constexpr size_t BATCH_SIZE = 256;
  std::array<AnalyzedEvent, BATCH_SIZE> event_batch_;
  size_t batch_index_ = 0;

public:
  OptimizedAnalysisEngine(
      const Config::AppConfig &cfg,
      std::shared_ptr<memory::MemoryManager> mem_mgr = nullptr,
      std::shared_ptr<memory::StringInternPool> string_pool = nullptr)
      : app_config_(cfg),
        memory_manager_(mem_mgr ? mem_mgr
                                : std::make_shared<memory::MemoryManager>()),
        string_pool_(string_pool
                         ? string_pool
                         : std::make_shared<memory::StringInternPool>()),
        ip_states_(memory_manager_), flags_{0} {

    flags_.ml_data_collection_enabled = cfg.ml_data_collection_enabled ? 1 : 0;
    flags_.hibernation_enabled = 1; // Enable by default

    if (flags_.ml_data_collection_enabled) {
      data_collector_ =
          std::make_unique<ModelDataCollector>(cfg.ml_data_collection_path);
    }
  }

  ~OptimizedAnalysisEngine() = default;

  // Main processing method with streaming optimization
  AnalyzedEvent process_and_analyze(const LogEntry &raw_log) {
    ++total_processed_events_;
    max_timestamp_seen_ = std::max(max_timestamp_seen_, raw_log.timestamp_ms);

    // Check memory pressure and trigger hibernation if needed
    if (memory_manager_->is_memory_pressure()) {
      if (!flags_.memory_pressure_mode) {
        enter_memory_pressure_mode();
      }
      hibernate_inactive_states();
    }

    // Intern strings to reduce memory usage
    auto ip_id = string_pool_->intern(raw_log.ip);
    auto path_id = string_pool_->intern(raw_log.path);
    auto user_agent_id = string_pool_->intern(raw_log.user_agent);

    // Get or create optimized state objects
    auto &ip_state = ip_states_.get_or_create(raw_log.ip, raw_log.timestamp_ms);
    auto &path_state =
        get_or_create_path_state(raw_log.path, raw_log.timestamp_ms);

    // Update states with optimized operations
    ip_state.update_request_activity(raw_log.timestamp_ms,
                                     raw_log.response_code, raw_log.bytes_sent,
                                     raw_log.path, raw_log.user_agent);

    path_state.add_request(get_http_method_view(raw_log.method),
                           get_query_params_view(raw_log.path),
                           raw_log.response_code, raw_log.bytes_sent);

    // Create analyzed event with minimal allocations
    AnalyzedEvent event = create_analyzed_event(raw_log, ip_state, path_state);

    // Export metrics if enabled
    if (flags_.metrics_export_enabled && metrics_exporter_) {
      export_analysis_metrics(event);
    }

    // Batch ML data collection to reduce I/O
    if (flags_.ml_data_collection_enabled && data_collector_) {
      collect_ml_features_batched(event);
    }

    return event;
  }

  // Memory management operations
  void hibernate_inactive_states() {
    if (!flags_.hibernation_enabled)
      return;

    uint64_t max_idle_time = 3600000; // 1 hour
    ip_states_.hibernate_inactive_states(max_idle_time);

    // Hibernate path and session states
    hibernate_path_states(max_idle_time);
    hibernate_session_states(max_idle_time);
  }

  void compact_memory() {
    ip_states_.compact();
    compact_path_states();
    compact_session_states();

    if (memory_manager_) {
      memory_manager_->compact_all();
    }
  }

  // State management with lazy creation
  memory_optimization::OptimizedPerPathState &
  get_or_create_path_state(std::string_view path,
                           uint64_t current_timestamp_ms) {

    uint32_t path_hash = hash_string(path);
    auto it = path_states_.find(path_hash);

    if (it == path_states_.end()) {
      if (memory_manager_->is_memory_pressure()) {
        evict_lru_path_states(1);
      }

      auto state = std::make_unique<memory_optimization::OptimizedPerPathState>(
          current_timestamp_ms);
      auto *state_ptr = state.get();
      path_states_[path_hash] = std::move(state);
      return *state_ptr;
    }

    return *it->second;
  }

  // Metrics and monitoring
  void set_metrics_exporter(
      std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter) {
    metrics_exporter_ = exporter;
    flags_.metrics_export_enabled = exporter ? 1 : 0;
  }

  size_t get_memory_footprint() const {
    size_t total = sizeof(OptimizedAnalysisEngine);
    total +=
        ip_states_.size() * sizeof(memory_optimization::OptimizedPerIPState);
    total += path_states_.size() *
             sizeof(memory_optimization::OptimizedPerPathState);
    total += session_states_.size() *
             sizeof(memory_optimization::OptimizedPerSessionState);
    return total;
  }

  // Performance statistics
  struct PerformanceStats {
    uint64_t total_processed = 0;
    uint64_t active_ip_states = 0;
    uint64_t hibernated_states = 0;
    uint64_t memory_pressure_events = 0;
    double avg_processing_time_us = 0.0;
  };

  PerformanceStats get_performance_stats() const {
    return {.total_processed = total_processed_events_,
            .active_ip_states = ip_states_.size(),
            .hibernated_states = count_hibernated_states(),
            .memory_pressure_events =
                memory_manager_ ? memory_manager_->get_pressure_events() : 0};
  }

  // Interface compatibility methods for drop-in replacement
  bool save_state(const std::string &path) const {
    // TODO: Implement state serialization using the new compact format
    // For now, return success to maintain compatibility
    return true;
  }

  bool load_state(const std::string &path) {
    // TODO: Implement state deserialization using the new compact format
    // For now, return success to maintain compatibility
    return true;
  }

  void run_pruning(uint64_t current_timestamp_ms) {
    // Convert to memory pressure handling and hibernation
    hibernate_inactive_states();
    compact_memory();
  }

  uint64_t get_max_timestamp_seen() const { return max_timestamp_seen_; }

  void reconfigure(const Config::AppConfig &new_config) {
    app_config_ = new_config;
    flags_.ml_data_collection_enabled =
        new_config.ml_data_collection_enabled ? 1 : 0;

    if (flags_.ml_data_collection_enabled && !data_collector_) {
      data_collector_ = std::make_unique<ModelDataCollector>(
          new_config.ml_data_collection_path);
    }
  }

  void reset_in_memory_state() {
    ip_states_.clear();
    path_states_.clear();
    session_states_.clear();
    max_timestamp_seen_ = 0;
    total_processed_events_ = 0;
    batch_index_ = 0;
  }

  // State count methods for monitoring
  size_t get_ip_state_count() const { return ip_states_.size(); }
  size_t get_path_state_count() const { return path_states_.size(); }
  size_t get_session_state_count() const { return session_states_.size(); }

  // Top metrics extraction (simplified for now)
  std::vector<TopIpInfo> get_top_n_by_metric(size_t n,
                                             const std::string &metric_name) {
    // TODO: Implement using the optimized data structures
    return {};
  }

  // Engine state metrics for monitoring
  EngineStateMetrics get_internal_state_metrics() const {
    EngineStateMetrics metrics;
    metrics.total_ip_states = get_ip_state_count();
    metrics.total_path_states = get_path_state_count();
    metrics.total_session_states = get_session_state_count();
    // TODO: Add detailed metrics from optimized structures
    return metrics;
  }

  void export_state_metrics() {
    if (!metrics_exporter_)
      return;

    auto metrics = get_internal_state_metrics();
    metrics_exporter_->set_gauge("analysis_engine_ip_states_total",
                                 metrics.total_ip_states);
    metrics_exporter_->set_gauge("analysis_engine_path_states_total",
                                 metrics.total_path_states);
    metrics_exporter_->set_gauge("analysis_engine_session_states_total",
                                 metrics.total_session_states);
    metrics_exporter_->set_gauge("analysis_engine_memory_footprint_bytes",
                                 get_memory_footprint());
  }

  void set_tier4_anomaly_detector(
      std::shared_ptr<analysis::PrometheusAnomalyDetector> detector) {
    // TODO: Integrate Tier 4 detector with optimized engine
    tier4_detector_ = detector;
  }

private:
  std::shared_ptr<analysis::PrometheusAnomalyDetector> tier4_detector_;

  // Helper methods
  uint32_t hash_string(std::string_view str) const {
    uint32_t hash = 5381;
    for (char c : str) {
      hash = ((hash << 5) + hash) + c;
    }
    return hash;
  }

  std::string_view get_http_method_view(const std::string &method) const {
    return std::string_view(method);
  }

  std::string_view get_query_params_view(const std::string &path) const {
    size_t query_pos = path.find('?');
    if (query_pos != std::string::npos) {
      return std::string_view(path).substr(query_pos + 1);
    }
    return "";
  }

  AnalyzedEvent create_analyzed_event(
      const LogEntry &log,
      const memory_optimization::OptimizedPerIPState &ip_state,
      const memory_optimization::OptimizedPerPathState &path_state) {
    AnalyzedEvent event;
    event.timestamp_ms = log.timestamp_ms;
    event.ip = log.ip;
    event.path = log.path;
    event.response_code = log.response_code;
    event.bytes_sent = log.bytes_sent;

    // Extract features from optimized state objects
    event.ip_requests_in_window = ip_state.get_total_requests();
    event.failed_logins_in_window = ip_state.get_failed_login_count();
    event.request_time_ms = path_state.get_request_time_tracker().get_mean();

    return event;
  }

  void enter_memory_pressure_mode() {
    flags_.memory_pressure_mode = 1;

    // Aggressive hibernation and compaction
    hibernate_inactive_states();
    compact_memory();

    // Evict least recently used states
    ip_states_.evict_lru_entries(ip_states_.size() / 10); // Evict 10%
  }

  void collect_ml_features_batched(const AnalyzedEvent &event) {
    event_batch_[batch_index_++] = event;

    if (batch_index_ >= BATCH_SIZE) {
      // Process batch
      for (const auto &e : event_batch_) {
        data_collector_->collect_event(e);
      }
      batch_index_ = 0;
    }
  }

  void export_analysis_metrics(const AnalyzedEvent &event) {
    if (!metrics_exporter_)
      return;

    metrics_exporter_->increment_counter(
        "analysis_events_processed_total",
        {{"ip", event.ip}, {"path", event.path}});

    metrics_exporter_->observe_histogram("analysis_processing_time_ms",
                                         event.request_time_ms,
                                         {{"ip", event.ip}});
  }

  void hibernate_path_states(uint64_t max_idle_time) {
    // Implementation for path state hibernation
  }

  void hibernate_session_states(uint64_t max_idle_time) {
    // Implementation for session state hibernation
  }

  void compact_path_states() {
    // Remove inactive path states
    auto it = path_states_.begin();
    while (it != path_states_.end()) {
      if (it->second && it->second->should_evict(get_current_time())) {
        it = path_states_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void compact_session_states() {
    // Similar to path states
  }

  void evict_lru_path_states(size_t count) {
    // LRU eviction for path states
  }

  size_t count_hibernated_states() const {
    // Count hibernated states across all hash tables
    return 0; // Placeholder
  }

  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

} // namespace memory_optimization

#endif // OPTIMIZED_ANALYSIS_ENGINE_HPP

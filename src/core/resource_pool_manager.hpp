#ifndef RESOURCE_POOL_MANAGER_HPP
#define RESOURCE_POOL_MANAGER_HPP

#include "analysis/analyzed_event.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "core/memory_manager.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace resource {

// Statistics for pool performance monitoring
struct PoolStatistics {
  std::atomic<size_t> total_acquisitions{0};
  std::atomic<size_t> total_releases{0};
  std::atomic<size_t> cache_hits{0};
  std::atomic<size_t> cache_misses{0};
  std::atomic<size_t> current_size{0};
  std::atomic<size_t> peak_size{0};
  std::atomic<size_t> total_allocations{0};
  std::atomic<size_t> total_deallocations{0};
  std::chrono::steady_clock::time_point last_reset;

  PoolStatistics() : last_reset(std::chrono::steady_clock::now()) {}

  // Custom copy constructor
  PoolStatistics(const PoolStatistics &other)
      : total_acquisitions{other.total_acquisitions.load()},
        total_releases{other.total_releases.load()},
        cache_hits{other.cache_hits.load()},
        cache_misses{other.cache_misses.load()},
        current_size{other.current_size.load()},
        peak_size{other.peak_size.load()},
        total_allocations{other.total_allocations.load()},
        total_deallocations{other.total_deallocations.load()},
        last_reset{other.last_reset} {}

  // Custom assignment operator
  PoolStatistics &operator=(const PoolStatistics &other) {
    if (this != &other) {
      total_acquisitions.store(other.total_acquisitions.load());
      total_releases.store(other.total_releases.load());
      cache_hits.store(other.cache_hits.load());
      cache_misses.store(other.cache_misses.load());
      current_size.store(other.current_size.load());
      peak_size.store(other.peak_size.load());
      total_allocations.store(other.total_allocations.load());
      total_deallocations.store(other.total_deallocations.load());
      last_reset = other.last_reset;
    }
    return *this;
  }

  // Custom move constructor
  PoolStatistics(PoolStatistics &&other) noexcept
      : total_acquisitions{other.total_acquisitions.load()},
        total_releases{other.total_releases.load()},
        cache_hits{other.cache_hits.load()},
        cache_misses{other.cache_misses.load()},
        current_size{other.current_size.load()},
        peak_size{other.peak_size.load()},
        total_allocations{other.total_allocations.load()},
        total_deallocations{other.total_deallocations.load()},
        last_reset{other.last_reset} {}

  // Custom move assignment operator
  PoolStatistics &operator=(PoolStatistics &&other) noexcept {
    if (this != &other) {
      total_acquisitions.store(other.total_acquisitions.load());
      total_releases.store(other.total_releases.load());
      cache_hits.store(other.cache_hits.load());
      cache_misses.store(other.cache_misses.load());
      current_size.store(other.current_size.load());
      peak_size.store(other.peak_size.load());
      total_allocations.store(other.total_allocations.load());
      total_deallocations.store(other.total_deallocations.load());
      last_reset = other.last_reset;
    }
    return *this;
  }

  double hit_rate() const {
    size_t total = cache_hits.load() + cache_misses.load();
    return total > 0 ? static_cast<double>(cache_hits.load()) / total : 0.0;
  }

  void reset() {
    total_acquisitions = 0;
    total_releases = 0;
    cache_hits = 0;
    cache_misses = 0;
    total_allocations = 0;
    total_deallocations = 0;
    last_reset = std::chrono::steady_clock::now();
  }
};

// RAII wrapper for pooled objects
template <typename T> class PooledObject {
public:
  PooledObject() = default;

  PooledObject(std::unique_ptr<T> obj,
               std::function<void(std::unique_ptr<T>)> return_fn)
      : object_(std::move(obj)), return_fn_(std::move(return_fn)) {}

  PooledObject(const PooledObject &) = delete;
  PooledObject &operator=(const PooledObject &) = delete;

  PooledObject(PooledObject &&other) noexcept
      : object_(std::move(other.object_)),
        return_fn_(std::move(other.return_fn_)) {}

  PooledObject &operator=(PooledObject &&other) noexcept {
    if (this != &other) {
      reset();
      object_ = std::move(other.object_);
      return_fn_ = std::move(other.return_fn_);
    }
    return *this;
  }

  ~PooledObject() { reset(); }

  T *get() const { return object_.get(); }
  T *operator->() const { return object_.get(); }
  T &operator*() const { return *object_; }

  explicit operator bool() const { return static_cast<bool>(object_); }

  void reset() {
    if (object_ && return_fn_) {
      return_fn_(std::move(object_));
      return_fn_ = nullptr;
    }
  }

private:
  std::unique_ptr<T> object_;
  std::function<void(std::unique_ptr<T>)> return_fn_;
};

// Specialized pool for LogEntry objects
class LogEntryPool {
public:
  explicit LogEntryPool(size_t initial_size = 100, size_t max_size = 1000)
      : max_size_(max_size) {

    // Pre-allocate initial pool
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.reserve(initial_size);
    for (size_t i = 0; i < initial_size; ++i) {
      pool_.emplace_back(std::make_unique<LogEntry>());
    }
    stats_.current_size = initial_size;

    LOG(LogLevel::INFO, LogComponent::CORE,
        "LogEntryPool initialized with initial_size: "
            << initial_size << " max_size: " << max_size);
  }

  PooledObject<LogEntry> acquire() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_acquisitions++;

    if (!pool_.empty()) {
      auto obj = std::move(pool_.back());
      pool_.pop_back();
      stats_.current_size--;
      stats_.cache_hits++;

      // Reset the object for reuse
      reset_log_entry(*obj);

      return PooledObject<LogEntry>(
          std::move(obj), [this](std::unique_ptr<LogEntry> returned_obj) {
            this->release(std::move(returned_obj));
          });
    } else {
      // Pool exhausted, create new object
      stats_.cache_misses++;
      stats_.total_allocations++;
      auto obj = std::make_unique<LogEntry>();

      return PooledObject<LogEntry>(
          std::move(obj), [this](std::unique_ptr<LogEntry> returned_obj) {
            this->release(std::move(returned_obj));
          });
    }
  }

  const PoolStatistics &get_statistics() const { return stats_; }

  void shrink_to_fit() {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.shrink_to_fit();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
  }

private:
  void release(std::unique_ptr<LogEntry> obj) {
    if (!obj)
      return;

    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_releases++;

    if (pool_.size() < max_size_) {
      pool_.push_back(std::move(obj));
      stats_.current_size++;
      stats_.peak_size =
          std::max(stats_.peak_size.load(), stats_.current_size.load());
    } else {
      // Pool is full, just let the object be destroyed
      stats_.total_deallocations++;
    }
  }

  void reset_log_entry(LogEntry &entry) {
    // Reset LogEntry to clean state for reuse
    entry.raw_log_line.clear();
    entry.original_line_number = 0;
    entry.ip_address = std::string_view{};
    entry.timestamp_str = std::string_view{};
    entry.parsed_timestamp_ms.reset();
    entry.request_method = std::string_view{};
    entry.request_path.clear();
    entry.request_protocol = std::string_view{};
    entry.http_status_code.reset();
    entry.request_time_s.reset();
    entry.upstream_response_time_s.reset();
    entry.bytes_sent.reset();
    entry.remote_user = std::string_view{};
    entry.referer = std::string_view{};
    entry.user_agent = std::string_view{};
    entry.host = std::string_view{};
    entry.country_code = std::string_view{};
    entry.upstream_addr = std::string_view{};
    entry.x_request_id = std::string_view{};
    entry.accept_encoding = std::string_view{};
    entry.successfully_parsed_structure = false;
  }

  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<LogEntry>> pool_;
  size_t max_size_;
  PoolStatistics stats_;
};

// Specialized pool for AnalyzedEvent objects
class AnalyzedEventPool {
public:
  explicit AnalyzedEventPool(size_t initial_size = 100, size_t max_size = 1000)
      : max_size_(max_size) {

    // Note: AnalyzedEvent requires a LogEntry for construction
    // We'll create them on-demand since they need a LogEntry parameter

    LOG(LogLevel::INFO, LogComponent::CORE,
        "AnalyzedEventPool initialized with max_size: " << max_size);
  }

  PooledObject<AnalyzedEvent> acquire(const LogEntry &log_entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_acquisitions++;

    if (!pool_.empty()) {
      auto obj = std::move(pool_.back());
      pool_.pop_back();
      stats_.current_size--;
      stats_.cache_hits++;

      // Reset and re-initialize with new LogEntry
      reset_analyzed_event(*obj, log_entry);

      return PooledObject<AnalyzedEvent>(
          std::move(obj), [this](std::unique_ptr<AnalyzedEvent> returned_obj) {
            this->release(std::move(returned_obj));
          });
    } else {
      // Pool exhausted, create new object
      stats_.cache_misses++;
      stats_.total_allocations++;
      auto obj = std::make_unique<AnalyzedEvent>(log_entry);

      return PooledObject<AnalyzedEvent>(
          std::move(obj), [this](std::unique_ptr<AnalyzedEvent> returned_obj) {
            this->release(std::move(returned_obj));
          });
    }
  }

  const PoolStatistics &get_statistics() const { return stats_; }

  void shrink_to_fit() {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.shrink_to_fit();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
  }

private:
  void release(std::unique_ptr<AnalyzedEvent> obj) {
    if (!obj)
      return;

    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_releases++;

    if (pool_.size() < max_size_) {
      pool_.push_back(std::move(obj));
      stats_.current_size++;
      stats_.peak_size =
          std::max(stats_.peak_size.load(), stats_.current_size.load());
    } else {
      // Pool is full, just let the object be destroyed
      stats_.total_deallocations++;
    }
  }

  void reset_analyzed_event(AnalyzedEvent &event, const LogEntry &new_log) {
    // Reset AnalyzedEvent to clean state and assign new LogEntry
    event.raw_log = new_log;

    // Reset all optional values
    event.current_ip_request_count_in_window.reset();
    event.current_ip_failed_login_count_in_window.reset();
    event.ip_hist_req_time_mean.reset();
    event.ip_hist_req_time_stddev.reset();
    event.ip_hist_req_time_samples.reset();
    event.ip_hist_bytes_mean.reset();
    event.ip_hist_bytes_stddev.reset();
    event.ip_hist_bytes_samples.reset();
    event.ip_hist_error_rate_mean.reset();
    event.ip_hist_error_rate_stddev.reset();
    event.ip_hist_error_rate_samples.reset();
    event.ip_hist_req_vol_mean.reset();
    event.ip_hist_req_vol_stddev.reset();
    event.ip_hist_req_vol_samples.reset();
    event.ip_req_time_zscore.reset();
    event.ip_bytes_sent_zscore.reset();
    event.ip_error_event_zscore.reset();
    event.ip_req_vol_zscore.reset();
    event.path_hist_req_time_mean.reset();
    event.path_hist_req_time_stddev.reset();
    event.path_req_time_zscore.reset();
    event.path_hist_bytes_mean.reset();
    event.path_hist_bytes_stddev.reset();
    event.path_bytes_sent_zscore.reset();
    event.path_hist_error_rate_mean.reset();
    event.path_hist_error_rate_stddev.reset();
    event.path_error_event_zscore.reset();
    event.ip_assets_per_html_ratio.reset();
    event.raw_session_state.reset();
    event.derived_session_features.reset();

    // Reset boolean flags
    event.is_first_request_from_ip = false;
    event.is_path_new_for_ip = false;
    event.is_ua_missing = false;
    event.is_ua_changed_for_ip = false;
    event.is_ua_known_bad = false;
    event.is_ua_outdated = false;
    event.is_ua_headless = false;
    event.is_ua_inconsistent = false;
    event.is_ua_cycling = false;
    event.found_suspicious_path_str = false;
    event.found_suspicious_ua_str = false;

    // Reset numeric values
    event.ip_html_requests_in_window = 0;
    event.ip_asset_requests_in_window = 0;

    // Clear collections
    event.detected_browser_version.clear();
    event.feature_vector.clear();
    event.prometheus_anomalies.clear();
  }

  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<AnalyzedEvent>> pool_;
  size_t max_size_;
  PoolStatistics stats_;
};

// Central resource pool manager that coordinates all pools
class ResourcePoolManager {
public:
  ResourcePoolManager(
      const memory::MemoryConfig &config = memory::MemoryConfig{})
      : memory_manager_(std::make_shared<memory::MemoryManager>(config)),
        log_entry_pool_(config.default_pool_size, config.max_pool_size),
        analyzed_event_pool_(config.default_pool_size, config.max_pool_size) {

    LOG(LogLevel::INFO, LogComponent::CORE,
        "ResourcePoolManager initialized with default sizes: log_entry="
            << config.default_pool_size
            << " analyzed_event=" << config.default_pool_size);
  }

  // Object acquisition methods
  PooledObject<LogEntry> acquire_log_entry() {
    return log_entry_pool_.acquire();
  }

  PooledObject<AnalyzedEvent>
  acquire_analyzed_event(const LogEntry &log_entry) {
    return analyzed_event_pool_.acquire(log_entry);
  }

  // Pool management
  void shrink_all_pools() {
    log_entry_pool_.shrink_to_fit();
    analyzed_event_pool_.shrink_to_fit();

    LOG(LogLevel::INFO, LogComponent::CORE, "All resource pools compacted");
  }

  // Statistics and monitoring
  struct ManagerStatistics {
    PoolStatistics log_entry_stats;
    PoolStatistics analyzed_event_stats;
    size_t total_memory_usage_bytes;
    double overall_hit_rate;
  };

  ManagerStatistics get_statistics() const {
    ManagerStatistics stats;
    stats.log_entry_stats = log_entry_pool_.get_statistics();
    stats.analyzed_event_stats = analyzed_event_pool_.get_statistics();
    stats.total_memory_usage_bytes = memory_manager_->get_total_memory_usage();

    // Calculate overall hit rate
    size_t total_hits = stats.log_entry_stats.cache_hits +
                        stats.analyzed_event_stats.cache_hits;
    size_t total_requests = stats.log_entry_stats.total_acquisitions +
                            stats.analyzed_event_stats.total_acquisitions;
    stats.overall_hit_rate =
        total_requests > 0 ? static_cast<double>(total_hits) / total_requests
                           : 0.0;

    return stats;
  }

  void reset_statistics() {
    const_cast<PoolStatistics &>(log_entry_pool_.get_statistics()).reset();
    const_cast<PoolStatistics &>(analyzed_event_pool_.get_statistics()).reset();
  }

  // Memory pressure handling
  void handle_memory_pressure() {
    if (memory_manager_->is_memory_pressure()) {
      LOG(LogLevel::WARN, LogComponent::CORE,
          "Memory pressure detected, shrinking resource pools");
      shrink_all_pools();
      memory_manager_->trigger_compaction();
    }
  }

  // Batch processing optimization
  template <typename Container>
  void
  process_batch(Container &log_entries,
                std::function<void(PooledObject<AnalyzedEvent>)> processor) {
    // Pre-reserve analyzed events for better cache locality
    std::vector<PooledObject<AnalyzedEvent>> analyzed_events;
    analyzed_events.reserve(log_entries.size());

    // Acquire all analyzed events first
    for (const auto &log_entry : log_entries) {
      analyzed_events.emplace_back(acquire_analyzed_event(log_entry));
    }

    // Process in batch for better memory access patterns
    for (auto &analyzed_event : analyzed_events) {
      processor(std::move(analyzed_event));
    }
  }

  std::shared_ptr<memory::MemoryManager> get_memory_manager() const {
    return memory_manager_;
  }

private:
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  LogEntryPool log_entry_pool_;
  AnalyzedEventPool analyzed_event_pool_;
};

} // namespace resource

#endif // RESOURCE_POOL_MANAGER_HPP

#ifndef MEMORY_MANAGER_HPP
#define MEMORY_MANAGER_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace memory {

// Forward declarations
template <typename T> class ObjectPool;
template <typename K, typename V> class LRUCache;

// Memory management configuration
struct MemoryConfig {
  size_t max_total_memory_mb = 2048;   // 2GB default limit
  size_t pressure_threshold_mb = 1536; // 75% of max
  size_t critical_threshold_mb = 1843; // 90% of max

  // Pool configurations
  size_t default_pool_size = 1000;
  size_t max_pool_size = 10000;
  double pool_growth_factor = 1.5;

  // LRU configurations
  size_t default_lru_capacity = 10000;
  double eviction_batch_size_ratio = 0.1; // Evict 10% at a time

  // Compaction settings
  bool auto_compaction_enabled = true;
  size_t compaction_interval_seconds = 300; // 5 minutes
  double fragmentation_threshold = 0.3; // 30% fragmentation triggers compaction

  // Monitoring settings
  bool detailed_tracking_enabled = false;
  double profiling_sampling_rate = 0.1; // Sample 10% of allocations
};

// Interface for memory-managed components
class IMemoryManaged {
public:
  virtual ~IMemoryManaged() = default;

  // Memory management operations
  virtual size_t get_memory_usage() const = 0;
  virtual size_t compact() = 0; // Returns bytes freed
  virtual void on_memory_pressure(size_t pressure_level) = 0;
  virtual bool can_evict() const = 0;

  // Metadata
  virtual std::string get_component_name() const = 0;
  virtual int get_priority() const = 0; // Lower = higher priority (kept longer)
};

// Memory pressure event
struct MemoryPressureEvent {
  size_t current_usage_mb;
  size_t limit_mb;
  size_t pressure_level; // 0=none, 1=low, 2=medium, 3=high, 4=critical
  double fragmentation_ratio;
  std::vector<std::string> affected_components;
};

// Memory eviction candidate
struct EvictionCandidate {
  IMemoryManaged *component;
  size_t estimated_savings;
  int priority;
  std::chrono::steady_clock::time_point last_access;
  double eviction_score; // Higher = more likely to evict
};

// Advanced memory manager with comprehensive optimization
class MemoryManager {
public:
  explicit MemoryManager(const MemoryConfig &config = MemoryConfig{});
  ~MemoryManager();

  // Component registration
  void register_component(std::shared_ptr<IMemoryManaged> component);
  void unregister_component(IMemoryManaged *component);

  // Memory monitoring and control
  size_t get_total_memory_usage() const;
  size_t get_memory_limit() const {
    return config_.max_total_memory_mb * 1024 * 1024;
  }
  double get_memory_utilization() const;
  bool is_memory_pressure() const;
  size_t get_memory_pressure_level() const;

  // Memory optimization operations
  size_t trigger_compaction();
  size_t trigger_eviction(size_t target_bytes_to_free = 0);
  void optimize_memory_layout();

  // Object pools management
  template <typename T>
  std::shared_ptr<ObjectPool<T>>
  get_or_create_pool(const std::string &pool_name);

  template <typename T> void release_pool(const std::string &pool_name);

  // LRU cache management
  template <typename K, typename V>
  std::shared_ptr<LRUCache<K, V>>
  get_or_create_lru_cache(const std::string &cache_name, size_t capacity = 0);

  // Memory allocation tracking
  void *allocate_tracked(size_t size, const std::string &component,
                         const std::string &location = "");
  void deallocate_tracked(void *ptr, const std::string &component);

  // Configuration and control
  void update_config(const MemoryConfig &new_config);
  const MemoryConfig &get_config() const { return config_; }

  // Monitoring and reporting
  void start_monitoring();
  void stop_monitoring();
  std::string generate_memory_report() const;
  MemoryPressureEvent get_current_pressure_event() const;

  // Event callbacks
  using MemoryPressureCallback =
      std::function<void(const MemoryPressureEvent &)>;
  void set_memory_pressure_callback(MemoryPressureCallback callback);

  // Advanced optimization features
  void enable_auto_tuning(bool enabled = true);
  void
  add_custom_eviction_strategy(std::function<std::vector<EvictionCandidate>(
                                   const std::vector<IMemoryManaged *> &)>
                                   strategy);

  // Memory debugging and analysis
  std::vector<std::string> analyze_memory_patterns() const;
  std::unordered_map<std::string, size_t> get_allocation_breakdown() const;
  void dump_memory_state(const std::string &filename) const;

private:
  void monitoring_thread();
  void compaction_thread();
  void check_memory_pressure();
  void handle_memory_pressure(size_t pressure_level);
  std::vector<EvictionCandidate> identify_eviction_candidates() const;
  void auto_tune_parameters();

  MemoryConfig config_;
  std::atomic<bool> monitoring_active_{false};
  std::atomic<bool> shutdown_requested_{false};

  mutable std::mutex components_mutex_;
  std::vector<std::weak_ptr<IMemoryManaged>> registered_components_;

  mutable std::mutex pools_mutex_;
  std::unordered_map<std::string, std::shared_ptr<void>> object_pools_;
  std::unordered_map<std::string, std::shared_ptr<void>> lru_caches_;

  std::thread monitoring_thread_;
  std::thread compaction_thread_;
  std::condition_variable compaction_cv_;
  mutable std::mutex compaction_mutex_;

  MemoryPressureCallback pressure_callback_;
  std::atomic<size_t> last_pressure_level_{0};

  // Statistics
  mutable std::mutex stats_mutex_;
  std::atomic<size_t> total_allocations_{0};
  std::atomic<size_t> total_deallocations_{0};
  std::atomic<size_t> total_compactions_{0};
  std::atomic<size_t> total_evictions_{0};
  std::atomic<size_t> bytes_freed_by_compaction_{0};
  std::atomic<size_t> bytes_freed_by_eviction_{0};

  // Auto-tuning
  std::atomic<bool> auto_tuning_enabled_{false};
  std::chrono::steady_clock::time_point last_auto_tune_;

  // Custom eviction strategies
  std::vector<std::function<std::vector<EvictionCandidate>(
      const std::vector<IMemoryManaged *> &)>>
      custom_eviction_strategies_;
};

// High-performance object pool with memory optimization
template <typename T> class ObjectPool {
public:
  explicit ObjectPool(size_t initial_size = 100, size_t max_size = 10000)
      : max_size_(max_size), allocated_count_(0) {
    pool_.reserve(initial_size);
    for (size_t i = 0; i < initial_size; ++i) {
      pool_.emplace_back(std::make_unique<T>());
    }
  }

  ~ObjectPool() = default;

private:
  // SFINAE helper to detect if T has a reset() method
  template <typename U> struct has_reset {
    template <typename V>
    static auto test(V *v) -> decltype(v->reset(), std::true_type{});
    template <typename V> static std::false_type test(...);

    static constexpr bool value = decltype(test<U>(nullptr))::value;
  };

  template <typename U>
  typename std::enable_if<has_reset<U>::value>::type
  reset_object_if_possible(U *obj) {
    obj->reset();
  }

  template <typename U>
  typename std::enable_if<!has_reset<U>::value>::type
  reset_object_if_possible(U * /* obj */) {
    // No reset method, do nothing
  }

public:
  // Acquire object from pool
  std::unique_ptr<T> acquire() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pool_.empty()) {
      // Create new object if pool is empty and under limit
      if (allocated_count_ < max_size_) {
        allocated_count_++;
        return std::make_unique<T>();
      } else {
        // Pool exhausted, return nullptr or wait
        return nullptr;
      }
    }

    auto obj = std::move(pool_.back());
    pool_.pop_back();
    return obj;
  }

  // Return object to pool
  void release(std::unique_ptr<T> obj) {
    if (!obj)
      return;

    std::lock_guard<std::mutex> lock(mutex_);

    // Reset object state if it has a reset method
    // Note: Using SFINAE since requires clause needs C++20
    reset_object_if_possible(obj.get());

    if (pool_.size() < max_size_) {
      pool_.push_back(std::move(obj));
    }
    // If pool is full, just let the object be destroyed
  }

  // Pool management
  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
  }

  size_t capacity() const { return max_size_; }

  void resize(size_t new_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (new_size < pool_.size()) {
      pool_.resize(new_size);
    }
    max_size_ = new_size;
  }

  // Memory optimization
  size_t shrink_to_fit() {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t old_capacity = pool_.capacity();
    std::vector<std::unique_ptr<T>> new_pool;
    new_pool.reserve(pool_.size());
    for (auto &obj : pool_) {
      new_pool.push_back(std::move(obj));
    }
    pool_ = std::move(new_pool);
    return (old_capacity - pool_.capacity()) * sizeof(T);
  }

private:
  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<T>> pool_;
  size_t max_size_;
  std::atomic<size_t> allocated_count_;
};

// Memory-efficient LRU cache with eviction callbacks
template <typename K, typename V> class LRUCache {
public:
  explicit LRUCache(size_t capacity) : capacity_(capacity) {
    cache_.reserve(capacity);
  }

  ~LRUCache() = default;

  // Cache operations
  bool get(const K &key, V &value) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_.find(key);
    if (it == cache_.end()) {
      cache_misses_++;
      return false;
    }

    // Move to front (most recently used)
    access_order_.splice(access_order_.begin(), access_order_,
                         it->second.order_it);
    value = it->second.value;
    cache_hits_++;
    return true;
  }

  void put(const K &key, const V &value) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_.find(key);
    if (it != cache_.end()) {
      // Update existing entry
      it->second.value = value;
      access_order_.splice(access_order_.begin(), access_order_,
                           it->second.order_it);
      return;
    }

    // Add new entry
    if (cache_.size() >= capacity_) {
      evict_lru();
    }

    access_order_.push_front(key);
    cache_[key] = {value, access_order_.begin()};
  }

  bool contains(const K &key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.find(key) != cache_.end();
  }

  void remove(const K &key) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_.find(key);
    if (it != cache_.end()) {
      access_order_.erase(it->second.order_it);
      cache_.erase(it);
    }
  }

  // Cache management
  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
    access_order_.clear();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
  }

  size_t capacity() const { return capacity_; }

  void resize(size_t new_capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    capacity_ = new_capacity;
    while (cache_.size() > capacity_) {
      evict_lru();
    }
  }

  // Statistics
  double hit_rate() const {
    if (cache_hits_ + cache_misses_ == 0)
      return 0.0;
    return static_cast<double>(cache_hits_) / (cache_hits_ + cache_misses_);
  }

  size_t hit_count() const { return cache_hits_; }
  size_t miss_count() const { return cache_misses_; }

private:
  struct CacheEntry {
    V value;
    typename std::list<K>::iterator order_it;
  };

  void evict_lru() {
    if (access_order_.empty())
      return;

    K lru_key = access_order_.back();
    cache_.erase(lru_key);
    access_order_.pop_back();
  }

  mutable std::mutex mutex_;
  size_t capacity_;
  std::unordered_map<K, CacheEntry> cache_;
  std::list<K> access_order_; // Front = most recent, back = least recent

  std::atomic<size_t> cache_hits_{0};
  std::atomic<size_t> cache_misses_{0};
};

// Template implementations for MemoryManager
template <typename T>
std::shared_ptr<ObjectPool<T>>
MemoryManager::get_or_create_pool(const std::string &pool_name) {
  std::lock_guard<std::mutex> lock(pools_mutex_);

  auto it = object_pools_.find(pool_name);
  if (it != object_pools_.end()) {
    return std::static_pointer_cast<ObjectPool<T>>(it->second);
  }

  auto pool = std::make_shared<ObjectPool<T>>(config_.default_pool_size,
                                              config_.max_pool_size);
  object_pools_[pool_name] = pool;
  return pool;
}

template <typename T>
void MemoryManager::release_pool(const std::string &pool_name) {
  std::lock_guard<std::mutex> lock(pools_mutex_);
  object_pools_.erase(pool_name);
}

template <typename K, typename V>
std::shared_ptr<LRUCache<K, V>>
MemoryManager::get_or_create_lru_cache(const std::string &cache_name,
                                       size_t capacity) {

  std::lock_guard<std::mutex> lock(pools_mutex_);

  auto it = lru_caches_.find(cache_name);
  if (it != lru_caches_.end()) {
    return std::static_pointer_cast<LRUCache<K, V>>(it->second);
  }

  if (capacity == 0) {
    capacity = config_.default_lru_capacity;
  }

  auto cache = std::make_shared<LRUCache<K, V>>(capacity);
  lru_caches_[cache_name] = cache;
  return cache;
}

} // namespace memory

#endif // MEMORY_MANAGER_HPP
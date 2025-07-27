#ifndef DYNAMIC_MEMORY_MANAGER_HPP
#define DYNAMIC_MEMORY_MANAGER_HPP

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace memory {

/**
 * Auto-tuning pool configuration
 */
struct PoolConfig {
  size_t initial_size = 64;
  size_t max_size = 1024;
  size_t growth_factor = 2;
  std::chrono::milliseconds adaptation_interval{5000}; // 5 seconds
  double utilization_threshold_high = 0.8;
  double utilization_threshold_low = 0.3;
  bool auto_shrink_enabled = true;
  bool auto_grow_enabled = true;
};

/**
 * Pool statistics for auto-tuning
 */
struct PoolStats {
  size_t current_size = 0;
  size_t active_objects = 0;
  size_t peak_usage = 0;
  size_t allocation_requests = 0;
  size_t allocation_failures = 0;
  size_t growth_events = 0;
  size_t shrink_events = 0;
  double average_utilization = 0.0;
  std::chrono::microseconds last_adaptation{0};
};

/**
 * Component memory budget
 */
struct ComponentBudget {
  size_t allocated_bytes = 0;
  size_t max_bytes = SIZE_MAX;
  size_t reserved_bytes = 0;
  double priority = 1.0; // Higher priority gets more memory during pressure
  bool allow_overcommit = false;
  std::chrono::microseconds last_rebalance{0};
};

/**
 * Auto-tuning object pool with adaptive sizing
 */
template <typename T> class AutoTuningPool {
private:
  std::vector<std::unique_ptr<T>> pool_;
  std::vector<bool> available_;
  mutable std::mutex pool_mutex_;

  PoolConfig config_;
  PoolStats stats_;

  std::atomic<bool> adaptation_enabled_{true};
  std::thread adaptation_thread_;
  std::atomic<bool> running_{false};

  void adaptation_loop();
  bool should_grow() const;
  bool should_shrink() const;
  void grow_pool();
  void shrink_pool();

public:
  explicit AutoTuningPool(const PoolConfig &config = PoolConfig{});
  ~AutoTuningPool();

  /**
   * Acquire object from pool
   */
  std::unique_ptr<T> acquire();

  /**
   * Return object to pool
   */
  void release(std::unique_ptr<T> obj);

  /**
   * Start adaptive tuning
   */
  void start_adaptation();

  /**
   * Stop adaptive tuning
   */
  void stop_adaptation();

  /**
   * Get current pool statistics
   */
  PoolStats get_stats() const;

  /**
   * Update configuration
   */
  void update_config(const PoolConfig &config);

  /**
   * Force pool resize
   */
  void resize(size_t new_size);

  /**
   * Get current utilization ratio
   */
  double get_utilization() const;
};

/**
 * Dynamic memory rebalancer
 */
class MemoryRebalancer {
private:
  mutable std::mutex budgets_mutex_;
  std::unordered_map<std::string, ComponentBudget> component_budgets_;

  size_t total_system_memory_;
  std::atomic<size_t> allocated_memory_{0};
  std::atomic<size_t> reserved_memory_{0};

  // Rebalancing parameters
  std::chrono::milliseconds rebalance_interval_{10000}; // 10 seconds
  double pressure_threshold_high_ = 0.85;
  double pressure_threshold_low_ = 0.7;

  std::unique_ptr<std::thread> rebalance_thread_;
  std::atomic<bool> running_{false};

  void rebalance_loop();
  void rebalance_budgets();
  void handle_memory_pressure();
  void reclaim_unused_memory();

public:
  MemoryRebalancer();
  ~MemoryRebalancer();

  /**
   * Register component with memory budget
   */
  void register_component(const std::string &component, size_t max_bytes,
                          double priority = 1.0);

  /**
   * Request memory allocation for component
   */
  bool request_allocation(const std::string &component, size_t bytes);

  /**
   * Release memory allocation for component
   */
  void release_allocation(const std::string &component, size_t bytes);

  /**
   * Update component priority
   */
  void update_priority(const std::string &component, double priority);

  /**
   * Get memory pressure level (0.0 to 1.0)
   */
  double get_memory_pressure() const;

  /**
   * Force rebalance operation
   */
  void force_rebalance();

  /**
   * Start automatic rebalancing
   */
  void start();

  /**
   * Stop automatic rebalancing
   */
  void stop();

  /**
   * Get component budget information
   */
  ComponentBudget get_component_budget(const std::string &component) const;

  /**
   * Get system memory statistics
   */
  struct SystemStats {
    size_t total_memory;
    size_t allocated_memory;
    size_t available_memory;
    double memory_pressure;
    size_t num_components;
  };

  SystemStats get_system_stats() const;
};

/**
 * Adaptive compaction scheduler
 */
class CompactionScheduler {
private:
  struct CompactionJob {
    std::string component;
    std::function<bool()> compact_func;
    std::chrono::microseconds last_run{0};
    std::chrono::microseconds interval{300000000}; // 5 minutes default
    double priority = 1.0;
    bool enabled = true;
  };

  std::vector<CompactionJob> jobs_;
  mutable std::mutex jobs_mutex_;

  std::unique_ptr<std::thread> scheduler_thread_;
  std::atomic<bool> running_{false};

  // Adaptive scheduling parameters
  double pressure_multiplier_ = 2.0; // Speed up compaction under pressure
  std::chrono::microseconds min_interval_{10000000};   // 10 seconds minimum
  std::chrono::microseconds max_interval_{1800000000}; // 30 minutes maximum

  void scheduler_loop();
  std::chrono::microseconds
  calculate_adaptive_interval(const CompactionJob &job, double memory_pressure);

public:
  CompactionScheduler();
  ~CompactionScheduler();

  /**
   * Register compaction function for component
   */
  void register_component(
      const std::string &component, std::function<bool()> compact_func,
      std::chrono::microseconds interval = std::chrono::microseconds(300000000),
      double priority = 1.0);

  /**
   * Unregister component
   */
  void unregister_component(const std::string &component);

  /**
   * Start scheduler
   */
  void start();

  /**
   * Stop scheduler
   */
  void stop();

  /**
   * Force compaction for specific component
   */
  bool force_compaction(const std::string &component);

  /**
   * Force compaction for all components
   */
  void force_compaction_all();

  /**
   * Update component priority
   */
  void update_priority(const std::string &component, double priority);

  /**
   * Enable/disable compaction for component
   */
  void set_enabled(const std::string &component, bool enabled);

  /**
   * Get compaction statistics
   */
  struct CompactionStats {
    size_t total_jobs;
    size_t active_jobs;
    size_t completed_compactions;
    std::chrono::microseconds total_compaction_time{0};
    std::vector<std::string> recent_compactions;
  };

  CompactionStats get_stats() const;
};

/**
 * Runtime memory optimization configuration
 */
class RuntimeMemoryOptimizer {
private:
  std::unordered_map<std::string, std::function<void(const std::string &,
                                                     const std::string &)>>
      config_handlers_;
  mutable std::mutex config_mutex_;

  // Optimization profiles
  enum class OptimizationProfile {
    MINIMAL_MEMORY,
    BALANCED,
    PERFORMANCE_FIRST,
    CUSTOM
  };

  OptimizationProfile current_profile_ = OptimizationProfile::BALANCED;
  std::unordered_map<std::string, std::string> custom_settings_;

public:
  /**
   * Register configuration handler for parameter
   */
  void register_handler(
      const std::string &parameter,
      std::function<void(const std::string &, const std::string &)> handler);

  /**
   * Set optimization profile
   */
  void set_profile(const std::string &profile_name);

  /**
   * Set custom parameter
   */
  void set_parameter(const std::string &parameter, const std::string &value);

  /**
   * Get current parameter value
   */
  std::string get_parameter(const std::string &parameter) const;

  /**
   * Apply profile to all registered handlers
   */
  void apply_profile();

  /**
   * Get available profiles
   */
  std::vector<std::string> get_available_profiles() const;

  /**
   * Enable minimal memory mode (emergency fallback)
   */
  void enable_minimal_memory_mode();

  /**
   * Check if minimal memory mode is active
   */
  bool is_minimal_memory_mode() const;
};

/**
 * Integrated dynamic memory management system
 */
class DynamicMemoryManager {
private:
  std::unique_ptr<MemoryRebalancer> rebalancer_;
  std::unique_ptr<CompactionScheduler> scheduler_;
  std::unique_ptr<RuntimeMemoryOptimizer> optimizer_;

  // Auto-tuning pools for common types
  // Use custom deleter for type-erased pool storage
  using PoolDeleter = std::function<void(void *)>;
  struct PoolEntry {
    void *ptr;
    PoolDeleter deleter;
    PoolEntry(void *p, PoolDeleter d) : ptr(p), deleter(std::move(d)) {}
    ~PoolEntry() {
      if (ptr && deleter)
        deleter(ptr);
    }
    PoolEntry(const PoolEntry &) = delete;
    PoolEntry &operator=(const PoolEntry &) = delete;
    PoolEntry(PoolEntry &&other) noexcept
        : ptr(other.ptr), deleter(std::move(other.deleter)) {
      other.ptr = nullptr;
    }
    PoolEntry &operator=(PoolEntry &&other) noexcept {
      if (this != &other) {
        if (ptr && deleter)
          deleter(ptr);
        ptr = other.ptr;
        deleter = std::move(other.deleter);
        other.ptr = nullptr;
      }
      return *this;
    }
  };
  std::unordered_map<std::string, std::unique_ptr<PoolEntry>> pools_;
  mutable std::mutex pools_mutex_;

  bool minimal_memory_mode_ = false;

public:
  DynamicMemoryManager();
  ~DynamicMemoryManager();

  /**
   * Initialize the dynamic memory management system
   */
  void initialize();

  /**
   * Shutdown the system
   */
  void shutdown();

  /**
   * Register component with memory management
   */
  void register_component(const std::string &component, size_t max_memory,
                          double priority = 1.0,
                          std::function<bool()> compact_func = nullptr);

  /**
   * Get memory rebalancer
   */
  MemoryRebalancer &get_rebalancer() { return *rebalancer_; }

  /**
   * Get compaction scheduler
   */
  CompactionScheduler &get_scheduler() { return *scheduler_; }

  /**
   * Get runtime optimizer
   */
  RuntimeMemoryOptimizer &get_optimizer() { return *optimizer_; }

  /**
   * Create auto-tuning pool for type
   */
  template <typename T>
  AutoTuningPool<T> *create_pool(const std::string &name,
                                 const PoolConfig &config = PoolConfig{});

  /**
   * Get auto-tuning pool for type
   */
  template <typename T> AutoTuningPool<T> *get_pool(const std::string &name);

  /**
   * Handle memory pressure event
   */
  void handle_memory_pressure(double pressure_level);

  /**
   * Generate comprehensive status report
   */
  std::string generate_status_report() const;
};

// Template implementations
template <typename T>
AutoTuningPool<T>::AutoTuningPool(const PoolConfig &config) : config_(config) {
  pool_.reserve(config.initial_size);
  available_.reserve(config.initial_size);

  // Initialize pool
  for (size_t i = 0; i < config.initial_size; ++i) {
    pool_.emplace_back(std::make_unique<T>());
    available_.push_back(true);
  }

  stats_.current_size = config.initial_size;
}

template <typename T> AutoTuningPool<T>::~AutoTuningPool() {
  stop_adaptation();
}

template <typename T> std::unique_ptr<T> AutoTuningPool<T>::acquire() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  stats_.allocation_requests++;

  for (size_t i = 0; i < pool_.size(); ++i) {
    if (available_[i]) {
      available_[i] = false;
      stats_.active_objects++;
      if (stats_.active_objects > stats_.peak_usage) {
        stats_.peak_usage = stats_.active_objects;
      }
      return std::move(pool_[i]);
    }
  }

  // Pool exhausted
  stats_.allocation_failures++;

  if (config_.auto_grow_enabled && pool_.size() < config_.max_size) {
    grow_pool();
    // Try again after growth
    for (size_t i = 0; i < pool_.size(); ++i) {
      if (available_[i]) {
        available_[i] = false;
        stats_.active_objects++;
        return std::move(pool_[i]);
      }
    }
  }

  // Create new object if pool can't be grown
  return std::make_unique<T>();
}

template <typename T> void AutoTuningPool<T>::release(std::unique_ptr<T> obj) {
  if (!obj)
    return;

  std::lock_guard<std::mutex> lock(pool_mutex_);

  // Find empty slot or add to pool
  for (size_t i = 0; i < pool_.size(); ++i) {
    if (!available_[i] && !pool_[i]) {
      pool_[i] = std::move(obj);
      available_[i] = true;
      stats_.active_objects--;
      return;
    }
  }

  // Pool is full, object will be destroyed
  stats_.active_objects--;
}

template <typename T> void AutoTuningPool<T>::stop_adaptation() {
  adaptation_enabled_.store(false);
  if (adaptation_thread_.joinable()) {
    running_.store(false);
    adaptation_thread_.join();
  }
}

template <typename T> void AutoTuningPool<T>::start_adaptation() {
  adaptation_enabled_.store(true);
  running_.store(true);
  adaptation_thread_ = std::thread(&AutoTuningPool<T>::adaptation_loop, this);
}

template <typename T> PoolStats AutoTuningPool<T>::get_stats() const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  return stats_;
}

template <typename T> double AutoTuningPool<T>::get_utilization() const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  if (stats_.current_size == 0)
    return 0.0;
  return static_cast<double>(stats_.active_objects) / stats_.current_size;
}

template <typename T> void AutoTuningPool<T>::grow_pool() {
  size_t new_size =
      std::min(stats_.current_size * config_.growth_factor, config_.max_size);
  if (new_size > stats_.current_size) {
    size_t additional = new_size - stats_.current_size;
    pool_.reserve(new_size);
    available_.reserve(new_size);

    for (size_t i = 0; i < additional; ++i) {
      pool_.emplace_back(std::make_unique<T>());
      available_.push_back(true);
    }

    stats_.current_size = new_size;
    stats_.growth_events++;
  }
}

template <typename T>
AutoTuningPool<T> *DynamicMemoryManager::create_pool(const std::string &name,
                                                     const PoolConfig &config) {
  std::lock_guard<std::mutex> lock(pools_mutex_);
  auto pool = std::make_unique<AutoTuningPool<T>>(config);
  auto *pool_ptr = pool.get();

  // Create deleter for this pool type
  auto deleter = [](void *ptr) {
    delete static_cast<AutoTuningPool<T> *>(ptr);
  };

  pools_[name] =
      std::make_unique<PoolEntry>(pool.release(), std::move(deleter));
  return pool_ptr;
}

template <typename T>
AutoTuningPool<T> *DynamicMemoryManager::get_pool(const std::string &name) {
  std::lock_guard<std::mutex> lock(pools_mutex_);
  auto it = pools_.find(name);
  if (it != pools_.end()) {
    return static_cast<AutoTuningPool<T> *>(it->second->ptr);
  }
  return nullptr;
}

} // namespace memory

#endif // DYNAMIC_MEMORY_MANAGER_HPP

#include "dynamic_memory_manager.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <sys/resource.h>
#include <unistd.h>

namespace memory {

// AutoTuningPool template method implementations
template <typename T> void AutoTuningPool<T>::adaptation_loop() {
  while (running_.load()) {
    std::this_thread::sleep_for(config_.adaptation_interval);

    if (!adaptation_enabled_.load())
      continue;

    double utilization = get_utilization();
    stats_.average_utilization = utilization;

    if (should_grow()) {
      grow_pool();
    } else if (should_shrink()) {
      shrink_pool();
    }
  }
}

template <typename T> bool AutoTuningPool<T>::should_grow() const {
  return config_.auto_grow_enabled && stats_.current_size < config_.max_size &&
         get_utilization() > config_.utilization_threshold_high;
}

template <typename T> bool AutoTuningPool<T>::should_shrink() const {
  return config_.auto_shrink_enabled &&
         stats_.current_size > config_.initial_size &&
         get_utilization() < config_.utilization_threshold_low;
}

template <typename T> void AutoTuningPool<T>::grow_pool() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

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

template <typename T> void AutoTuningPool<T>::shrink_pool() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  size_t new_size = std::max(stats_.current_size / config_.growth_factor,
                             config_.initial_size);
  if (new_size < stats_.current_size) {
    // Remove unused objects from the end
    size_t to_remove = stats_.current_size - new_size;
    size_t removed = 0;

    for (int i = static_cast<int>(pool_.size()) - 1;
         i >= 0 && removed < to_remove; --i) {
      if (available_[i]) {
        pool_.erase(pool_.begin() + i);
        available_.erase(available_.begin() + i);
        removed++;
      }
    }

    stats_.current_size = pool_.size();
    stats_.shrink_events++;
  }
}

template <typename T> void AutoTuningPool<T>::start_adaptation() {
  if (running_.load())
    return;

  running_.store(true);
  adaptation_thread_ =
      std::make_unique<std::thread>(&AutoTuningPool<T>::adaptation_loop, this);
}

template <typename T> void AutoTuningPool<T>::stop_adaptation() {
  if (!running_.load())
    return;

  running_.store(false);
  if (adaptation_thread_ && adaptation_thread_->joinable()) {
    adaptation_thread_->join();
  }
  adaptation_thread_.reset();
}

template <typename T> PoolStats AutoTuningPool<T>::get_stats() const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  return stats_;
}

template <typename T>
void AutoTuningPool<T>::update_config(const PoolConfig &config) {
  config_ = config;
}

template <typename T> void AutoTuningPool<T>::resize(size_t new_size) {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  if (new_size > stats_.current_size) {
    // Grow
    pool_.reserve(new_size);
    available_.reserve(new_size);

    for (size_t i = stats_.current_size; i < new_size; ++i) {
      pool_.emplace_back(std::make_unique<T>());
      available_.push_back(true);
    }
  } else if (new_size < stats_.current_size) {
    // Shrink
    pool_.resize(new_size);
    available_.resize(new_size);
  }

  stats_.current_size = new_size;
}

template <typename T> double AutoTuningPool<T>::get_utilization() const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  return stats_.current_size > 0
             ? static_cast<double>(stats_.active_objects) / stats_.current_size
             : 0.0;
}

// MemoryRebalancer implementation
MemoryRebalancer::MemoryRebalancer() {
  // Get total system memory
  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  total_system_memory_ = static_cast<size_t>(sysconf(_SC_PHYS_PAGES)) *
                         static_cast<size_t>(sysconf(_SC_PAGE_SIZE));
}

MemoryRebalancer::~MemoryRebalancer() { stop(); }

void MemoryRebalancer::register_component(const std::string &component,
                                          size_t max_bytes, double priority) {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  ComponentBudget budget;
  budget.max_bytes = max_bytes;
  budget.priority = priority;

  component_budgets_[component] = budget;
}

bool MemoryRebalancer::request_allocation(const std::string &component,
                                          size_t bytes) {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  auto it = component_budgets_.find(component);
  if (it == component_budgets_.end()) {
    return false; // Component not registered
  }

  ComponentBudget &budget = it->second;

  // Check if allocation would exceed budget
  if (!budget.allow_overcommit &&
      budget.allocated_bytes + bytes > budget.max_bytes) {
    return false;
  }

  // Update allocation
  budget.allocated_bytes += bytes;
  allocated_memory_.fetch_add(bytes);

  return true;
}

void MemoryRebalancer::release_allocation(const std::string &component,
                                          size_t bytes) {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  auto it = component_budgets_.find(component);
  if (it != component_budgets_.end()) {
    ComponentBudget &budget = it->second;
    budget.allocated_bytes =
        budget.allocated_bytes >= bytes ? budget.allocated_bytes - bytes : 0;
    allocated_memory_.fetch_sub(bytes);
  }
}

void MemoryRebalancer::update_priority(const std::string &component,
                                       double priority) {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  auto it = component_budgets_.find(component);
  if (it != component_budgets_.end()) {
    it->second.priority = priority;
  }
}

double MemoryRebalancer::get_memory_pressure() const {
  if (total_system_memory_ == 0)
    return 0.0;
  return static_cast<double>(allocated_memory_.load()) / total_system_memory_;
}

void MemoryRebalancer::force_rebalance() { rebalance_budgets(); }

void MemoryRebalancer::start() {
  if (running_.load())
    return;

  running_.store(true);
  rebalance_thread_ =
      std::make_unique<std::thread>(&MemoryRebalancer::rebalance_loop, this);
}

void MemoryRebalancer::stop() {
  if (!running_.load())
    return;

  running_.store(false);
  if (rebalance_thread_ && rebalance_thread_->joinable()) {
    rebalance_thread_->join();
  }
  rebalance_thread_.reset();
}

ComponentBudget
MemoryRebalancer::get_component_budget(const std::string &component) const {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  auto it = component_budgets_.find(component);
  return it != component_budgets_.end() ? it->second : ComponentBudget{};
}

MemoryRebalancer::SystemStats MemoryRebalancer::get_system_stats() const {
  SystemStats stats;
  stats.total_memory = total_system_memory_;
  stats.allocated_memory = allocated_memory_.load();
  stats.available_memory = stats.total_memory > stats.allocated_memory
                               ? stats.total_memory - stats.allocated_memory
                               : 0;
  stats.memory_pressure = get_memory_pressure();

  std::lock_guard<std::mutex> lock(budgets_mutex_);
  stats.num_components = component_budgets_.size();

  return stats;
}

void MemoryRebalancer::rebalance_loop() {
  while (running_.load()) {
    std::this_thread::sleep_for(rebalance_interval_);

    double pressure = get_memory_pressure();
    if (pressure > pressure_threshold_high_) {
      handle_memory_pressure();
    } else if (pressure < pressure_threshold_low_) {
      reclaim_unused_memory();
    }

    rebalance_budgets();
  }
}

void MemoryRebalancer::rebalance_budgets() {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  // Simple priority-based rebalancing
  double total_priority = 0.0;
  for (const auto &[name, budget] : component_budgets_) {
    total_priority += budget.priority;
  }

  if (total_priority > 0.0) {
    size_t available_memory =
        total_system_memory_ > allocated_memory_.load()
            ? total_system_memory_ - allocated_memory_.load()
            : 0;

    for (auto &[name, budget] : component_budgets_) {
      double share = budget.priority / total_priority;
      budget.max_bytes = static_cast<size_t>(available_memory * share) +
                         budget.allocated_bytes;
    }
  }
}

void MemoryRebalancer::handle_memory_pressure() {
  // Implement memory pressure handling logic
  // This could trigger compaction, reduce allocations, etc.
}

void MemoryRebalancer::reclaim_unused_memory() {
  // Implement memory reclamation logic
  // This could return unused memory to the system
}

// CompactionScheduler implementation
CompactionScheduler::CompactionScheduler() {}

CompactionScheduler::~CompactionScheduler() { stop(); }

void CompactionScheduler::register_component(const std::string &component,
                                             std::function<bool()> compact_func,
                                             std::chrono::microseconds interval,
                                             double priority) {
  std::lock_guard<std::mutex> lock(jobs_mutex_);

  CompactionJob job;
  job.component = component;
  job.compact_func = compact_func;
  job.interval = interval;
  job.priority = priority;

  jobs_.push_back(job);
}

void CompactionScheduler::start() {
  if (running_.load())
    return;

  running_.store(true);
  scheduler_thread_ =
      std::make_unique<std::thread>(&CompactionScheduler::scheduler_loop, this);
}

void CompactionScheduler::stop() {
  if (!running_.load())
    return;

  running_.store(false);
  if (scheduler_thread_ && scheduler_thread_->joinable()) {
    scheduler_thread_->join();
  }
  scheduler_thread_.reset();
}

bool CompactionScheduler::force_compaction(const std::string &component) {
  std::lock_guard<std::mutex> lock(jobs_mutex_);

  for (auto &job : jobs_) {
    if (job.component == component && job.compact_func) {
      return job.compact_func();
    }
  }
  return false;
}

void CompactionScheduler::scheduler_loop() {
  while (running_.load()) {
    auto now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch());

    std::lock_guard<std::mutex> lock(jobs_mutex_);
    for (auto &job : jobs_) {
      if (!job.enabled || !job.compact_func)
        continue;

      if (now - job.last_run >= job.interval) {
        if (job.compact_func()) {
          job.last_run = now;
        }
      }
    }

    std::this_thread::sleep_for(
        std::chrono::milliseconds(1000)); // Check every second
  }
}

// RuntimeMemoryOptimizer implementation
void RuntimeMemoryOptimizer::register_handler(
    const std::string &parameter,
    std::function<void(const std::string &, const std::string &)> handler) {
  std::lock_guard<std::mutex> lock(config_mutex_);
  config_handlers_[parameter] = handler;
}

void RuntimeMemoryOptimizer::set_parameter(const std::string &parameter,
                                           const std::string &value) {
  std::lock_guard<std::mutex> lock(config_mutex_);
  custom_settings_[parameter] = value;

  auto it = config_handlers_.find(parameter);
  if (it != config_handlers_.end()) {
    it->second(parameter, value);
  }
}

std::string
RuntimeMemoryOptimizer::get_parameter(const std::string &parameter) const {
  std::lock_guard<std::mutex> lock(config_mutex_);
  auto it = custom_settings_.find(parameter);
  return it != custom_settings_.end() ? it->second : "";
}

std::vector<std::string>
RuntimeMemoryOptimizer::get_available_profiles() const {
  return {"MINIMAL_MEMORY", "BALANCED", "PERFORMANCE_FIRST", "CUSTOM"};
}

// DynamicMemoryManager implementation
DynamicMemoryManager::DynamicMemoryManager()
    : rebalancer_(std::make_unique<MemoryRebalancer>()),
      scheduler_(std::make_unique<CompactionScheduler>()),
      optimizer_(std::make_unique<RuntimeMemoryOptimizer>()) {}

DynamicMemoryManager::~DynamicMemoryManager() { shutdown(); }

void DynamicMemoryManager::initialize() {
  rebalancer_->start();
  scheduler_->start();
}

void DynamicMemoryManager::shutdown() {
  if (rebalancer_)
    rebalancer_->stop();
  if (scheduler_)
    scheduler_->stop();
}

void DynamicMemoryManager::register_component(
    const std::string &component, size_t max_memory, double priority,
    std::function<bool()> compact_func) {
  rebalancer_->register_component(component, max_memory, priority);

  if (compact_func) {
    scheduler_->register_component(component, compact_func);
  }
}

std::string DynamicMemoryManager::generate_status_report() const {
  std::ostringstream report;

  report << "=== Dynamic Memory Manager Status ===\n";

  auto system_stats = rebalancer_->get_system_stats();
  report << "Total Memory: " << (system_stats.total_memory / (1024 * 1024))
         << " MB\n";
  report << "Allocated Memory: "
         << (system_stats.allocated_memory / (1024 * 1024)) << " MB\n";
  report << "Memory Pressure: " << (system_stats.memory_pressure * 100)
         << "%\n";
  report << "Registered Components: " << system_stats.num_components << "\n\n";

  std::lock_guard<std::mutex> lock(pools_mutex_);
  report << "Active Pools: " << pools_.size() << "\n";

  return report.str();
}

} // namespace memory

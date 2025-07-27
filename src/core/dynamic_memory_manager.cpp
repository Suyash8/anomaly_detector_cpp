#include "dynamic_memory_manager.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>

namespace memory {

// ============================================================================
// MemoryRebalancer Implementation
// ============================================================================

MemoryRebalancer::MemoryRebalancer() : running_(false) {
  // Get system memory information
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    total_system_memory_ =
        static_cast<size_t>(usage.ru_maxrss) * 1024; // Convert KB to bytes
  } else {
    total_system_memory_ = 1024 * 1024 * 1024; // Default 1GB
  }
}

MemoryRebalancer::~MemoryRebalancer() { stop(); }

void MemoryRebalancer::register_component(const std::string &component,
                                          size_t max_bytes, double priority) {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  ComponentBudget budget;
  budget.allocated_bytes = 0;
  budget.max_bytes = max_bytes;
  budget.reserved_bytes = 0;
  budget.priority = priority;
  budget.allow_overcommit = false;
  budget.last_rebalance = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

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

  // Check if request can be satisfied within current budget
  if (budget.allocated_bytes + bytes <= budget.max_bytes) {
    budget.allocated_bytes += bytes;
    allocated_memory_.fetch_add(bytes);
    return true;
  }

  return false; // Cannot satisfy request
}

void MemoryRebalancer::release_allocation(const std::string &component,
                                          size_t bytes) {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  auto it = component_budgets_.find(component);
  if (it != component_budgets_.end()) {
    ComponentBudget &budget = it->second;
    size_t to_release = std::min(bytes, budget.allocated_bytes);
    budget.allocated_bytes -= to_release;
    allocated_memory_.fetch_sub(to_release);
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
  size_t total_allocated = allocated_memory_.load();
  if (total_system_memory_ == 0)
    return 0.0;
  return static_cast<double>(total_allocated) / total_system_memory_;
}

void MemoryRebalancer::force_rebalance() { rebalance_budgets(); }

void MemoryRebalancer::start() {
  if (!running_.load()) {
    running_.store(true);
    rebalance_thread_ =
        std::make_unique<std::thread>(&MemoryRebalancer::rebalance_loop, this);
  }
}

void MemoryRebalancer::stop() {
  if (running_.load()) {
    running_.store(false);
    if (rebalance_thread_ && rebalance_thread_->joinable()) {
      rebalance_thread_->join();
    }
  }
}

ComponentBudget
MemoryRebalancer::get_component_budget(const std::string &component) const {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  auto it = component_budgets_.find(component);
  return (it != component_budgets_.end()) ? it->second : ComponentBudget{};
}

MemoryRebalancer::SystemStats MemoryRebalancer::get_system_stats() const {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  SystemStats stats;
  stats.total_memory = total_system_memory_;
  stats.allocated_memory = allocated_memory_.load();
  stats.available_memory = (stats.total_memory > stats.allocated_memory)
                               ? stats.total_memory - stats.allocated_memory
                               : 0;
  stats.memory_pressure = get_memory_pressure();
  stats.num_components = component_budgets_.size();

  return stats;
}

void MemoryRebalancer::rebalance_loop() {
  while (running_.load()) {
    rebalance_budgets();
    std::this_thread::sleep_for(rebalance_interval_);
  }
}

void MemoryRebalancer::rebalance_budgets() {
  std::lock_guard<std::mutex> lock(budgets_mutex_);

  double pressure = get_memory_pressure();

  if (pressure > pressure_threshold_high_) {
    handle_memory_pressure();
  } else if (pressure < pressure_threshold_low_) {
    reclaim_unused_memory();
  }
}

void MemoryRebalancer::handle_memory_pressure() {
  // Under high pressure, reduce budgets for low-priority components
  for (auto &[name, budget] : component_budgets_) {
    if (budget.priority < 1.0 && budget.max_bytes > budget.allocated_bytes) {
      size_t reduction = (budget.max_bytes - budget.allocated_bytes) / 4;
      budget.max_bytes -= reduction;
    }
  }
}

void MemoryRebalancer::reclaim_unused_memory() {
  // Under low pressure, return unused memory to high-priority components
  for (auto &[name, budget] : component_budgets_) {
    if (budget.priority > 1.0) {
      size_t utilization = budget.allocated_bytes;
      size_t unused =
          (budget.max_bytes > utilization) ? budget.max_bytes - utilization : 0;

      if (unused > budget.max_bytes / 2) {
        budget.max_bytes += unused / 4; // Increase budget by 25% of unused
      }
    }
  }
}

// ============================================================================
// CompactionScheduler Implementation
// ============================================================================

CompactionScheduler::CompactionScheduler() : running_(false) {}

CompactionScheduler::~CompactionScheduler() { stop(); }

void CompactionScheduler::register_component(const std::string &component,
                                             std::function<bool()> compact_func,
                                             std::chrono::microseconds interval,
                                             double priority) {

  std::lock_guard<std::mutex> lock(jobs_mutex_);

  CompactionJob job;
  job.component = component;
  job.compact_func = std::move(compact_func);
  job.interval = interval;
  job.priority = priority;
  job.enabled = true;
  job.last_run = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  jobs_.push_back(std::move(job));
}

void CompactionScheduler::start() {
  if (!running_.load()) {
    running_.store(true);
    scheduler_thread_ = std::make_unique<std::thread>(
        &CompactionScheduler::scheduler_loop, this);
  }
}

void CompactionScheduler::stop() {
  if (running_.load()) {
    running_.store(false);
    if (scheduler_thread_ && scheduler_thread_->joinable()) {
      scheduler_thread_->join();
    }
  }
}

bool CompactionScheduler::force_compaction(const std::string &component) {
  std::lock_guard<std::mutex> lock(jobs_mutex_);

  for (auto &job : jobs_) {
    if (job.component == component && job.enabled) {
      if (job.compact_func) {
        bool result = job.compact_func();
        job.last_run = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch());
        return result;
      }
      break;
    }
  }
  return false; // Component not found or no compaction function
}
CompactionScheduler::CompactionStats CompactionScheduler::get_stats() const {
  std::lock_guard<std::mutex> lock(jobs_mutex_);

  CompactionStats stats;
  stats.total_jobs = jobs_.size();
  stats.active_jobs = 0;

  for (const auto &job : jobs_) {
    if (job.enabled) {
      stats.active_jobs++;
    }
  }

  return stats;
}

void CompactionScheduler::scheduler_loop() {
  while (running_.load()) {
    auto now = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch());

    {
      std::lock_guard<std::mutex> lock(jobs_mutex_);

      for (auto &job : jobs_) {
        if (!job.enabled)
          continue;

        if (now - job.last_run >= job.interval) {
          if (job.compact_func && job.compact_func()) {
            job.last_run = now;
          }
        }
      }
    }

    // Sleep for a short time before checking again
    std::this_thread::sleep_for(std::chrono::seconds(10));
  }
}

// ============================================================================
// RuntimeMemoryOptimizer Implementation
// ============================================================================

void RuntimeMemoryOptimizer::register_handler(
    const std::string &parameter,
    std::function<void(const std::string &, const std::string &)> handler) {
  // Simple stub implementation
  (void)parameter;
  (void)handler;
}

void RuntimeMemoryOptimizer::set_parameter(const std::string &key,
                                           const std::string &value) {
  // Simple stub implementation
  (void)key;
  (void)value;
}

std::string
RuntimeMemoryOptimizer::get_parameter(const std::string &key) const {
  // Simple stub implementation
  (void)key;
  return "";
}

std::vector<std::string>
RuntimeMemoryOptimizer::get_available_profiles() const {
  return {"balanced", "high_performance", "minimal"};
}

void RuntimeMemoryOptimizer::set_profile(const std::string &profile_name) {
  (void)profile_name;
}

void RuntimeMemoryOptimizer::enable_minimal_memory_mode() {
  // Simple stub implementation
}

bool RuntimeMemoryOptimizer::is_minimal_memory_mode() const { return false; }

// ============================================================================
// DynamicMemoryManager Implementation
// ============================================================================

DynamicMemoryManager::DynamicMemoryManager()
    : rebalancer_(std::make_unique<MemoryRebalancer>()),
      scheduler_(std::make_unique<CompactionScheduler>()),
      optimizer_(std::make_unique<RuntimeMemoryOptimizer>()) {}

DynamicMemoryManager::~DynamicMemoryManager() { shutdown(); }

void DynamicMemoryManager::initialize() {
  // Start background services
  rebalancer_->start();
  scheduler_->start();
}

void DynamicMemoryManager::shutdown() {
  if (rebalancer_) {
    rebalancer_->stop();
  }
  if (scheduler_) {
    scheduler_->stop();
  }
}

void DynamicMemoryManager::register_component(
    const std::string &name, size_t initial_memory, double priority,
    std::function<bool()> compaction_func) {

  // Register with rebalancer
  rebalancer_->register_component(name, initial_memory, priority);

  // Register compaction function if provided
  if (compaction_func) {
    scheduler_->register_component(
        name, std::move(compaction_func),
        std::chrono::minutes(5), // Default 5-minute interval
        priority);
  }
}

std::string DynamicMemoryManager::generate_status_report() const {
  std::ostringstream report;

  report << "=== Dynamic Memory Manager Status ===\\n";

  // Rebalancer stats
  auto system_stats = rebalancer_->get_system_stats();
  report << "Memory Usage:\\n";
  report << "  Total: " << (system_stats.total_memory / 1024 / 1024)
         << " MB\\n";
  report << "  Allocated: " << (system_stats.allocated_memory / 1024 / 1024)
         << " MB\\n";
  report << "  Available: " << (system_stats.available_memory / 1024 / 1024)
         << " MB\\n";
  report << "  Pressure: " << (system_stats.memory_pressure * 100) << "%\\n";
  report << "  Components: " << system_stats.num_components << "\\n";

  // Runtime optimization
  report << "\\nOptimization:\\n";
  report << "  Minimal Mode: "
         << (optimizer_->is_minimal_memory_mode() ? "ON" : "OFF") << "\\n";

  return report.str();
}

} // namespace memory

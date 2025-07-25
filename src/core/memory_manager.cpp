#include "core/memory_manager.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef __linux__
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

namespace memory {

MemoryManager::MemoryManager(const MemoryConfig &config) : config_(config) {
  registered_components_.reserve(100); // Pre-allocate for efficiency
}

MemoryManager::~MemoryManager() {
  shutdown_requested_ = true;
  stop_monitoring();

  if (monitoring_thread_.joinable()) {
    monitoring_thread_.join();
  }

  if (compaction_thread_.joinable()) {
    compaction_cv_.notify_all();
    compaction_thread_.join();
  }
}

void MemoryManager::register_component(
    std::shared_ptr<IMemoryManaged> component) {
  if (!component)
    return;

  std::lock_guard<std::mutex> lock(components_mutex_);
  registered_components_.push_back(std::weak_ptr<IMemoryManaged>(component));
}

void MemoryManager::unregister_component(IMemoryManaged *component) {
  if (!component)
    return;

  std::lock_guard<std::mutex> lock(components_mutex_);
  registered_components_.erase(
      std::remove_if(
          registered_components_.begin(), registered_components_.end(),
          [component](const std::weak_ptr<IMemoryManaged> &weak_ptr) {
            auto shared = weak_ptr.lock();
            return !shared || shared.get() == component;
          }),
      registered_components_.end());
}

size_t MemoryManager::get_total_memory_usage() const {
  std::lock_guard<std::mutex> lock(components_mutex_);

  size_t total = 0;
  for (const auto &component_weak : registered_components_) {
    if (auto component = component_weak.lock()) {
      total += component->get_memory_usage();
    }
  }

  return total;
}

double MemoryManager::get_memory_utilization() const {
  size_t current_usage = get_total_memory_usage();
  size_t limit = get_memory_limit();

  if (limit == 0)
    return 0.0;
  return static_cast<double>(current_usage) / limit;
}

bool MemoryManager::is_memory_pressure() const {
  return get_memory_pressure_level() >= 2; // Medium or higher
}

size_t MemoryManager::get_memory_pressure_level() const {
  double utilization = get_memory_utilization();

  if (utilization >= 0.90)
    return 4; // Critical
  if (utilization >= 0.75)
    return 3; // High
  if (utilization >= 0.60)
    return 2; // Medium
  if (utilization >= 0.40)
    return 1; // Low
  return 0;   // None
}

size_t MemoryManager::trigger_compaction() {
  std::lock_guard<std::mutex> lock(components_mutex_);

  size_t total_freed = 0;
  for (const auto &component_weak : registered_components_) {
    if (auto component = component_weak.lock()) {
      total_freed += component->compact();
    }
  }

  total_compactions_++;
  bytes_freed_by_compaction_.fetch_add(total_freed);

  return total_freed;
}

size_t MemoryManager::trigger_eviction(size_t target_bytes_to_free) {
  auto candidates = identify_eviction_candidates();

  // Sort by eviction score (highest first)
  std::sort(candidates.begin(), candidates.end(),
            [](const EvictionCandidate &a, const EvictionCandidate &b) {
              return a.eviction_score > b.eviction_score;
            });

  size_t total_freed = 0;
  size_t target =
      (target_bytes_to_free > 0)
          ? target_bytes_to_free
          : (get_memory_limit() * config_.eviction_batch_size_ratio);

  for (const auto &candidate : candidates) {
    if (total_freed >= target)
      break;
    if (!candidate.component->can_evict())
      continue;

    // Trigger eviction on the component
    candidate.component->on_memory_pressure(4); // Critical pressure = eviction
    total_freed += candidate.estimated_savings;
    total_evictions_++;
  }

  bytes_freed_by_eviction_.fetch_add(total_freed);
  return total_freed;
}

void MemoryManager::optimize_memory_layout() {
  // Trigger compaction
  trigger_compaction();

  // Shrink object pools
  std::lock_guard<std::mutex> lock(pools_mutex_);
  for (auto &[pool_name, pool_base] : object_pools_) {
    // Pool shrinking would be done via specific pool interface
    // This is a placeholder for pool-specific optimization
    (void)pool_name; // Suppress unused variable warning
    (void)pool_base; // Suppress unused variable warning
  }

  // Check if eviction is needed after compaction
  if (is_memory_pressure()) {
    trigger_eviction();
  }
}

void *MemoryManager::allocate_tracked(size_t size, const std::string &component,
                                      const std::string &location) {
  (void)component; // For future memory profiler integration
  (void)location;  // For future memory profiler integration

  void *ptr = std::aligned_alloc(sizeof(void *), size);
  if (ptr) {
    total_allocations_++;
    // TODO: Integrate with memory profiler when available
  }
  return ptr;
}

void MemoryManager::deallocate_tracked(void *ptr,
                                       const std::string &component) {
  (void)component; // For future memory profiler integration

  if (ptr) {
    std::free(ptr);
    total_deallocations_++;
    // TODO: Integrate with memory profiler when available
  }
}

void MemoryManager::update_config(const MemoryConfig &new_config) {
  config_ = new_config;

  // Update object pools with new configuration
  std::lock_guard<std::mutex> lock(pools_mutex_);
  // TODO: Resize pools based on new configuration
}

void MemoryManager::start_monitoring() {
  if (monitoring_active_)
    return;

  monitoring_active_ = true;
  shutdown_requested_ = false;

  monitoring_thread_ = std::thread(&MemoryManager::monitoring_thread, this);

  if (config_.auto_compaction_enabled) {
    compaction_thread_ = std::thread(&MemoryManager::compaction_thread, this);
  }
}

void MemoryManager::stop_monitoring() {
  monitoring_active_ = false;
  shutdown_requested_ = true;

  compaction_cv_.notify_all();
}

std::string MemoryManager::generate_memory_report() const {
  std::ostringstream report;

  report << "=== Memory Manager Report ===\n\n";

  // Overall statistics
  size_t total_usage = get_total_memory_usage();
  size_t limit = get_memory_limit();
  double utilization = get_memory_utilization();

  report << "Overall Memory Usage:\n";
  report << "  Current Usage: " << (total_usage / 1024 / 1024) << " MB\n";
  report << "  Memory Limit: " << (limit / 1024 / 1024) << " MB\n";
  report << "  Utilization: " << std::fixed << std::setprecision(1)
         << (utilization * 100) << "%\n";
  report << "  Pressure Level: " << get_memory_pressure_level() << "/4\n\n";

  // Component breakdown
  report << "Component Memory Usage:\n";
  std::lock_guard<std::mutex> lock(components_mutex_);

  std::vector<std::pair<std::string, size_t>> component_usage;
  for (const auto &component_weak : registered_components_) {
    if (auto component = component_weak.lock()) {
      component_usage.emplace_back(component->get_component_name(),
                                   component->get_memory_usage());
    }
  }

  std::sort(component_usage.begin(), component_usage.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });

  for (const auto &usage : component_usage) {
    report << "  " << usage.first << ": " << (usage.second / 1024) << " KB\n";
  }

  // Management statistics
  report << "\nMemory Management Statistics:\n";
  report << "  Total Allocations: " << total_allocations_.load() << "\n";
  report << "  Total Deallocations: " << total_deallocations_.load() << "\n";
  report << "  Compactions Performed: " << total_compactions_.load() << "\n";
  report << "  Evictions Performed: " << total_evictions_.load() << "\n";
  report << "  Bytes Freed by Compaction: "
         << (bytes_freed_by_compaction_.load() / 1024) << " KB\n";
  report << "  Bytes Freed by Eviction: "
         << (bytes_freed_by_eviction_.load() / 1024) << " KB\n";

  return report.str();
}

MemoryPressureEvent MemoryManager::get_current_pressure_event() const {
  MemoryPressureEvent event;

  event.current_usage_mb = get_total_memory_usage() / 1024 / 1024;
  event.limit_mb = get_memory_limit() / 1024 / 1024;
  event.pressure_level = get_memory_pressure_level();
  event.fragmentation_ratio = 0.0; // TODO: Calculate actual fragmentation

  std::lock_guard<std::mutex> lock(components_mutex_);
  for (const auto &component_weak : registered_components_) {
    if (auto component = component_weak.lock()) {
      event.affected_components.push_back(component->get_component_name());
    }
  }

  return event;
}

void MemoryManager::set_memory_pressure_callback(
    MemoryPressureCallback callback) {
  pressure_callback_ = callback;
}

void MemoryManager::enable_auto_tuning(bool enabled) {
  auto_tuning_enabled_ = enabled;
  if (enabled) {
    last_auto_tune_ = std::chrono::steady_clock::now();
  }
}

void MemoryManager::add_custom_eviction_strategy(
    std::function<
        std::vector<EvictionCandidate>(const std::vector<IMemoryManaged *> &)>
        strategy) {
  custom_eviction_strategies_.push_back(strategy);
}

std::vector<std::string> MemoryManager::analyze_memory_patterns() const {
  std::vector<std::string> patterns;

  // Analyze allocation/deallocation ratio
  size_t allocs = total_allocations_.load();
  size_t deallocs = total_deallocations_.load();

  if (allocs > 0) {
    double dealloc_ratio = static_cast<double>(deallocs) / allocs;
    if (dealloc_ratio < 0.8) {
      patterns.push_back("Potential memory leak: Low deallocation ratio (" +
                         std::to_string(dealloc_ratio * 100) + "%)");
    }
  }

  // Analyze memory pressure frequency
  if (get_memory_pressure_level() >= 3) {
    patterns.push_back("High memory pressure detected: Consider increasing "
                       "limits or optimizing usage");
  }

  // Analyze compaction effectiveness
  size_t compactions = total_compactions_.load();
  size_t freed_by_compaction = bytes_freed_by_compaction_.load();

  if (compactions > 0 && freed_by_compaction / compactions <
                             1024 * 1024) { // Less than 1MB per compaction
    patterns.push_back(
        "Low compaction effectiveness: Consider adjusting compaction strategy");
  }

  return patterns;
}

std::unordered_map<std::string, size_t>
MemoryManager::get_allocation_breakdown() const {
  std::unordered_map<std::string, size_t> breakdown;

  std::lock_guard<std::mutex> lock(components_mutex_);
  for (const auto &component_weak : registered_components_) {
    if (auto component = component_weak.lock()) {
      breakdown[component->get_component_name()] =
          component->get_memory_usage();
    }
  }

  return breakdown;
}

void MemoryManager::dump_memory_state(const std::string &filename) const {
  std::ofstream file(filename);
  if (file.is_open()) {
    file << generate_memory_report();
    file.close();
  }
}

void MemoryManager::monitoring_thread() {
  while (monitoring_active_ && !shutdown_requested_) {
    check_memory_pressure();

    if (auto_tuning_enabled_) {
      auto_tune_parameters();
    }

    std::this_thread::sleep_for(
        std::chrono::seconds(5)); // Check every 5 seconds
  }
}

void MemoryManager::compaction_thread() {
  std::unique_lock<std::mutex> lock(compaction_mutex_);

  while (!shutdown_requested_) {
    // Wait for compaction interval or shutdown
    if (compaction_cv_.wait_for(
            lock, std::chrono::seconds(config_.compaction_interval_seconds),
            [this] { return shutdown_requested_.load(); })) {
      break; // Shutdown requested
    }

    // Check if compaction is needed
    if (is_memory_pressure() || (/* TODO: check fragmentation */ false)) {
      trigger_compaction();
    }
  }
}

void MemoryManager::check_memory_pressure() {
  size_t current_pressure = get_memory_pressure_level();
  size_t last_pressure = last_pressure_level_.load();

  if (current_pressure != last_pressure) {
    last_pressure_level_ = current_pressure;

    if (current_pressure >= 2) { // Medium or higher pressure
      handle_memory_pressure(current_pressure);

      if (pressure_callback_) {
        pressure_callback_(get_current_pressure_event());
      }
    }
  }
}

void MemoryManager::handle_memory_pressure(size_t pressure_level) {
  switch (pressure_level) {
  case 2: // Medium pressure - trigger compaction
    trigger_compaction();
    break;

  case 3: // High pressure - trigger compaction and light eviction
    trigger_compaction();
    trigger_eviction(get_memory_limit() * 0.05); // Free 5% of limit
    break;

  case 4: // Critical pressure - aggressive eviction
    trigger_compaction();
    trigger_eviction(get_memory_limit() * 0.15); // Free 15% of limit
    break;

  default:
    break;
  }
}

std::vector<EvictionCandidate>
MemoryManager::identify_eviction_candidates() const {
  std::vector<EvictionCandidate> candidates;
  auto now = std::chrono::steady_clock::now();

  std::lock_guard<std::mutex> lock(components_mutex_);
  for (const auto &component_weak : registered_components_) {
    if (auto component = component_weak.lock()) {
      if (!component->can_evict())
        continue;

      EvictionCandidate candidate;
      candidate.component = component.get();
      candidate.estimated_savings = component->get_memory_usage();
      candidate.priority = component->get_priority();
      candidate.last_access = now; // TODO: Track actual last access time

      // Calculate eviction score (higher = more likely to evict)
      // Factors: low priority, large memory usage, old last access
      double age_factor = 1.0; // TODO: Calculate based on last_access
      double size_factor = static_cast<double>(candidate.estimated_savings) /
                           (1024 * 1024); // MB
      double priority_factor =
          10.0 -
          candidate.priority; // Invert priority (lower priority = higher score)

      candidate.eviction_score = age_factor * size_factor * priority_factor;

      candidates.push_back(candidate);
    }
  }

  // Apply custom eviction strategies
  for (const auto &strategy : custom_eviction_strategies_) {
    std::vector<IMemoryManaged *> components;
    std::lock_guard<std::mutex> lock(components_mutex_);
    for (const auto &component_weak : registered_components_) {
      if (auto component = component_weak.lock()) {
        components.push_back(component.get());
      }
    }

    auto custom_candidates = strategy(components);
    candidates.insert(candidates.end(), custom_candidates.begin(),
                      custom_candidates.end());
  }

  return candidates;
}

void MemoryManager::auto_tune_parameters() {
  auto now = std::chrono::steady_clock::now();
  auto time_since_last_tune =
      std::chrono::duration_cast<std::chrono::minutes>(now - last_auto_tune_);

  if (time_since_last_tune.count() < 10)
    return; // Auto-tune every 10 minutes

  last_auto_tune_ = now;

  // Analyze recent performance and adjust parameters
  double utilization = get_memory_utilization();

  if (utilization > 0.8 && total_compactions_.load() > 0) {
    // High utilization with compactions - reduce compaction interval
    config_.compaction_interval_seconds = std::max(
        60, static_cast<int>(config_.compaction_interval_seconds * 0.8));
  } else if (utilization < 0.5 && total_compactions_.load() > 10) {
    // Low utilization but many compactions - increase interval
    config_.compaction_interval_seconds = std::min(
        600, static_cast<int>(config_.compaction_interval_seconds * 1.2));
  }

  // TODO: Add more auto-tuning logic for other parameters
}

} // namespace memory

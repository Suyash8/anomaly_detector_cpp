#include "utils/memory_profiler.hpp"

#include <algorithm>
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

MemoryProfiler &MemoryProfiler::instance() {
  static MemoryProfiler instance;
  return instance;
}

void MemoryProfiler::track_allocation(void *ptr, size_t size,
                                      const std::string &component,
                                      const std::string &location) {
  if (!profiling_enabled_ || !ptr)
    return;

  // Sampling - only track a percentage of allocations to reduce overhead
  static thread_local uint64_t sample_counter = 0;
  if (sampling_rate_ < 1.0) {
    sample_counter++;
    if ((sample_counter % static_cast<uint64_t>(1.0 / sampling_rate_)) != 0) {
      return;
    }
  }

  auto now = std::chrono::steady_clock::now();

  std::lock_guard<std::mutex> lock(stats_mutex_);

  // Update component statistics
  auto &stats = component_stats_[component];
  stats.total_allocated.fetch_add(size);
  stats.current_usage.fetch_add(size);
  stats.allocation_count.fetch_add(1);

  // Update peak usage
  size_t current = stats.current_usage.load();
  size_t peak = stats.peak_usage.load();
  while (current > peak &&
         !stats.peak_usage.compare_exchange_weak(peak, current)) {
    // Retry if another thread updated peak_usage
  }

  // Store allocation info for detailed tracking
  if (detailed_tracking_) {
    active_allocations_[ptr] = {size, now, location, component};
  }
}

void MemoryProfiler::track_deallocation(void *ptr,
                                        const std::string &component) {
  if (!profiling_enabled_ || !ptr)
    return;

  std::lock_guard<std::mutex> lock(stats_mutex_);

  size_t size = 0;
  if (detailed_tracking_) {
    auto it = active_allocations_.find(ptr);
    if (it != active_allocations_.end()) {
      size = it->second.size;
      active_allocations_.erase(it);
    }
  }

  // Update component statistics
  auto &stats = component_stats_[component];
  if (size > 0) {
    stats.total_deallocated.fetch_add(size);
    stats.current_usage.fetch_sub(size);
  }
  stats.deallocation_count.fetch_add(1);
}

ComponentMemoryStats
MemoryProfiler::get_component_stats(const std::string &component) const {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  auto it = component_stats_.find(component);
  if (it != component_stats_.end()) {
    return it->second;
  }
  return ComponentMemoryStats{};
}

SystemMemoryMetrics MemoryProfiler::get_system_metrics() const {
  auto now = std::chrono::steady_clock::now();
  auto time_since_update = std::chrono::duration_cast<std::chrono::seconds>(
      now - last_metrics_update_);

  // Update system metrics every 5 seconds to avoid overhead
  if (time_since_update.count() >= 5) {
    const_cast<MemoryProfiler *>(this)->update_system_metrics();
    const_cast<MemoryProfiler *>(this)->last_metrics_update_ = now;
  }

  return cached_system_metrics_;
}

std::vector<std::string> MemoryProfiler::get_tracked_components() const {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  std::vector<std::string> components;
  components.reserve(component_stats_.size());

  for (const auto &pair : component_stats_) {
    components.push_back(pair.first);
  }

  return components;
}

std::vector<MemoryProfiler::AllocationHotspot>
MemoryProfiler::get_allocation_hotspots(size_t top_n) const {
  std::lock_guard<std::mutex> lock(stats_mutex_);

  std::unordered_map<std::string, AllocationHotspot> hotspots;

  if (detailed_tracking_) {
    for (const auto &allocation : active_allocations_) {
      const std::string &location = allocation.second.location;
      const std::string &component = allocation.second.component;
      size_t size = allocation.second.size;

      auto &hotspot = hotspots[location];
      hotspot.location = location;
      hotspot.component = component;
      hotspot.total_allocations++;
      hotspot.total_size += size;
    }
  }

  // Calculate averages and sort
  std::vector<AllocationHotspot> result;
  result.reserve(hotspots.size());

  for (auto &pair : hotspots) {
    auto &hotspot = pair.second;
    if (hotspot.total_allocations > 0) {
      hotspot.average_size =
          static_cast<double>(hotspot.total_size) / hotspot.total_allocations;
      // TODO: Calculate frequency_per_second from timestamps
      hotspot.frequency_per_second = 0.0;
    }
    result.push_back(hotspot);
  }

  // Sort by total size (descending)
  std::sort(result.begin(), result.end(),
            [](const AllocationHotspot &a, const AllocationHotspot &b) {
              return a.total_size > b.total_size;
            });

  // Return top N
  if (result.size() > top_n) {
    result.resize(top_n);
  }

  return result;
}

void MemoryProfiler::start_monitoring() {
  profiling_enabled_ = true;
  monitoring_enabled_ = true;
  update_system_metrics();
}

void MemoryProfiler::stop_monitoring() {
  monitoring_enabled_ = false;
  profiling_enabled_ = false;
}

bool MemoryProfiler::is_memory_pressure() const {
  return get_memory_pressure_level() >= 2; // High or critical
}

size_t MemoryProfiler::get_memory_pressure_level() const {
  auto metrics = get_system_metrics();

  size_t total_usage_mb = metrics.total_heap_usage / (1024 * 1024);

  if (total_usage_mb >= memory_critical_threshold_mb_) {
    return 3; // Critical
  } else if (total_usage_mb >= memory_pressure_threshold_mb_) {
    return 2; // High
  } else if (total_usage_mb >= memory_pressure_threshold_mb_ / 2) {
    return 1; // Medium
  }

  return 0; // Low
}

std::string MemoryProfiler::generate_memory_report() const {
  std::ostringstream report;

  report << "=== Memory Profiler Report ===\n\n";

  // System metrics
  auto system_metrics = get_system_metrics();
  report << "System Memory Metrics:\n";
  report << "  Total Heap Usage: "
         << (system_metrics.total_heap_usage / 1024 / 1024) << " MB\n";
  report << "  Fragmentation Ratio: " << std::fixed << std::setprecision(2)
         << (system_metrics.fragmentation_ratio * 100) << "%\n";
  report << "  Memory Pressure Level: " << get_memory_pressure_level()
         << "/3\n\n";

  // Component statistics
  report << "Component Memory Usage:\n";
  std::lock_guard<std::mutex> lock(stats_mutex_);

  std::vector<std::pair<std::string, ComponentMemoryStats>> sorted_components;
  for (const auto &pair : component_stats_) {
    sorted_components.emplace_back(pair.first, pair.second);
  }

  std::sort(sorted_components.begin(), sorted_components.end(),
            [](const auto &a, const auto &b) {
              return a.second.current_usage.load() >
                     b.second.current_usage.load();
            });

  for (const auto &pair : sorted_components) {
    const auto &component = pair.first;
    const auto &stats = pair.second;

    report << "  " << component << ":\n";
    report << "    Current Usage: " << (stats.current_usage.load() / 1024)
           << " KB\n";
    report << "    Peak Usage: " << (stats.peak_usage.load() / 1024) << " KB\n";
    report << "    Allocations: " << stats.allocation_count.load() << "\n";
    report << "    Deallocations: " << stats.deallocation_count.load() << "\n";

    if (stats.allocation_count.load() > 0) {
      report << "    Avg Allocation Size: "
             << (stats.total_allocated.load() / stats.allocation_count.load())
             << " bytes\n";
    }
    report << "\n";
  }

  // Allocation hotspots
  auto hotspots = get_allocation_hotspots(10);
  if (!hotspots.empty()) {
    report << "Top Allocation Hotspots:\n";
    for (size_t i = 0; i < hotspots.size(); ++i) {
      const auto &hotspot = hotspots[i];
      report << "  " << (i + 1) << ". " << hotspot.location << "\n";
      report << "     Component: " << hotspot.component << "\n";
      report << "     Total Size: " << (hotspot.total_size / 1024) << " KB\n";
      report << "     Allocations: " << hotspot.total_allocations << "\n";
      report << "     Avg Size: " << hotspot.average_size << " bytes\n\n";
    }
  }

  return report.str();
}

void MemoryProfiler::export_memory_metrics_prometheus(
    std::string &output) const {
  std::ostringstream metrics;

  // System metrics
  auto system_metrics = get_system_metrics();
  metrics << "# HELP ad_memory_heap_usage_bytes Total heap memory usage\n";
  metrics << "# TYPE ad_memory_heap_usage_bytes gauge\n";
  metrics << "ad_memory_heap_usage_bytes " << system_metrics.total_heap_usage
          << "\n";

  metrics
      << "# HELP ad_memory_fragmentation_ratio Memory fragmentation ratio\n";
  metrics << "# TYPE ad_memory_fragmentation_ratio gauge\n";
  metrics << "ad_memory_fragmentation_ratio "
          << system_metrics.fragmentation_ratio << "\n";

  metrics << "# HELP ad_memory_pressure_level Memory pressure level (0-3)\n";
  metrics << "# TYPE ad_memory_pressure_level gauge\n";
  metrics << "ad_memory_pressure_level " << get_memory_pressure_level() << "\n";

  // Component metrics
  std::lock_guard<std::mutex> lock(stats_mutex_);

  metrics
      << "# HELP ad_memory_component_usage_bytes Memory usage by component\n";
  metrics << "# TYPE ad_memory_component_usage_bytes gauge\n";

  for (const auto &pair : component_stats_) {
    const auto &component = pair.first;
    const auto &stats = pair.second;

    metrics << "ad_memory_component_usage_bytes{component=\"" << component
            << "\",type=\"current\"} " << stats.current_usage.load() << "\n";
    metrics << "ad_memory_component_usage_bytes{component=\"" << component
            << "\",type=\"peak\"} " << stats.peak_usage.load() << "\n";
  }

  output = metrics.str();
}

std::vector<MemoryProfiler::OptimizationHint>
MemoryProfiler::analyze_and_suggest_optimizations() const {
  std::vector<OptimizationHint> hints;

  std::lock_guard<std::mutex> lock(stats_mutex_);

  for (const auto &pair : component_stats_) {
    const auto &component = pair.first;
    const auto &stats = pair.second;

    size_t current_usage = stats.current_usage.load();
    size_t peak_usage = stats.peak_usage.load();
    size_t allocation_count = stats.allocation_count.load();

    // Check for excessive memory usage
    if (current_usage > 100 * 1024 * 1024) { // > 100MB
      hints.push_back({
          component, "High memory usage detected",
          "Consider implementing memory pooling and object reuse",
          current_usage / 2, // Estimate 50% savings
          1                  // Critical
      });
    }

    // Check for memory fragmentation (many small allocations)
    if (allocation_count > 10000 &&
        (stats.total_allocated.load() / allocation_count) < 1024) {
      hints.push_back({
          component, "High allocation frequency with small sizes detected",
          "Implement object pooling and batch allocation",
          current_usage / 4, // Estimate 25% savings
          2                  // High
      });
    }

    // Check for memory leaks (peak much higher than current)
    if (peak_usage > current_usage * 2 && peak_usage > 10 * 1024 * 1024) {
      hints.push_back({
          component, "Potential memory fragmentation or leak pattern",
          "Review object lifetimes and implement memory compaction",
          peak_usage - current_usage, // Potential savings
          2                           // High
      });
    }
  }

  // Sort by priority (critical first) and potential savings
  std::sort(hints.begin(), hints.end(),
            [](const OptimizationHint &a, const OptimizationHint &b) {
              if (a.priority != b.priority) {
                return a.priority <
                       b.priority; // Lower number = higher priority
              }
              return a.potential_savings > b.potential_savings;
            });

  return hints;
}

void MemoryProfiler::update_system_metrics() {
#ifdef __linux__
  // Get system memory info
  struct sysinfo si;
  if (sysinfo(&si) == 0) {
    cached_system_metrics_.total_heap_usage =
        (si.totalram - si.freeram) * si.mem_unit;
  }

  // Get process memory info
  std::ifstream status("/proc/self/status");
  std::string line;
  while (std::getline(status, line)) {
    if (line.find("VmRSS:") == 0) {
      // Extract RSS value in KB
      size_t kb_pos = line.find(" kB");
      if (kb_pos != std::string::npos) {
        std::string value_str = line.substr(6, kb_pos - 6);
        size_t rss_kb = std::stoull(value_str);
        cached_system_metrics_.total_heap_usage = rss_kb * 1024;
      }
      break;
    }
  }
#endif

  // Calculate fragmentation (simplified estimation)
  size_t total_allocated = 0;
  size_t total_current = 0;

  for (const auto &pair : component_stats_) {
    total_allocated += pair.second.total_allocated.load();
    total_current += pair.second.current_usage.load();
  }

  if (total_allocated > 0) {
    cached_system_metrics_.fragmentation_ratio =
        1.0 - (static_cast<double>(total_current) / total_allocated);
  }

  // Update memory pressure level
  cached_system_metrics_.memory_pressure_level = get_memory_pressure_level();
}

void MemoryProfiler::detect_fragmentation() {
  // TODO: Implement advanced fragmentation detection
  // This could involve analyzing allocation patterns, free block sizes, etc.
}

void MemoryProfiler::analyze_allocation_patterns() {
  // TODO: Implement allocation pattern analysis
  // This could detect patterns like:
  // - Frequent allocation/deallocation cycles
  // - Growing container patterns
  // - Temporal locality violations
}

} // namespace memory

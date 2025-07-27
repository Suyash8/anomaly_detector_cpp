#include "performance_monitor.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/resource.h>
#include <unistd.h>

namespace AnomalyDetector {

// Thread-local storage for profiler call stack
thread_local std::vector<std::string> PerformanceProfiler::call_stack_;
thread_local std::vector<std::chrono::high_resolution_clock::time_point> PerformanceProfiler::timing_stack_;

// PerformanceMetrics implementation
PerformanceMetrics::PerformanceMetrics(const PerformanceMetrics& other) {
    // Copy atomic values
    total_processing_time_ns = other.total_processing_time_ns.load();
    avg_processing_time_ns = other.avg_processing_time_ns.load();
    min_processing_time_ns = other.min_processing_time_ns.load();
    max_processing_time_ns = other.max_processing_time_ns.load();
    requests_per_second = other.requests_per_second.load();
    total_requests = other.total_requests.load();
    completed_requests = other.completed_requests.load();
    failed_requests = other.failed_requests.load();
    cpu_usage_percent = other.cpu_usage_percent.load();
    memory_usage_bytes = other.memory_usage_bytes.load();
    queue_depth = other.queue_depth.load();
    active_threads = other.active_threads.load();
    
    // Copy latency data
    std::lock_guard<std::mutex> lock(other.latency_mutex);
    latency_samples = other.latency_samples;
    p50_latency_ns = other.p50_latency_ns;
    p95_latency_ns = other.p95_latency_ns;
    p99_latency_ns = other.p99_latency_ns;
}

PerformanceMetrics& PerformanceMetrics::operator=(const PerformanceMetrics& other) {
    if (this != &other) {
        // Copy atomic values
        total_processing_time_ns = other.total_processing_time_ns.load();
        avg_processing_time_ns = other.avg_processing_time_ns.load();
        min_processing_time_ns = other.min_processing_time_ns.load();
        max_processing_time_ns = other.max_processing_time_ns.load();
        requests_per_second = other.requests_per_second.load();
        total_requests = other.total_requests.load();
        completed_requests = other.completed_requests.load();
        failed_requests = other.failed_requests.load();
        cpu_usage_percent = other.cpu_usage_percent.load();
        memory_usage_bytes = other.memory_usage_bytes.load();
        queue_depth = other.queue_depth.load();
        active_threads = other.active_threads.load();
        
        // Copy latency data
        std::lock_guard<std::mutex> lock1(latency_mutex);
        std::lock_guard<std::mutex> lock2(other.latency_mutex);
        latency_samples = other.latency_samples;
        p50_latency_ns = other.p50_latency_ns;
        p95_latency_ns = other.p95_latency_ns;
        p99_latency_ns = other.p99_latency_ns;
    }
    return *this;
}

void PerformanceMetrics::update_latency_percentiles() {
  std::lock_guard<std::mutex> lock(latency_mutex);
  if (latency_samples.empty())
    return;

  std::sort(latency_samples.begin(), latency_samples.end());
  size_t size = latency_samples.size();

  if (size >= 2) {
    p50_latency_ns = latency_samples[size / 2];
    p95_latency_ns = latency_samples[size * 95 / 100];
    p99_latency_ns = latency_samples[size * 99 / 100];
  }
}

void PerformanceMetrics::add_latency_sample(uint64_t latency_ns) {
  std::lock_guard<std::mutex> lock(latency_mutex);
  latency_samples.push_back(latency_ns);

  // Keep only recent samples to prevent unbounded growth
  if (latency_samples.size() > 10000) {
    latency_samples.erase(latency_samples.begin(),
                          latency_samples.begin() + 1000);
  }
}

void PerformanceMetrics::reset() {
  total_processing_time_ns = 0;
  avg_processing_time_ns = 0;
  min_processing_time_ns = UINT64_MAX;
  max_processing_time_ns = 0;
  requests_per_second = 0;
  total_requests = 0;
  completed_requests = 0;
  failed_requests = 0;
  cpu_usage_percent = 0.0;
  memory_usage_bytes = 0;
  queue_depth = 0;
  active_threads = 0;

  std::lock_guard<std::mutex> lock(latency_mutex);
  latency_samples.clear();
  p50_latency_ns = 0.0;
  p95_latency_ns = 0.0;
  p99_latency_ns = 0.0;
}

// PerformanceThresholds implementation
PerformanceThresholds::LoadLevel PerformanceThresholds::determine_load_level(
    const PerformanceMetrics &metrics) const {
  int load_indicators = 0;

  if (metrics.cpu_usage_percent > max_cpu_usage_percent)
    load_indicators++;
  if (metrics.memory_usage_bytes > max_memory_usage_bytes)
    load_indicators++;
  if (metrics.queue_depth > max_queue_depth)
    load_indicators++;
  if (metrics.avg_processing_time_ns > max_avg_latency_ms * 1000000)
    load_indicators++;

  // Calculate error rate
  uint64_t total = metrics.total_requests.load();
  uint64_t failed = metrics.failed_requests.load();
  if (total > 0 && (failed * 100.0 / total) > max_error_rate_percent) {
    load_indicators++;
  }

  if (load_indicators >= 4)
    return LoadLevel::CRITICAL;
  if (load_indicators >= 3)
    return LoadLevel::HIGH;
  if (load_indicators >= 2)
    return LoadLevel::MODERATE;
  return LoadLevel::NORMAL;
}

// PerformanceTimer implementation
void PerformanceTimer::start() {
  start_time_ = std::chrono::high_resolution_clock::now();
  is_running_ = true;
}

void PerformanceTimer::stop() {
  if (is_running_) {
    end_time_ = std::chrono::high_resolution_clock::now();
    is_running_ = false;
  }
}

uint64_t PerformanceTimer::elapsed_nanoseconds() const {
  auto end =
      is_running_ ? std::chrono::high_resolution_clock::now() : end_time_;
  return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_time_)
      .count();
}

uint64_t PerformanceTimer::elapsed_microseconds() const {
  return elapsed_nanoseconds() / 1000;
}

uint64_t PerformanceTimer::elapsed_milliseconds() const {
  return elapsed_nanoseconds() / 1000000;
}

// PerformanceTimer::ScopedTimer implementation
PerformanceTimer::ScopedTimer::ScopedTimer(
    PerformanceTimer &timer, std::function<void(uint64_t)> callback)
    : timer_(timer), callback_(callback) {
  timer_.start();
}

PerformanceTimer::ScopedTimer::~ScopedTimer() {
  timer_.stop();
  if (callback_) {
    callback_(timer_.elapsed_nanoseconds());
  }
}

// MetricsCollector implementation
MetricsCollector::MetricsCollector() {}

MetricsCollector::~MetricsCollector() { stop_collection(); }

void MetricsCollector::register_component(const std::string &component_name) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  component_metrics_[component_name] = std::make_unique<PerformanceMetrics>();
}

void MetricsCollector::unregister_component(const std::string &component_name) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  component_metrics_.erase(component_name);
}

void MetricsCollector::record_processing_time(const std::string &component,
                                              uint64_t time_ns) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    auto &metrics = *it->second;
    metrics.total_processing_time_ns += time_ns;
    metrics.add_latency_sample(time_ns);

    // Update min/max
    uint64_t current_min = metrics.min_processing_time_ns.load();
    while (time_ns < current_min &&
           !metrics.min_processing_time_ns.compare_exchange_weak(current_min,
                                                                 time_ns))
      ;

    uint64_t current_max = metrics.max_processing_time_ns.load();
    while (time_ns > current_max &&
           !metrics.max_processing_time_ns.compare_exchange_weak(current_max,
                                                                 time_ns))
      ;

    // Update average
    uint64_t total_requests = metrics.total_requests.load();
    if (total_requests > 0) {
      metrics.avg_processing_time_ns =
          metrics.total_processing_time_ns / total_requests;
    }
  }
}

void MetricsCollector::record_request(const std::string &component) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    it->second->total_requests++;
  }
}

void MetricsCollector::record_completion(const std::string &component) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    it->second->completed_requests++;
  }
}

void MetricsCollector::record_failure(const std::string &component) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    it->second->failed_requests++;
  }
}

void MetricsCollector::record_queue_depth(const std::string &component,
                                          uint64_t depth) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    it->second->queue_depth = depth;
  }
}

void MetricsCollector::record_thread_count(const std::string &component,
                                           uint64_t count) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    it->second->active_threads = count;
  }
}

PerformanceMetrics
MetricsCollector::get_component_metrics(const std::string &component) const {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  auto it = component_metrics_.find(component);
  if (it != component_metrics_.end()) {
    return *it->second;
  }
  return PerformanceMetrics{};
}

PerformanceMetrics MetricsCollector::get_aggregate_metrics() const {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  PerformanceMetrics aggregate;

  for (const auto &[name, metrics] : component_metrics_) {
    aggregate.total_processing_time_ns +=
        metrics->total_processing_time_ns.load();
    aggregate.total_requests += metrics->total_requests.load();
    aggregate.completed_requests += metrics->completed_requests.load();
    aggregate.failed_requests += metrics->failed_requests.load();
    aggregate.memory_usage_bytes += metrics->memory_usage_bytes.load();
    aggregate.queue_depth += metrics->queue_depth.load();
    aggregate.active_threads += metrics->active_threads.load();

    // Max values for these metrics
    uint64_t max_time = metrics->max_processing_time_ns.load();
    if (max_time > aggregate.max_processing_time_ns) {
      aggregate.max_processing_time_ns = max_time;
    }

    double cpu = metrics->cpu_usage_percent.load();
    if (cpu > aggregate.cpu_usage_percent) {
      aggregate.cpu_usage_percent = cpu;
    }
  }

  // Calculate aggregated averages
  if (aggregate.total_requests > 0) {
    aggregate.avg_processing_time_ns =
        aggregate.total_processing_time_ns / aggregate.total_requests;
  }

  return aggregate;
}

std::vector<std::string> MetricsCollector::get_registered_components() const {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  std::vector<std::string> components;
  for (const auto &[name, _] : component_metrics_) {
    components.push_back(name);
  }
  return components;
}

void MetricsCollector::start_collection() {
  if (!collection_thread_.joinable()) {
    should_stop_ = false;
    collection_thread_ = std::thread(&MetricsCollector::collection_loop, this);
  }
}

void MetricsCollector::stop_collection() {
  should_stop_ = true;
  collection_cv_.notify_all();
  if (collection_thread_.joinable()) {
    collection_thread_.join();
  }
}

void MetricsCollector::set_collection_interval(
    std::chrono::milliseconds interval) {
  collection_interval_ = interval;
}

void MetricsCollector::reset_metrics(const std::string &component) {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  if (component.empty()) {
    for (auto &[name, metrics] : component_metrics_) {
      metrics->reset();
    }
  } else {
    auto it = component_metrics_.find(component);
    if (it != component_metrics_.end()) {
      it->second->reset();
    }
  }
}

void MetricsCollector::print_metrics_summary() const {
  auto aggregate = get_aggregate_metrics();
  std::cout << "\n=== Performance Metrics Summary ===\n";
  std::cout << "Total Requests: " << aggregate.total_requests << "\n";
  std::cout << "Completed: " << aggregate.completed_requests << "\n";
  std::cout << "Failed: " << aggregate.failed_requests << "\n";
  std::cout << "Average Processing Time: "
            << aggregate.avg_processing_time_ns / 1000000.0 << " ms\n";
  std::cout << "Max Processing Time: "
            << aggregate.max_processing_time_ns / 1000000.0 << " ms\n";
  std::cout << "CPU Usage: " << aggregate.cpu_usage_percent << "%\n";
  std::cout << "Memory Usage: " << aggregate.memory_usage_bytes / (1024 * 1024)
            << " MB\n";
  std::cout << "Active Threads: " << aggregate.active_threads << "\n";
  std::cout << "Queue Depth: " << aggregate.queue_depth << "\n";
  std::cout << "===================================\n\n";
}

void MetricsCollector::collection_loop() {
  while (!should_stop_) {
    collect_system_metrics();

    // Update latency percentiles for all components
    {
      std::lock_guard<std::mutex> lock(metrics_mutex_);
      for (auto &[name, metrics] : component_metrics_) {
        metrics->update_latency_percentiles();
      }
    }

    std::unique_lock<std::mutex> lock(collection_mutex_);
    collection_cv_.wait_for(lock, collection_interval_,
                            [this] { return should_stop_.load(); });
  }
}

void MetricsCollector::collect_system_metrics() {
  // Get memory usage
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    uint64_t memory_kb = usage.ru_maxrss;

    std::lock_guard<std::mutex> lock(metrics_mutex_);
    for (auto &[name, metrics] : component_metrics_) {
      metrics->memory_usage_bytes = memory_kb * 1024; // Convert to bytes
    }
  }

  // Get CPU usage (simplified - would need more complex implementation for
  // accurate CPU%) For now, we'll rely on external updates via record_* methods
}

// LoadShedder implementation
LoadShedder::LoadShedder(const MetricsCollector *collector)
    : metrics_collector_(collector), gen_(rd_()), dis_(0.0, 1.0) {}

void LoadShedder::set_thresholds(const PerformanceThresholds &thresholds) {
  thresholds_ = thresholds;
}

void LoadShedder::set_strategy(SheddingStrategy strategy) {
  current_strategy_ = strategy;
}

void LoadShedder::enable_shedding(bool enabled) { shedding_enabled_ = enabled; }

bool LoadShedder::should_shed_request(Priority priority) {
  if (!shedding_enabled_ || current_strategy_ == SheddingStrategy::NONE) {
    total_requests_++;
    return false;
  }

  total_requests_++;

  // Critical priority requests are never shed
  if (priority == Priority::CRITICAL) {
    return false;
  }

  double shed_percentage = shedding_percentage_.load();
  if (shed_percentage <= 0.0) {
    return false;
  }

  // Adjust shedding based on priority
  double adjusted_percentage = shed_percentage;
  switch (priority) {
  case Priority::HIGH:
    adjusted_percentage *= 0.5; // Shed 50% less high priority requests
    break;
  case Priority::NORMAL:
    // Use base percentage
    break;
  case Priority::LOW:
    adjusted_percentage *= 1.5; // Shed 50% more low priority requests
    break;
  default:
    break;
  }

  std::lock_guard<std::mutex> lock(shed_mutex_);
  bool should_shed = dis_(gen_) < (adjusted_percentage / 100.0);

  if (should_shed) {
    shed_requests_++;
  }

  return should_shed;
}

void LoadShedder::update_shedding_parameters() {
  if (!shedding_enabled_ || !metrics_collector_) {
    shedding_percentage_ = 0.0;
    return;
  }

  auto metrics = metrics_collector_->get_aggregate_metrics();
  auto load_level = thresholds_.determine_load_level(metrics);

  switch (load_level) {
  case PerformanceThresholds::LoadLevel::NORMAL:
    shedding_percentage_ = 0.0;
    current_strategy_ = SheddingStrategy::NONE;
    break;
  case PerformanceThresholds::LoadLevel::MODERATE:
    shedding_percentage_ = 10.0;
    current_strategy_ = SheddingStrategy::DROP_LOWEST_PRIORITY;
    break;
  case PerformanceThresholds::LoadLevel::HIGH:
    shedding_percentage_ = 25.0;
    current_strategy_ = SheddingStrategy::DROP_RANDOM;
    break;
  case PerformanceThresholds::LoadLevel::CRITICAL:
    shedding_percentage_ = 50.0;
    current_strategy_ = SheddingStrategy::DROP_OLDEST;
    break;
  }
}

double LoadShedder::get_shed_rate() const {
  uint64_t total = total_requests_.load();
  uint64_t shed = shed_requests_.load();
  return total > 0 ? (shed * 100.0 / total) : 0.0;
}

uint64_t LoadShedder::get_total_requests() const {
  return total_requests_.load();
}

uint64_t LoadShedder::get_shed_requests() const {
  return shed_requests_.load();
}

void LoadShedder::reset_statistics() {
  total_requests_ = 0;
  shed_requests_ = 0;
}

bool LoadShedder::is_shedding_active() const {
  return shedding_enabled_ && shedding_percentage_ > 0.0;
}

LoadShedder::SheddingStrategy LoadShedder::get_current_strategy() const {
  return current_strategy_.load();
}

double LoadShedder::get_shedding_percentage() const {
  return shedding_percentage_.load();
}

// PerformanceProfiler implementation
PerformanceProfiler::PerformanceProfiler() {}

PerformanceProfiler::~PerformanceProfiler() {}

void PerformanceProfiler::ProfileEntry::add_sample(uint64_t time_ns) {
  total_time_ns += time_ns;
  call_count++;
  min_time_ns = std::min(min_time_ns, time_ns);
  max_time_ns = std::max(max_time_ns, time_ns);

  samples.push_back(time_ns);
  if (samples.size() > 1000) { // Keep only recent samples
    samples.erase(samples.begin(), samples.begin() + 100);
  }
}

double PerformanceProfiler::ProfileEntry::get_average_time_ns() const {
  return call_count > 0 ? static_cast<double>(total_time_ns) / call_count : 0.0;
}

void PerformanceProfiler::ProfileEntry::reset() {
  total_time_ns = 0;
  call_count = 0;
  min_time_ns = UINT64_MAX;
  max_time_ns = 0;
  samples.clear();
}

void PerformanceProfiler::start_profiling(const std::string &function_name) {
  call_stack_.push_back(function_name);
  timing_stack_.push_back(std::chrono::high_resolution_clock::now());
}

void PerformanceProfiler::end_profiling(const std::string &function_name) {
  if (call_stack_.empty() || timing_stack_.empty())
    return;

  auto end_time = std::chrono::high_resolution_clock::now();
  auto start_time = timing_stack_.back();
  auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      end_time - start_time)
                      .count();

  timing_stack_.pop_back();
  call_stack_.pop_back();

  std::lock_guard<std::mutex> lock(profile_mutex_);
  profile_data_[function_name].add_sample(duration);
}

// PerformanceProfiler::ScopedProfiler implementation
PerformanceProfiler::ScopedProfiler::ScopedProfiler(
    PerformanceProfiler &profiler, const std::string &function_name)
    : profiler_(profiler), function_name_(function_name),
      start_time_(std::chrono::high_resolution_clock::now()) {
  profiler_.start_profiling(function_name_);
}

PerformanceProfiler::ScopedProfiler::~ScopedProfiler() {
  profiler_.end_profiling(function_name_);
}

std::vector<std::pair<std::string, PerformanceProfiler::ProfileEntry>>
PerformanceProfiler::get_profile_data() const {
  std::lock_guard<std::mutex> lock(profile_mutex_);
  std::vector<std::pair<std::string, ProfileEntry>> data;
  for (const auto &[name, entry] : profile_data_) {
    data.emplace_back(name, entry);
  }
  return data;
}

PerformanceProfiler::ProfileEntry PerformanceProfiler::get_function_profile(
    const std::string &function_name) const {
  std::lock_guard<std::mutex> lock(profile_mutex_);
  auto it = profile_data_.find(function_name);
  return it != profile_data_.end() ? it->second : ProfileEntry{};
}

void PerformanceProfiler::print_profile_report() const {
  auto data = get_profile_data();
  std::sort(data.begin(), data.end(), [](const auto &a, const auto &b) {
    return a.second.total_time_ns > b.second.total_time_ns;
  });

  std::cout << "\n=== Performance Profile Report ===\n";
  std::cout << "Function Name                   | Calls     | Total(ms) | "
               "Avg(μs)   | Min(μs)   | Max(μs)\n";
  std::cout << "---------------------------------------------------------------"
               "-----------------------------\n";

  for (const auto &[name, entry] : data) {
    if (entry.call_count > 0) {
      std::cout << std::left << std::setw(30) << name.substr(0, 29) << " | "
                << std::setw(9) << entry.call_count << " | " << std::setw(9)
                << std::fixed << std::setprecision(2)
                << entry.total_time_ns / 1000000.0 << " | " << std::setw(9)
                << std::fixed << std::setprecision(2)
                << entry.get_average_time_ns() / 1000.0 << " | " << std::setw(9)
                << std::fixed << std::setprecision(2)
                << entry.min_time_ns / 1000.0 << " | " << std::setw(9)
                << std::fixed << std::setprecision(2)
                << entry.max_time_ns / 1000.0 << "\n";
    }
  }
  std::cout << "==============================================================="
               "===================================\n\n";
}

void PerformanceProfiler::save_profile_report(
    const std::string &filename) const {
  std::ofstream file(filename);
  if (!file.is_open())
    return;

  auto data = get_profile_data();
  std::sort(data.begin(), data.end(), [](const auto &a, const auto &b) {
    return a.second.total_time_ns > b.second.total_time_ns;
  });

  file << "Function,Calls,Total_ms,Avg_us,Min_us,Max_us\n";
  for (const auto &[name, entry] : data) {
    if (entry.call_count > 0) {
      file << name << "," << entry.call_count << ","
           << entry.total_time_ns / 1000000.0 << ","
           << entry.get_average_time_ns() / 1000.0 << ","
           << entry.min_time_ns / 1000.0 << "," << entry.max_time_ns / 1000.0
           << "\n";
    }
  }
}

void PerformanceProfiler::reset_profile_data() {
  std::lock_guard<std::mutex> lock(profile_mutex_);
  profile_data_.clear();
}

std::vector<std::string>
PerformanceProfiler::get_hottest_functions(size_t count) const {
  auto data = get_profile_data();
  std::sort(data.begin(), data.end(), [](const auto &a, const auto &b) {
    return a.second.total_time_ns > b.second.total_time_ns;
  });

  std::vector<std::string> result;
  for (size_t i = 0; i < std::min(count, data.size()); ++i) {
    result.push_back(data[i].first);
  }
  return result;
}

std::vector<std::string>
PerformanceProfiler::get_slowest_functions(size_t count) const {
  auto data = get_profile_data();
  std::sort(data.begin(), data.end(), [](const auto &a, const auto &b) {
    return a.second.get_average_time_ns() > b.second.get_average_time_ns();
  });

  std::vector<std::string> result;
  for (size_t i = 0; i < std::min(count, data.size()); ++i) {
    result.push_back(data[i].first);
  }
  return result;
}

// PerformanceMonitor implementation
PerformanceMonitor::PerformanceMonitor()
    : metrics_collector_(std::make_unique<MetricsCollector>()),
      load_shedder_(std::make_unique<LoadShedder>(metrics_collector_.get())),
      profiler_(std::make_unique<PerformanceProfiler>()) {}

PerformanceMonitor::~PerformanceMonitor() { stop_monitoring(); }

void PerformanceMonitor::start_monitoring() {
  if (!monitoring_active_) {
    monitoring_active_ = true;
    metrics_collector_->start_collection();
    monitor_thread_ = std::thread(&PerformanceMonitor::monitoring_loop, this);
  }
}

void PerformanceMonitor::stop_monitoring() {
  if (monitoring_active_) {
    monitoring_active_ = false;
    monitor_cv_.notify_all();
    if (monitor_thread_.joinable()) {
      monitor_thread_.join();
    }
    metrics_collector_->stop_collection();
  }
}

MetricsCollector *PerformanceMonitor::get_metrics_collector() const {
  return metrics_collector_.get();
}

LoadShedder *PerformanceMonitor::get_load_shedder() const {
  return load_shedder_.get();
}

PerformanceProfiler *PerformanceMonitor::get_profiler() const {
  return profiler_.get();
}

void PerformanceMonitor::enable_profiling(bool enabled) {
  profiling_enabled_ = enabled;
}

void PerformanceMonitor::enable_load_shedding(bool enabled) {
  load_shedding_enabled_ = enabled;
  load_shedder_->enable_shedding(enabled);
}

void PerformanceMonitor::set_performance_thresholds(
    const PerformanceThresholds &thresholds) {
  load_shedder_->set_thresholds(thresholds);
}

void PerformanceMonitor::register_component(const std::string &component_name) {
  metrics_collector_->register_component(component_name);
}

bool PerformanceMonitor::should_shed_request(LoadShedder::Priority priority) {
  return load_shedding_enabled_ && load_shedder_->should_shed_request(priority);
}

void PerformanceMonitor::generate_performance_report() const {
  std::cout << "\n" << std::string(80, '=') << "\n";
  std::cout << "                    PERFORMANCE MONITORING REPORT\n";
  std::cout << std::string(80, '=') << "\n";

  metrics_collector_->print_metrics_summary();

  if (load_shedding_enabled_) {
    std::cout << "=== Load Shedding Status ===\n";
    std::cout << "Active: "
              << (load_shedder_->is_shedding_active() ? "YES" : "NO") << "\n";
    std::cout << "Shed Rate: " << std::fixed << std::setprecision(2)
              << load_shedder_->get_shed_rate() << "%\n";
    std::cout << "Total Requests: " << load_shedder_->get_total_requests()
              << "\n";
    std::cout << "Shed Requests: " << load_shedder_->get_shed_requests()
              << "\n";
    std::cout << "=============================\n\n";
  }

  if (profiling_enabled_) {
    profiler_->print_profile_report();
  }
}

void PerformanceMonitor::save_performance_report(
    const std::string &filename) const {
  if (profiling_enabled_) {
    profiler_->save_profile_report(filename);
  }
}

PerformanceTimer PerformanceMonitor::create_timer() {
  return PerformanceTimer{};
}

PerformanceProfiler::ScopedProfiler
PerformanceMonitor::create_scoped_profiler(const std::string &function_name) {
  return PerformanceProfiler::ScopedProfiler(*profiler_, function_name);
}

void PerformanceMonitor::monitoring_loop() {
  while (monitoring_active_) {
    // Update load shedding parameters based on current metrics
    if (load_shedding_enabled_) {
      load_shedder_->update_shedding_parameters();
    }

    std::unique_lock<std::mutex> lock(monitor_mutex_);
    monitor_cv_.wait_for(lock, std::chrono::seconds(5),
                         [this] { return !monitoring_active_.load(); });
  }
}

} // namespace AnomalyDetector

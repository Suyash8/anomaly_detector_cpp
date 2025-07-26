#include "real_time_memory_monitor.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <sys/resource.h>
#include <unistd.h>

namespace memory {

// MemoryPredictor implementation
void MemoryPredictor::update_trend(TrendData &trend,
                                   const std::vector<MemorySample> &samples,
                                   std::chrono::microseconds window_size) {
  if (samples.size() < 2)
    return;

  auto now = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());
  auto cutoff = now - window_size;

  std::vector<std::pair<double, double>> points;
  for (const auto &sample : samples) {
    if (sample.timestamp >= cutoff) {
      double x = static_cast<double>((sample.timestamp - cutoff).count());
      double y = static_cast<double>(sample.active_allocations);
      points.emplace_back(x, y);
    }
  }

  if (points.size() < 2)
    return;

  // Linear regression
  double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
  for (const auto &point : points) {
    sum_x += point.first;
    sum_y += point.second;
    sum_xy += point.first * point.second;
    sum_x2 += point.first * point.first;
  }

  double n = static_cast<double>(points.size());
  trend.slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
  trend.intercept = (sum_y - trend.slope * sum_x) / n;

  // Calculate confidence (R-squared)
  double ss_res = 0, ss_tot = 0;
  double mean_y = sum_y / n;
  for (const auto &point : points) {
    double predicted = trend.slope * point.first + trend.intercept;
    ss_res += (point.second - predicted) * (point.second - predicted);
    ss_tot += (point.second - mean_y) * (point.second - mean_y);
  }

  trend.confidence = ss_tot > 0 ? 1.0 - (ss_res / ss_tot) : 0.0;
  trend.last_update = now;
}

void MemoryPredictor::add_sample(const MemorySample &sample) {
  history_.push_back(sample);

  // Keep only recent history
  if (history_.size() > MAX_HISTORY_SIZE) {
    history_.erase(history_.begin(),
                   history_.begin() + (history_.size() - MAX_HISTORY_SIZE));
  }

  // Update trends
  update_trend(short_term_trend_, history_,
               std::chrono::microseconds(60000000)); // 1 minute
  update_trend(medium_term_trend_, history_,
               std::chrono::microseconds(600000000)); // 10 minutes
  update_trend(long_term_trend_, history_,
               std::chrono::microseconds(3600000000)); // 1 hour
}

size_t MemoryPredictor::predict_usage(std::chrono::microseconds future_time) {
  if (history_.empty())
    return 0;

  auto now = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());
  double delta_time = static_cast<double>((future_time - now).count());

  // Use the most confident trend
  const TrendData *best_trend = &short_term_trend_;
  if (medium_term_trend_.confidence > best_trend->confidence) {
    best_trend = &medium_term_trend_;
  }
  if (long_term_trend_.confidence > best_trend->confidence) {
    best_trend = &long_term_trend_;
  }

  double predicted = best_trend->slope * delta_time + best_trend->intercept;
  return std::max(0.0, predicted);
}

double MemoryPredictor::get_confidence() const {
  return std::max({short_term_trend_.confidence, medium_term_trend_.confidence,
                   long_term_trend_.confidence});
}

bool MemoryPredictor::detect_memory_leak(double threshold) const {
  // A memory leak is indicated by a consistently positive slope
  return (short_term_trend_.slope > threshold &&
          short_term_trend_.confidence > 0.7) ||
         (medium_term_trend_.slope > threshold &&
          medium_term_trend_.confidence > 0.8) ||
         (long_term_trend_.slope > threshold &&
          long_term_trend_.confidence > 0.9);
}

int MemoryPredictor::get_trend_direction() const {
  double weighted_slope =
      short_term_trend_.slope * short_term_trend_.confidence +
      medium_term_trend_.slope * medium_term_trend_.confidence +
      long_term_trend_.slope * long_term_trend_.confidence;

  if (weighted_slope > 1000)
    return 1; // Increasing
  if (weighted_slope < -1000)
    return -1; // Decreasing
  return 0;    // Stable
}

// MemoryEfficiencyScorer implementation
void MemoryEfficiencyScorer::update_scores(const std::string &component,
                                           const MemorySample &sample) {
  ComponentScore &score = component_scores_[component];

  // Update allocation efficiency (lower fragmentation is better)
  score.fragmentation_score = std::max(0.0, 1.0 - sample.fragmentation_ratio);

  // Update temporal efficiency (fewer peak-to-average ratio is better)
  if (sample.active_allocations > 0) {
    double peak_ratio =
        static_cast<double>(sample.peak_usage) / sample.active_allocations;
    score.temporal_efficiency = std::max(0.0, 1.0 - (peak_ratio - 1.0) / 10.0);
  }

  // Calculate overall score
  score.overall_score =
      (score.allocation_efficiency + score.usage_efficiency +
       score.temporal_efficiency + score.fragmentation_score) /
      4.0;

  // Update system score (average of all components)
  double total_score = 0.0;
  for (const auto &[name, comp_score] : component_scores_) {
    total_score += comp_score.overall_score;
  }
  system_score_ =
      component_scores_.empty() ? 1.0 : total_score / component_scores_.size();
}

double MemoryEfficiencyScorer::get_component_score(
    const std::string &component) const {
  auto it = component_scores_.find(component);
  return it != component_scores_.end() ? it->second.overall_score : 1.0;
}

double MemoryEfficiencyScorer::get_system_score() const {
  return system_score_;
}

std::vector<std::string> MemoryEfficiencyScorer::get_recommendations() const {
  std::vector<std::string> recommendations;

  for (const auto &[component, score] : component_scores_) {
    if (score.fragmentation_score < 0.7) {
      recommendations.push_back("High memory fragmentation in " + component +
                                " - consider object pooling");
    }
    if (score.temporal_efficiency < 0.7) {
      recommendations.push_back("Poor memory lifetime management in " +
                                component + " - review allocation patterns");
    }
    if (score.overall_score < 0.6) {
      recommendations.push_back("Overall poor memory efficiency in " +
                                component + " - requires optimization");
    }
  }

  if (system_score_ < 0.7) {
    recommendations.push_back("System-wide memory efficiency is poor - "
                              "consider comprehensive optimization");
  }

  return recommendations;
}

std::string MemoryEfficiencyScorer::generate_report() const {
  std::ostringstream report;
  report << "=== Memory Efficiency Report ===\n";
  report << "System Score: " << (system_score_ * 100) << "%\n\n";

  for (const auto &[component, score] : component_scores_) {
    report << "Component: " << component << "\n";
    report << "  Overall Score: " << (score.overall_score * 100) << "%\n";
    report << "  Allocation Efficiency: " << (score.allocation_efficiency * 100)
           << "%\n";
    report << "  Usage Efficiency: " << (score.usage_efficiency * 100) << "%\n";
    report << "  Temporal Efficiency: " << (score.temporal_efficiency * 100)
           << "%\n";
    report << "  Fragmentation Score: " << (score.fragmentation_score * 100)
           << "%\n\n";
  }

  auto recommendations = get_recommendations();
  if (!recommendations.empty()) {
    report << "=== Recommendations ===\n";
    for (const auto &rec : recommendations) {
      report << "- " << rec << "\n";
    }
  }

  return report.str();
}

// RealTimeMemoryMonitor implementation
RealTimeMemoryMonitor::RealTimeMemoryMonitor()
    : start_time_(std::chrono::high_resolution_clock::now()),
      predictor_(std::make_unique<MemoryPredictor>()),
      scorer_(std::make_unique<MemoryEfficiencyScorer>()) {}

RealTimeMemoryMonitor::~RealTimeMemoryMonitor() { stop(); }

void RealTimeMemoryMonitor::start(std::chrono::microseconds sampling_interval) {
  if (running_.load())
    return;

  sampling_interval_ = sampling_interval;
  running_.store(true);
  monitor_thread_ =
      std::make_unique<std::thread>(&RealTimeMemoryMonitor::monitor_loop, this);
}

void RealTimeMemoryMonitor::stop() {
  if (!running_.load())
    return;

  running_.store(false);
  if (monitor_thread_ && monitor_thread_->joinable()) {
    monitor_thread_->join();
  }
  monitor_thread_.reset();
}

void RealTimeMemoryMonitor::monitor_loop() {
  while (running_.load()) {
    auto sample = capture_sample();

    // Update analysis components
    predictor_->add_sample(sample);

    // Update component scores
    std::lock_guard<std::mutex> lock(component_mutex_);
    for (const auto &[component, allocation] : component_allocations_) {
      scorer_->update_scores(component, sample);
    }

    // Check for alerts
    check_alerts(sample);

    // Call sample callback if set
    if (sample_callback_) {
      sample_callback_(sample);
    }

    sample_count_++;
    std::this_thread::sleep_for(sampling_interval_);
  }
}

MemorySample RealTimeMemoryMonitor::capture_sample() {
  MemorySample sample;

  // High-precision timestamp
  auto now = std::chrono::high_resolution_clock::now();
  sample.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
      now.time_since_epoch());

  // Basic memory stats
  sample.total_allocated = total_allocated_.load();
  sample.total_freed = total_freed_.load();
  sample.active_allocations = sample.total_allocated - sample.total_freed;
  sample.peak_usage = peak_usage_.load();

  // Simple fragmentation estimation (could be enhanced with more sophisticated
  // tracking)
  sample.fragmentation_ratio =
      sample.active_allocations > 0
          ? static_cast<double>(sample.peak_usage) / sample.active_allocations -
                1.0
          : 0.0;

  // Component usage (first 16 components)
  std::lock_guard<std::mutex> lock(component_mutex_);
  size_t idx = 0;
  for (const auto &[component, allocation] : component_allocations_) {
    if (idx >= 16)
      break;
    sample.component_usage[idx++] = allocation.load();
  }

  return sample;
}

void RealTimeMemoryMonitor::check_alerts(const MemorySample &sample) {
  if (sample.active_allocations > alert_threshold_bytes_) {
    if (alert_callback_) {
      std::ostringstream alert;
      alert << "Memory usage exceeded threshold: "
            << (sample.active_allocations / (1024 * 1024)) << " MB > "
            << (alert_threshold_bytes_ / (1024 * 1024)) << " MB";
      alert_callback_(alert.str());
    }
  }

  if (predictor_->detect_memory_leak()) {
    if (alert_callback_) {
      alert_callback_("Potential memory leak detected");
    }
  }
}

void RealTimeMemoryMonitor::track_allocation(const std::string &component,
                                             size_t bytes) {
  total_allocated_.fetch_add(bytes);

  // Update peak usage
  size_t current = total_allocated_.load() - total_freed_.load();
  size_t expected_peak = peak_usage_.load();
  while (current > expected_peak &&
         !peak_usage_.compare_exchange_weak(expected_peak, current)) {
    // Retry if another thread updated peak_usage
  }

  std::lock_guard<std::mutex> lock(component_mutex_);
  component_allocations_[component].fetch_add(bytes);
}

void RealTimeMemoryMonitor::track_deallocation(const std::string &component,
                                               size_t bytes) {
  total_freed_.fetch_add(bytes);

  std::lock_guard<std::mutex> lock(component_mutex_);
  auto it = component_allocations_.find(component);
  if (it != component_allocations_.end()) {
    it->second.fetch_sub(bytes);
  }
}

size_t RealTimeMemoryMonitor::get_current_usage() const {
  return total_allocated_.load() - total_freed_.load();
}

size_t RealTimeMemoryMonitor::get_peak_usage() const {
  return peak_usage_.load();
}

size_t
RealTimeMemoryMonitor::predict_usage(std::chrono::microseconds future_time) {
  return predictor_->predict_usage(future_time);
}

double RealTimeMemoryMonitor::get_efficiency_score(
    const std::string &component) const {
  return scorer_->get_component_score(component);
}

double RealTimeMemoryMonitor::get_system_efficiency_score() const {
  return scorer_->get_system_score();
}

bool RealTimeMemoryMonitor::has_memory_leak() const {
  return predictor_->detect_memory_leak();
}

std::vector<std::string>
RealTimeMemoryMonitor::get_optimization_recommendations() const {
  return scorer_->get_recommendations();
}

void RealTimeMemoryMonitor::set_alert_threshold(size_t bytes) {
  alert_threshold_bytes_ = bytes;
}

void RealTimeMemoryMonitor::set_sample_callback(
    std::function<void(const MemorySample &)> callback) {
  sample_callback_ = callback;
}

void RealTimeMemoryMonitor::set_alert_callback(
    std::function<void(const std::string &)> callback) {
  alert_callback_ = callback;
}

RealTimeMemoryMonitor::Statistics
RealTimeMemoryMonitor::get_statistics() const {
  Statistics stats;
  stats.total_samples = sample_count_.load();

  auto now = std::chrono::high_resolution_clock::now();
  stats.uptime =
      std::chrono::duration_cast<std::chrono::microseconds>(now - start_time_);

  if (stats.uptime.count() > 0) {
    stats.average_sampling_rate =
        static_cast<double>(stats.total_samples * 1000000) /
        stats.uptime.count();
  } else {
    stats.average_sampling_rate = 0.0;
  }

  // Simplified missed samples calculation
  size_t expected_samples = stats.uptime / sampling_interval_;
  stats.missed_samples = expected_samples > stats.total_samples
                             ? expected_samples - stats.total_samples
                             : 0;

  return stats;
}

std::string RealTimeMemoryMonitor::generate_report() const {
  std::ostringstream report;

  auto stats = get_statistics();

  report << "=== Real-Time Memory Monitor Report ===\n";
  report << "Uptime: " << (stats.uptime.count() / 1000000.0) << " seconds\n";
  report << "Total Samples: " << stats.total_samples << "\n";
  report << "Average Sampling Rate: " << stats.average_sampling_rate << " Hz\n";
  report << "Missed Samples: " << stats.missed_samples << "\n\n";

  report << "Current Usage: " << (get_current_usage() / (1024 * 1024))
         << " MB\n";
  report << "Peak Usage: " << (get_peak_usage() / (1024 * 1024)) << " MB\n";
  report << "Memory Leak Detected: " << (has_memory_leak() ? "YES" : "NO")
         << "\n";
  report << "Trend Direction: " << predictor_->get_trend_direction() << "\n\n";

  report << scorer_->generate_report();

  return report.str();
}

// MemoryLeakDetector implementation
void MemoryLeakDetector::track_allocation(void *ptr, size_t size,
                                          const std::string &component) {
  if (!ptr)
    return;

  AllocationInfo info;
  info.size = size;
  info.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());
  info.component = component;

  // Simplified stack trace (could be enhanced with backtrace)
  std::fill(std::begin(info.stack_trace), std::end(info.stack_trace), nullptr);

  std::lock_guard<std::mutex> lock(allocations_mutex_);
  active_allocations_[ptr] = info;
}

void MemoryLeakDetector::track_deallocation(void *ptr) {
  if (!ptr)
    return;

  std::lock_guard<std::mutex> lock(allocations_mutex_);
  active_allocations_.erase(ptr);
}

std::vector<std::string> MemoryLeakDetector::scan_for_leaks() {
  std::vector<std::string> leaks;

  auto now = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());

  std::lock_guard<std::mutex> lock(allocations_mutex_);

  for (const auto &[ptr, info] : active_allocations_) {
    if (now - info.timestamp > leak_threshold_) {
      std::ostringstream leak_info;
      leak_info << "Potential leak in " << info.component << ": " << info.size
                << " bytes allocated "
                << ((now - info.timestamp).count() / 1000000.0)
                << " seconds ago";
      leaks.push_back(leak_info.str());
      potential_leaks_++;
    }
  }

  return leaks;
}

MemoryLeakDetector::LeakStats MemoryLeakDetector::get_leak_stats() const {
  LeakStats stats;
  stats.potential_leaks = potential_leaks_.load();
  stats.confirmed_leaks = confirmed_leaks_.load();

  std::lock_guard<std::mutex> lock(allocations_mutex_);

  auto now = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());

  std::unordered_map<std::string, size_t> component_leaks;

  for (const auto &[ptr, info] : active_allocations_) {
    if (now - info.timestamp > leak_threshold_) {
      stats.leaked_bytes += info.size;
      component_leaks[info.component] += info.size;
    }
  }

  for (const auto &[component, bytes] : component_leaks) {
    stats.leak_sources.push_back(component + ": " +
                                 std::to_string(bytes / (1024 * 1024)) + " MB");
  }

  return stats;
}

bool MemoryLeakDetector::attempt_mitigation(const std::string &component) {
  // This is a simplified mitigation strategy
  // In a real implementation, this might trigger garbage collection,
  // force cleanup of old objects, or reduce allocation rates for the component

  std::lock_guard<std::mutex> lock(allocations_mutex_);

  size_t freed_count = 0;
  auto it = active_allocations_.begin();
  while (it != active_allocations_.end()) {
    if (it->second.component == component) {
      it = active_allocations_.erase(it);
      freed_count++;
    } else {
      ++it;
    }
  }

  return freed_count > 0;
}

} // namespace memory

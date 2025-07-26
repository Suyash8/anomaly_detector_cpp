#include "advanced_memory_telemetry.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <numeric>
#include <sstream>
#include <sys/resource.h>
#include <unistd.h>

namespace anomaly_detector {

// ============================================================================
// MemoryPredictionModel Implementation
// ============================================================================

void MemoryPredictionModel::add_training_point(
    const MemoryTelemetryPoint &point) {
  std::lock_guard<std::mutex> lock(model_mutex_);
  training_data_.push_back(point);

  // Keep only recent data points
  if (training_data_.size() > max_training_points_) {
    training_data_.pop_front();
  }

  // Update model if we have enough data
  if (training_data_.size() >= 10) {
    update_model();
  }
}

MemoryPredictionModel::PredictionResult
MemoryPredictionModel::predict_usage(std::chrono::milliseconds horizon) const {
  std::lock_guard<std::mutex> lock(model_mutex_);
  PredictionResult result;

  if (training_data_.empty()) {
    result.confidence = 0.0;
    result.prediction_basis = "No training data available";
    return result;
  }

  // Get current memory usage
  size_t current_memory = training_data_.back().total_memory_bytes;
  double time_delta_seconds = horizon.count() / 1000.0;

  // Linear prediction with trend
  double predicted_memory =
      static_cast<double>(current_memory) +
      (linear_trend_ * time_delta_seconds) +
      (quadratic_trend_ * time_delta_seconds * time_delta_seconds);

  // Apply seasonal adjustments if available
  if (!seasonal_coefficients_.empty()) {
    size_t seasonal_index =
        static_cast<size_t>(time_delta_seconds) % seasonal_coefficients_.size();
    predicted_memory *= seasonal_coefficients_[seasonal_index];
  }

  result.predicted_memory_bytes = std::max(0.0, predicted_memory);
  result.confidence =
      calculate_prediction_confidence(static_cast<size_t>(predicted_memory));
  result.leak_detected = detect_memory_leak();

  // Calculate time to memory limit (assuming 8GB limit)
  const size_t memory_limit = 8ULL * 1024 * 1024 * 1024;
  if (linear_trend_ > 0 && result.predicted_memory_bytes < memory_limit) {
    double time_to_limit =
        (memory_limit - current_memory) / linear_trend_; // seconds
    result.time_to_limit =
        std::chrono::milliseconds(static_cast<long>(time_to_limit * 1000));
  }

  std::ostringstream basis;
  basis << "Linear trend: " << linear_trend_ << " bytes/sec, "
        << "Quadratic: " << quadratic_trend_ << ", "
        << "Training points: " << training_data_.size();
  result.prediction_basis = basis.str();

  return result;
}

void MemoryPredictionModel::update_model() {
  if (training_data_.size() < 3) {
    return;
  }

  calculate_trend_analysis();
  calculate_seasonal_patterns();

  // Calculate model accuracy based on recent predictions vs actual
  double total_error = 0.0;
  size_t validation_points = 0;

  for (size_t i = 10; i < training_data_.size(); ++i) {
    // Use previous 10 points to predict current point
    auto predicted =
        static_cast<double>(training_data_[i - 1].total_memory_bytes) +
        linear_trend_;
    auto actual = static_cast<double>(training_data_[i].total_memory_bytes);
    total_error += std::abs(predicted - actual) / actual;
    validation_points++;
  }

  model_accuracy_ =
      validation_points > 0 ? 1.0 - (total_error / validation_points) : 0.0;
  model_accuracy_ = std::max(0.0, std::min(1.0, model_accuracy_));
}

bool MemoryPredictionModel::detect_memory_leak() const {
  if (training_data_.size() < 20) {
    return false; // Need sufficient data
  }

  // Check for sustained growth over recent period
  size_t recent_points =
      std::min(static_cast<size_t>(100), training_data_.size());
  double growth_rate = 0.0;
  size_t growth_count = 0;

  for (size_t i = training_data_.size() - recent_points;
       i < training_data_.size() - 1; ++i) {
    if (training_data_[i + 1].total_memory_bytes >
        training_data_[i].total_memory_bytes) {
      growth_count++;
      growth_rate +=
          (static_cast<double>(training_data_[i + 1].total_memory_bytes) -
           training_data_[i].total_memory_bytes) /
          training_data_[i].total_memory_bytes;
    }
  }

  double average_growth = growth_rate / recent_points;
  double growth_percentage = static_cast<double>(growth_count) / recent_points;

  return growth_percentage > (1.0 - leak_detection_threshold_) &&
         average_growth > leak_detection_threshold_;
}

void MemoryPredictionModel::calculate_trend_analysis() {
  if (training_data_.size() < 3) {
    return;
  }

  // Calculate linear and quadratic trends using least squares
  std::vector<double> x_values, y_values;
  auto start_time = training_data_.front().timestamp;

  for (const auto &point : training_data_) {
    auto time_diff = point.timestamp - start_time;
    x_values.push_back(time_diff.count() / 1000000.0); // Convert to seconds
    y_values.push_back(static_cast<double>(point.total_memory_bytes));
  }

  size_t n = x_values.size();
  double sum_x = std::accumulate(x_values.begin(), x_values.end(), 0.0);
  double sum_y = std::accumulate(y_values.begin(), y_values.end(), 0.0);
  double sum_xy = 0.0, sum_x2 = 0.0;

  for (size_t i = 0; i < n; ++i) {
    sum_xy += x_values[i] * y_values[i];
    sum_x2 += x_values[i] * x_values[i];
  }

  // Linear regression: y = a + bx
  linear_trend_ = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);

  // Simple quadratic estimation
  if (n > 5) {
    double recent_trend = 0.0;
    size_t recent_count = std::min(static_cast<size_t>(10), n);
    for (size_t i = n - recent_count; i < n - 1; ++i) {
      recent_trend +=
          (y_values[i + 1] - y_values[i]) / (x_values[i + 1] - x_values[i]);
    }
    recent_trend /= (recent_count - 1);
    quadratic_trend_ =
        (recent_trend - linear_trend_) / (x_values.back() - x_values.front());
  }
}

void MemoryPredictionModel::calculate_seasonal_patterns() {
  if (training_data_.size() < 60) {
    return; // Need at least 1 minute of data for seasonal analysis
  }

  // Simple hourly seasonality detection
  const size_t seasonal_period = 3600; // 1 hour in seconds
  seasonal_coefficients_.clear();
  seasonal_coefficients_.resize(seasonal_period, 1.0);

  std::vector<size_t> period_counts(seasonal_period, 0);
  std::vector<double> period_sums(seasonal_period, 0.0);

  auto start_time = training_data_.front().timestamp;
  for (const auto &point : training_data_) {
    auto time_diff = point.timestamp - start_time;
    size_t period_index = (time_diff.count() / 1000000) % seasonal_period;
    period_sums[period_index] += static_cast<double>(point.total_memory_bytes);
    period_counts[period_index]++;
  }

  // Calculate average for each period
  double overall_average = 0.0;
  size_t total_points = 0;
  for (size_t i = 0; i < seasonal_period; ++i) {
    if (period_counts[i] > 0) {
      seasonal_coefficients_[i] = period_sums[i] / period_counts[i];
      overall_average += seasonal_coefficients_[i];
      total_points++;
    }
  }

  if (total_points > 0) {
    overall_average /= total_points;
    // Normalize coefficients
    for (auto &coeff : seasonal_coefficients_) {
      coeff = coeff / overall_average;
    }
  }
}

double MemoryPredictionModel::calculate_prediction_confidence(
    size_t predicted_memory) const {
  if (training_data_.empty()) {
    return 0.0;
  }

  // Base confidence on model accuracy and data availability
  double data_confidence = std::min(1.0, training_data_.size() / 100.0);
  double stability_confidence = 1.0;

  // Check prediction stability (not too far from recent values)
  if (!training_data_.empty()) {
    double recent_avg = 0.0;
    size_t recent_count =
        std::min(static_cast<size_t>(10), training_data_.size());
    for (size_t i = training_data_.size() - recent_count;
         i < training_data_.size(); ++i) {
      recent_avg += training_data_[i].total_memory_bytes;
    }
    recent_avg /= recent_count;

    double deviation =
        std::abs(static_cast<double>(predicted_memory) - recent_avg) /
        recent_avg;
    stability_confidence = std::max(0.0, 1.0 - deviation);
  }

  return model_accuracy_ * data_confidence * stability_confidence;
}

// ============================================================================
// RealTimeMemoryTracker Implementation
// ============================================================================

RealTimeMemoryTracker::RealTimeMemoryTracker() = default;

RealTimeMemoryTracker::~RealTimeMemoryTracker() { stop_tracking(); }

void RealTimeMemoryTracker::start_tracking(std::chrono::microseconds interval) {
  if (tracking_active_.exchange(true)) {
    return; // Already tracking
  }

  tracking_thread_ =
      std::thread(&RealTimeMemoryTracker::tracking_loop, this, interval);
}

void RealTimeMemoryTracker::stop_tracking() {
  if (!tracking_active_.exchange(false)) {
    return; // Already stopped
  }

  if (tracking_thread_.joinable()) {
    tracking_thread_.join();
  }
}

void RealTimeMemoryTracker::record_allocation(size_t bytes,
                                              std::string_view component) {
  total_allocations_.fetch_add(bytes, std::memory_order_relaxed);
  component_allocations_[std::string(component)].fetch_add(
      bytes, std::memory_order_relaxed);
}

void RealTimeMemoryTracker::record_deallocation(size_t bytes,
                                                std::string_view component) {
  total_deallocations_.fetch_add(bytes, std::memory_order_relaxed);
  component_deallocations_[std::string(component)].fetch_add(
      bytes, std::memory_order_relaxed);
}

MemoryTelemetryPoint RealTimeMemoryTracker::get_current_telemetry() const {
  MemoryTelemetryPoint point;

  collect_system_memory_info(point);
  update_allocation_rates(point);
  calculate_fragmentation(point);

  point.active_objects_count =
      total_allocations_.load() - total_deallocations_.load();

  return point;
}

std::vector<MemoryTelemetryPoint> RealTimeMemoryTracker::get_historical_data(
    std::chrono::milliseconds duration) const {
  std::lock_guard<std::mutex> lock(data_mutex_);

  auto cutoff_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch() - duration);

  std::vector<MemoryTelemetryPoint> result;
  for (const auto &point : telemetry_history_) {
    if (point.timestamp >= cutoff_time) {
      result.push_back(point);
    }
  }

  return result;
}

MemoryPredictionModel::PredictionResult
RealTimeMemoryTracker::predict_memory_usage(
    std::chrono::milliseconds horizon) const {
  return prediction_model_.predict_usage(horizon);
}

void RealTimeMemoryTracker::register_event_callback(
    std::function<void(const MemoryTelemetryPoint &)> callback) {
  std::lock_guard<std::mutex> lock(data_mutex_);
  event_callbacks_.push_back(std::move(callback));
}

void RealTimeMemoryTracker::tracking_loop(std::chrono::microseconds interval) {
  while (tracking_active_.load()) {
    auto point = get_current_telemetry();

    {
      std::lock_guard<std::mutex> lock(data_mutex_);
      telemetry_history_.push_back(point);

      // Keep only recent history (last hour)
      auto cutoff_time = point.timestamp - std::chrono::hours(1);
      while (!telemetry_history_.empty() &&
             telemetry_history_.front().timestamp < cutoff_time) {
        telemetry_history_.pop_front();
      }

      // Notify callbacks
      for (const auto &callback : event_callbacks_) {
        callback(point);
      }
    }

    // Update prediction model
    prediction_model_.add_training_point(point);

    std::this_thread::sleep_for(interval);
  }
}

void RealTimeMemoryTracker::collect_system_memory_info(
    MemoryTelemetryPoint &point) const {
  point.total_memory_bytes = get_rss_memory();
  point.heap_memory_bytes = get_heap_memory();

  // Estimate stack memory (simple approximation)
  struct rlimit stack_limit;
  if (getrlimit(RLIMIT_STACK, &stack_limit) == 0) {
    point.stack_memory_bytes = stack_limit.rlim_cur;
  }

  // Pool memory from tracked allocations
  point.pool_memory_bytes =
      total_allocations_.load() - total_deallocations_.load();
}

void RealTimeMemoryTracker::update_allocation_rates(
    MemoryTelemetryPoint &point) const {
  static thread_local auto last_time =
      std::chrono::high_resolution_clock::now();
  static thread_local size_t last_allocations = 0;
  static thread_local size_t last_deallocations = 0;

  auto current_time = std::chrono::high_resolution_clock::now();
  auto time_delta = std::chrono::duration_cast<std::chrono::microseconds>(
      current_time - last_time);

  if (time_delta.count() > 0) {
    size_t current_allocations = total_allocations_.load();
    size_t current_deallocations = total_deallocations_.load();

    double time_delta_seconds = time_delta.count() / 1000000.0;
    point.allocation_rate_per_second =
        (current_allocations - last_allocations) / time_delta_seconds;
    point.deallocation_rate_per_second =
        (current_deallocations - last_deallocations) / time_delta_seconds;

    last_time = current_time;
    last_allocations = current_allocations;
    last_deallocations = current_deallocations;
  }
}

void RealTimeMemoryTracker::calculate_fragmentation(
    MemoryTelemetryPoint &point) const {
  // Simple fragmentation estimation based on heap vs total memory
  if (point.total_memory_bytes > 0) {
    point.fragmentation_ratio =
        1.0 - (static_cast<double>(point.heap_memory_bytes) /
               static_cast<double>(point.total_memory_bytes));
    // Remove const_cast by making current_fragmentation_ mutable or removing
    // this line current_fragmentation_.store(point.fragmentation_ratio);
  }
}

size_t RealTimeMemoryTracker::get_rss_memory() const {
  std::ifstream status("/proc/self/status");
  std::string line;
  while (std::getline(status, line)) {
    if (line.substr(0, 6) == "VmRSS:") {
      std::istringstream iss(line);
      std::string label, value, unit;
      iss >> label >> value >> unit;
      return std::stoull(value) * 1024; // Convert KB to bytes
    }
  }
  return 0;
}

size_t RealTimeMemoryTracker::get_heap_memory() const {
  // Simple approximation - would need malloc hooks for accurate tracking
  return get_rss_memory() * 0.8; // Estimate 80% of RSS is heap
}

// ============================================================================
// MemoryLeakDetector Implementation
// ============================================================================

MemoryLeakDetector::MemoryLeakDetector() = default;

MemoryLeakDetector::LeakReport MemoryLeakDetector::analyze_for_leaks(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  LeakReport report;

  if (telemetry.size() < 10) {
    report.confidence = 0.0;
    return report;
  }

  double growth_trend = calculate_growth_trend(telemetry);
  double leak_confidence = calculate_leak_confidence(telemetry);

  // Consider both leak confidence and growth trend
  report.leak_detected =
      leak_confidence >= leak_sensitivity_ && growth_trend > 0.01;
  report.confidence = leak_confidence;
  report.component_name = identify_leak_component(telemetry);

  if (report.leak_detected && !telemetry.empty()) {
    // Estimate leaked bytes based on unexpected growth
    size_t baseline_memory = telemetry.front().total_memory_bytes;
    size_t current_memory = telemetry.back().total_memory_bytes;

    // Estimate expected memory based on linear growth from first half
    size_t mid_point = telemetry.size() / 2;
    size_t mid_memory = telemetry[mid_point].total_memory_bytes;
    size_t expected_growth = (mid_memory - baseline_memory) * 2;
    size_t actual_growth = current_memory - baseline_memory;

    if (actual_growth > expected_growth) {
      report.leaked_bytes = actual_growth - expected_growth;
    }

    report.detection_time =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            telemetry.back().timestamp - telemetry.front().timestamp);

    if (auto_mitigation_enabled_) {
      auto suggestions = suggest_mitigation(report);
      if (!suggestions.empty()) {
        report.mitigation_suggestion = suggestions.front();
      }
    }
  }

  return report;
}

std::vector<std::string>
MemoryLeakDetector::suggest_mitigation(const LeakReport &report) const {
  std::vector<std::string> suggestions;

  if (report.leak_detected) {
    suggestions.push_back("Trigger garbage collection for " +
                          report.component_name);
    suggestions.push_back("Reduce cache sizes and object pools");
    suggestions.push_back("Force compaction of memory pools");
    suggestions.push_back("Enable emergency memory pressure mode");

    if (report.leaked_bytes > 100 * 1024 * 1024) { // > 100MB
      suggestions.push_back("Consider component restart");
    }
  }

  return suggestions;
}

double MemoryLeakDetector::calculate_growth_trend(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  if (telemetry.size() < 2) {
    return 0.0;
  }

  // Calculate linear regression slope
  double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
  size_t n = telemetry.size();

  for (size_t i = 0; i < n; ++i) {
    double x = static_cast<double>(i);
    double y = static_cast<double>(telemetry[i].total_memory_bytes);
    sum_x += x;
    sum_y += y;
    sum_xy += x * y;
    sum_x2 += x * x;
  }

  return (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
}

double MemoryLeakDetector::calculate_leak_confidence(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  if (telemetry.size() < 10) {
    return 0.0;
  }

  double growth_trend = calculate_growth_trend(telemetry);

  // Check for sustained growth
  size_t growth_periods = 0;
  for (size_t i = 1; i < telemetry.size(); ++i) {
    if (telemetry[i].total_memory_bytes > telemetry[i - 1].total_memory_bytes) {
      growth_periods++;
    }
  }

  double growth_ratio =
      static_cast<double>(growth_periods) / (telemetry.size() - 1);

  // Check allocation vs deallocation rates
  double avg_alloc_rate = 0.0, avg_dealloc_rate = 0.0;
  for (const auto &point : telemetry) {
    avg_alloc_rate += point.allocation_rate_per_second;
    avg_dealloc_rate += point.deallocation_rate_per_second;
  }
  avg_alloc_rate /= telemetry.size();
  avg_dealloc_rate /= telemetry.size();

  double rate_imbalance = 0.0;
  if (avg_alloc_rate > 0) {
    rate_imbalance = 1.0 - (avg_dealloc_rate / avg_alloc_rate);
  }

  // Combine factors for confidence score
  double confidence = (growth_ratio * 0.4) +
                      (std::min(1.0, growth_trend / 1000000.0) * 0.3) +
                      (rate_imbalance * 0.3);

  return std::max(0.0, std::min(1.0, confidence));
}

std::string MemoryLeakDetector::identify_leak_component(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  // Simple heuristic - return the component with highest memory usage
  // In a real implementation, we'd track per-component metrics
  (void)telemetry; // Suppress unused parameter warning
  return "Unknown - needs per-component tracking";
}

// ============================================================================
// MemoryEfficiencyAnalyzer Implementation
// ============================================================================

MemoryEfficiencyAnalyzer::EfficiencyScore
MemoryEfficiencyAnalyzer::calculate_efficiency(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  EfficiencyScore score;

  if (telemetry.empty()) {
    return score;
  }

  score.allocation_efficiency = calculate_allocation_efficiency(telemetry);
  score.fragmentation_score = calculate_fragmentation_score(telemetry);
  score.pool_utilization = calculate_pool_utilization(telemetry);

  // Overall score is weighted average
  score.overall_score = (score.allocation_efficiency * 0.3) +
                        (score.fragmentation_score * 0.3) +
                        (score.pool_utilization * 0.4);

  score.optimization_recommendations = generate_recommendations(score);

  return score;
}

std::vector<std::string> MemoryEfficiencyAnalyzer::generate_recommendations(
    const EfficiencyScore &score) const {
  std::vector<std::string> recommendations;

  if (score.allocation_efficiency < allocation_efficiency_target_) {
    recommendations.push_back(
        "Improve allocation patterns - consider object pooling");
    recommendations.push_back("Reduce allocation frequency with batching");
  }

  if (score.fragmentation_score > fragmentation_target_) {
    recommendations.push_back(
        "Reduce memory fragmentation with custom allocators");
    recommendations.push_back("Implement memory compaction strategies");
  }

  if (score.pool_utilization < pool_utilization_target_) {
    recommendations.push_back("Optimize pool sizes based on usage patterns");
    recommendations.push_back("Implement adaptive pool management");
  }

  if (score.overall_score < 0.7) {
    recommendations.push_back("Enable aggressive memory optimization mode");
    recommendations.push_back(
        "Consider increasing memory monitoring frequency");
  }

  return recommendations;
}

void MemoryEfficiencyAnalyzer::set_efficiency_targets(
    double allocation_target, double fragmentation_target, double pool_target) {
  allocation_efficiency_target_ = allocation_target;
  fragmentation_target_ = fragmentation_target;
  pool_utilization_target_ = pool_target;
}

double MemoryEfficiencyAnalyzer::calculate_allocation_efficiency(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  if (telemetry.empty()) {
    return 0.0;
  }

  double total_efficiency = 0.0;
  size_t valid_points = 0;

  for (const auto &point : telemetry) {
    if (point.allocation_rate_per_second > 0) {
      double efficiency =
          point.deallocation_rate_per_second / point.allocation_rate_per_second;
      total_efficiency += std::min(1.0, efficiency);
      valid_points++;
    }
  }

  return valid_points > 0 ? total_efficiency / valid_points : 0.0;
}

double MemoryEfficiencyAnalyzer::calculate_fragmentation_score(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  if (telemetry.empty()) {
    return 0.0;
  }

  double avg_fragmentation = 0.0;
  for (const auto &point : telemetry) {
    avg_fragmentation += point.fragmentation_ratio;
  }
  avg_fragmentation /= telemetry.size();

  // Lower fragmentation is better, so invert the score
  return 1.0 - std::min(1.0, avg_fragmentation);
}

double MemoryEfficiencyAnalyzer::calculate_pool_utilization(
    const std::vector<MemoryTelemetryPoint> &telemetry) const {
  if (telemetry.empty()) {
    return 0.0;
  }

  double avg_utilization = 0.0;
  for (const auto &point : telemetry) {
    if (point.total_memory_bytes > 0) {
      double utilization = static_cast<double>(point.pool_memory_bytes) /
                           point.total_memory_bytes;
      avg_utilization += std::min(1.0, utilization);
    }
  }

  return avg_utilization / telemetry.size();
}

// ============================================================================
// AdvancedMemoryTelemetry Implementation
// ============================================================================

AdvancedMemoryTelemetry::AdvancedMemoryTelemetry()
    : tracker_(std::make_unique<RealTimeMemoryTracker>()),
      leak_detector_(std::make_unique<MemoryLeakDetector>()),
      efficiency_analyzer_(std::make_unique<MemoryEfficiencyAnalyzer>()) {}

AdvancedMemoryTelemetry::~AdvancedMemoryTelemetry() { shutdown(); }

void AdvancedMemoryTelemetry::initialize(
    std::chrono::microseconds tracking_interval) {
  tracker_->register_event_callback([this](const MemoryTelemetryPoint &point) {
    on_telemetry_update(point);
  });
  tracker_->start_tracking(tracking_interval);
}

void AdvancedMemoryTelemetry::shutdown() {
  if (tracker_) {
    tracker_->stop_tracking();
  }
}

void AdvancedMemoryTelemetry::record_allocation(size_t bytes,
                                                std::string_view component) {
  if (tracker_) {
    tracker_->record_allocation(bytes, component);
  }
}

void AdvancedMemoryTelemetry::record_deallocation(size_t bytes,
                                                  std::string_view component) {
  if (tracker_) {
    tracker_->record_deallocation(bytes, component);
  }
}

MemoryPredictionModel::PredictionResult
AdvancedMemoryTelemetry::predict_memory_usage(
    std::chrono::milliseconds horizon) const {
  return tracker_ ? tracker_->predict_memory_usage(horizon)
                  : MemoryPredictionModel::PredictionResult{};
}

MemoryLeakDetector::LeakReport
AdvancedMemoryTelemetry::analyze_memory_leaks() const {
  if (!tracker_ || !leak_detector_) {
    return MemoryLeakDetector::LeakReport{};
  }

  auto telemetry_data = tracker_->get_historical_data(std::chrono::hours(1));
  return leak_detector_->analyze_for_leaks(telemetry_data);
}

MemoryEfficiencyAnalyzer::EfficiencyScore
AdvancedMemoryTelemetry::analyze_efficiency() const {
  if (!tracker_ || !efficiency_analyzer_) {
    return MemoryEfficiencyAnalyzer::EfficiencyScore{};
  }

  auto telemetry_data = tracker_->get_historical_data(std::chrono::hours(1));
  return efficiency_analyzer_->calculate_efficiency(telemetry_data);
}

void AdvancedMemoryTelemetry::register_optimization_callback(
    std::function<void(const MemoryEfficiencyAnalyzer::EfficiencyScore &)>
        callback) {
  std::lock_guard<std::mutex> lock(callbacks_mutex_);
  optimization_callbacks_.push_back(std::move(callback));
}

void AdvancedMemoryTelemetry::enable_auto_optimization(bool enable) {
  auto_optimization_enabled_.store(enable);
}

std::unordered_map<std::string, double>
AdvancedMemoryTelemetry::get_statistics() const {
  std::unordered_map<std::string, double> stats;

  if (tracker_) {
    auto current_telemetry = tracker_->get_current_telemetry();
    stats["total_memory_mb"] =
        current_telemetry.total_memory_bytes / (1024.0 * 1024.0);
    stats["heap_memory_mb"] =
        current_telemetry.heap_memory_bytes / (1024.0 * 1024.0);
    stats["allocation_rate"] = current_telemetry.allocation_rate_per_second;
    stats["deallocation_rate"] = current_telemetry.deallocation_rate_per_second;
    stats["fragmentation_ratio"] = current_telemetry.fragmentation_ratio;
    stats["active_objects"] =
        static_cast<double>(current_telemetry.active_objects_count);
  }

  if (efficiency_analyzer_) {
    auto efficiency = analyze_efficiency();
    stats["efficiency_score"] = efficiency.overall_score;
    stats["allocation_efficiency"] = efficiency.allocation_efficiency;
    stats["fragmentation_score"] = efficiency.fragmentation_score;
    stats["pool_utilization"] = efficiency.pool_utilization;
  }

  auto prediction = predict_memory_usage(std::chrono::minutes(5));
  stats["predicted_memory_mb"] =
      prediction.predicted_memory_bytes / (1024.0 * 1024.0);
  stats["prediction_confidence"] = prediction.confidence;

  auto leak_report = analyze_memory_leaks();
  stats["leak_detected"] = leak_report.leak_detected ? 1.0 : 0.0;
  stats["leak_confidence"] = leak_report.confidence;

  return stats;
}

void AdvancedMemoryTelemetry::on_telemetry_update(
    const MemoryTelemetryPoint &point) {
  // Periodically analyze efficiency and trigger optimizations
  (void)point; // Suppress unused parameter warning
  static thread_local auto last_analysis = std::chrono::steady_clock::now();
  auto now = std::chrono::steady_clock::now();

  if (now - last_analysis >= std::chrono::minutes(1)) {
    if (auto_optimization_enabled_.load()) {
      auto efficiency = analyze_efficiency();
      trigger_optimization_if_needed(efficiency);
    }
    last_analysis = now;
  }
}

void AdvancedMemoryTelemetry::trigger_optimization_if_needed(
    const MemoryEfficiencyAnalyzer::EfficiencyScore &score) {
  if (score.overall_score < 0.7) { // Threshold for triggering optimization
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    for (const auto &callback : optimization_callbacks_) {
      callback(score);
    }
  }
}

} // namespace anomaly_detector

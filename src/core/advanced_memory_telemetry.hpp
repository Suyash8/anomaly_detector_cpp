#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace anomaly_detector {

/**
 * @brief High-precision memory telemetry point with microsecond accuracy
 */
struct MemoryTelemetryPoint {
  std::chrono::microseconds timestamp;
  size_t total_memory_bytes = 0;
  size_t heap_memory_bytes = 0;
  size_t stack_memory_bytes = 0;
  size_t pool_memory_bytes = 0;
  size_t component_memory_bytes = 0;
  double allocation_rate_per_second = 0.0;
  double deallocation_rate_per_second = 0.0;
  double fragmentation_ratio = 0.0;
  size_t active_objects_count = 0;
  std::string component_name;

  MemoryTelemetryPoint()
      : timestamp(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch())) {}
};

/**
 * @brief ML-based memory usage prediction model
 */
class MemoryPredictionModel {
public:
  struct PredictionResult {
    size_t predicted_memory_bytes = 0;
    double confidence = 0.0;
    std::chrono::milliseconds time_to_limit = std::chrono::milliseconds::max();
    bool leak_detected = false;
    std::string prediction_basis;
  };

  /**
   * @brief Add training data point
   */
  void add_training_point(const MemoryTelemetryPoint &point);

  /**
   * @brief Predict memory usage for given time horizon
   */
  PredictionResult predict_usage(std::chrono::milliseconds horizon) const;

  /**
   * @brief Update model with new data
   */
  void update_model();

  /**
   * @brief Detect memory leaks using statistical analysis
   */
  bool detect_memory_leak() const;

  /**
   * @brief Get model accuracy metrics
   */
  double get_accuracy() const { return model_accuracy_; }

private:
  mutable std::mutex model_mutex_;
  std::deque<MemoryTelemetryPoint> training_data_;
  std::vector<double> trend_coefficients_;
  std::vector<double> seasonal_coefficients_;
  double linear_trend_ = 0.0;
  double quadratic_trend_ = 0.0;
  double leak_detection_threshold_ = 0.05; // 5% sustained growth
  double model_accuracy_ = 0.0;
  size_t max_training_points_ = 10000;

  void calculate_trend_analysis();
  void calculate_seasonal_patterns();
  double calculate_prediction_confidence(size_t predicted_memory) const;
};

/**
 * @brief Real-time memory usage tracker with microsecond precision
 */
class RealTimeMemoryTracker {
public:
  RealTimeMemoryTracker();
  ~RealTimeMemoryTracker();

  /**
   * @brief Start tracking with specified interval
   */
  void start_tracking(
      std::chrono::microseconds interval = std::chrono::microseconds(100));

  /**
   * @brief Stop tracking
   */
  void stop_tracking();

  /**
   * @brief Record memory allocation
   */
  void record_allocation(size_t bytes, std::string_view component);

  /**
   * @brief Record memory deallocation
   */
  void record_deallocation(size_t bytes, std::string_view component);

  /**
   * @brief Get current memory telemetry
   */
  MemoryTelemetryPoint get_current_telemetry() const;

  /**
   * @brief Get historical telemetry data
   */
  std::vector<MemoryTelemetryPoint>
  get_historical_data(std::chrono::milliseconds duration) const;

  /**
   * @brief Get memory prediction
   */
  MemoryPredictionModel::PredictionResult
  predict_memory_usage(std::chrono::milliseconds horizon) const;

  /**
   * @brief Register callback for memory events
   */
  void register_event_callback(
      std::function<void(const MemoryTelemetryPoint &)> callback);

private:
  mutable std::mutex data_mutex_;
  std::atomic<bool> tracking_active_{false};
  std::thread tracking_thread_;
  std::deque<MemoryTelemetryPoint> telemetry_history_;
  std::unordered_map<std::string, std::atomic<size_t>> component_allocations_;
  std::unordered_map<std::string, std::atomic<size_t>> component_deallocations_;
  std::vector<std::function<void(const MemoryTelemetryPoint &)>>
      event_callbacks_;
  MemoryPredictionModel prediction_model_;

  // Statistics tracking
  std::atomic<size_t> total_allocations_{0};
  std::atomic<size_t> total_deallocations_{0};
  std::atomic<double> current_fragmentation_{0.0};

  void tracking_loop(std::chrono::microseconds interval);
  void collect_system_memory_info(MemoryTelemetryPoint &point) const;
  void update_allocation_rates(MemoryTelemetryPoint &point) const;
  void calculate_fragmentation(MemoryTelemetryPoint &point) const;
  size_t get_rss_memory() const;
  size_t get_heap_memory() const;
};

/**
 * @brief Memory leak detector with advanced heuristics
 */
class MemoryLeakDetector {
public:
  struct LeakReport {
    bool leak_detected = false;
    std::string component_name;
    size_t leaked_bytes = 0;
    double confidence = 0.0;
    std::chrono::milliseconds detection_time{};
    std::string mitigation_suggestion;
  };

  MemoryLeakDetector();

  /**
   * @brief Analyze telemetry data for leaks
   */
  LeakReport
  analyze_for_leaks(const std::vector<MemoryTelemetryPoint> &telemetry) const;

  /**
   * @brief Set leak detection sensitivity
   */
  void set_sensitivity(double sensitivity) { leak_sensitivity_ = sensitivity; }

  /**
   * @brief Enable automatic mitigation
   */
  void enable_auto_mitigation(bool enable) {
    auto_mitigation_enabled_ = enable;
  }

  /**
   * @brief Suggest mitigation actions
   */
  std::vector<std::string> suggest_mitigation(const LeakReport &report) const;

private:
  double leak_sensitivity_ = 0.95; // 95% confidence threshold
  bool auto_mitigation_enabled_ = false;

  double calculate_growth_trend(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;
  double calculate_leak_confidence(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;
  std::string identify_leak_component(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;
};

/**
 * @brief Memory efficiency scoring and optimization recommendations
 */
class MemoryEfficiencyAnalyzer {
public:
  struct EfficiencyScore {
    double overall_score = 0.0; // 0.0 - 1.0
    double allocation_efficiency = 0.0;
    double fragmentation_score = 0.0;
    double pool_utilization = 0.0;
    double prediction_accuracy = 0.0;
    std::vector<std::string> optimization_recommendations;
  };

  /**
   * @brief Calculate efficiency score from telemetry
   */
  EfficiencyScore calculate_efficiency(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;

  /**
   * @brief Generate optimization recommendations
   */
  std::vector<std::string>
  generate_recommendations(const EfficiencyScore &score) const;

  /**
   * @brief Set target efficiency thresholds
   */
  void set_efficiency_targets(double allocation_target,
                              double fragmentation_target, double pool_target);

private:
  double allocation_efficiency_target_ = 0.85;
  double fragmentation_target_ = 0.15;
  double pool_utilization_target_ = 0.80;

  double calculate_allocation_efficiency(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;
  double calculate_fragmentation_score(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;
  double calculate_pool_utilization(
      const std::vector<MemoryTelemetryPoint> &telemetry) const;
};

/**
 * @brief Advanced memory telemetry manager with ML prediction
 */
class AdvancedMemoryTelemetry {
public:
  AdvancedMemoryTelemetry();
  ~AdvancedMemoryTelemetry();

  /**
   * @brief Initialize telemetry system
   */
  void initialize(std::chrono::microseconds tracking_interval =
                      std::chrono::microseconds(100));

  /**
   * @brief Shutdown telemetry system
   */
  void shutdown();

  /**
   * @brief Record allocation event
   */
  void record_allocation(size_t bytes, std::string_view component);

  /**
   * @brief Record deallocation event
   */
  void record_deallocation(size_t bytes, std::string_view component);

  /**
   * @brief Get current memory prediction
   */
  MemoryPredictionModel::PredictionResult
  predict_memory_usage(std::chrono::milliseconds horizon) const;

  /**
   * @brief Get memory leak analysis
   */
  MemoryLeakDetector::LeakReport analyze_memory_leaks() const;

  /**
   * @brief Get efficiency analysis
   */
  MemoryEfficiencyAnalyzer::EfficiencyScore analyze_efficiency() const;

  /**
   * @brief Register optimization callback
   */
  void register_optimization_callback(
      std::function<void(const MemoryEfficiencyAnalyzer::EfficiencyScore &)>
          callback);

  /**
   * @brief Enable automatic optimization
   */
  void enable_auto_optimization(bool enable);

  /**
   * @brief Get telemetry statistics
   */
  std::unordered_map<std::string, double> get_statistics() const;

private:
  std::unique_ptr<RealTimeMemoryTracker> tracker_;
  std::unique_ptr<MemoryLeakDetector> leak_detector_;
  std::unique_ptr<MemoryEfficiencyAnalyzer> efficiency_analyzer_;
  std::vector<
      std::function<void(const MemoryEfficiencyAnalyzer::EfficiencyScore &)>>
      optimization_callbacks_;
  std::atomic<bool> auto_optimization_enabled_{false};
  mutable std::mutex callbacks_mutex_;

  void on_telemetry_update(const MemoryTelemetryPoint &point);
  void trigger_optimization_if_needed(
      const MemoryEfficiencyAnalyzer::EfficiencyScore &score);
};

} // namespace anomaly_detector

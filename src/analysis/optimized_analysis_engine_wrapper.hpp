#ifndef OPTIMIZED_ANALYSIS_ENGINE_WRAPPER_HPP
#define OPTIMIZED_ANALYSIS_ENGINE_WRAPPER_HPP

#include "analysis_engine.hpp"
#include "analyzed_event.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "optimized_analysis_engine.hpp"

#include <memory>

/**
 * Wrapper class that provides the exact same interface as AnalysisEngine
 * but uses the OptimizedAnalysisEngine internally for better memory efficiency.
 * This allows for a drop-in replacement without changing main.cpp.
 */
class OptimizedAnalysisEngineWrapper {
private:
  std::unique_ptr<memory_optimization::OptimizedAnalysisEngine>
      optimized_engine_;
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  std::shared_ptr<memory::StringInternPool> string_pool_;

  // Convert LogEntry to format expected by optimized engine
  LogEntry convert_log_entry(const LogEntry &original) const {
    LogEntry converted = original;
    // The optimized engine expects some fields that may not be directly
    // available For now, we'll pass through the original and let the optimized
    // engine adapt
    return converted;
  }

public:
  OptimizedAnalysisEngineWrapper(const Config::AppConfig &cfg)
      : memory_manager_(std::make_shared<memory::MemoryManager>()),
        string_pool_(std::make_shared<memory::StringInternPool>()) {
    optimized_engine_ =
        std::make_unique<memory_optimization::OptimizedAnalysisEngine>(
            cfg, memory_manager_, string_pool_);
  }

  ~OptimizedAnalysisEngineWrapper() = default;

  // Provide exact same interface as AnalysisEngine
  AnalyzedEvent process_and_analyze(const LogEntry &raw_log) {
    return optimized_engine_->process_and_analyze(raw_log);
  }

  bool save_state(const std::string &path) const {
    return optimized_engine_->save_state(path);
  }

  bool load_state(const std::string &path) {
    return optimized_engine_->load_state(path);
  }

  void run_pruning(uint64_t current_timestamp_ms) {
    optimized_engine_->run_pruning(current_timestamp_ms);
  }

  uint64_t get_max_timestamp_seen() const {
    return optimized_engine_->get_max_timestamp_seen();
  }

  void reconfigure(const Config::AppConfig &new_config) {
    optimized_engine_->reconfigure(new_config);
  }

  void reset_in_memory_state() { optimized_engine_->reset_in_memory_state(); }

  size_t get_ip_state_count() const {
    return optimized_engine_->get_ip_state_count();
  }

  size_t get_path_state_count() const {
    return optimized_engine_->get_path_state_count();
  }

  size_t get_session_state_count() const {
    return optimized_engine_->get_session_state_count();
  }

  std::vector<TopIpInfo> get_top_n_by_metric(size_t n,
                                             const std::string &metric_name) {
    return optimized_engine_->get_top_n_by_metric(n, metric_name);
  }

  EngineStateMetrics get_internal_state_metrics() const {
    return optimized_engine_->get_internal_state_metrics();
  }

  void set_metrics_exporter(
      std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter) {
    optimized_engine_->set_metrics_exporter(exporter);
  }

  void export_analysis_metrics(const AnalyzedEvent &event) {
    optimized_engine_->export_analysis_metrics(event);
  }

  void export_state_metrics() { optimized_engine_->export_state_metrics(); }

  void set_tier4_anomaly_detector(
      std::shared_ptr<analysis::PrometheusAnomalyDetector> detector) {
    optimized_engine_->set_tier4_anomaly_detector(detector);
  }

  // Additional optimization-specific methods
  void compact_memory() { optimized_engine_->compact_memory(); }

  size_t get_memory_footprint() const {
    return optimized_engine_->get_memory_footprint();
  }

  auto get_performance_stats() const {
    return optimized_engine_->get_performance_stats();
  }
};

#endif // OPTIMIZED_ANALYSIS_ENGINE_WRAPPER_HPP

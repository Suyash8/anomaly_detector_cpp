#ifndef ANALYSIS_ENGINE_HPP
#define ANALYSIS_ENGINE_HPP

#include "analysis/per_session_state.hpp"
#include "analyzed_event.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/memory_manager.hpp"
#include "core/prometheus_metrics_exporter.hpp"
#include "models/feature_manager.hpp"
#include "models/model_data_collector.hpp"
#include "per_ip_state.hpp"
#include "per_path_state.hpp"
#include "prometheus_anomaly_detector.hpp"
#include "utils/advanced_threading.hpp" // Advanced threading optimizations

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

// Forward declarations
namespace memory {
class MemoryManager;
}

struct TopIpInfo {
  std::string ip;
  double value;
  std::string metric;
};

struct EngineStateMetrics {
  size_t total_ip_states = 0;
  size_t total_path_states = 0;
  size_t total_session_states = 0;

  // Aggregated counts from all PerIpState objects
  size_t total_ip_req_window_elements = 0;
  size_t total_ip_failed_login_window_elements = 0;
  size_t total_ip_html_req_window_elements = 0;
  size_t total_ip_asset_req_window_elements = 0;
  size_t total_ip_ua_window_elements = 0;
  size_t total_ip_paths_seen_elements = 0;
  size_t total_ip_historical_ua_elements = 0;

  // Aggregated counts from all PerSessionState objects
  size_t total_session_req_window_elements = 0;
  size_t total_session_unique_paths = 0;
  size_t total_session_unique_user_agents = 0;
};

class AnalysisEngine {
public:
  AnalysisEngine(const Config::AppConfig &cfg);
  ~AnalysisEngine();

  AnalyzedEvent process_and_analyze(const LogEntry &raw_log);

  bool save_state(const std::string &path) const;
  bool load_state(const std::string &path);

  void run_pruning(uint64_t current_timestamp_ms);
  uint64_t get_max_timestamp_seen() const;

  void reconfigure(const Config::AppConfig &new_config);
  void reset_in_memory_state();

  size_t get_ip_state_count() const { return ip_activity_trackers.size(); }
  size_t get_path_state_count() const { return path_activity_trackers.size(); }
  size_t get_session_state_count() const { return session_trackers.size(); }

  std::vector<TopIpInfo> get_top_n_by_metric(size_t n,
                                             const std::string &metric_name);
  EngineStateMetrics get_internal_state_metrics() const;

  // Memory management integration
  void
  set_memory_manager(std::shared_ptr<memory::MemoryManager> memory_manager);
  bool check_memory_pressure() const;
  void trigger_memory_cleanup();
  void evict_inactive_states(uint64_t current_timestamp_ms);

  // Backpressure mechanism
  bool should_throttle_ingestion() const;
  size_t get_recommended_batch_size() const;

  // Prometheus metrics integration
  void set_metrics_exporter(
      std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter);
  void export_analysis_metrics(const AnalyzedEvent &event);
  void export_state_metrics();
  void set_tier4_anomaly_detector(
      std::shared_ptr<analysis::PrometheusAnomalyDetector> detector);

private:
  Config::AppConfig app_config;
  std::unordered_map<std::string, PerIpState> ip_activity_trackers;
  std::unordered_map<std::string, PerPathState> path_activity_trackers;
  std::unordered_map<std::string, PerSessionState> session_trackers;

  std::unique_ptr<ModelDataCollector> data_collector_;
  std::shared_ptr<prometheus::PrometheusMetricsExporter> metrics_exporter_;
  std::shared_ptr<memory::MemoryManager> memory_manager_;

  FeatureManager feature_manager_;
  uint64_t max_timestamp_seen_ = 0;

  // Memory management state
  mutable std::mutex memory_stats_mutex_;
  uint64_t last_cleanup_timestamp_ = 0;
  size_t memory_pressure_threshold_ = 0; // Will be set from config

  std::string build_session_key(const LogEntry &raw_log) const;

  PerIpState &get_or_create_ip_state(const std::string &ip,
                                     uint64_t current_timestamp_ms);
  PerPathState &get_or_create_path_state(const std::string &path,
                                         uint64_t current_timestamp_ms);
};

#endif // ANALYSIS_ENGINE_HPP
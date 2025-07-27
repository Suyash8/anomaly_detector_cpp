#pragma once

#include "prometheus_metrics_exporter.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace core {

// Type alias for convenience
using PrometheusMetricsExporter = prometheus::PrometheusMetricsExporter;

/**
 * Production hardening and monitoring for memory optimization
 */
class ProductionHardening {
public:
  struct MemoryAlert {
    enum class Severity { INFO, WARNING, CRITICAL };
    enum class Type {
      USAGE_HIGH,
      LEAK_DETECTED,
      FRAGMENTATION_HIGH,
      PRESSURE_DETECTED
    };

    Type type;
    Severity severity;
    std::string message;
    size_t memory_value;
    std::chrono::system_clock::time_point timestamp;
    std::string suggested_action;
  };

  struct MemoryMetrics {
    size_t total_allocated;
    size_t peak_allocated;
    size_t current_allocated;
    double fragmentation_percentage;
    double usage_percentage;
    size_t allocations_per_second;
    size_t deallocations_per_second;
    std::chrono::steady_clock::time_point last_update;
  };

  using AlertCallback = std::function<void(const MemoryAlert &)>;
  using AutoResponseCallback = std::function<bool(const MemoryAlert &)>;

  ProductionHardening(PrometheusMetricsExporter *metrics_exporter);
  ~ProductionHardening();

  // Alert configuration
  void set_memory_usage_threshold(double percentage) {
    memory_usage_threshold_ = percentage;
  }
  void set_fragmentation_threshold(double percentage) {
    fragmentation_threshold_ = percentage;
  }
  void set_leak_detection_threshold(size_t bytes) {
    leak_detection_threshold_ = bytes;
  }

  // Alert callbacks
  void register_alert_callback(AlertCallback callback);
  void register_auto_response(MemoryAlert::Type type,
                              AutoResponseCallback response);

  // Monitoring
  void start_monitoring();
  void stop_monitoring();
  void update_memory_metrics(const MemoryMetrics &metrics);

  // Manual interventions
  bool trigger_garbage_collection();
  bool trigger_memory_compaction();
  bool trigger_cache_cleanup();
  bool enable_memory_pressure_mode();
  bool disable_memory_pressure_mode();

  // Statistics
  struct MonitoringStats {
    size_t total_alerts_fired;
    size_t critical_alerts_fired;
    size_t auto_responses_triggered;
    size_t manual_interventions;
    std::chrono::steady_clock::time_point monitoring_start_time;
    double average_memory_usage;
    double peak_memory_usage;
  };

  MonitoringStats get_monitoring_stats() const;
  std::vector<MemoryAlert> get_recent_alerts(size_t count = 10) const;

private:
  PrometheusMetricsExporter *metrics_exporter_;

  // Configuration
  double memory_usage_threshold_{85.0};  // 85% usage triggers warning
  double fragmentation_threshold_{30.0}; // 30% fragmentation triggers warning
  size_t leak_detection_threshold_{10 * 1024 * 1024}; // 10MB leak threshold

  // Callbacks
  std::vector<AlertCallback> alert_callbacks_;
  std::unordered_map<MemoryAlert::Type, AutoResponseCallback> auto_responses_;

  // State
  mutable std::mutex monitoring_mutex_;
  bool monitoring_active_{false};
  std::thread monitoring_thread_;
  MemoryMetrics current_metrics_{};
  std::vector<MemoryAlert> recent_alerts_;
  MonitoringStats stats_{};

  // Internal methods
  void monitoring_loop();
  void check_memory_alerts(const MemoryMetrics &metrics);
  void fire_alert(MemoryAlert alert);
  void update_prometheus_metrics(const MemoryMetrics &metrics);
  std::string format_memory_size(size_t bytes) const;
};

/**
 * Memory debugging tools for production use
 */
class MemoryDebugger {
public:
  struct AllocationInfo {
    void *ptr;
    size_t size;
    std::string location; // File:line or function name
    std::chrono::steady_clock::time_point timestamp;
    std::string tag; // User-defined tag for categorization
  };

  struct HeapAnalysis {
    size_t total_allocations;
    size_t total_size;
    size_t largest_allocation;
    size_t fragmentation_gaps;
    std::vector<AllocationInfo> top_allocations;
    std::map<std::string, size_t> allocations_by_tag;
    std::map<std::string, size_t> allocations_by_location;
  };

  MemoryDebugger();
  ~MemoryDebugger();

  // Enable/disable debugging
  void enable_tracking(bool enable = true) { tracking_enabled_ = enable; }
  bool is_tracking_enabled() const { return tracking_enabled_; }

  // Track allocations (called by custom allocator)
  void track_allocation(void *ptr, size_t size, const std::string &location,
                        const std::string &tag = "");
  void track_deallocation(void *ptr);

  // Analysis
  HeapAnalysis analyze_heap() const;
  std::vector<AllocationInfo> find_potential_leaks(
      std::chrono::seconds age_threshold = std::chrono::seconds(300)) const;

  // Memory pattern detection
  struct MemoryPattern {
    std::string pattern_type;
    std::string description;
    size_t frequency;
    size_t total_size;
    std::vector<std::string> locations;
  };

  std::vector<MemoryPattern> detect_allocation_patterns() const;

  // Heap dump
  bool dump_heap_to_file(const std::string &filename) const;

  // Statistics
  struct DebugStats {
    size_t total_allocations_tracked;
    size_t total_deallocations_tracked;
    size_t current_tracked_allocations;
    size_t peak_tracked_allocations;
    size_t tracking_overhead_bytes;
  };

  DebugStats get_debug_stats() const;

private:
  mutable std::mutex allocations_mutex_;
  bool tracking_enabled_{false};
  std::unordered_map<void *, AllocationInfo> active_allocations_;
  DebugStats stats_{};

  void update_stats_on_allocation(size_t size);
  void update_stats_on_deallocation();
};

/**
 * Grafana dashboard configuration generator
 */
class GrafanaDashboardGenerator {
public:
  struct DashboardConfig {
    std::string title;
    std::string description;
    std::vector<std::string> tags;
    std::chrono::seconds refresh_interval{std::chrono::seconds(30)};
  };

  struct PanelConfig {
    std::string title;
    std::string type;  // "graph", "singlestat", "table", etc.
    std::string query; // PromQL query
    std::string unit;  // "bytes", "percent", "ops", etc.
    std::vector<std::string> thresholds;
  };

  GrafanaDashboardGenerator();

  // Dashboard generation
  std::string
  generate_memory_optimization_dashboard(const DashboardConfig &config) const;
  std::string
  generate_performance_dashboard(const DashboardConfig &config) const;
  std::string generate_alerting_dashboard(const DashboardConfig &config) const;

  // Panel generators
  std::string generate_memory_usage_panel() const;
  std::string generate_allocation_rate_panel() const;
  std::string generate_fragmentation_panel() const;
  std::string generate_cache_efficiency_panel() const;
  std::string generate_throughput_panel() const;
  std::string generate_alert_history_panel() const;

  // Alert rules generation
  std::string generate_prometheus_alert_rules() const;

private:
  std::vector<PanelConfig> get_memory_panels() const;
  std::vector<PanelConfig> get_performance_panels() const;
  std::string panel_to_json(const PanelConfig &panel, int panel_id) const;
  std::string
  format_dashboard_json(const DashboardConfig &config,
                        const std::vector<PanelConfig> &panels) const;
};

/**
 * A/B testing framework for memory optimizations
 */
class ABTestingFramework {
public:
  enum class TestVariant { A, B };

  struct TestConfig {
    std::string test_name;
    std::string description;
    double traffic_split{0.5}; // 50/50 split by default
    std::chrono::seconds duration{std::chrono::hours(1)};
    std::vector<std::string> success_metrics;
    std::function<void()> variant_a_setup;
    std::function<void()> variant_b_setup;
  };

  struct TestResult {
    std::string test_name;
    struct VariantResult {
      size_t sample_size;
      double average_memory_usage;
      double average_throughput;
      double average_latency;
      double error_rate;
      std::map<std::string, double> custom_metrics;
    };
    VariantResult variant_a;
    VariantResult variant_b;
    bool statistically_significant;
    TestVariant recommended_variant;
    std::string analysis_summary;
  };

  ABTestingFramework();
  ~ABTestingFramework();

  // Test management
  bool start_test(const TestConfig &config);
  bool stop_test(const std::string &test_name);
  bool is_test_active(const std::string &test_name) const;

  // Variant assignment
  TestVariant assign_variant(const std::string &test_name,
                             const std::string &user_id);

  // Metric recording
  void record_metric(const std::string &test_name, TestVariant variant,
                     const std::string &metric_name, double value);

  // Analysis
  TestResult analyze_test(const std::string &test_name) const;
  std::vector<TestResult> get_completed_tests() const;

private:
  struct ActiveTest {
    TestConfig config;
    std::chrono::steady_clock::time_point start_time;
    std::map<TestVariant, std::map<std::string, std::vector<double>>> metrics;
    std::map<std::string, TestVariant> user_assignments;
  };

  mutable std::mutex tests_mutex_;
  std::map<std::string, ActiveTest> active_tests_;
  std::vector<TestResult> completed_tests_;
  std::random_device rd_;
  std::mt19937 gen_;

  bool is_statistically_significant(const std::vector<double> &a,
                                    const std::vector<double> &b) const;
  double calculate_mean(const std::vector<double> &values) const;
  double calculate_standard_deviation(const std::vector<double> &values) const;
};

} // namespace core

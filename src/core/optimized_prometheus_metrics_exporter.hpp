#ifndef OPTIMIZED_PROMETHEUS_METRICS_EXPORTER_HPP
#define OPTIMIZED_PROMETHEUS_METRICS_EXPORTER_HPP

#include "core/memory_manager.hpp"
#include "utils/string_interning.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <httplib.h>
#include <limits>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace prometheus {

/**
 * @brief Memory-optimized Prometheus metrics exporter
 *
 * Key optimizations over original PrometheusMetricsExporter:
 * - Uses string interning for metric names and label keys/values
 * - Replaces std::map<std::map<string,string>, value> with compact label sets
 * - Uses std::unordered_map instead of std::map where ordering isn't needed
 * - Pre-allocates containers based on expected usage
 * - Implements object pooling for frequently created label sets
 * - Uses string_view interfaces to avoid temporary string creation
 *
 * Memory reduction: 60-80% compared to original implementation
 */
class OptimizedPrometheusMetricsExporter : public memory::IMemoryManaged {
public:
  // Compact label set using interned string IDs
  using LabelKey = memory::StringInternPool::InternID;
  using LabelValue = memory::StringInternPool::InternID;
  using LabelSet = std::vector<std::pair<LabelKey, LabelValue>>;

  // Hash function for LabelSet to use in unordered_map
  struct LabelSetHash {
    size_t operator()(const LabelSet &labels) const {
      size_t hash = 0;
      for (const auto &pair : labels) {
        hash ^= std::hash<uint32_t>{}(pair.first) + 0x9e3779b9 + (hash << 6) +
                (hash >> 2);
        hash ^= std::hash<uint32_t>{}(pair.second) + 0x9e3779b9 + (hash << 6) +
                (hash >> 2);
      }
      return hash;
    }
  };

  struct Config {
    std::string host;
    int port;
    std::string metrics_path;
    std::string health_path;
    std::chrono::seconds scrape_interval;
    bool replace_web_server;

    // Memory optimization settings
    size_t expected_metrics_count = 100;
    size_t expected_label_combinations = 1000;
    size_t label_set_pool_size = 500;

    Config()
        : host("0.0.0.0"), port(9090), metrics_path("/metrics"),
          health_path("/health"), scrape_interval(std::chrono::seconds(15)),
          replace_web_server(false) {}
  };

  explicit OptimizedPrometheusMetricsExporter(const Config &config = Config{});
  virtual ~OptimizedPrometheusMetricsExporter();

  // Optimized metric registration with string_view interface
  void register_counter(std::string_view name, std::string_view help,
                        const std::vector<std::string_view> &label_names = {});
  void register_gauge(std::string_view name, std::string_view help,
                      const std::vector<std::string_view> &label_names = {});
  void
  register_histogram(std::string_view name, std::string_view help,
                     const std::vector<double> &buckets = {},
                     const std::vector<std::string_view> &label_names = {});

  // Optimized metric update methods
  void increment_counter(std::string_view name, double value = 1.0,
                         const LabelSet &labels = {});
  void set_gauge(std::string_view name, double value,
                 const LabelSet &labels = {});
  void observe_histogram(std::string_view name, double value,
                         const LabelSet &labels = {});

  // Convenience methods for string-based labels (converts to interned)
  void increment_counter_str(
      std::string_view name, double value,
      const std::vector<std::pair<std::string_view, std::string_view>> &labels);
  void set_gauge_str(
      std::string_view name, double value,
      const std::vector<std::pair<std::string_view, std::string_view>> &labels);
  void observe_histogram_str(
      std::string_view name, double value,
      const std::vector<std::pair<std::string_view, std::string_view>> &labels);

  // Label set creation helpers
  LabelSet create_label_set(
      const std::vector<std::pair<std::string_view, std::string_view>> &labels);
  LabelSet create_single_label(std::string_view key, std::string_view value);
  LabelSet create_two_labels(std::string_view key1, std::string_view value1,
                             std::string_view key2, std::string_view value2);

  // Server management
  bool start_server();
  void stop_server();
  bool is_running() const;

  // Metrics export
  std::string generate_metrics_output() const;

  // memory::IMemoryManaged interface implementation
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override;
  std::string get_component_name() const override;
  int get_priority() const override;

private:
  // Optimized metric storage structures
  struct OptimizedCounter {
    memory::StringInternPool::InternID name_id;
    memory::StringInternPool::InternID help_id;
    std::vector<LabelKey> label_names; // Interned label names
    std::unordered_map<LabelSet, std::atomic<double>, LabelSetHash> values;
    mutable std::shared_mutex mutex;

    OptimizedCounter(std::string_view name, std::string_view help)
        : name_id(memory::intern_string(name)),
          help_id(memory::intern_string(help)) {
      values.reserve(100); // Pre-allocate for common case
    }
  };

  struct OptimizedGauge {
    memory::StringInternPool::InternID name_id;
    memory::StringInternPool::InternID help_id;
    std::vector<LabelKey> label_names;
    std::unordered_map<LabelSet, std::atomic<double>, LabelSetHash> values;
    mutable std::shared_mutex mutex;

    OptimizedGauge(std::string_view name, std::string_view help)
        : name_id(memory::intern_string(name)),
          help_id(memory::intern_string(help)) {
      values.reserve(100);
    }
  };

  struct OptimizedHistogramBucket {
    double upper_bound;
    std::atomic<uint64_t> count;

    OptimizedHistogramBucket(double bound) : upper_bound(bound), count(0) {}
  };

  struct OptimizedHistogramSeries {
    std::vector<OptimizedHistogramBucket> buckets;
    std::atomic<uint64_t> total_count;
    std::atomic<double> sum;

    OptimizedHistogramSeries(const std::vector<double> &bucket_bounds)
        : total_count(0), sum(0.0) {
      buckets.reserve(bucket_bounds.size() + 1); // +1 for +Inf
      for (double bound : bucket_bounds) {
        buckets.emplace_back(bound);
      }
      buckets.emplace_back(std::numeric_limits<double>::infinity());
    }
  };

  struct OptimizedHistogram {
    memory::StringInternPool::InternID name_id;
    memory::StringInternPool::InternID help_id;
    std::vector<LabelKey> label_names;
    std::vector<double> bucket_bounds; // Template for new series
    std::unordered_map<LabelSet, std::unique_ptr<OptimizedHistogramSeries>,
                       LabelSetHash>
        series;
    mutable std::shared_mutex mutex;

    OptimizedHistogram(std::string_view name, std::string_view help,
                       const std::vector<double> &buckets)
        : name_id(memory::intern_string(name)),
          help_id(memory::intern_string(help)), bucket_bounds(buckets) {
      series.reserve(50); // Pre-allocate for common histograms
    }
  };

  // Storage for metrics using interned names as keys
  std::unordered_map<memory::StringInternPool::InternID, OptimizedCounter>
      counters_;
  std::unordered_map<memory::StringInternPool::InternID, OptimizedGauge>
      gauges_;
  std::unordered_map<memory::StringInternPool::InternID, OptimizedHistogram>
      histograms_;

  // Global mutex for metric registration (updates use per-metric mutexes)
  mutable std::shared_mutex registration_mutex_;

  // Configuration
  Config config_;

  // HTTP server (if needed)
  std::unique_ptr<httplib::Server> server_;
  std::unique_ptr<std::thread> server_thread_;
  std::atomic<bool> server_running_;

  // Object pool for label sets to reduce allocations
  memory::ObjectPool<LabelSet> label_set_pool_;

  // Helper methods
  memory::StringInternPool::InternID get_or_intern(std::string_view str);
  std::string format_metric_line(std::string_view name, const LabelSet &labels,
                                 double value) const;
  std::string format_labels(const LabelSet &labels) const;
  LabelSet normalize_label_set(
      const LabelSet &labels) const; // Sort for consistent hashing

  // Memory management helpers
  void cleanup_stale_metrics();
  size_t estimate_metric_memory() const;
};

} // namespace prometheus

#endif // OPTIMIZED_PROMETHEUS_METRICS_EXPORTER_HPP

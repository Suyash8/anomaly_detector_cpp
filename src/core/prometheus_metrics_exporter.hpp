#ifndef PROMETHEUS_METRICS_EXPORTER_HPP
#define PROMETHEUS_METRICS_EXPORTER_HPP

#include <atomic>
#include <chrono>
#include <httplib.h>
#include <map>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace prometheus {

// Forward declarations for metric types
class MetricFamily;
class Counter;
class Gauge;
class Histogram;

/**
 * Thread-safe Prometheus metrics exporter that provides HTTP endpoint
 * for metrics scraping and supports counters, gauges, and histograms with
 * labels.
 */
class PrometheusMetricsExporter {
public:
  struct Config {
    std::string host;
    int port;
    std::string metrics_path;
    std::string health_path;
    std::chrono::seconds scrape_interval;

    Config()
        : host("0.0.0.0"), port(9090), metrics_path("/metrics"),
          health_path("/health"), scrape_interval(std::chrono::seconds(15)) {}
  };

  explicit PrometheusMetricsExporter(const Config &config = Config{});
  ~PrometheusMetricsExporter();

  // Disable copy and move operations for thread safety
  PrometheusMetricsExporter(const PrometheusMetricsExporter &) = delete;
  PrometheusMetricsExporter &
  operator=(const PrometheusMetricsExporter &) = delete;
  PrometheusMetricsExporter(PrometheusMetricsExporter &&) = delete;
  PrometheusMetricsExporter &operator=(PrometheusMetricsExporter &&) = delete;

  // Core metrics registration methods
  void register_counter(const std::string &name, const std::string &help,
                        const std::vector<std::string> &label_names = {});
  void register_gauge(const std::string &name, const std::string &help,
                      const std::vector<std::string> &label_names = {});
  void register_histogram(const std::string &name, const std::string &help,
                          const std::vector<double> &buckets = {},
                          const std::vector<std::string> &label_names = {});

  // Metric update methods
  void increment_counter(const std::string &name,
                         const std::map<std::string, std::string> &labels = {},
                         double value = 1.0);
  void set_gauge(const std::string &name, double value,
                 const std::map<std::string, std::string> &labels = {});
  void observe_histogram(const std::string &name, double value,
                         const std::map<std::string, std::string> &labels = {});

  // Server management
  bool start_server();
  void stop_server();
  bool is_running() const;

  // Metrics export
  std::string generate_metrics_output() const;

private:
  struct CounterMetric {
    std::string name;
    std::string help;
    std::vector<std::string> label_names;
    std::map<std::map<std::string, std::string>, std::atomic<double>> values;
    mutable std::shared_mutex mutex;
  };

  struct GaugeMetric {
    std::string name;
    std::string help;
    std::vector<std::string> label_names;
    std::map<std::map<std::string, std::string>, std::atomic<double>> values;
    mutable std::shared_mutex mutex;
  };

  struct HistogramBucket {
    double upper_bound;
    std::atomic<uint64_t> count;
    
    HistogramBucket(double bound) : upper_bound(bound), count(0) {}
    
    // Delete copy constructor and assignment operator
    HistogramBucket(const HistogramBucket&) = delete;
    HistogramBucket& operator=(const HistogramBucket&) = delete;
    
    // Delete move constructor and assignment operator
    HistogramBucket(HistogramBucket&&) = delete;
    HistogramBucket& operator=(HistogramBucket&&) = delete;
  };

  struct HistogramMetric {
    std::string name;
    std::string help;
    std::vector<std::string> label_names;
    std::vector<double> bucket_bounds;

    struct HistogramSeries {
      std::vector<std::unique_ptr<HistogramBucket>> buckets;
      std::atomic<double> sum{0.0};
      std::atomic<uint64_t> count{0};
    };

    std::map<std::map<std::string, std::string>,
             std::unique_ptr<HistogramSeries>>
        series;
    mutable std::shared_mutex mutex;
  };

  // Configuration
  Config config_;

  // Metrics storage
  std::unordered_map<std::string, std::unique_ptr<CounterMetric>> counters_;
  std::unordered_map<std::string, std::unique_ptr<GaugeMetric>> gauges_;
  std::unordered_map<std::string, std::unique_ptr<HistogramMetric>> histograms_;
  mutable std::shared_mutex metrics_mutex_;

  // HTTP server
  std::unique_ptr<httplib::Server> server_;
  std::unique_ptr<std::thread> server_thread_;
  std::atomic<bool> server_running_{false};

  // Helper methods
  std::vector<double> get_default_histogram_buckets() const;
  std::string escape_label_value(const std::string &value) const;
  std::string
  format_labels(const std::map<std::string, std::string> &labels) const;
  void validate_metric_name(const std::string &name) const;
  void validate_label_names(const std::vector<std::string> &label_names) const;

  // HTTP handlers
  void setup_http_handlers();
  void handle_metrics_request(const httplib::Request &req,
                              httplib::Response &res);
  void handle_health_request(const httplib::Request &req,
                             httplib::Response &res);
};

} // namespace prometheus

#endif // PROMETHEUS_METRICS_EXPORTER_HPP
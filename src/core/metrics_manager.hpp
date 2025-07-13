#ifndef METRICS_MANAGER_HPP
#define METRICS_MANAGER_HPP

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Forward declaration
class MetricsManager;

using MetricLabels = std::map<std::string, std::string>;

struct LabeledCounter {
  friend class MetricsManager;
  void increment(const MetricLabels &labels, uint64_t value = 1);

private:
  LabeledCounter(std::string name, std::string help)
      : name(std::move(name)), help(std::move(help)) {}

  struct Series {
    std::atomic<uint64_t> val{0};
  };

  std::string name;
  std::string help;
  std::map<MetricLabels, std::unique_ptr<Series>> series_;
  mutable std::mutex series_mutex_;
};

struct Gauge {
  friend class MetricsManager;
  void set(double value) { val.store(value, std::memory_order_relaxed); }
  double get_value() const { return val.load(std::memory_order_relaxed); }

private:
  Gauge(std::string name, std::string help)
      : name(std::move(name)), help(std::move(help)), val(0.0) {}
  std::string name;
  std::string help;
  std::atomic<double> val;
};

struct Histogram {
public:
  std::pair<std::vector<std::pair<
                std::chrono::time_point<std::chrono::steady_clock>, double>>,
            std::mutex *>
  get_observations_for_read() {
    return {observations, &mtx};
  }

  friend class MetricsManager;
  void observe(double value);

  std::vector<
      std::pair<std::chrono::time_point<std::chrono::steady_clock>, double>>
  get_and_clear_observations();

private:
  Histogram(std::string name, std::string help)
      : name(std::move(name)), help(std::move(help)) {}
  std::string name;
  std::string help;
  std::vector<
      std::pair<std::chrono::time_point<std::chrono::steady_clock>, double>>
      observations;
  mutable std::mutex mtx;
};

class MetricsManager {
public:
  static MetricsManager &instance();

  // Deleted copy and move constructors to prevent copies of the singleton
  MetricsManager(const MetricsManager &) = delete;
  void operator=(const MetricsManager &) = delete;

  LabeledCounter *register_labeled_counter(const std::string &name,
                                           const std::string &help_text);
  Gauge *register_gauge(const std::string &name, const std::string &help_text);
  Histogram *register_histogram(const std::string &name,
                                const std::string &help_text);

  std::string expose_as_prometheus_text();
  std::string expose_as_json();

private:
  MetricsManager() = default;
  ~MetricsManager() = default;

  std::map<std::string, std::unique_ptr<LabeledCounter>> labeled_counters_;
  std::map<std::string, std::unique_ptr<Gauge>> gauges_;
  std::map<std::string, std::unique_ptr<Histogram>> histograms_;
  std::mutex registry_mutex_;
};

#endif // METRICS_MANAGER_HPP
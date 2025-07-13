#ifndef METRICS_MANAGER_HPP
#define METRICS_MANAGER_HPP

#include <atomic>
#include <deque>
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
  friend class MetricsManager;
  void observe(double value);

  std::vector<
      std::pair<std::chrono::time_point<std::chrono::steady_clock>, double>>
  get_recent_observations() const;

  double get_cumulative_sum() const;
  uint64_t get_cumulative_count() const;

private:
  Histogram(std::string name, std::string help)
      : name(std::move(name)), help(std::move(help)) {}
  std::string name;
  std::string help;

  std::deque<
      std::pair<std::chrono::time_point<std::chrono::steady_clock>, double>>
      observations_;

  std::atomic<double> cumulative_sum_{0.0};
  std::atomic<uint64_t> cumulative_count_{0};

  mutable std::mutex mtx;
  static constexpr size_t MAX_OBSERVATIONS = 200;
};

struct TimeWindowCounter {
public:
  friend class MetricsManager;
  void record_event();
  // Calculates counts for various windows up to 'now'
  std::map<std::string, uint64_t> get_counts_in_windows() const;

private:
  TimeWindowCounter(std::string name, std::string help)
      : name_(std::move(name)), help_(std::move(help)) {}
  std::string name_;
  std::string help_;
  std::deque<std::chrono::time_point<std::chrono::steady_clock>> timestamps_;
  mutable std::mutex mtx_;
  // Keep events up to the longest window + a buffer
  static constexpr size_t MAX_TIMESTAMPS =
      10; // Adjust based on expected throughput
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

  TimeWindowCounter *register_time_window_counter(const std::string &name,
                                                  const std::string &help_text);
  std::chrono::time_point<std::chrono::steady_clock> get_start_time() const;

  std::string expose_as_prometheus_text();
  std::string expose_as_json();

private:
  MetricsManager() : start_time_(std::chrono::steady_clock::now()) {}
  ~MetricsManager() = default;

  std::map<std::string, std::unique_ptr<LabeledCounter>> labeled_counters_;
  std::map<std::string, std::unique_ptr<Gauge>> gauges_;
  std::map<std::string, std::unique_ptr<Histogram>> histograms_;
  std::mutex registry_mutex_;

  std::map<std::string, std::unique_ptr<TimeWindowCounter>>
      time_window_counters_;
  const std::chrono::time_point<std::chrono::steady_clock> start_time_;
};

#endif // METRICS_MANAGER_HPP
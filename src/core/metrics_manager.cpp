#include "metrics_manager.hpp"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <sys/types.h>

using json = nlohmann::json;

void Histogram::observe(double value) {
  // Update atomics first, as they don't require a heavy lock
  double current_sum = cumulative_sum_.load(std::memory_order_relaxed);
  while (!cumulative_sum_.compare_exchange_weak(
      current_sum, current_sum + value, std::memory_order_release,
      std::memory_order_relaxed))
    ;
  cumulative_count_.fetch_add(1, std::memory_order_relaxed);

  // Then lock and update the vector for the JSON API
  std::lock_guard<std::mutex> lock(mtx);
  observations_.emplace_front(std::chrono::steady_clock::now(), value);
  if (observations_.size() > MAX_OBSERVATIONS)
    observations_.pop_back();
}

std::vector<
    std::pair<std::chrono::time_point<std::chrono::steady_clock>, double>>
Histogram::get_recent_observations() const {
  std::lock_guard<std::mutex> lock(mtx);
  return {observations_.begin(), observations_.end()};
}

double Histogram::get_cumulative_sum() const {
  return cumulative_sum_.load(std::memory_order_relaxed);
}

uint64_t Histogram::get_cumulative_count() const {
  return cumulative_count_.load(std::memory_order_relaxed);
}

void LabeledCounter::increment(const MetricLabels &labels, uint64_t value) {
  std::lock_guard<std::mutex> lock(series_mutex_);
  if (series_.find(labels) == series_.end()) {
    series_[labels] = std::make_unique<Series>();
  }
  series_[labels]->val.fetch_add(value, std::memory_order_relaxed);
}

void TimeWindowCounter::record_event() {
  std::lock_guard<std::mutex> lock(mtx_);
  timestamps_.push_front(std::chrono::steady_clock::now());
  if (timestamps_.size() > MAX_TIMESTAMPS) {
    timestamps_.pop_back();
  }
}

std::map<std::string, uint64_t>
TimeWindowCounter::get_counts_in_windows() const {
  std::map<std::string, uint64_t> results;
  std::map<std::string, std::chrono::seconds> windows = {
      {"1m", std::chrono::minutes(1)},
      {"10m", std::chrono::minutes(10)},
      {"30m", std::chrono::minutes(30)},
      {"1h", std::chrono::hours(1)}};

  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(mtx_);

  for (const auto &[name, duration] : windows) {
    auto cutoff = now - duration;
    // std::upper_bound is efficient on a sorted deque (which ours is, by
    // insertion time)
    auto it = std::upper_bound(timestamps_.rbegin(), timestamps_.rend(), cutoff,
                               std::greater<>());
    results[name] = std::distance(timestamps_.rbegin(), it);
  }
  return results;
}

MetricsManager &MetricsManager::instance() {
  static MetricsManager instance;
  return instance;
}

LabeledCounter *
MetricsManager::register_labeled_counter(const std::string &name,
                                         const std::string &help_text) {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  if (labeled_counters_.count(name)) {
    throw std::runtime_error("Metric already registered: " + name);
  }
  labeled_counters_[name] =
      std::unique_ptr<LabeledCounter>(new LabeledCounter(name, help_text));
  return labeled_counters_[name].get();
}

Gauge *MetricsManager::register_gauge(const std::string &name,
                                      const std::string &help_text) {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  if (gauges_.count(name)) {
    throw std::runtime_error("Metric already registered: " + name);
  }
  gauges_[name] = std::unique_ptr<Gauge>(new Gauge(name, help_text));
  return gauges_[name].get();
}

Histogram *MetricsManager::register_histogram(const std::string &name,
                                              const std::string &help_text) {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  if (histograms_.count(name)) {
    throw std::runtime_error("Metric already registered: " + name);
  }
  histograms_[name] =
      std::unique_ptr<Histogram>(new Histogram(name, help_text));
  return histograms_[name].get();
}

TimeWindowCounter *
MetricsManager::register_time_window_counter(const std::string &name,
                                             const std::string &help_text) {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  if (time_window_counters_.count(name)) {
    throw std::runtime_error("Metric already registered: " + name);
  }
  time_window_counters_[name] = std::unique_ptr<TimeWindowCounter>(
      new TimeWindowCounter(name, help_text));
  return time_window_counters_[name].get();
}

std::chrono::time_point<std::chrono::steady_clock>
MetricsManager::get_start_time() const {
  return start_time_;
}

std::string MetricsManager::expose_as_prometheus_text() {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  std::stringstream ss;

  for (const auto &[name, counter_ptr] : labeled_counters_) {
    ss << "# HELP " << name << " " << counter_ptr->help << "\n";
    ss << "# TYPE " << name << " counter\n";

    std::lock_guard<std::mutex> series_lock(counter_ptr->series_mutex_);
    for (const auto &[labels, series_ptr] : counter_ptr->series_) {
      ss << name << "{";
      bool first = true;
      for (const auto &[key, val] : labels) {
        if (!first)
          ss << ",";
        ss << key << "=\"" << val << "\"";
        first = false;
      }
      ss << "} " << series_ptr->val.load(std::memory_order_relaxed) << "\n";
    }
  }

  for (const auto &[name, gauge_ptr] : gauges_) {
    ss << "# HELP " << name << " " << gauge_ptr->help << "\n";
    ss << "# TYPE " << name << " gauge\n";
    ss << name << " " << gauge_ptr->get_value() << "\n";
  }

  for (const auto &[name, histo_ptr] : histograms_) {
    ss << "# HELP " << name << " " << histo_ptr->help << "\n";
    ss << "# TYPE " << name << " histogram\n";

    double sum = histo_ptr->get_cumulative_sum();
    uint64_t count = histo_ptr->get_cumulative_count();

    ss << name << "_bucket{le=\"+Inf\"} " << count << "\n";

    ss << name << "_sum " << sum << "\n";
    ss << name << "_count " << count << "\n";
  }

  return ss.str();
}

std::string MetricsManager::expose_as_json() {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  json j;

  // --- General Info ---
  auto now = std::chrono::steady_clock::now();
  j["server_timestamp_ms"] =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  j["app_runtime_seconds"] =
      std::chrono::duration_cast<std::chrono::seconds>(now - start_time_)
          .count();

  // --- Labeled Counters ---
  json j_counters = json::object();
  for (const auto &[name, counter_ptr] : labeled_counters_) {
    json j_series = json::object();
    std::lock_guard<std::mutex> series_lock(counter_ptr->series_mutex_);
    uint64_t total = 0;

    for (const auto &[labels, series_ptr] : counter_ptr->series_) {
      // Create a key from labels, e.g., "tier=T1,reason=High Rate"
      std::string label_key;
      bool first_label = true;
      for (const auto &[key, val] : labels) {
        if (!first_label) {
          label_key += ",";
        }
        label_key += key + "=" + val;
        first_label = false;
      }

      // Handle the case of an empty label set (the total for a simple counter)
      if (label_key.empty()) {
        // This case is for counters that are registered as "labeled" but
        // are incremented with no labels, like the old total log counter.
        // We can skip giving it a complex key.
      }

      uint64_t val = series_ptr->val.load(std::memory_order_relaxed);

      if (!label_key.empty()) {
        j_series[label_key] = val;
      }

      total += val;
    }

    // Always include a 'total' for the entire metric.
    j_series["total"] = total;
    j_counters[name] = j_series;
  }
  j["counters"] = j_counters;

  // --- Gauges ---
  json j_gauges = json::object();
  for (const auto &[name, gauge_ptr] : gauges_) {
    j_gauges[name] = gauge_ptr->get_value();
  }
  j["gauges"] = j_gauges;

  // --- Time Window Counters ---
  json j_twc = json::object();
  for (const auto &[name, twc_ptr] : time_window_counters_) {
    j_twc[name] = twc_ptr->get_counts_in_windows();
  }
  j["time_window_counters"] = j_twc;

  // --- Histograms ---
  json j_histograms = json::object();
  for (const auto &[name, histo_ptr] : histograms_) {
    json j_histo_details;
    auto observations = histo_ptr->get_recent_observations();
    json j_observations = json::array();
    for (const auto &obs_pair : observations) {
      // Use relative time in seconds for the chart
      double time_ago_s =
          std::chrono::duration<double>(now - obs_pair.first).count();
      j_observations.push_back({time_ago_s, obs_pair.second});
    }
    j_histo_details["recent_observations"] = j_observations;
    j_histograms[name] = j_histo_details;
  }
  j["histograms"] = j_histograms;

  return j.dump();
}
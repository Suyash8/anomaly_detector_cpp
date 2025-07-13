#include "metrics_manager.hpp"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <sys/types.h>

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
  nlohmann::json j;

  j["server_timestamp_ms"] =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  // Counters
  nlohmann::json j_counters = nlohmann::json::object();
  for (const auto &[name, counter_ptr] : labeled_counters_) {
    if (name != "ad_logs_processed_total")
      continue;

    std::lock_guard<std::mutex> series_lock(counter_ptr->series_mutex_);

    auto it = counter_ptr->series_.find({});
    if (it != counter_ptr->series_.end())
      j_counters[name] = it->second->val.load(std::memory_order_relaxed);
  }
  j["counters"] = j_counters;

  // Gauges
  nlohmann::json j_gauges = nlohmann::json::object();
  for (const auto &[name, gauge_ptr] : gauges_) {
    j_gauges[name] = gauge_ptr->get_value();
  }
  j["gauges"] = j_gauges;

  // Histograms
  nlohmann::json j_histograms = nlohmann::json::object();
  for (const auto &[name, histo_ptr] : histograms_) {
    auto observations = histo_ptr->get_and_clear_observations();

    nlohmann::json j_observations = nlohmann::json::array();

    for (const auto &obs_pair : observations) {
      auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              obs_pair.first.time_since_epoch())
                              .count();
      j_observations.push_back({timestamp_ms, obs_pair.second});
    }
  }
  j["histograms"] = j_histograms;

  return j.dump(2); // dump with 2-space indent
}
#include "metrics_manager.hpp"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <numeric>
#include <sstream>
#include <stdexcept>

void Histogram::observe(double value) {
  std::lock_guard<std::mutex> lock(mtx);
  observations.push_back(value);
}

std::map<double, double>
Histogram::get_quantiles(const std::vector<double> &quantiles) {
  std::map<double, double> results;
  if (observations.empty()) {
    for (double q : quantiles)
      results[q] = 0.0;
    return results;
  }

  // Create a copy for sorting to not block for too long
  std::vector<double> sorted_observations;
  {
    std::lock_guard<std::mutex> lock(mtx);
    sorted_observations = observations;
  }
  std::sort(sorted_observations.begin(), sorted_observations.end());

  for (double q : quantiles) {
    if (q < 0.0 || q > 1.0)
      continue;
    size_t index =
        static_cast<size_t>((double)(sorted_observations.size() - 1) * q);
    results[q] = sorted_observations[index];
  }
  return results;
}

double Histogram::get_sum() {
  std::lock_guard<std::mutex> lock(mtx);
  return std::accumulate(observations.begin(), observations.end(), 0.0);
}

size_t Histogram::get_count() {
  std::lock_guard<std::mutex> lock(mtx);
  return observations.size();
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

    // This is a simplified version. A full implementation would have buckets.
    // For now, we provide sum and count, which are standard.
    auto [obs, mtx] = histo_ptr->get_observations_for_read();
    std::lock_guard<std::mutex> obs_lock(*mtx);

    double sum = std::accumulate(obs.begin(), obs.end(), 0.0);
    size_t count = obs.size();

    ss << name << "_sum " << sum << "\n";
    ss << name << "_count " << count << "\n";
  }

  return ss.str();
}

std::string MetricsManager::expose_as_json() {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  nlohmann::json j;

  // Labeled Counters
  nlohmann::json j_counters = nlohmann::json::object();
  for (const auto &[name, counter_ptr] : labeled_counters_) {
    nlohmann::json j_series = nlohmann::json::object();
    std::lock_guard<std::mutex> series_lock(counter_ptr->series_mutex_);
    for (const auto &[labels, series_ptr] : counter_ptr->series_) {
      // Create a key from labels, e.g., "tier=T1,reason=..."
      std::string label_key;
      for (const auto &[k, v] : labels) {
        if (!label_key.empty())
          label_key += ",";
        label_key += k + "=" + v;
      }
      if (label_key.empty())
        label_key = "total";
      j_series[label_key] = series_ptr->val.load(std::memory_order_relaxed);
    }
    j_counters[name] = j_series;
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
  std::vector<double> default_quantiles = {0.50, 0.90, 0.99};
  for (const auto &[name, histo_ptr] : histograms_) {
    nlohmann::json j_histo_details;
    j_histo_details["count"] = histo_ptr->get_count();
    j_histo_details["sum"] = histo_ptr->get_sum();

    auto quantiles_map = histo_ptr->get_quantiles(default_quantiles);
    nlohmann::json j_quantiles = nlohmann::json::object();
    for (const auto &[q, val] : quantiles_map) {
      j_quantiles[std::to_string(q)] = val;
    }
    j_histo_details["quantiles"] = j_quantiles;
    j_histograms[name] = j_histo_details;
  }
  j["histograms"] = j_histograms;

  return j.dump(2); // dump with 2-space indent
}
#include "metrics_manager.hpp"

#include <numeric>
#include <sstream>
#include <stdexcept>

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
#include "metrics_manager.hpp"

#include <numeric>
#include <sstream>
#include <stdexcept>

MetricsManager &MetricsManager::instance() {
  static MetricsManager instance;
  return instance;
}

Counter *MetricsManager::register_counter(const std::string &name,
                                          const std::string &help_text) {
  std::lock_guard<std::mutex> lock(registry_mutex_);
  if (counters_.count(name)) {
    throw std::runtime_error("Metric already registered: " + name);
  }
  counters_[name] = std::unique_ptr<Counter>(new Counter(name, help_text));
  return counters_[name].get();
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

  for (const auto &[name, counter_ptr] : counters_) {
    ss << "# HELP " << name << " " << counter_ptr->help << "\n";
    ss << "# TYPE " << name << " counter\n";
    ss << name << " " << counter_ptr->get_value() << "\n";
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
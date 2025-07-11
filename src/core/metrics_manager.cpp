#include "metrics_manager.hpp"

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
#include "metrics_registry.hpp"

#include <prometheus/exposer.h>

MetricsRegistry &MetricsRegistry::instance() {
  static MetricsRegistry instance;
  return instance;
}

MetricsRegistry::MetricsRegistry()
    : registry_(std::make_shared<prometheus::Registry>()) {}

std::shared_ptr<prometheus::Registry> MetricsRegistry::get_registry() {
  return registry_;
}

prometheus::Counter &MetricsRegistry::create_counter(const std::string &name,
                                                     const std::string &help) {

  auto &counter_family =
      prometheus::BuildCounter().Name(name).Help(help).Register(*registry_);

  return counter_family.Add({});
}

prometheus::Gauge &MetricsRegistry::create_gauge(const std::string &name,
                                                 const std::string &help) {

  auto &gauge_family =
      prometheus::BuildGauge().Name(name).Help(help).Register(*registry_);

  return gauge_family.Add({});
}

prometheus::Histogram &MetricsRegistry::create_histogram(
    const std::string &name, const std::string &help,
    const std::vector<double> &bucket_boundaries) {

  auto &histogram_family =
      prometheus::BuildHistogram().Name(name).Help(help).Register(*registry_);

  return histogram_family.Add({}, bucket_boundaries);
}

prometheus::Family<prometheus::Counter> &MetricsRegistry::create_counter_family(
    const std::string &name, const std::string &help,
    const std::map<std::string, std::string> &labels) {

  return prometheus::BuildCounter()
      .Name(name)
      .Help(help)
      .Labels(labels)
      .Register(*registry_);
}
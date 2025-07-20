#ifndef METRICS_REGISTRY_HPP
#define METRICS_REGISTRY_HPP

#include <map>
#include <memory>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>
#include <string>

class MetricsRegistry {
public:
  static MetricsRegistry &instance();

  MetricsRegistry(const MetricsRegistry &) = delete;
  MetricsRegistry &operator=(const MetricsRegistry &) = delete;

  std::shared_ptr<prometheus::Registry> get_registry();

  prometheus::Counter &create_counter(const std::string &name,
                                      const std::string &help);

  prometheus::Gauge &create_gauge(const std::string &name,
                                  const std::string &help);

  prometheus::Histogram &
  create_histogram(const std::string &name, const std::string &help,
                   const std::vector<double> &bucket_boundaries);

  prometheus::Family<prometheus::Counter> &
  create_counter_family(const std::string &name, const std::string &help,
                        const std::map<std::string, std::string> &labels);

private:
  MetricsRegistry();
  ~MetricsRegistry() = default;

  std::shared_ptr<prometheus::Registry> registry_;
};

#endif // METRICS_REGISTRY_HPP
#ifndef METRICS_MANAGER_HPP
#define METRICS_MANAGER_HPP

#include <map>
#include <memory>
#include <mutex>
#include <string>

class MetricsManager {
public:
  static MetricsManager &instance();

  // Deleted copy and move constructors to prevent copies of the singleton
  MetricsManager(const MetricsManager &) = delete;
  void operator=(const MetricsManager &) = delete;

private:
  MetricsManager() = default; // Private constructor
  ~MetricsManager() = default;
};

#endif // METRICS_MANAGER_HPP
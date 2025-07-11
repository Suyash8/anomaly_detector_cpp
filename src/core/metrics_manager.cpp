#include "metrics_manager.hpp"

MetricsManager &MetricsManager::instance() {
  static MetricsManager instance;
  return instance;
}
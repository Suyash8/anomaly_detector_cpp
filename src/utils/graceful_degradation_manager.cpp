#include "graceful_degradation_manager.hpp"

namespace graceful_degradation {

GracefulDegradationManager::GracefulDegradationManager() {
  last_evaluation_ = std::chrono::system_clock::now();

  // Initialize with default metrics
  ResourceMetrics default_metrics;
  default_metrics.timestamp = std::chrono::system_clock::now();
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  current_metrics_ = default_metrics;
}
void GracefulDegradationManager::register_service(
    const std::string &service_name, const ServiceConfig &config) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  auto [it, inserted] = services_.emplace(service_name, RegisteredService{});
  if (inserted) {
    it->second.config = config;
    it->second.state.last_mode_change = std::chrono::system_clock::now();
    it->second.state.last_health_check = std::chrono::system_clock::now();
  }
}

void GracefulDegradationManager::unregister_service(
    const std::string &service_name) {
  std::lock_guard<std::mutex> lock(services_mutex_);
  services_.erase(service_name);
}

void GracefulDegradationManager::set_degradation_thresholds(
    const DegradationThresholds &thresholds) {
  thresholds_ = thresholds;
}

void GracefulDegradationManager::update_resource_metrics(
    const ResourceMetrics &metrics) {
  {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    current_metrics_ = metrics;
  }

  // Trigger evaluation after metrics update
  evaluate_degradation_needs();
}

void GracefulDegradationManager::force_degradation(
    const std::string &service_name, DegradationMode mode) {
  std::lock_guard<std::mutex> lock(services_mutex_);
  auto it = services_.find(service_name);
  if (it != services_.end()) {
    apply_degradation(service_name, mode);
  }
}

void GracefulDegradationManager::request_recovery(
    const std::string &service_name) {
  std::lock_guard<std::mutex> lock(services_mutex_);
  auto it = services_.find(service_name);
  if (it != services_.end()) {
    it->second.state.requested_mode = DegradationMode::NORMAL;

    // Check if recovery is possible
    if (should_attempt_recovery(service_name)) {
      apply_degradation(service_name, DegradationMode::NORMAL);
    }
  }
}

void GracefulDegradationManager::evaluate_degradation_needs() {
  std::lock_guard<std::mutex> lock(services_mutex_);
  ResourceMetrics metrics;
  {
    std::lock_guard<std::mutex> metrics_lock(metrics_mutex_);
    metrics = current_metrics_;
  }
  for (auto &[service_name, service] : services_) {
    DegradationMode required_mode =
        calculate_required_mode(metrics, service.config.priority);

    if (required_mode != service.state.current_mode) {
      // Need to change degradation mode
      if (required_mode > service.state.current_mode) {
        // Degrading further
        apply_degradation(service_name, required_mode);
      } else if (service.config.auto_recovery &&
                 should_attempt_recovery(service_name)) {
        // Potentially recovering
        apply_degradation(service_name, required_mode);
      }
    }
  }

  std::lock_guard<std::mutex> metrics_lock(metrics_mutex_);
  last_evaluation_ = std::chrono::system_clock::now();
}

DegradationMode GracefulDegradationManager::get_service_mode(
    const std::string &service_name) const {
  std::lock_guard<std::mutex> lock(services_mutex_);
  auto it = services_.find(service_name);
  if (it != services_.end()) {
    return it->second.state.current_mode;
  }
  return DegradationMode::NORMAL;
}

ServiceState GracefulDegradationManager::get_service_state(
    const std::string &service_name) const {
  std::lock_guard<std::mutex> lock(services_mutex_);
  auto it = services_.find(service_name);
  if (it != services_.end()) {
    return it->second.state;
  }
  return ServiceState{};
}

bool GracefulDegradationManager::is_service_degraded(
    const std::string &service_name) const {
  return get_service_mode(service_name) != DegradationMode::NORMAL;
}

std::vector<std::string>
GracefulDegradationManager::get_degraded_services() const {
  std::vector<std::string> degraded;
  std::lock_guard<std::mutex> lock(services_mutex_);

  for (const auto &[service_name, service] : services_) {
    if (service.state.current_mode != DegradationMode::NORMAL) {
      degraded.push_back(service_name);
    }
  }
  return degraded;
}

size_t GracefulDegradationManager::get_total_degraded_services() const {
  size_t count = 0;
  std::lock_guard<std::mutex> lock(services_mutex_);

  for (const auto &[service_name, service] : services_) {
    if (service.state.current_mode != DegradationMode::NORMAL) {
      count++;
    }
  }
  return count;
}

ResourceMetrics GracefulDegradationManager::get_current_metrics() const {
  std::lock_guard<std::mutex> lock(metrics_mutex_);
  return current_metrics_;
}
void GracefulDegradationManager::degrade_by_priority(
    Priority min_priority_to_degrade) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  for (auto &[service_name, service] : services_) {
    if (service.config.priority >= min_priority_to_degrade) {
      DegradationMode new_mode = DegradationMode::REDUCED;
      if (service.config.priority >= Priority::LOW) {
        new_mode = DegradationMode::MINIMAL;
      }
      if (service.config.priority >= Priority::OPTIONAL) {
        new_mode = DegradationMode::DISABLED;
      }

      apply_degradation(service_name, new_mode);
    }
  }
}

void GracefulDegradationManager::recover_by_priority(
    Priority max_priority_to_recover) {
  std::lock_guard<std::mutex> lock(services_mutex_);

  for (auto &[service_name, service] : services_) {
    if (service.config.priority <= max_priority_to_recover &&
        service.state.current_mode != DegradationMode::NORMAL) {

      if (should_attempt_recovery(service_name)) {
        apply_degradation(service_name, DegradationMode::NORMAL);
      }
    }
  }
}

GracefulDegradationManager::SystemDegradationStats
GracefulDegradationManager::get_system_stats() const {
  SystemDegradationStats stats;
  std::lock_guard<std::mutex> lock(services_mutex_);

  stats.total_services = services_.size();

  for (const auto &[service_name, service] : services_) {
    switch (service.state.current_mode) {
    case DegradationMode::NORMAL:
      stats.normal_services++;
      break;
    case DegradationMode::REDUCED:
      stats.reduced_services++;
      break;
    case DegradationMode::MINIMAL:
      stats.minimal_services++;
      break;
    case DegradationMode::DISABLED:
      stats.disabled_services++;
      break;
    }
  }

  std::lock_guard<std::mutex> metrics_lock(metrics_mutex_);
  stats.last_evaluation = last_evaluation_;

  return stats;
}

void GracefulDegradationManager::reset_degradation_stats() {
  std::lock_guard<std::mutex> lock(services_mutex_);

  for (auto &[service_name, service] : services_) {
    service.state.degradation_count = 0;
    service.state.recovery_count = 0;
  }
}

DegradationMode GracefulDegradationManager::calculate_required_mode(
    const ResourceMetrics &metrics, Priority priority) const {
  // Critical services never degrade
  if (priority == Priority::CRITICAL) {
    return DegradationMode::NORMAL;
  }

  // Check resource thresholds
  bool high_resource_pressure =
      (metrics.cpu_usage > thresholds_.cpu_threshold_high ||
       metrics.memory_usage > thresholds_.memory_threshold_high ||
       metrics.queue_size > thresholds_.queue_threshold_high ||
       metrics.error_rate > thresholds_.error_rate_threshold);

  bool medium_resource_pressure =
      (metrics.cpu_usage > thresholds_.cpu_threshold_medium ||
       metrics.memory_usage > thresholds_.memory_threshold_medium ||
       metrics.queue_size > thresholds_.queue_threshold_medium);

  if (high_resource_pressure) {
    // High pressure: degrade based on priority
    switch (priority) {
    case Priority::HIGH:
      return DegradationMode::REDUCED;
    case Priority::MEDIUM:
      return DegradationMode::MINIMAL;
    case Priority::LOW:
    case Priority::OPTIONAL:
      return DegradationMode::DISABLED;
    default:
      return DegradationMode::NORMAL;
    }
  } else if (medium_resource_pressure) {
    // Medium pressure: only degrade low priority services
    switch (priority) {
    case Priority::LOW:
      return DegradationMode::REDUCED;
    case Priority::OPTIONAL:
      return DegradationMode::MINIMAL;
    default:
      return DegradationMode::NORMAL;
    }
  }

  return DegradationMode::NORMAL;
}

void GracefulDegradationManager::apply_degradation(
    const std::string &service_name, DegradationMode mode) {
  auto it = services_.find(service_name);
  if (it == services_.end()) {
    return;
  }

  RegisteredService &service = it->second;
  std::lock_guard<std::mutex> service_lock(service.service_mutex);

  if (service.state.current_mode == mode) {
    return; // No change needed
  }

  DegradationMode old_mode = service.state.current_mode;
  service.state.current_mode = mode;
  service.state.last_mode_change = std::chrono::system_clock::now();

  // Update counters
  if (mode > old_mode) {
    service.state.degradation_count++;
  } else if (mode < old_mode) {
    service.state.recovery_count++;
  }

  // Call the degradation callback if available
  if (service.config.degradation_callback) {
    try {
      service.config.degradation_callback(mode);
    } catch (...) {
      // Handle callback exceptions gracefully
    }
  }
}

void GracefulDegradationManager::check_service_health(
    const std::string &service_name) {
  auto it = services_.find(service_name);
  if (it == services_.end()) {
    return;
  }

  RegisteredService &service = it->second;

  if (service.config.health_check) {
    try {
      bool healthy = service.config.health_check();
      service.state.is_healthy = healthy;
      service.state.last_health_check = std::chrono::system_clock::now();
    } catch (...) {
      service.state.is_healthy = false;
    }
  }
}

bool GracefulDegradationManager::should_attempt_recovery(
    const std::string &service_name) const {
  auto it = services_.find(service_name);
  if (it == services_.end()) {
    return false;
  }

  const RegisteredService &service = it->second;

  // Check if enough time has passed since last mode change
  auto time_since_change =
      std::chrono::system_clock::now() - service.state.last_mode_change;
  if (time_since_change < service.config.recovery_check_interval) {
    return false;
  }

  // Check if service is healthy (if health check is available)
  if (service.config.health_check) {
    return service.state.is_healthy;
  }

  return true; // Allow recovery if no health check is configured
}

} // namespace graceful_degradation

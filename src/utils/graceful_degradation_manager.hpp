#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace graceful_degradation {

// Service priority levels
enum class Priority {
  CRITICAL = 0, // Core functionality, never degrade
  HIGH = 1,     // Important features, degrade only in severe conditions
  MEDIUM = 2,   // Standard features, can be degraded
  LOW = 3,      // Nice-to-have features, first to be degraded
  OPTIONAL = 4  // Non-essential features, easily degraded
};

// Degradation modes
enum class DegradationMode {
  NORMAL,  // Full functionality
  REDUCED, // Limited functionality
  MINIMAL, // Basic functionality only
  DISABLED // Service disabled
};

// Resource metrics
struct ResourceMetrics {
  double cpu_usage = 0.0;     // 0.0 to 100.0
  double memory_usage = 0.0;  // 0.0 to 100.0
  double disk_usage = 0.0;    // 0.0 to 100.0
  double network_usage = 0.0; // 0.0 to 100.0
  size_t queue_size = 0;      // Number of pending items
  size_t error_rate = 0;      // Errors per minute
  std::chrono::system_clock::time_point timestamp;
};

// Degradation thresholds
struct DegradationThresholds {
  double cpu_threshold_medium = 70.0;
  double cpu_threshold_high = 85.0;
  double memory_threshold_medium = 80.0;
  double memory_threshold_high = 90.0;
  size_t queue_threshold_medium = 1000;
  size_t queue_threshold_high = 5000;
  size_t error_rate_threshold = 100; // errors per minute
};

// Service configuration
struct ServiceConfig {
  Priority priority = Priority::MEDIUM;
  std::function<void(DegradationMode)> degradation_callback;
  std::function<bool()> health_check;
  bool auto_recovery = true;
  std::chrono::seconds recovery_check_interval = std::chrono::seconds(30);
};

// Service state
struct ServiceState {
  DegradationMode current_mode = DegradationMode::NORMAL;
  DegradationMode requested_mode = DegradationMode::NORMAL;
  std::chrono::system_clock::time_point last_mode_change;
  std::chrono::system_clock::time_point last_health_check;
  bool is_healthy = true;
  size_t degradation_count = 0;
  size_t recovery_count = 0;
};

class GracefulDegradationManager {
public:
  GracefulDegradationManager();
  ~GracefulDegradationManager() = default;

  // Service management
  void register_service(const std::string &service_name,
                        const ServiceConfig &config);
  void unregister_service(const std::string &service_name);

  // Degradation control
  void set_degradation_thresholds(const DegradationThresholds &thresholds);
  void update_resource_metrics(const ResourceMetrics &metrics);
  void force_degradation(const std::string &service_name, DegradationMode mode);
  void request_recovery(const std::string &service_name);

  // Automatic degradation based on system state
  void evaluate_degradation_needs();

  // Service state queries
  DegradationMode get_service_mode(const std::string &service_name) const;
  ServiceState get_service_state(const std::string &service_name) const;
  bool is_service_degraded(const std::string &service_name) const;

  // System-wide queries
  std::vector<std::string> get_degraded_services() const;
  size_t get_total_degraded_services() const;
  ResourceMetrics get_current_metrics() const;

  // Priority-based degradation
  void degrade_by_priority(Priority min_priority_to_degrade);
  void recover_by_priority(Priority max_priority_to_recover);

  // Metrics and monitoring
  struct SystemDegradationStats {
    size_t total_services = 0;
    size_t normal_services = 0;
    size_t reduced_services = 0;
    size_t minimal_services = 0;
    size_t disabled_services = 0;
    std::chrono::system_clock::time_point last_evaluation;
  };

  SystemDegradationStats get_system_stats() const;
  void reset_degradation_stats();

private:
  struct RegisteredService {
    ServiceConfig config;
    ServiceState state;
    std::mutex service_mutex;

    // Make RegisteredService movable
    RegisteredService() = default;
    RegisteredService(const RegisteredService &) = delete;
    RegisteredService &operator=(const RegisteredService &) = delete;

    RegisteredService(RegisteredService &&other) noexcept
        : config(std::move(other.config)), state(std::move(other.state)) {}

    RegisteredService &operator=(RegisteredService &&other) noexcept {
      if (this != &other) {
        config = std::move(other.config);
        state = std::move(other.state);
      }
      return *this;
    }
  };

  DegradationMode calculate_required_mode(const ResourceMetrics &metrics,
                                          Priority priority) const;
  void apply_degradation(const std::string &service_name, DegradationMode mode);
  void check_service_health(const std::string &service_name);
  bool should_attempt_recovery(const std::string &service_name) const;

  mutable std::mutex services_mutex_;
  std::unordered_map<std::string, RegisteredService> services_;

  ResourceMetrics current_metrics_;
  DegradationThresholds thresholds_;

  mutable std::mutex metrics_mutex_;
  std::chrono::system_clock::time_point last_evaluation_;
};

} // namespace graceful_degradation

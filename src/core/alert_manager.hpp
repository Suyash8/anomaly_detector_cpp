#ifndef ALERT_MANAGER_HPP
#define ALERT_MANAGER_HPP

#include "config.hpp"
#include "io/alert_dispatch/base_dispatcher.hpp"
#include "utils/thread_safe_queue.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

struct Alert;

namespace prometheus {
class PrometheusMetricsExporter;
}

namespace Config {
struct AppConfig;
}

class AlertManager {
public:
  AlertManager();
  ~AlertManager();
  void initialize(const Config::AppConfig &app_config);
  void record_alert(const Alert &new_alert);
  void flush_all_alerts();
  void reconfigure(const Config::AppConfig &new_config);
  void set_metrics_exporter(
      std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter);

  std::vector<Alert> get_recent_alerts(size_t limit) const;

private:
  void dispatcher_loop();
  std::string format_alert_to_human_readable(const Alert &alert_data) const;
  void register_alert_manager_metrics();

  std::vector<std::unique_ptr<IAlertDispatcher>> dispatchers_;
  std::shared_ptr<prometheus::PrometheusMetricsExporter> metrics_exporter_;

  ThreadSafeQueue<Alert> alert_queue_;
  std::thread dispatcher_thread_;
  std::atomic<bool> shutdown_flag_{false};

  bool output_alerts_to_stdout;
  uint64_t throttle_duration_ms_ = 0;
  size_t alert_throttle_max_intervening_alerts_ = 0;
  size_t total_alerts_recorded_ = 0;
  std::atomic<size_t> alerts_throttled_{0};
  std::atomic<size_t> alerts_processed_{0};

  std::unordered_map<std::string, std::pair<uint64_t, size_t>>
      recent_alert_timestamps_;

  // Metrics tracking
  std::unordered_map<std::string, std::atomic<size_t>>
      dispatcher_success_counts_;
  std::unordered_map<std::string, std::atomic<size_t>>
      dispatcher_failure_counts_;

  mutable std::mutex recent_alerts_mutex_;
  std::deque<Alert> recent_alerts_;
  static constexpr size_t MAX_RECENT_ALERTS = 50;
};

#endif // ALERT_MANAGER_HPP
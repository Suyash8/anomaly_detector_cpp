#ifndef ALERT_MANAGER_HPP
#define ALERT_MANAGER_HPP

#include "../io/alert_dispatch/base_dispatcher.hpp"
#include "config.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

struct Alert;

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

private:
  std::string format_alert_to_human_readable(const Alert &alert_data) const;

  std::vector<std::unique_ptr<IAlertDispatcher>> dispatchers_;

  bool output_alerts_to_stdout;
  uint64_t throttle_duration_ms_ = 0;
  size_t alert_throttle_max_intervening_alerts_ = 0;
  size_t total_alerts_recorded_ = 0;

  std::unordered_map<std::string, std::pair<uint64_t, size_t>>
      recent_alert_timestamps_;
};

#endif // ALERT_MANAGER_HPP
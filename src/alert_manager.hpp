#ifndef ALERT_MANAGER_HPP
#define ALERT_MANAGER_HPP

#include "analyzed_event.hpp"
#include "config.hpp"

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

// Forward declare AppConfig if AlertManager needs it for initialization
namespace Config {
struct AppConfig;
}

// Enum class for type-safe alert items
enum class AlertTier { TIER1_HEURISTIC, TIER2_STATISTICAL, TIER3_ML };

enum class AlertAction {
  NO_ACTION = 0,  // No action needed (eg, for allowlisted items)
  LOG = 1,        // Log the event for observation, no immediate threat
  CHALLENGE = 2,  // Issue a challenge (eg, CAPTCHA) for suspected bots
  RATE_LIMIT = 3, // Temporarily rate-limit the source IP
  BLOCK = 4       // Block the source IP for a period
};

std::string alert_action_to_string(AlertAction action);
std::string alert_tier_to_string_representation(AlertTier tier);

struct Alert {
  uint64_t event_timestamp_ms;
  std::string source_ip;
  std::string alert_reason;
  AlertTier detection_tier;

  AlertAction action_code;
  std::string suggested_action;
  double normalized_score;

  std::string offending_key_identifier;
  uint64_t associated_log_line;
  std::string raw_log_trigger_sample;
  std::string ml_feature_contribution;

  std::shared_ptr<const AnalyzedEvent> event_context;

  Alert(std::shared_ptr<const AnalyzedEvent> event, const std::string &reason,
        AlertTier tier, AlertAction action, const std::string &action_str,
        double score, const std::string &key_id = "");
};

class AlertManager {
public:
  AlertManager();
  ~AlertManager();
  void initialize(const Config::AppConfig &app_config);
  void record_alert(const Alert &new_alert);
  void flush_all_alerts();

private:
  std::string format_alert_to_human_readable(const Alert &alert_data) const;
  std::string format_alert_to_json(const Alert &alert_data) const;
  std::string escape_json_value(const std::string &input) const;

  bool output_alerts_to_stdout;
  bool output_alerts_to_file;
  std::string alert_file_output_path;
  std::ofstream alert_file_stream;

  uint64_t throttle_duration_ms_ = 0;
  size_t alert_throttle_max_intervening_alerts_ = 0;

  // Key: "IP:RuleReason", Value: {Timestamp of last alert, Count of intervening
  // alerts}
  std::unordered_map<std::string, std::pair<uint64_t, size_t>>
      recent_alert_timestamps_;
};

#endif // ALERT_MANAGER_HPP
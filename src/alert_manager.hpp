#ifndef ALERT_MANAGER_HPP
#define ALERT_MANAGER_HPP

#include "analyzed_event.hpp"
#include "config.hpp"

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>

// Forward declare AppConfig if AlertManager needs it for initialization
namespace Config {
struct AppConfig;
}

// Enum class for type-safe alert items
enum class AlertTier { TIER1_HEURISTIC, TIER2_STATISTICAL, TIER3_ML };

// Helper function to convert AlertTier to string (declaration)
std::string alert_tier_to_string_representation(AlertTier tier);

struct Alert {
  uint64_t event_timestamp_ms;
  std::string source_ip;
  std::string alert_reason;
  AlertTier detection_tier;
  std::string suggested_action;

  // Optional fields for more context
  std::string offending_key_identifier;
  double anomaly_score;
  uint64_t associated_log_line;
  std::string raw_log_trigger_sample;
  std::string ml_feature_contribution;

  std::shared_ptr<const AnalyzedEvent> event_context;

  // Constructor for convenience
  Alert(std::shared_ptr<const AnalyzedEvent> event, const std::string &reason,
        AlertTier tier, const std::string &action, double score,
        const std::string &key_id = "");
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
  std::ofstream alert_file_stream; // For writing alerts to a file

  // For simplicity, we will write directly. Buffering could be added
  // std::vector<Alert> buffered_alerts;
};

#endif // ALERT_MANAGER_HPP
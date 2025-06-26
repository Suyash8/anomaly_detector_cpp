#ifndef ALERT_HPP
#define ALERT_HPP

#include "../analysis/analyzed_event.hpp"

#include <cstdint>
#include <memory>
#include <string>

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
  std::shared_ptr<const AnalyzedEvent> event_context;
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

  Alert(std::shared_ptr<const AnalyzedEvent> event, const std::string &reason,
        AlertTier tier, AlertAction action, const std::string &action_str,
        double score, const std::string &key_id = "");
};

#endif // ALERT_HPP
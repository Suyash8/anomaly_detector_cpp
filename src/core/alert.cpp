#include "alert.hpp"
#include "analysis/analyzed_event.hpp"

#include <memory>
#include <string>

std::string alert_action_to_string(AlertAction action) {
  switch (action) {
  case AlertAction::NO_ACTION:
    return "NO_ACTION";
  case AlertAction::LOG:
    return "LOG";
  case AlertAction::CHALLENGE:
    return "CHALLENGE";
  case AlertAction::RATE_LIMIT:
    return "RATE_LIMIT";
  case AlertAction::BLOCK:
    return "BLOCK";
  default:
    return "UNKNOWN_ACTION";
  }
}

std::string alert_tier_to_string_representation(AlertTier tier) {
  switch (tier) {
  case AlertTier::TIER1_HEURISTIC:
    return "TIER1_HEURISTIC";
  case AlertTier::TIER2_STATISTICAL:
    return "TIER2_STATISTICAL";
  case AlertTier::TIER3_ML:
    return "TIER3_ML";
  default:
    return "UNKNOWN_TIER";
  }
}

Alert::Alert(std::shared_ptr<const AnalyzedEvent> event,
             std::string_view reason, AlertTier tier, AlertAction action,
             std::string_view action_str, double score, std::string_view key_id)
    : event_context(event),
      event_timestamp_ms(event->raw_log.parsed_timestamp_ms.value_or(0)),
      source_ip(event->raw_log.ip_address), alert_reason(reason),
      detection_tier(tier), action_code(action), suggested_action(action_str),
      normalized_score(score),
      offending_key_identifier(key_id.empty() ? event->raw_log.ip_address
                                              : key_id),
      associated_log_line(event->raw_log.original_line_number),
      raw_log_trigger_sample(event->raw_log.raw_log_line),
      ml_feature_contribution("") {}
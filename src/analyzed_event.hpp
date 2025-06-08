#ifndef ANALYZED_EVENT_HPP
#define ANALYZED_EVENT_HPP

#include "log_entry.hpp"
#include <cstddef>
#include <optional>

struct AnalyzedEvent {
  LogEntry raw_log; // Keep the original log entry

  // Fields to be populated by AnalysisEngine
  // Initial Tier 1 related analysis results (previously calculated in
  // RuleEngine)
  std::optional<size_t> current_ip_request_count_in_window;
  std::optional<size_t> current_ip_failed_login_count_in_window;

  // Placeholder for future enrichments
  // bool is_user_agent_suspicious_placeholder = false;
  // double some_statistical_score_placeholder = 0.0;

  // Default constructor
  AnalyzedEvent(const LogEntry &log) : raw_log(log) {}
};

#endif // ANALYZED_EVENT_HPP
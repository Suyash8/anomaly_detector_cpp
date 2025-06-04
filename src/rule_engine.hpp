#ifndef RULE_ENGINE_HPP
#define RULE_ENGINE_HPP

#include "alert_manager.hpp"
#include "config.hpp"
#include "log_entry.hpp"
#include "sliding_window.hpp"

#include <string>
#include <unordered_map>
#include <unordered_set>

struct PerIpState {
  // Sliding window to track request timestamps for this IP
  // The ValueType of SlidingWindow will be uint64_t (the timestamp itself, or a
  // dummy value)
  SlidingWindow<uint64_t> request_timestamps_window;

  // Could add more state here later, e.g., failed login window, etc.
  // SlidingWindow<uint64_t> failed_login_window;

  uint64_t last_seen_timestamp_ms; // To help with pruning inactive IPs later

  // Constructor for PerIpState
  PerIpState(uint64_t current_timestamp_ms, uint64_t window_duration_ms_config)
      : request_timestamps_window(
            window_duration_ms_config,
            0), // Configure with duration, no max elements for now
        last_seen_timestamp_ms(current_timestamp_ms) {}

  // Default constructor needed for unordered_map if not using emplace with all
  // args
  PerIpState() : request_timestamps_window(0, 0), last_seen_timestamp_ms(0) {}
};

class RuleEngine {
public:
  RuleEngine(AlertManager &manager, const Config::AppConfig &cfg);
  ~RuleEngine();
  void process_log_entry(const LogEntry &entry);
  bool load_ip_allowlist(const std::string &filepath);

private:
  AlertManager &alert_mgr;
  const Config::AppConfig &app_config;
  std::unordered_set<std::string> ip_allowlist_cache;

  // Map to store state for each IP address encountered
  // Key: IP address (std::string)
  // Value: PerIpState struct
  std::unordered_map<std::string, PerIpState> ip_activity_trackers;

private:
  // Helper to get or create PerIpState for an IP
  PerIpState &get_or_create_ip_state(const std::string &ip,
                                     uint64_t current_timestamp_ms);

  // Placeholder for Tier 1 rule checks
  void apply_tier1_rules(const LogEntry &entry, PerIpState &current_ip_state);

  // Placeholder for Tier 2 rule checks
  // void apply_tier2_rules(const LogEntry& entry);

  // Placeholder for Tier 3 rule checks
  // void apply_tier3_rules(const LogEntry& entry);

  // Tier 1 specific rule checks
  void check_requests_per_ip_rule(const LogEntry &entry, PerIpState &ip_state);
  // void check_failed_logins_rule(const LogEntry& entry, PerIpState& ip_state);
};

#endif // RULE_ENGINE_HPP
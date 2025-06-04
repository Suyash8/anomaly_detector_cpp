#ifndef RULE_ENGINE_HPP
#define RULE_ENGINE_HPP

#include "alert_manager.hpp"
#include "config.hpp"
#include "log_entry.hpp"

#include <string>
#include <unordered_set>

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

private:
  // Placeholder for Tier 1 rule checks
  void apply_tier1_rules(const LogEntry &entry);

  // Placeholder for Tier 2 rule checks
  // void apply_tier2_rules(const LogEntry& entry);

  // Placeholder for Tier 3 rule checks
  // void apply_tier3_rules(const LogEntry& entry);
};

#endif // RULE_ENGINE_HPP
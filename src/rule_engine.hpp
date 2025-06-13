#ifndef RULE_ENGINE_HPP
#define RULE_ENGINE_HPP

#include "alert_manager.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"

#include <string>
#include <unordered_set>

class RuleEngine {
public:
  RuleEngine(AlertManager &manager, const Config::AppConfig &cfg);
  ~RuleEngine();
  void evaluate_rules(const AnalyzedEvent &event);
  bool load_ip_allowlist(const std::string &filepath);

private:
  AlertManager &alert_mgr;
  const Config::AppConfig &app_config;
  std::unordered_set<std::string> ip_allowlist_cache;

private:
  void check_requests_per_ip_rule(const AnalyzedEvent &event);
  void check_failed_logins_rule(const AnalyzedEvent &event);
  void check_asset_ratio_rule(const AnalyzedEvent &event);
  void check_ip_zscore_rules(const AnalyzedEvent &event);
  void check_user_agent_rules(const AnalyzedEvent &event);
  void check_suspicious_string_rules(const AnalyzedEvent &event);

  // To be later refactored to AnalysisWngine

  void check_asset_scraping_rule_placeholder(const AnalyzedEvent &event);
  void check_header_anomalies_rule_placeholder(const AnalyzedEvent &event);

  bool is_path_an_asset(
      const std::string &request_path) const; // Stays for asset scraping
};

#endif // RULE_ENGINE_HPP
#ifndef RULE_ENGINE_HPP
#define RULE_ENGINE_HPP

#include "aho_corasick.hpp"
#include "alert_manager.hpp"
#include "analyzed_event.hpp"
#include "config.hpp"
#include "ml_models/base_model.hpp"
#include "utils.hpp"

#include <memory>
#include <string>

class RuleEngine {
public:
  RuleEngine(AlertManager &manager, const Config::AppConfig &cfg);
  ~RuleEngine();
  void evaluate_rules(const AnalyzedEvent &event);
  bool load_ip_allowlist(const std::string &filepath);

  void reconfigure(const Config::AppConfig &new_config);

private:
  AlertManager &alert_mgr;
  Config::AppConfig app_config;

  std::vector<Utils::CIDRBlock> cidr_allowlist_cache_;
  std::unique_ptr<IAnomalyModel> anomaly_model_;

  std::unique_ptr<Utils::AhoCorasick> suspicious_path_matcher_;
  std::unique_ptr<Utils::AhoCorasick> suspicious_ua_matcher_;

private:
  void create_and_record_alert(const AnalyzedEvent &event,
                               const std::string &reason, AlertTier tier,
                               AlertAction action,
                               const std::string &action_str, double score,
                               const std::string &key_id = "");

  void check_requests_per_ip_rule(const AnalyzedEvent &event);
  void check_failed_logins_rule(const AnalyzedEvent &event);
  void check_suspicious_string_rules(const AnalyzedEvent &event);
  void check_user_agent_rules(const AnalyzedEvent &event);
  void check_asset_ratio_rule(const AnalyzedEvent &event);

  void check_ip_zscore_rules(const AnalyzedEvent &event);
  void check_path_zscore_rules(const AnalyzedEvent &event);
  void check_new_seen_rules(const AnalyzedEvent &event);
  void check_historical_comparison_rules(const AnalyzedEvent &event);

  void check_ml_rules(const AnalyzedEvent &event);
};

#endif // RULE_ENGINE_HPP
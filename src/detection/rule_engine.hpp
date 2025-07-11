#ifndef RULE_ENGINE_HPP
#define RULE_ENGINE_HPP

#include "analysis/analyzed_event.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "io/threat_intel/intel_manager.hpp"
#include "models/model_manager.hpp"
#include "utils/aho_corasick.hpp"
#include "utils/utils.hpp"

#include <memory>
#include <string>
#include <string_view>

class RuleEngine {
public:
  RuleEngine(AlertManager &manager, const Config::AppConfig &cfg,
             std::shared_ptr<ModelManager> model_manager);
  ~RuleEngine();
  void evaluate_rules(const AnalyzedEvent &event);
  bool load_ip_allowlist(const std::string &filepath);

  void reconfigure(const Config::AppConfig &new_config);

private:
  AlertManager &alert_mgr;
  Config::AppConfig app_config;

  std::shared_ptr<IntelManager> intel_manager_;
  std::vector<Utils::CIDRBlock> cidr_allowlist_cache_;
  std::shared_ptr<ModelManager> model_manager_;

  std::unique_ptr<Utils::AhoCorasick> suspicious_path_matcher_;
  std::unique_ptr<Utils::AhoCorasick> suspicious_ua_matcher_;

private:
  void create_and_record_alert(const AnalyzedEvent &event,
                               std::string_view reason, AlertTier tier,
                               AlertAction action, std::string_view action_str,
                               double score, std::string_view key_id = "");

  void check_requests_per_ip_rule(const AnalyzedEvent &event);
  void check_failed_logins_rule(const AnalyzedEvent &event);
  void check_suspicious_string_rules(const AnalyzedEvent &event);
  void check_user_agent_rules(const AnalyzedEvent &event);
  void check_asset_ratio_rule(const AnalyzedEvent &event);
  void check_session_rules(const AnalyzedEvent &event);
  void check_ip_zscore_rules(const AnalyzedEvent &event);
  void check_path_zscore_rules(const AnalyzedEvent &event);
  void check_new_seen_rules(const AnalyzedEvent &event);
  void check_historical_comparison_rules(const AnalyzedEvent &event);

  void check_ml_rules(const AnalyzedEvent &event);
};

#endif // RULE_ENGINE_HPP
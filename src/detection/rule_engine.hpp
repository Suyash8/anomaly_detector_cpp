#ifndef RULE_ENGINE_HPP
#define RULE_ENGINE_HPP

#include "analysis/analyzed_event.hpp"
#include "analysis/prometheus_anomaly_detector.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/prometheus_metrics_exporter.hpp"
#include "io/threat_intel/intel_manager.hpp"
#include "models/model_manager.hpp"
#include "utils/aho_corasick.hpp"
#include "utils/utils.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

class RuleEngine {
public:
  RuleEngine(AlertManager &manager, const Config::AppConfig &cfg,
             std::shared_ptr<ModelManager> model_manager);
  ~RuleEngine();
  void evaluate_rules(const AnalyzedEvent &event);
  bool load_ip_allowlist(const std::string &filepath);

  void reconfigure(const Config::AppConfig &new_config);
  void set_metrics_exporter(
      std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter);
  void set_tier4_anomaly_detector(
      std::shared_ptr<analysis::PrometheusAnomalyDetector> detector);

private:
  AlertManager &alert_mgr;
  Config::AppConfig app_config;

  std::shared_ptr<IntelManager> intel_manager_;
  std::vector<Utils::CIDRBlock> cidr_allowlist_cache_;
  std::shared_ptr<ModelManager> model_manager_;
  std::shared_ptr<prometheus::PrometheusMetricsExporter> metrics_exporter_;
  std::shared_ptr<analysis::PrometheusAnomalyDetector> tier4_detector_;

  std::unique_ptr<Utils::AhoCorasick> suspicious_path_matcher_;
  std::unique_ptr<Utils::AhoCorasick> suspicious_ua_matcher_;

  // Metrics tracking
  std::unordered_map<std::string, uint64_t> rule_evaluation_counts_;
  std::unordered_map<std::string, uint64_t> rule_hit_counts_;

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

  // Helper methods for metrics
  void track_rule_evaluation(const std::string &rule_name);
  void track_rule_hit(const std::string &rule_name);
  void register_rule_engine_metrics();
};

#endif // RULE_ENGINE_HPP
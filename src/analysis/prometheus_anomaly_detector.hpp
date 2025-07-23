#pragma once
#include "prometheus_client.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace analysis {

struct PromQLRule {
  std::string name;
  std::string
      promql_template; // e.g.
                       // "sum(rate(http_requests_total{ip=\"{{ip}}\"}[5m]))"
  double threshold;
  std::string comparison;                       // e.g. ">", "<", ">=", etc.
  std::map<std::string, std::string> variables; // e.g. {"ip": "1.2.3.4"}
};

struct PrometheusAnomalyResult {
  std::string rule_name;
  double value;
  bool is_anomaly;
  std::string details;
};

class PrometheusAnomalyDetector {
public:
  PrometheusAnomalyDetector(std::shared_ptr<PrometheusClient> client);

  // Add a rule (thread-safe)
  void add_rule(const PromQLRule &rule);

  // Remove a rule by name
  void remove_rule(const std::string &rule_name);

  // Evaluate all rules, substituting variables as needed
  std::vector<PrometheusAnomalyResult>
  evaluate_all(const std::map<std::string, std::string> &context_vars = {});

  // Evaluate a single rule by name
  std::optional<PrometheusAnomalyResult>
  evaluate_rule(const std::string &rule_name,
                const std::map<std::string, std::string> &context_vars = {});

  // List all rules
  std::vector<PromQLRule> list_rules() const;

private:
  std::shared_ptr<PrometheusClient> client_;
  std::vector<PromQLRule> rules_;
  mutable std::mutex rules_mutex_;

  // Helper: substitute variables in PromQL template
  std::string substitute(const std::string &templ,
                         const std::map<std::string, std::string> &vars) const;
};

} // namespace analysis

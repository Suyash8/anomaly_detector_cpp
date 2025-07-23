#include "prometheus_anomaly_detector.hpp"

#include <mutex>
#include <nlohmann/json.hpp>

using namespace analysis;

PrometheusAnomalyDetector::PrometheusAnomalyDetector(
    std::shared_ptr<PrometheusClient> client)
    : client_(std::move(client)) {}

void PrometheusAnomalyDetector::add_rule(const PromQLRule &rule) {
  std::lock_guard<std::mutex> lock(rules_mutex_);
  rules_.push_back(rule);
}

void PrometheusAnomalyDetector::remove_rule(const std::string &rule_name) {
  std::lock_guard<std::mutex> lock(rules_mutex_);
  rules_.erase(
      std::remove_if(rules_.begin(), rules_.end(),
                     [&](const PromQLRule &r) { return r.name == rule_name; }),
      rules_.end());
}

std::vector<PromQLRule> PrometheusAnomalyDetector::list_rules() const {
  std::lock_guard<std::mutex> lock(rules_mutex_);
  return rules_;
}

std::string PrometheusAnomalyDetector::substitute(
    const std::string &templ,
    const std::map<std::string, std::string> &vars) const {
  std::string result = templ;
  for (const auto &kv : vars) {
    std::string pat = "{{" + kv.first + "}}";
    size_t pos = 0;
    while ((pos = result.find(pat, pos)) != std::string::npos) {
      result.replace(pos, pat.length(), kv.second);
      pos += kv.second.length();
    }
  }
  return result;
}

std::vector<PrometheusAnomalyResult> PrometheusAnomalyDetector::evaluate_all(
    const std::map<std::string, std::string> &context_vars) {
  std::vector<PrometheusAnomalyResult> results;
  std::lock_guard<std::mutex> lock(rules_mutex_);
  for (const auto &rule : rules_) {
    auto res = evaluate_rule(rule.name, context_vars);
    if (res)
      results.push_back(*res);
  }
  return results;
}

std::optional<PrometheusAnomalyResult> PrometheusAnomalyDetector::evaluate_rule(
    const std::string &rule_name,
    const std::map<std::string, std::string> &context_vars) {
  PromQLRule rule;
  {
    std::lock_guard<std::mutex> lock(rules_mutex_);
    auto it =
        std::find_if(rules_.begin(), rules_.end(),
                     [&](const PromQLRule &r) { return r.name == rule_name; });
    if (it == rules_.end())
      return std::nullopt;
    rule = *it;
  }
  // Merge context_vars and rule.variables (context_vars take precedence)
  std::map<std::string, std::string> merged_vars = rule.variables;
  for (const auto &kv : context_vars)
    merged_vars[kv.first] = kv.second;
  std::string promql = substitute(rule.promql_template, merged_vars);
  std::string response;
  try {
    response = client_->query(promql);
  } catch (const std::exception &e) {
    return PrometheusAnomalyResult{rule.name, 0.0, false,
                                   std::string("Query error: ") + e.what()};
  }
  // Parse JSON and extract value
  double value = 0.0;
  try {
    auto json = nlohmann::json::parse(response);
    if (json["status"] != "success")
      return PrometheusAnomalyResult{rule.name, 0.0, false, "Prometheus error"};
    auto &result = json["data"]["result"];
    if (!result.is_array() || result.empty() || !result[0]["value"].is_array())
      return PrometheusAnomalyResult{rule.name, 0.0, false, "No data"};
    value = std::stod(result[0]["value"][1].get<std::string>());
  } catch (const std::exception &e) {
    return PrometheusAnomalyResult{rule.name, 0.0, false,
                                   std::string("Parse error: ") + e.what()};
  }
  // Evaluate comparison
  bool is_anomaly = false;
  if (rule.comparison == ">")
    is_anomaly = value > rule.threshold;
  else if (rule.comparison == ">=")
    is_anomaly = value >= rule.threshold;
  else if (rule.comparison == "<")
    is_anomaly = value < rule.threshold;
  else if (rule.comparison == "<=")
    is_anomaly = value <= rule.threshold;
  else if (rule.comparison == "==")
    is_anomaly = value == rule.threshold;
  else if (rule.comparison == "!=")
    is_anomaly = value != rule.threshold;
  else
    return PrometheusAnomalyResult{rule.name, value, false,
                                   "Invalid comparison operator"};
  return PrometheusAnomalyResult{rule.name, value, is_anomaly, "OK"};
}

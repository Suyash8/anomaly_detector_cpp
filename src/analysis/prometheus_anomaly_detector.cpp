#include "prometheus_anomaly_detector.hpp"

#include <mutex>
#include <nlohmann/json.hpp>

using namespace analysis;

PrometheusAnomalyDetector::PrometheusAnomalyDetector(
    std::shared_ptr<PrometheusClient> client)
    : client_(std::move(client)) {}

bool PrometheusAnomalyDetector::add_rule(const PromQLRule &rule) {
  if (!validate_rule(rule))
    return false;
  std::lock_guard<std::mutex> lock(rules_mutex_);
  for (const auto &r : rules_) {
    if (r.name == rule.name)
      return false; // Duplicate
  }
  rules_.push_back(rule);
  return true;
}

bool PrometheusAnomalyDetector::remove_rule(const std::string &rule_name) {
  std::lock_guard<std::mutex> lock(rules_mutex_);
  auto it =
      std::remove_if(rules_.begin(), rules_.end(),
                     [&](const PromQLRule &r) { return r.name == rule_name; });
  if (it == rules_.end())
    return false;
  rules_.erase(it, rules_.end());
  return true;
}

bool PrometheusAnomalyDetector::update_rule(const PromQLRule &rule) {
  if (!validate_rule(rule))
    return false;
  std::lock_guard<std::mutex> lock(rules_mutex_);
  for (auto &r : rules_) {
    if (r.name == rule.name) {
      r = rule;
      return true;
    }
  }
  return false;
}

std::optional<PromQLRule>
PrometheusAnomalyDetector::get_rule(const std::string &rule_name) const {
  std::lock_guard<std::mutex> lock(rules_mutex_);
  for (const auto &r : rules_) {
    if (r.name == rule_name)
      return r;
  }
  return std::nullopt;
}

bool PrometheusAnomalyDetector::validate_rule(const PromQLRule &rule) {
  static const std::set<std::string> valid_ops = {
      ">", "<", ">=", "<=", "==", "!="};
  if (rule.name.empty() || rule.promql_template.empty())
    return false;
  if (valid_ops.find(rule.comparison) == valid_ops.end())
    return false;
  return true;
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
    return PrometheusAnomalyResult{rule.name, 0.0, false, 0.0,
                                   std::string("Query error: ") + e.what()};
  }
  // Parse JSON and extract value
  double value = 0.0;
  try {
    auto json = nlohmann::json::parse(response);
    if (json["status"] != "success")
      return PrometheusAnomalyResult{rule.name, 0.0, false, 0.0,
                                     "Prometheus error"};
    auto &result = json["data"]["result"];
    if (!result.is_array() || result.empty() || !result[0]["value"].is_array())
      return PrometheusAnomalyResult{rule.name, 0.0, false, 0.0, "No data"};
    value = std::stod(result[0]["value"][1].get<std::string>());
  } catch (const std::exception &e) {
    return PrometheusAnomalyResult{rule.name, 0.0, false, 0.0,
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
    return PrometheusAnomalyResult{rule.name, value, false, 0.0,
                                   "Invalid comparison operator"};
  // Simple scoring: absolute distance from threshold
  double score = std::abs(value - rule.threshold);
  return PrometheusAnomalyResult{rule.name, value, is_anomaly, score, "OK"};
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

#ifndef OPTIMIZED_RULE_ENGINE_HPP
#define OPTIMIZED_RULE_ENGINE_HPP

#include "../core/memory_manager.hpp"
#include "../utils/string_interning.hpp"
#include "analysis/analyzed_event.hpp"
#include "analysis/prometheus_anomaly_detector.hpp"
#include "core/alert_manager.hpp"
#include "core/config.hpp"
#include "core/prometheus_metrics_exporter.hpp"
#include "io/threat_intel/intel_manager.hpp"
#include "models/model_manager.hpp"
#include "utils/aho_corasick.hpp"
#include "utils/utils.hpp"

#include <array>
#include <functional>
#include <memory>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace memory_optimization {

/**
 * Compiled rule representation for faster execution
 * Rules are pre-compiled into bytecode-like structures for maximum performance
 */
struct CompiledRule {
  enum class OpCode : uint8_t {
    COMPARE_EQ = 0,
    COMPARE_GT = 1,
    COMPARE_LT = 2,
    COMPARE_GTE = 3,
    COMPARE_LTE = 4,
    REGEX_MATCH = 5,
    STRING_CONTAINS = 6,
    LOGICAL_AND = 7,
    LOGICAL_OR = 8,
    RETURN_TRUE = 9,
    RETURN_FALSE = 10
  };

  struct Instruction {
    OpCode op;
    uint16_t field_id; // Which field to operate on
    uint16_t param_id; // Parameter index
    float threshold;   // Numeric threshold for comparisons
  };

  std::string rule_name;
  uint8_t tier;
  float score_multiplier;
  std::vector<Instruction> bytecode;

  // Pre-compiled regex patterns (cached)
  std::shared_ptr<std::regex> compiled_regex;

  // Rule execution statistics
  mutable uint64_t evaluation_count = 0;
  mutable uint64_t hit_count = 0;
  mutable double avg_execution_time_ns = 0.0;
};

/**
 * Pre-allocated rule evaluation context to avoid allocations during rule
 * execution All temporary objects and buffers are reused across evaluations
 */
class RuleEvaluationContext {
private:
  // Pre-allocated buffers for string operations
  static constexpr size_t MAX_STRING_SIZE = 2048;
  static constexpr size_t MAX_REGEX_GROUPS = 16;

  std::array<char, MAX_STRING_SIZE> string_buffer_;
  std::array<std::string_view, MAX_REGEX_GROUPS> regex_groups_;
  std::array<float, 32> numeric_stack_; // Stack for numeric operations
  std::array<bool, 32> boolean_stack_;  // Stack for boolean operations

  size_t numeric_stack_size_ = 0;
  size_t boolean_stack_size_ = 0;

  // Field extractors (avoid string allocations)
  std::unordered_map<uint16_t, std::function<float(const AnalyzedEvent &)>>
      numeric_extractors_;
  std::unordered_map<uint16_t,
                     std::function<std::string_view(const AnalyzedEvent &)>>
      string_extractors_;

public:
  RuleEvaluationContext() { initialize_extractors(); }

  // Execute compiled rule bytecode
  bool execute_rule(const CompiledRule &rule, const AnalyzedEvent &event) {
    numeric_stack_size_ = 0;
    boolean_stack_size_ = 0;

    auto start_time = std::chrono::high_resolution_clock::now();

    for (const auto &instruction : rule.bytecode) {
      if (!execute_instruction(instruction, event, rule)) {
        break;
      }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end_time - start_time);

    // Update rule statistics
    ++rule.evaluation_count;
    rule.avg_execution_time_ns =
        (rule.avg_execution_time_ns * (rule.evaluation_count - 1) +
         duration.count()) /
        rule.evaluation_count;

    return boolean_stack_size_ > 0 ? boolean_stack_[boolean_stack_size_ - 1]
                                   : false;
  }

private:
  void initialize_extractors() {
    // Numeric field extractors
    numeric_extractors_[0] = [](const AnalyzedEvent &e) {
      return static_cast<float>(e.response_code);
    };
    numeric_extractors_[1] = [](const AnalyzedEvent &e) {
      return static_cast<float>(e.bytes_sent);
    };
    numeric_extractors_[2] = [](const AnalyzedEvent &e) {
      return static_cast<float>(e.ip_requests_in_window);
    };
    numeric_extractors_[3] = [](const AnalyzedEvent &e) {
      return static_cast<float>(e.failed_logins_in_window);
    };
    numeric_extractors_[4] = [](const AnalyzedEvent &e) {
      return e.request_time_ms;
    };

    // String field extractors
    string_extractors_[0] = [](const AnalyzedEvent &e) {
      return std::string_view(e.ip);
    };
    string_extractors_[1] = [](const AnalyzedEvent &e) {
      return std::string_view(e.path);
    };
    string_extractors_[2] = [](const AnalyzedEvent &e) {
      return std::string_view(e.user_agent);
    };
    string_extractors_[3] = [](const AnalyzedEvent &e) {
      return std::string_view(e.method);
    };
  }

  bool execute_instruction(const CompiledRule::Instruction &instr,
                           const AnalyzedEvent &event,
                           const CompiledRule &rule) {
    switch (instr.op) {
    case CompiledRule::OpCode::COMPARE_GT: {
      float value = numeric_extractors_[instr.field_id](event);
      boolean_stack_[boolean_stack_size_++] = value > instr.threshold;
      break;
    }
    case CompiledRule::OpCode::COMPARE_LT: {
      float value = numeric_extractors_[instr.field_id](event);
      boolean_stack_[boolean_stack_size_++] = value < instr.threshold;
      break;
    }
    case CompiledRule::OpCode::REGEX_MATCH: {
      if (rule.compiled_regex) {
        std::string_view str = string_extractors_[instr.field_id](event);
        boolean_stack_[boolean_stack_size_++] =
            std::regex_search(str.begin(), str.end(), *rule.compiled_regex);
      } else {
        boolean_stack_[boolean_stack_size_++] = false;
      }
      break;
    }
    case CompiledRule::OpCode::STRING_CONTAINS: {
      // Fast string contains using Boyer-Moore or similar
      std::string_view str = string_extractors_[instr.field_id](event);
      // Placeholder - would implement optimized string search
      boolean_stack_[boolean_stack_size_++] =
          str.find("suspicious") != std::string_view::npos;
      break;
    }
    case CompiledRule::OpCode::LOGICAL_AND: {
      if (boolean_stack_size_ >= 2) {
        bool b = boolean_stack_[--boolean_stack_size_];
        boolean_stack_[boolean_stack_size_ - 1] =
            boolean_stack_[boolean_stack_size_ - 1] && b;
      }
      break;
    }
    case CompiledRule::OpCode::LOGICAL_OR: {
      if (boolean_stack_size_ >= 2) {
        bool b = boolean_stack_[--boolean_stack_size_];
        boolean_stack_[boolean_stack_size_ - 1] =
            boolean_stack_[boolean_stack_size_ - 1] || b;
      }
      break;
    }
    case CompiledRule::OpCode::RETURN_TRUE: {
      boolean_stack_[boolean_stack_size_++] = true;
      return false; // Stop execution
    }
    case CompiledRule::OpCode::RETURN_FALSE: {
      boolean_stack_[boolean_stack_size_++] = false;
      return false; // Stop execution
    }
    default:
      return false;
    }
    return true;
  }
};

/**
 * Optimized RuleEngine with memory-efficient rule execution
 * Features:
 * - Pre-compiled rules to bytecode for faster execution
 * - Pre-allocated evaluation contexts to avoid allocations
 * - Cached regex patterns with lazy compilation
 * - Fixed-size alert buffers with circular overwrite
 * - Stack-based allocation for temporary objects
 */
class OptimizedRuleEngine {
private:
  // Dependencies
  AlertManager &alert_mgr_;
  Config::AppConfig app_config_;
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  std::shared_ptr<memory::StringInternPool> string_pool_;

  // External services
  std::shared_ptr<IntelManager> intel_manager_;
  std::shared_ptr<ModelManager> model_manager_;
  std::shared_ptr<prometheus::PrometheusMetricsExporter> metrics_exporter_;
  std::shared_ptr<analysis::PrometheusAnomalyDetector> tier4_detector_;

  // Optimized rule storage
  std::vector<CompiledRule> tier1_rules_;
  std::vector<CompiledRule> tier2_rules_;
  std::vector<CompiledRule> tier3_rules_;

  // Pre-allocated evaluation contexts (one per thread)
  static constexpr size_t MAX_THREADS = 16;
  std::array<std::unique_ptr<RuleEvaluationContext>, MAX_THREADS>
      eval_contexts_;

  // Fixed-size alert buffer with circular overwrite
  static constexpr size_t ALERT_BUFFER_SIZE = 1024;
  struct AlertEntry {
    AnalyzedEvent event;
    std::string rule_name;
    float score;
    uint64_t timestamp;
    bool valid = false;
  };
  std::array<AlertEntry, ALERT_BUFFER_SIZE> alert_buffer_;
  size_t alert_buffer_head_ = 0;

  // Cached allowlist data structures
  std::vector<Utils::CIDRBlock> cidr_allowlist_cache_;
  memory::BloomFilter<std::string> ip_allowlist_bloom_;

  // Performance counters (bit-packed)
  struct {
    uint64_t total_evaluations : 48;
    uint64_t tier1_hits : 16;
    uint64_t tier2_hits : 16;
    uint64_t tier3_hits : 16;
    uint64_t tier4_hits : 16;
  } perf_counters_;

public:
  OptimizedRuleEngine(
      AlertManager &manager, const Config::AppConfig &cfg,
      std::shared_ptr<ModelManager> model_manager,
      std::shared_ptr<memory::MemoryManager> mem_mgr = nullptr,
      std::shared_ptr<memory::StringInternPool> string_pool = nullptr)
      : alert_mgr_(manager), app_config_(cfg),
        memory_manager_(mem_mgr ? mem_mgr
                                : std::make_shared<memory::MemoryManager>()),
        string_pool_(string_pool
                         ? string_pool
                         : std::make_shared<memory::StringInternPool>()),
        model_manager_(model_manager),
        ip_allowlist_bloom_(10000, 0.01) // 10k IPs, 1% false positive rate
        ,
        perf_counters_{0} {

    initialize_evaluation_contexts();
    compile_rules();
  }

  ~OptimizedRuleEngine() = default;

  // Main rule evaluation with optimized execution
  void evaluate_rules(const AnalyzedEvent &event) {
    ++perf_counters_.total_evaluations;

    // Fast allowlist check using Bloom filter + exact match
    if (is_ip_allowlisted(event.ip)) {
      return;
    }

    // Get thread-local evaluation context (simplified to context 0 for now)
    auto &context = *eval_contexts_[0];

    float total_score = 0.0f;
    std::vector<std::string> triggered_rules;
    triggered_rules.reserve(8); // Pre-allocate for common case

    // Tier 1: Fast bytecode execution
    if (app_config_.tier1.enabled) {
      total_score +=
          evaluate_tier_rules(tier1_rules_, event, context, triggered_rules);
    }

    // Tier 2: Advanced pattern matching
    if (app_config_.tier2.enabled && total_score < 100.0f) {
      total_score +=
          evaluate_tier_rules(tier2_rules_, event, context, triggered_rules);
    }

    // Tier 3: ML-based detection
    if (app_config_.tier3.enabled && total_score < 100.0f) {
      total_score += evaluate_ml_rules(event, triggered_rules);
    }

    // Tier 4: Prometheus-based detection
    if (app_config_.tier4.enabled && tier4_detector_ && total_score < 100.0f) {
      total_score += evaluate_tier4_rules(event, triggered_rules);
    }

    // Generate alert if threshold exceeded
    if (total_score >= app_config_.alert_threshold) {
      generate_optimized_alert(event, triggered_rules, total_score);
    }

    // Export metrics efficiently
    if (metrics_exporter_) {
      export_rule_metrics(triggered_rules, total_score);
    }
  }

  // Configuration and management
  void reconfigure(const Config::AppConfig &new_config) {
    app_config_ = new_config;
    compile_rules(); // Recompile rules for new configuration
  }

  void set_metrics_exporter(
      std::shared_ptr<prometheus::PrometheusMetricsExporter> exporter) {
    metrics_exporter_ = exporter;
  }

  void set_tier4_anomaly_detector(
      std::shared_ptr<analysis::PrometheusAnomalyDetector> detector) {
    tier4_detector_ = detector;
  }

  bool load_ip_allowlist(const std::string &filepath) {
    cidr_allowlist_cache_.clear();
    ip_allowlist_bloom_.clear();

    // Load and populate both CIDR cache and Bloom filter
    // Implementation would read from file and populate both structures

    return true;
  }

  // Performance monitoring
  struct PerformanceMetrics {
    uint64_t total_evaluations;
    uint64_t tier1_hits;
    uint64_t tier2_hits;
    uint64_t tier3_hits;
    uint64_t tier4_hits;
    double avg_evaluation_time_us;
    size_t active_rules;
    size_t memory_usage_bytes;
  };

  PerformanceMetrics get_performance_metrics() const {
    return {.total_evaluations = perf_counters_.total_evaluations,
            .tier1_hits = perf_counters_.tier1_hits,
            .tier2_hits = perf_counters_.tier2_hits,
            .tier3_hits = perf_counters_.tier3_hits,
            .tier4_hits = perf_counters_.tier4_hits,
            .avg_evaluation_time_us = calculate_avg_evaluation_time(),
            .active_rules =
                tier1_rules_.size() + tier2_rules_.size() + tier3_rules_.size(),
            .memory_usage_bytes = calculate_memory_usage()};
  }

private:
  void initialize_evaluation_contexts() {
    for (size_t i = 0; i < MAX_THREADS; ++i) {
      eval_contexts_[i] = std::make_unique<RuleEvaluationContext>();
    }
  }

  void compile_rules() {
    tier1_rules_.clear();
    tier2_rules_.clear();
    tier3_rules_.clear();

    // Compile Tier 1 rules (fast numeric comparisons)
    compile_tier1_rules();

    // Compile Tier 2 rules (pattern matching)
    compile_tier2_rules();

    // Compile Tier 3 rules (ML-based)
    compile_tier3_rules();
  }

  void compile_tier1_rules() {
    // Example: Failed login threshold rule
    CompiledRule rule;
    rule.rule_name = "failed_login_threshold";
    rule.tier = 1;
    rule.score_multiplier = 15.0f;

    // Bytecode: if (failed_logins_in_window > threshold) return true
    rule.bytecode.push_back({.op = CompiledRule::OpCode::COMPARE_GT,
                             .field_id = 3, // failed_logins_in_window
                             .param_id = 0,
                             .threshold = static_cast<float>(
                                 app_config_.tier1.failed_login_threshold)});
    rule.bytecode.push_back({.op = CompiledRule::OpCode::RETURN_TRUE,
                             .field_id = 0,
                             .param_id = 0,
                             .threshold = 0.0f});

    tier1_rules_.push_back(std::move(rule));

    // Add more compiled tier 1 rules...
  }

  void compile_tier2_rules() {
    // Example: Suspicious path regex rule
    CompiledRule rule;
    rule.rule_name = "suspicious_path_pattern";
    rule.tier = 2;
    rule.score_multiplier = 25.0f;

    // Pre-compile regex
    rule.compiled_regex = std::make_shared<std::regex>(
        R"((\.\.\/|admin|config|backup|\.env))",
        std::regex_constants::icase | std::regex_constants::optimize);

    rule.bytecode.push_back({.op = CompiledRule::OpCode::REGEX_MATCH,
                             .field_id = 1, // path
                             .param_id = 0,
                             .threshold = 0.0f});
    rule.bytecode.push_back({.op = CompiledRule::OpCode::RETURN_TRUE,
                             .field_id = 0,
                             .param_id = 0,
                             .threshold = 0.0f});

    tier2_rules_.push_back(std::move(rule));
  }

  void compile_tier3_rules() {
    // ML rules are handled differently - they call into the ML pipeline
    CompiledRule rule;
    rule.rule_name = "ml_anomaly_detection";
    rule.tier = 3;
    rule.score_multiplier = 1.0f; // Score comes from ML model

    tier3_rules_.push_back(std::move(rule));
  }

  float evaluate_tier_rules(const std::vector<CompiledRule> &rules,
                            const AnalyzedEvent &event,
                            RuleEvaluationContext &context,
                            std::vector<std::string> &triggered_rules) {
    float total_score = 0.0f;

    for (const auto &rule : rules) {
      if (context.execute_rule(rule, event)) {
        total_score += rule.score_multiplier;
        triggered_rules.push_back(rule.rule_name);

        // Update hit counters
        if (rule.tier == 1)
          ++perf_counters_.tier1_hits;
        else if (rule.tier == 2)
          ++perf_counters_.tier2_hits;

        ++rule.hit_count;
      }
    }

    return total_score;
  }

  float evaluate_ml_rules(const AnalyzedEvent &event,
                          std::vector<std::string> &triggered_rules) {
    if (!model_manager_)
      return 0.0f;

    // Extract features and run ML inference
    auto features = extract_ml_features(event);
    float ml_score = model_manager_->predict_anomaly_score(features);

    if (ml_score > app_config_.tier3.ml_threshold) {
      triggered_rules.push_back("ml_anomaly_detection");
      ++perf_counters_.tier3_hits;
      return ml_score;
    }

    return 0.0f;
  }

  float evaluate_tier4_rules(const AnalyzedEvent &event,
                             std::vector<std::string> &triggered_rules) {
    // Tier 4 evaluation would call into PrometheusAnomalyDetector
    // This is a placeholder for the actual implementation
    return 0.0f;
  }

  bool is_ip_allowlisted(const std::string &ip) const {
    // Fast Bloom filter check first
    if (!ip_allowlist_bloom_.contains(ip)) {
      return false;
    }

    // Exact CIDR check for potential matches
    uint32_t ip_addr = ip_string_to_uint32(ip);
    for (const auto &cidr : cidr_allowlist_cache_) {
      if ((ip_addr & cidr.netmask) == cidr.network) {
        return true;
      }
    }

    return false;
  }

  void generate_optimized_alert(const AnalyzedEvent &event,
                                const std::vector<std::string> &triggered_rules,
                                float score) {
    // Use circular buffer to avoid allocations
    auto &alert_entry = alert_buffer_[alert_buffer_head_];
    alert_entry.event = event;
    alert_entry.rule_name = join_strings(triggered_rules);
    alert_entry.score = score;
    alert_entry.timestamp = get_current_time();
    alert_entry.valid = true;

    alert_buffer_head_ = (alert_buffer_head_ + 1) % ALERT_BUFFER_SIZE;

    // Create Alert object and dispatch
    Alert alert;
    alert.timestamp_ms = event.timestamp_ms;
    alert.ip = event.ip;
    alert.score = score;
    alert.triggered_rules = join_strings(triggered_rules);

    alert_mgr_.generate_alert(alert);
  }

  // Helper methods
  uint32_t ip_string_to_uint32(const std::string &ip) const {
    // Convert IP string to uint32_t for fast comparison
    return 0; // Placeholder implementation
  }

  std::string join_strings(const std::vector<std::string> &strings) const {
    if (strings.empty())
      return "";

    std::string result = strings[0];
    for (size_t i = 1; i < strings.size(); ++i) {
      result += ", " + strings[i];
    }
    return result;
  }

  std::vector<float> extract_ml_features(const AnalyzedEvent &event) const {
    // Extract features for ML inference
    return {static_cast<float>(event.ip_requests_in_window),
            static_cast<float>(event.failed_logins_in_window),
            event.request_time_ms, static_cast<float>(event.bytes_sent)};
  }

  void export_rule_metrics(const std::vector<std::string> &triggered_rules,
                           float score) {
    for (const auto &rule : triggered_rules) {
      metrics_exporter_->increment_counter("rule_hits_total", {{"rule", rule}});
    }

    metrics_exporter_->observe_histogram("rule_evaluation_score", score, {});
  }

  double calculate_avg_evaluation_time() const {
    double total_time = 0.0;
    size_t rule_count = 0;

    for (const auto &rule : tier1_rules_) {
      total_time += rule.avg_execution_time_ns;
      ++rule_count;
    }
    for (const auto &rule : tier2_rules_) {
      total_time += rule.avg_execution_time_ns;
      ++rule_count;
    }

    return rule_count > 0 ? (total_time / rule_count) / 1000.0
                          : 0.0; // Convert to microseconds
  }

  size_t calculate_memory_usage() const {
    size_t total = sizeof(OptimizedRuleEngine);
    total += tier1_rules_.size() * sizeof(CompiledRule);
    total += tier2_rules_.size() * sizeof(CompiledRule);
    total += tier3_rules_.size() * sizeof(CompiledRule);
    total += sizeof(AlertEntry) * ALERT_BUFFER_SIZE;
    return total;
  }

  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

} // namespace memory_optimization

#endif // OPTIMIZED_RULE_ENGINE_HPP

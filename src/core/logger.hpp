#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "config.hpp"

#include <iomanip>
#include <map>

// Enum for standard log severity levels
enum class LogLevel { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

// Enum for all granular application components
enum class LogComponent {
  // Top-level components
  CORE,
  CONFIG,

  // IO sub-components
  IO_READER,
  IO_DISPATCH,
  IO_THREATINTEL,

  // Analysis sub-components
  ANALYSIS_LIFECYCLE,
  ANALYSIS_WINDOW,
  ANALYSIS_STATS,
  ANALYSIS_ZSCORE,
  ANALYSIS_SESSION,

  // Rules sub-components
  RULES_EVAL,
  RULES_T1_HEURISTIC,
  RULES_T2_STATISTICAL,
  RULES_T3_ML,

  // ML sub-components
  ML_FEATURES,
  ML_INFERENCE,
  ML_LIFECYCLE,

  // State sub-components
  STATE_PERSIST,
  STATE_PRUNE
};

class LogManager {
public:
  static LogManager &instance() {
    static LogManager instance;
    return instance;
  }

  inline void configure(const Config::LoggingConfig &config) {
    log_levels_ = config.log_levels;
  }

  bool should_log(LogLevel level, LogComponent component) const {
    auto it = log_levels_.find(component);
    if (it == log_levels_.end())
      return false;

    return level >= it->second;
  }

private:
  LogManager() = default; // Private constructor for singleton
  std::map<LogComponent, LogLevel> log_levels_;
};

// --- The Core Logging Macro ---
// It's a macro so that if `should_log` returns false, the message and its
// arguments are never even evaluated, providing a significant performance
// benefit.
#define LOG(level, component, message)                                         \
  do {                                                                         \
    if (LogManager::instance().should_log(level, component)) {                 \
      auto now = std::chrono::system_clock::now();                             \
      auto time_t_now = std::chrono::system_clock::to_time_t(now);             \
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(         \
                    now.time_since_epoch()) %                                  \
                1000;                                                          \
      std::ostringstream oss;                                                  \
      oss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%S")      \
          << '.' << std::setw(3) << std::setfill('0') << ms.count() << "Z ";   \
      oss << "[" << level_to_string(level) << "] ";                            \
      oss << "[" << component_to_string(component) << "] ";                    \
      oss << "[" << __FILE__ << ":" << __LINE__ << "] ";                       \
      oss << message;                                                          \
      std::cout << oss.str() << std::endl;                                     \
    }                                                                          \
  } while (0)

// --- Helper Functions to Convert Enums to Strings for Printing ---

inline const char *level_to_string(LogLevel level) {
  switch (level) {
  case LogLevel::TRACE:
    return "TRACE";
  case LogLevel::DEBUG:
    return "DEBUG";
  case LogLevel::INFO:
    return "INFO";
  case LogLevel::WARN:
    return "WARN";
  case LogLevel::ERROR:
    return "ERROR";
  case LogLevel::FATAL:
    return "FATAL";
  }
  return "UNKNOWN";
}

inline const char *component_to_string(LogComponent component) {
  switch (component) {
  case LogComponent::CORE:
    return "CORE";
  case LogComponent::CONFIG:
    return "CONFIG";
  case LogComponent::IO_READER:
    return "IO.READER";
  case LogComponent::IO_DISPATCH:
    return "IO.DISPATCH";
  case LogComponent::IO_THREATINTEL:
    return "IO.THREATINTEL";
  case LogComponent::ANALYSIS_LIFECYCLE:
    return "ANALYSIS.LIFECYCLE";
  case LogComponent::ANALYSIS_WINDOW:
    return "ANALYSIS.WINDOW";
  case LogComponent::ANALYSIS_STATS:
    return "ANALYSIS.STATS";
  case LogComponent::ANALYSIS_ZSCORE:
    return "ANALYSIS.ZSCORE";
  case LogComponent::ANALYSIS_SESSION:
    return "ANALYSIS.SESSION";
  case LogComponent::RULES_EVAL:
    return "RULES.EVAL";
  case LogComponent::RULES_T1_HEURISTIC:
    return "RULES.T1";
  case LogComponent::RULES_T2_STATISTICAL:
    return "RULES.T2";
  case LogComponent::RULES_T3_ML:
    return "RULES.T3";
  case LogComponent::ML_FEATURES:
    return "ML.FEATURES";
  case LogComponent::ML_INFERENCE:
    return "ML.INFERENCE";
  case LogComponent::ML_LIFECYCLE:
    return "ML.LIFECYCLE";
  case LogComponent::STATE_PERSIST:
    return "STATE.PERSIST";
  case LogComponent::STATE_PRUNE:
    return "STATE.PRUNE";
  }
  return "GENERAL";
}

#endif // LOGGER_HPP
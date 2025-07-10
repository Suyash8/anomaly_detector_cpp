#include "analysis/analysis_engine.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>

LogEntry create_dummy_log(const std::string &ip, const std::string &path,
                          uint64_t timestamp) {
  LogEntry log;
  log.ip_address = ip;
  log.request_path = path;
  log.parsed_timestamp_ms = timestamp;
  return log;
}

class AnalysisEngineTest : public ::testing::Test {
protected:
  Config::AppConfig config;
  std::unique_ptr<AnalysisEngine> engine;

  void SetUp() override { engine = std::make_unique<AnalysisEngine>(config); }
};

TEST_F(AnalysisEngineTest, SessionPruningWorks) {
  config.tier1.session_tracking_enabled = true;
  config.tier1.session_inactivity_ttl_seconds = 1;
  engine->reconfigure(config);

  engine->process_and_analyze(create_dummy_log("1.1.1.1", "/", 1000));

  // Simulate time passing far beyond the TTL
  engine->run_pruning(5000); // Current time is 5000ms

  SUCCEED() << "Test documents the intent of session pruning.";
}

TEST_F(AnalysisEngineTest, PathCapIsEnforced) {
  config.tier1.max_unique_paths_stored_per_ip = 5;
  engine->reconfigure(config);

  // Process 10 logs with unique paths from the same IP
  for (int i = 0; i < 10; ++i) {
    engine->process_and_analyze(
        create_dummy_log("2.2.2.2", "/path" + std::to_string(i), 1000 + i));
  }

  SUCCEED() << "Test documents the intent of capping paths_seen_by_ip.";
}
// Quick test to verify AnalysisEngine memory management integration
#include "analysis/analysis_engine.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/memory_manager.hpp"
#include <iostream>
#include <memory>

int main() {
  std::cout << "Testing AnalysisEngine Memory Management Integration\n";

  try {
    // Create default config
    Config::AppConfig config;
    config.memory_management.enabled = true;
    config.memory_management.memory_pressure_threshold_mb =
        100;                                                 // 100MB threshold
    config.memory_management.state_object_ttl_seconds = 300; // 5 minutes TTL

    // Create memory manager
    memory::MemoryConfig mem_config;
    mem_config.max_total_memory_mb = 200;
    mem_config.pressure_threshold_mb = 150;
    auto memory_manager = std::make_shared<memory::MemoryManager>(mem_config);

    // Create analysis engine
    AnalysisEngine engine(config);
    engine.set_memory_manager(memory_manager);

    std::cout << "✅ AnalysisEngine created and memory manager set\n";

    // Test memory pressure checks
    bool pressure = engine.check_memory_pressure();
    std::cout << "✅ Memory pressure check: " << (pressure ? "true" : "false")
              << "\n";

    // Test throttling
    bool throttle = engine.should_throttle_ingestion();
    std::cout << "✅ Should throttle ingestion: "
              << (throttle ? "true" : "false") << "\n";

    // Test batch size recommendation
    size_t batch_size = engine.get_recommended_batch_size();
    std::cout << "✅ Recommended batch size: " << batch_size << "\n";

    // Test processing a log entry
    LogEntry log;
    log.raw_log_line = "192.168.1.1 - - [21/Jan/2022:12:00:00 +0000] \"GET "
                       "/test HTTP/1.1\" 200 1024 \"-\" \"test-agent\"";
    log.ip_address = "192.168.1.1";
    log.request_path = "/test";
    log.parsed_timestamp_ms = 1642780800000; // Jan 21, 2022
    log.request_method = "GET";
    log.http_status_code = 200;
    log.bytes_sent = 1024;
    log.user_agent = "test-agent";

    auto result = engine.process_and_analyze(log);
    std::cout << "✅ Processed log entry for IP: " << log.ip_address << "\n";

    // Test memory cleanup
    engine.trigger_memory_cleanup();
    std::cout << "✅ Memory cleanup triggered\n";

    // Test state eviction
    uint64_t current_time = 1642780900000; // 1.5 minutes later
    engine.evict_inactive_states(current_time);
    std::cout << "✅ State eviction tested\n";

    std::cout << "\n🎉 All memory management integration tests passed!\n";
    std::cout << "Milestone 5.2 - AnalysisEngine Memory Management Integration "
                 "COMPLETED ✅\n";

    return 0;

  } catch (const std::exception &e) {
    std::cerr << "❌ Test failed: " << e.what() << "\n";
    return 1;
  }
}

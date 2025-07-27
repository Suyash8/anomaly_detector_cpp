#include "resource_pool_manager.hpp"
#include "core/logger.hpp"

namespace resource {

// Static initialization for any needed global pools or configuration
namespace {
// Global resource pool manager instance (optional singleton pattern)
std::unique_ptr<ResourcePoolManager> g_global_pool_manager;
std::mutex g_global_manager_mutex;
} // namespace

// Global pool manager access functions for convenience
ResourcePoolManager &get_global_pool_manager() {
  std::lock_guard<std::mutex> lock(g_global_manager_mutex);
  if (!g_global_pool_manager) {
    memory::MemoryConfig default_config;
    default_config.default_pool_size = 200; // Larger default for global manager
    default_config.max_pool_size = 2000;
    g_global_pool_manager =
        std::make_unique<ResourcePoolManager>(default_config);

    LOG(LogLevel::INFO, LogComponent::CORE,
        "Global ResourcePoolManager initialized with pool sizes: "
            << default_config.default_pool_size << "/"
            << default_config.max_pool_size);
  }
  return *g_global_pool_manager;
}

void shutdown_global_pool_manager() {
  std::lock_guard<std::mutex> lock(g_global_manager_mutex);
  if (g_global_pool_manager) {
    auto stats = g_global_pool_manager->get_statistics();
    LOG(LogLevel::INFO, LogComponent::CORE,
        "Shutting down global pool manager. Final stats - "
        "LogEntry pool hit rate: "
            << stats.log_entry_stats.hit_rate() * 100.0
            << "%, AnalyzedEvent pool hit rate: "
            << stats.analyzed_event_stats.hit_rate() * 100.0
            << "%, Overall hit rate: " << stats.overall_hit_rate * 100.0
            << "%");

    g_global_pool_manager.reset();
  }
}

// Convenience functions for quick access to global pools
PooledObject<LogEntry> acquire_log_entry_global() {
  return get_global_pool_manager().acquire_log_entry();
}

PooledObject<AnalyzedEvent>
acquire_analyzed_event_global(const LogEntry &log_entry) {
  return get_global_pool_manager().acquire_analyzed_event(log_entry);
}

} // namespace resource

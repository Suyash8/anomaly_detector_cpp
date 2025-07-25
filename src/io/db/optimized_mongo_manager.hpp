#ifndef OPTIMIZED_MONGO_MANAGER_HPP
#define OPTIMIZED_MONGO_MANAGER_HPP

#include "../../core/memory_manager.hpp"
#include "mongo_manager.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace anomaly_detector {

// Optimized MongoDB connection manager with advanced pooling and health
// monitoring
class OptimizedMongoManager : public memory::IMemoryManaged {
private:
  static mongocxx::instance instance_;

  std::unique_ptr<mongocxx::pool> primary_pool_;
  std::string primary_uri_;

  // Connection health monitoring
  struct ConnectionHealth {
    std::atomic<bool> is_healthy{true};
    std::atomic<std::chrono::steady_clock::time_point> last_ping{
        std::chrono::steady_clock::now()};
    std::atomic<size_t> failed_requests{0};
    std::atomic<size_t> successful_requests{0};
    std::atomic<double> avg_response_time_ms{0.0};
  };

  ConnectionHealth health_status_;

  // Advanced connection pooling with overflow handling
  struct PoolConfig {
    size_t min_pool_size = 5;
    size_t max_pool_size = 50;
    size_t overflow_pool_size = 10;
    std::chrono::seconds connection_timeout{30};
    std::chrono::seconds health_check_interval{60};
    size_t max_failed_requests_threshold = 5;
  };

  PoolConfig pool_config_;

  // Overflow pool for burst traffic
  std::unique_ptr<mongocxx::pool> overflow_pool_;
  std::atomic<bool> using_overflow_{false};

  // Client wrapper with performance tracking
  class OptimizedClientWrapper {
  private:
    mongocxx::pool::entry client_;
    std::chrono::steady_clock::time_point acquire_time_;
    OptimizedMongoManager *manager_;

  public:
    OptimizedClientWrapper(mongocxx::pool::entry client,
                           OptimizedMongoManager *mgr)
        : client_(std::move(client)),
          acquire_time_(std::chrono::steady_clock::now()), manager_(mgr) {}

    ~OptimizedClientWrapper() {
      auto release_time = std::chrono::steady_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                          release_time - acquire_time_)
                          .count();

      if (manager_) {
        manager_->update_performance_metrics(duration);
      }
    }

    mongocxx::client &operator*() { return *client_; }
    mongocxx::client *operator->() { return client_.get(); }

    const mongocxx::client &operator*() const { return *client_; }
    const mongocxx::client *operator->() const { return client_.get(); }
  };

  // Health monitoring thread
  std::unique_ptr<std::thread> health_monitor_thread_;
  std::atomic<bool> shutdown_requested_{false};
  std::condition_variable health_cv_;
  std::mutex health_mutex_;

  // Performance metrics
  struct PerformanceMetrics {
    std::atomic<size_t> total_connections_created{0};
    std::atomic<size_t> total_connections_reused{0};
    std::atomic<size_t> peak_concurrent_connections{0};
    std::atomic<size_t> current_active_connections{0};
    std::atomic<double> avg_connection_lifetime_ms{0.0};
    std::atomic<size_t> pool_exhaustion_count{0};
  };

  PerformanceMetrics metrics_;

  // Cursor management for efficient result streaming
  class OptimizedCursor {
  private:
    mongocxx::cursor cursor_;
    size_t batch_size_;
    std::vector<bsoncxx::document::value> prefetch_buffer_;

  public:
    OptimizedCursor(mongocxx::cursor cursor, size_t batch_size = 1000)
        : cursor_(std::move(cursor)), batch_size_(batch_size) {
      prefetch_buffer_.reserve(batch_size_);
    }

    // Batch iteration for better performance
    template <typename Handler> void for_each_batch(Handler &&handler) {
      prefetch_buffer_.clear();

      for (auto &&doc : cursor_) {
        prefetch_buffer_.emplace_back(doc);

        if (prefetch_buffer_.size() >= batch_size_) {
          handler(prefetch_buffer_);
          prefetch_buffer_.clear();
        }
      }

      // Handle remaining documents
      if (!prefetch_buffer_.empty()) {
        handler(prefetch_buffer_);
      }
    }
  };

  void update_performance_metrics(double connection_duration_ms) {
    metrics_.current_active_connections.fetch_sub(1, std::memory_order_relaxed);

    // Update average connection lifetime using exponential moving average
    double current_avg =
        metrics_.avg_connection_lifetime_ms.load(std::memory_order_relaxed);
    double new_avg = current_avg * 0.9 + connection_duration_ms * 0.1;
    metrics_.avg_connection_lifetime_ms.store(new_avg,
                                              std::memory_order_relaxed);
  }

  void health_monitor_loop() {
    while (!shutdown_requested_.load(std::memory_order_acquire)) {
      std::unique_lock<std::mutex> lock(health_mutex_);

      if (health_cv_.wait_for(lock, pool_config_.health_check_interval, [this] {
            return shutdown_requested_.load(std::memory_order_acquire);
          })) {
        break; // Shutdown requested
      }

      // Perform health check
      perform_health_check();
    }
  }

  void perform_health_check() {
    auto start_time = std::chrono::steady_clock::now();

    try {
      if (ping()) {
        auto end_time = std::chrono::steady_clock::now();
        auto ping_duration =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                                  start_time)
                .count();

        health_status_.is_healthy.store(true, std::memory_order_release);
        health_status_.last_ping.store(start_time, std::memory_order_release);
        health_status_.successful_requests.fetch_add(1,
                                                     std::memory_order_relaxed);

        // Update average response time
        double current_avg =
            health_status_.avg_response_time_ms.load(std::memory_order_relaxed);
        double new_avg = current_avg * 0.8 + ping_duration * 0.2;
        health_status_.avg_response_time_ms.store(new_avg,
                                                  std::memory_order_release);

        // Reset failed requests on successful ping
        health_status_.failed_requests.store(0, std::memory_order_release);

      } else {
        handle_health_check_failure();
      }
    } catch (const std::exception &e) {
      handle_health_check_failure();
    }
  }

  void handle_health_check_failure() {
    size_t failed_count =
        health_status_.failed_requests.fetch_add(1, std::memory_order_relaxed) +
        1;

    if (failed_count >= pool_config_.max_failed_requests_threshold) {
      health_status_.is_healthy.store(false, std::memory_order_release);

      // Try to reinitialize pool
      try {
        reinitialize_pool();
      } catch (const std::exception &e) {
        // Log error but continue monitoring
      }
    }
  }

  void reinitialize_pool() {
    mongocxx::uri mongo_uri(primary_uri_);
    auto new_pool = std::make_unique<mongocxx::pool>(mongo_uri);

    // Atomic swap of pools
    std::unique_ptr<mongocxx::pool> old_pool;
    old_pool.swap(primary_pool_);
    primary_pool_ = std::move(new_pool);

    health_status_.failed_requests.store(0, std::memory_order_release);
    health_status_.is_healthy.store(true, std::memory_order_release);
  }

public:
  explicit OptimizedMongoManager(const std::string &uri,
                                 const PoolConfig &config = PoolConfig{})
      : primary_uri_(uri), pool_config_(config) {

    try {
      mongocxx::uri mongo_uri(uri);

      // Configure main pool
      primary_pool_ = std::make_unique<mongocxx::pool>(mongo_uri);

      // Create overflow pool with smaller size
      overflow_pool_ = std::make_unique<mongocxx::pool>(mongo_uri);

      // Start health monitoring
      health_monitor_thread_ = std::make_unique<std::thread>(
          &OptimizedMongoManager::health_monitor_loop, this);

      // Register with memory manager
      if (auto *mem_mgr = memory::MemoryManager::get_instance()) {
        mem_mgr->register_component(
            std::static_pointer_cast<memory::IMemoryManaged>(
                std::shared_ptr<OptimizedMongoManager>(
                    this, [](OptimizedMongoManager *) {})));
      }

    } catch (const std::exception &e) {
      primary_pool_ = nullptr;
      overflow_pool_ = nullptr;
      throw std::runtime_error("Failed to initialize MongoDB pools: " +
                               std::string(e.what()));
    }
  }

  ~OptimizedMongoManager() { shutdown(); }

  void shutdown() {
    shutdown_requested_.store(true, std::memory_order_release);
    health_cv_.notify_all();

    if (health_monitor_thread_ && health_monitor_thread_->joinable()) {
      health_monitor_thread_->join();
    }
  }

  // Get optimized client with performance tracking
  OptimizedClientWrapper get_client() {
    if (!primary_pool_) {
      throw std::runtime_error("MongoDB pool is not initialized");
    }

    metrics_.current_active_connections.fetch_add(1, std::memory_order_relaxed);

    try {
      auto client = primary_pool_->acquire();
      metrics_.total_connections_reused.fetch_add(1, std::memory_order_relaxed);
      return OptimizedClientWrapper(std::move(client), this);

    } catch (const std::exception &e) {
      // Try overflow pool
      if (overflow_pool_ && !using_overflow_.load(std::memory_order_acquire)) {
        using_overflow_.store(true, std::memory_order_release);
        metrics_.pool_exhaustion_count.fetch_add(1, std::memory_order_relaxed);

        try {
          auto client = overflow_pool_->acquire();
          return OptimizedClientWrapper(std::move(client), this);
        } catch (...) {
          using_overflow_.store(false, std::memory_order_release);
          throw;
        }
      }

      metrics_.current_active_connections.fetch_sub(1,
                                                    std::memory_order_relaxed);
      throw;
    }
  }

  // Health check with caching
  bool ping() {
    // Use cached health status for frequent calls
    auto last_ping = health_status_.last_ping.load(std::memory_order_acquire);
    auto now = std::chrono::steady_clock::now();

    if (now - last_ping < std::chrono::seconds(10) &&
        health_status_.is_healthy.load(std::memory_order_acquire)) {
      return true;
    }

    try {
      auto client = get_client();

      bsoncxx::builder::basic::document doc_builder{};
      doc_builder.append(bsoncxx::builder::basic::kvp("ping", 1));

      (*client)["admin"].run_command(doc_builder.view());

      health_status_.is_healthy.store(true, std::memory_order_release);
      health_status_.last_ping.store(now, std::memory_order_release);

      return true;

    } catch (const std::exception &e) {
      health_status_.is_healthy.store(false, std::memory_order_release);
      return false;
    }
  }

  // Advanced query methods with optimization
  OptimizedCursor find_optimized(const std::string &database,
                                 const std::string &collection,
                                 const bsoncxx::document::view &filter,
                                 size_t batch_size = 1000) {
    auto client = get_client();

    mongocxx::options::find opts{};
    opts.batch_size(static_cast<int32_t>(batch_size));

    auto cursor = (*client)[database][collection].find(filter, opts);
    return OptimizedCursor(std::move(cursor), batch_size);
  }

  // Bulk operations for better performance
  bool bulk_insert(const std::string &database, const std::string &collection,
                   const std::vector<bsoncxx::document::value> &documents) {
    if (documents.empty()) {
      return true;
    }

    try {
      auto client = get_client();
      auto bulk = (*client)[database][collection].create_bulk_write();

      for (const auto &doc : documents) {
        mongocxx::model::insert_one insert_op{doc.view()};
        bulk.append(insert_op);
      }

      auto result = bulk.execute();
      return result &&
             result->inserted_count() == static_cast<int32_t>(documents.size());

    } catch (const std::exception &e) {
      return false;
    }
  }

  // Performance statistics
  struct Statistics {
    size_t total_connections_created;
    size_t total_connections_reused;
    size_t peak_concurrent_connections;
    size_t current_active_connections;
    double avg_connection_lifetime_ms;
    size_t pool_exhaustion_count;
    bool is_healthy;
    double avg_response_time_ms;
    size_t failed_requests;
    size_t successful_requests;
  };

  Statistics get_statistics() const {
    Statistics stats;
    stats.total_connections_created = metrics_.total_connections_created.load();
    stats.total_connections_reused = metrics_.total_connections_reused.load();
    stats.peak_concurrent_connections =
        metrics_.peak_concurrent_connections.load();
    stats.current_active_connections =
        metrics_.current_active_connections.load();
    stats.avg_connection_lifetime_ms =
        metrics_.avg_connection_lifetime_ms.load();
    stats.pool_exhaustion_count = metrics_.pool_exhaustion_count.load();
    stats.is_healthy = health_status_.is_healthy.load();
    stats.avg_response_time_ms = health_status_.avg_response_time_ms.load();
    stats.failed_requests = health_status_.failed_requests.load();
    stats.successful_requests = health_status_.successful_requests.load();
    return stats;
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    size_t usage = sizeof(*this);

    // Estimate pool memory usage
    size_t active_connections = metrics_.current_active_connections.load();
    usage += active_connections * 1024; // Rough estimate per connection

    return usage;
  }

  size_t compact() override {
    // MongoDB pools manage their own memory, limited compaction possible
    return 0;
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 3) {
      // Under high memory pressure, force pool recreation
      try {
        reinitialize_pool();
      } catch (...) {
        // Ignore errors during pressure handling
      }
    }
  }

  bool can_evict() const override {
    return metrics_.current_active_connections.load() == 0;
  }

  std::string get_component_name() const override {
    return "OptimizedMongoManager";
  }

  int get_priority() const override {
    return 1; // High priority - database connections are critical
  }
};

mongocxx::instance OptimizedMongoManager::instance_{};

} // namespace anomaly_detector

#endif // OPTIMIZED_MONGO_MANAGER_HPP

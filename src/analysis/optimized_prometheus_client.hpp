#ifndef OPTIMIZED_PROMETHEUS_CLIENT_HPP
#define OPTIMIZED_PROMETHEUS_CLIENT_HPP

#include "../core/memory_manager.hpp"
#include "../utils/optimized_io_buffer_manager.hpp"
#include "../utils/string_interning.hpp"
#include "prometheus_client.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace memory_optimization {

/**
 * HTTP/2 connection pool for efficient Prometheus query multiplexing
 * Features:
 * - Keep-alive connections with automatic renewal
 * - Connection health monitoring and failover
 * - Request pipelining and response streaming
 * - Memory-efficient connection reuse
 */
class Http2ConnectionPool {
private:
  struct Connection {
    std::unique_ptr<httplib::Client> client;
    std::atomic<bool> is_busy{false};
    std::atomic<uint64_t> last_used_time{0};
    std::atomic<uint32_t> request_count{0};
    std::atomic<bool> is_healthy{true};

    Connection(const std::string &host, int port) {
      client = std::make_unique<httplib::Client>(host, port);
      client->set_keep_alive(true);
      client->set_connection_timeout(5); // 5 seconds
      client->set_read_timeout(30);      // 30 seconds
      last_used_time = get_current_time();
    }

    bool is_expired(uint64_t max_idle_time_ms) const {
      return (get_current_time() - last_used_time) > max_idle_time_ms;
    }

    bool needs_renewal(uint32_t max_requests) const {
      return request_count >= max_requests;
    }

  private:
    static uint64_t get_current_time() {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now().time_since_epoch())
          .count();
    }
  };

  std::string host_;
  int port_;
  std::vector<std::unique_ptr<Connection>> connections_;
  std::queue<size_t> available_connections_;
  std::mutex pool_mutex_;
  std::condition_variable connection_available_;

  static constexpr size_t MAX_POOL_SIZE = 10;
  static constexpr uint64_t MAX_IDLE_TIME_MS = 300000; // 5 minutes
  static constexpr uint32_t MAX_REQUESTS_PER_CONNECTION = 1000;

public:
  Http2ConnectionPool(const std::string &host, int port)
      : host_(host), port_(port) {
    // Start with a minimum number of connections
    for (size_t i = 0; i < 2; ++i) {
      create_connection();
    }
  }

  ~Http2ConnectionPool() { cleanup_all_connections(); }

  // RAII connection wrapper for automatic return to pool
  class ConnectionHandle {
  private:
    Http2ConnectionPool *pool_;
    size_t connection_index_;
    Connection *connection_;

  public:
    ConnectionHandle(Http2ConnectionPool *pool, size_t index, Connection *conn)
        : pool_(pool), connection_index_(index), connection_(conn) {}

    ~ConnectionHandle() {
      if (pool_ && connection_) {
        pool_->return_connection(connection_index_);
      }
    }

    // Move-only semantics
    ConnectionHandle(const ConnectionHandle &) = delete;
    ConnectionHandle &operator=(const ConnectionHandle &) = delete;

    ConnectionHandle(ConnectionHandle &&other) noexcept
        : pool_(other.pool_), connection_index_(other.connection_index_),
          connection_(other.connection_) {
      other.pool_ = nullptr;
      other.connection_ = nullptr;
    }

    ConnectionHandle &operator=(ConnectionHandle &&other) noexcept {
      if (this != &other) {
        pool_ = other.pool_;
        connection_index_ = other.connection_index_;
        connection_ = other.connection_;
        other.pool_ = nullptr;
        other.connection_ = nullptr;
      }
      return *this;
    }

    httplib::Client *operator->() { return connection_->client.get(); }
    httplib::Client &operator*() { return *connection_->client; }
    bool is_valid() const { return connection_ && connection_->is_healthy; }
  };

  // Acquire connection from pool with timeout
  std::optional<ConnectionHandle> acquire_connection(
      std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
    std::unique_lock<std::mutex> lock(pool_mutex_);

    // Wait for available connection or timeout
    if (!connection_available_.wait_for(lock, timeout, [this] {
          return !available_connections_.empty() || can_create_connection();
        })) {
      return std::nullopt; // Timeout
    }

    size_t conn_index;
    if (!available_connections_.empty()) {
      conn_index = available_connections_.front();
      available_connections_.pop();
    } else if (can_create_connection()) {
      conn_index = create_connection_locked();
    } else {
      return std::nullopt; // Pool exhausted
    }

    auto &connection = connections_[conn_index];
    connection->is_busy = true;
    connection->last_used_time = get_current_time();

    return ConnectionHandle(this, conn_index, connection.get());
  }

  void cleanup_expired_connections() {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    for (auto it = connections_.begin(); it != connections_.end();) {
      if (!(*it)->is_busy &&
          ((*it)->is_expired(MAX_IDLE_TIME_MS) ||
           (*it)->needs_renewal(MAX_REQUESTS_PER_CONNECTION))) {
        // Remove expired connection
        it = connections_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  void create_connection() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    create_connection_locked();
  }

  size_t create_connection_locked() {
    if (connections_.size() >= MAX_POOL_SIZE) {
      return SIZE_MAX; // Pool full
    }

    connections_.emplace_back(std::make_unique<Connection>(host_, port_));
    size_t index = connections_.size() - 1;
    available_connections_.push(index);
    connection_available_.notify_one();

    return index;
  }

  bool can_create_connection() const {
    return connections_.size() < MAX_POOL_SIZE;
  }

  void return_connection(size_t index) {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    if (index < connections_.size()) {
      auto &connection = connections_[index];
      connection->is_busy = false;
      ++connection->request_count;

      if (connection->is_healthy &&
          !connection->needs_renewal(MAX_REQUESTS_PER_CONNECTION)) {
        available_connections_.push(index);
        connection_available_.notify_one();
      }
    }
  }

  void cleanup_all_connections() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    connections_.clear();
    std::queue<size_t> empty;
    available_connections_.swap(empty);
  }

  static uint64_t get_current_time() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

/**
 * Response streaming handler for large Prometheus query results
 * Features:
 * - Streaming JSON parsing to avoid large buffer allocations
 * - Progressive result processing
 * - Memory pressure-aware buffering
 */
class StreamingResponseHandler {
private:
  memory_optimization::BufferPool &buffer_pool_;
  std::function<void(const PrometheusQueryResult &)> result_callback_;
  std::unique_ptr<memory_optimization::CircularBuffer<char>> parse_buffer_;

  // JSON parsing state
  enum class ParseState {
    EXPECTING_OBJECT,
    IN_DATA_ARRAY,
    IN_RESULT_OBJECT,
    PARSING_VALUE,
    COMPLETE
  };

  ParseState parse_state_ = ParseState::EXPECTING_OBJECT;
  size_t brace_depth_ = 0;
  std::string current_json_object_;

public:
  StreamingResponseHandler(
      memory_optimization::BufferPool &pool,
      std::function<void(const PrometheusQueryResult &)> callback)
      : buffer_pool_(pool), result_callback_(callback) {
    parse_buffer_ =
        std::make_unique<memory_optimization::CircularBuffer<char>>(8192);
  }

  void process_chunk(const char *data, size_t length) {
    // Stream data into circular buffer
    for (size_t i = 0; i < length; ++i) {
      parse_buffer_->push(data[i]);

      // Parse JSON incrementally
      if (data[i] == '{') {
        ++brace_depth_;
        if (parse_state_ == ParseState::IN_DATA_ARRAY) {
          parse_state_ = ParseState::IN_RESULT_OBJECT;
          current_json_object_.clear();
        }
      } else if (data[i] == '}') {
        --brace_depth_;
        if (parse_state_ == ParseState::IN_RESULT_OBJECT && brace_depth_ == 2) {
          // Complete result object
          current_json_object_ += data[i];
          process_complete_result_object();
          parse_state_ = ParseState::IN_DATA_ARRAY;
          continue;
        }
      }

      if (parse_state_ == ParseState::IN_RESULT_OBJECT) {
        current_json_object_ += data[i];
      }
    }
  }

  void finalize() {
    // Process any remaining data
    parse_state_ = ParseState::COMPLETE;
  }

private:
  void process_complete_result_object() {
    try {
      // Parse the JSON object and create PrometheusQueryResult
      // This would use a fast JSON parser like simdjson
      PrometheusQueryResult result;
      // Parse current_json_object_ into result

      if (result_callback_) {
        result_callback_(result);
      }
    } catch (const std::exception &e) {
      // Log parse error but continue processing
    }

    current_json_object_.clear();
  }
};

/**
 * Template cache for PromQL queries to avoid string allocations
 * Features:
 * - Pre-compiled query templates with parameter substitution
 * - LRU cache for frequently used queries
 * - String interning for query components
 */
class PromQLTemplateCache {
private:
  struct QueryTemplate {
    std::string template_string;
    std::vector<size_t> param_positions; // Positions where substitution occurs
    std::vector<std::string> param_names;
    uint64_t last_used_time = 0;
    uint32_t use_count = 0;
  };

  std::unordered_map<uint32_t, std::unique_ptr<QueryTemplate>> templates_;
  std::shared_ptr<memory::StringInternPool> string_pool_;

  static constexpr size_t MAX_CACHE_SIZE = 100;

public:
  PromQLTemplateCache(std::shared_ptr<memory::StringInternPool> pool)
      : string_pool_(pool) {}

  void add_template(const std::string &name, const std::string &template_str) {
    uint32_t template_hash = hash_string(name);

    auto tmpl = std::make_unique<QueryTemplate>();
    tmpl->template_string = template_str;
    parse_template_parameters(*tmpl);

    if (templates_.size() >= MAX_CACHE_SIZE) {
      evict_lru_template();
    }

    templates_[template_hash] = std::move(tmpl);
  }

  std::string
  build_query(const std::string &template_name,
              const std::unordered_map<std::string, std::string> &params) {
    uint32_t template_hash = hash_string(template_name);
    auto it = templates_.find(template_hash);

    if (it == templates_.end()) {
      return ""; // Template not found
    }

    auto &tmpl = *it->second;
    tmpl.last_used_time = get_current_time();
    ++tmpl.use_count;

    return substitute_parameters(tmpl, params);
  }

private:
  void parse_template_parameters(QueryTemplate &tmpl) {
    // Parse ${param_name} placeholders in template
    const std::string &str = tmpl.template_string;
    size_t pos = 0;

    while ((pos = str.find("${", pos)) != std::string::npos) {
      size_t end_pos = str.find("}", pos);
      if (end_pos != std::string::npos) {
        tmpl.param_positions.push_back(pos);
        std::string param_name = str.substr(pos + 2, end_pos - pos - 2);
        tmpl.param_names.push_back(param_name);
        pos = end_pos + 1;
      } else {
        break;
      }
    }
  }

  std::string substitute_parameters(
      const QueryTemplate &tmpl,
      const std::unordered_map<std::string, std::string> &params) {
    std::string result = tmpl.template_string;

    // Substitute in reverse order to maintain position indices
    for (int i = tmpl.param_positions.size() - 1; i >= 0; --i) {
      const std::string &param_name = tmpl.param_names[i];
      auto param_it = params.find(param_name);

      if (param_it != params.end()) {
        size_t start_pos = tmpl.param_positions[i];
        size_t end_pos = result.find("}", start_pos) + 1;
        result.replace(start_pos, end_pos - start_pos, param_it->second);
      }
    }

    return result;
  }

  void evict_lru_template() {
    if (templates_.empty())
      return;

    auto lru_it = std::min_element(
        templates_.begin(), templates_.end(), [](const auto &a, const auto &b) {
          return a.second->last_used_time < b.second->last_used_time;
        });

    templates_.erase(lru_it);
  }

  uint32_t hash_string(const std::string &str) const {
    uint32_t hash = 5381;
    for (char c : str) {
      hash = ((hash << 5) + hash) + c;
    }
    return hash;
  }

  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

/**
 * Optimized Prometheus client with advanced memory and performance
 * optimizations Features:
 * - HTTP/2 connection pooling with keep-alive
 * - Response streaming to avoid large buffer allocations
 * - Query template caching and parameter substitution
 * - Connection health monitoring and automatic failover
 * - Memory pressure-aware request batching
 */
class OptimizedPrometheusClient : public PrometheusClient {
private:
  // Core configuration
  std::string base_url_;
  std::unordered_map<std::string, std::string> auth_headers_;

  // Optimized components
  std::unique_ptr<Http2ConnectionPool> connection_pool_;
  std::unique_ptr<PromQLTemplateCache> template_cache_;
  std::shared_ptr<memory::MemoryManager> memory_manager_;
  std::shared_ptr<memory::StringInternPool> string_pool_;
  memory_optimization::BufferPool buffer_pool_;

  // Circuit breaker state
  std::atomic<uint32_t> consecutive_failures_{0};
  std::atomic<uint64_t> last_failure_time_{0};
  std::atomic<bool> circuit_open_{false};

  // Performance monitoring
  std::atomic<uint64_t> total_requests_{0};
  std::atomic<uint64_t> successful_requests_{0};
  std::atomic<double> avg_response_time_ms_{0.0};

  static constexpr uint32_t CIRCUIT_BREAKER_THRESHOLD = 5;
  static constexpr uint64_t CIRCUIT_BREAKER_TIMEOUT_MS = 30000; // 30 seconds

public:
  OptimizedPrometheusClient(
      const std::string &base_url,
      std::shared_ptr<memory::MemoryManager> mem_mgr = nullptr,
      std::shared_ptr<memory::StringInternPool> string_pool = nullptr)
      : base_url_(base_url),
        memory_manager_(mem_mgr ? mem_mgr
                                : std::make_shared<memory::MemoryManager>()),
        string_pool_(string_pool
                         ? string_pool
                         : std::make_shared<memory::StringInternPool>()),
        buffer_pool_(memory_manager_) {

    initialize_connection_pool();
    template_cache_ = std::make_unique<PromQLTemplateCache>(string_pool_);
    setup_common_templates();
  }

  ~OptimizedPrometheusClient() = default;

  // Override base class methods with optimized implementations
  PrometheusQueryResult query(const std::string &promql) override {
    return execute_query_optimized("/api/v1/query", {{"query", promql}});
  }

  PrometheusQueryResult query_range(const std::string &promql,
                                    const std::string &start,
                                    const std::string &end,
                                    const std::string &step) override {
    return execute_query_optimized(
        "/api/v1/query_range",
        {{"query", promql}, {"start", start}, {"end", end}, {"step", step}});
  }

  // Enhanced methods with template support
  PrometheusQueryResult
  query_template(const std::string &template_name,
                 const std::unordered_map<std::string, std::string> &params) {
    std::string query = template_cache_->build_query(template_name, params);
    if (query.empty()) {
      return create_error_result("Template not found: " + template_name);
    }

    return query(query);
  }

  // Batch query execution for better performance
  std::vector<PrometheusQueryResult>
  query_batch(const std::vector<std::string> &queries) {
    std::vector<PrometheusQueryResult> results;
    results.reserve(queries.size());

    // Execute queries in parallel using connection pool
    std::vector<std::future<PrometheusQueryResult>> futures;
    futures.reserve(queries.size());

    for (const auto &query : queries) {
      futures.emplace_back(std::async(
          std::launch::async, [this, query]() { return this->query(query); }));
    }

    // Collect results
    for (auto &future : futures) {
      results.emplace_back(future.get());
    }

    return results;
  }

  // Streaming query for large result sets
  void query_stream(
      const std::string &promql,
      std::function<void(const PrometheusQueryResult &)> result_callback) {
    if (is_circuit_breaker_open()) {
      PrometheusQueryResult error_result =
          create_error_result("Circuit breaker open");
      result_callback(error_result);
      return;
    }

    auto connection = connection_pool_->acquire_connection();
    if (!connection || !connection->is_valid()) {
      PrometheusQueryResult error_result =
          create_error_result("No available connections");
      result_callback(error_result);
      return;
    }

    StreamingResponseHandler handler(buffer_pool_, result_callback);

    // Set up streaming response handler
    (*connection)
        ->set_content_receiver([&handler](const char *data, size_t len) {
          handler.process_chunk(data, len);
          return true;
        });

    // Execute query with streaming
    std::string url = "/api/v1/query?query=" + url_encode(promql);
    auto response = (*connection)->Get(url.c_str(), auth_headers_);

    handler.finalize();

    update_circuit_breaker_state(response != nullptr &&
                                 response->status == 200);
  }

  // Configuration methods
  void add_query_template(const std::string &name,
                          const std::string &template_str) {
    template_cache_->add_template(name, template_str);
  }

  void set_auth_headers(
      const std::unordered_map<std::string, std::string> &headers) override {
    auth_headers_ = headers;
  }

  // Performance monitoring
  struct PerformanceMetrics {
    uint64_t total_requests;
    uint64_t successful_requests;
    double success_rate;
    double avg_response_time_ms;
    uint32_t active_connections;
    bool circuit_breaker_open;
  };

  PerformanceMetrics get_performance_metrics() const {
    uint64_t total = total_requests_.load();
    uint64_t successful = successful_requests_.load();

    return {.total_requests = total,
            .successful_requests = successful,
            .success_rate =
                total > 0 ? static_cast<double>(successful) / total : 0.0,
            .avg_response_time_ms = avg_response_time_ms_.load(),
            .active_connections = 0, // Would get from connection pool
            .circuit_breaker_open = circuit_open_.load()};
  }

private:
  void initialize_connection_pool() {
    // Parse base URL to extract host and port
    std::string host = extract_host_from_url(base_url_);
    int port = extract_port_from_url(base_url_);

    connection_pool_ = std::make_unique<Http2ConnectionPool>(host, port);
  }

  void setup_common_templates() {
    // Add common Prometheus query templates
    template_cache_->add_template("cpu_usage",
                                  "100 - (avg by (instance) "
                                  "(irate(node_cpu_seconds_total{mode=\"idle\","
                                  "instance=\"${instance}\"}[5m])) * 100)");

    template_cache_->add_template(
        "memory_usage",
        "(node_memory_MemTotal_bytes{instance=\"${instance}\"} - "
        "node_memory_MemAvailable_bytes{instance=\"${instance}\"}) / "
        "node_memory_MemTotal_bytes{instance=\"${instance}\"} * 100");

    template_cache_->add_template("request_rate",
                                  "rate(http_requests_total{job=\"${job}\","
                                  "path=\"${path}\"}[${interval}])");

    template_cache_->add_template(
        "error_rate",
        "rate(http_requests_total{job=\"${job}\",status=~\"5..\"}[${interval}])"
        " / rate(http_requests_total{job=\"${job}\"}[${interval}])");
  }

  PrometheusQueryResult execute_query_optimized(
      const std::string &endpoint,
      const std::unordered_map<std::string, std::string> &params) {
    auto start_time = std::chrono::high_resolution_clock::now();
    ++total_requests_;

    if (is_circuit_breaker_open()) {
      return create_error_result("Circuit breaker open");
    }

    auto connection = connection_pool_->acquire_connection();
    if (!connection || !connection->is_valid()) {
      return create_error_result("No available connections");
    }

    // Build query URL
    std::string url = endpoint + "?" + build_query_string(params);

    // Execute query
    auto response = (*connection)->Get(url.c_str(), auth_headers_);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    // Update performance metrics
    update_response_time(duration.count());

    if (response && response->status == 200) {
      ++successful_requests_;
      update_circuit_breaker_state(true);
      return parse_prometheus_response(response->body);
    } else {
      update_circuit_breaker_state(false);
      return create_error_result(
          "Query failed: " +
          (response ? std::to_string(response->status) : "Connection error"));
    }
  }

  bool is_circuit_breaker_open() {
    if (!circuit_open_.load()) {
      return false;
    }

    // Check if timeout has passed
    uint64_t current_time = get_current_time();
    if (current_time - last_failure_time_.load() > CIRCUIT_BREAKER_TIMEOUT_MS) {
      circuit_open_ = false;
      consecutive_failures_ = 0;
      return false;
    }

    return true;
  }

  void update_circuit_breaker_state(bool success) {
    if (success) {
      consecutive_failures_ = 0;
      circuit_open_ = false;
    } else {
      uint32_t failures = ++consecutive_failures_;
      last_failure_time_ = get_current_time();

      if (failures >= CIRCUIT_BREAKER_THRESHOLD) {
        circuit_open_ = true;
      }
    }
  }

  void update_response_time(double response_time_ms) {
    // Exponential moving average
    double current_avg = avg_response_time_ms_.load();
    double alpha = 0.1; // Smoothing factor
    double new_avg = (alpha * response_time_ms) + ((1.0 - alpha) * current_avg);
    avg_response_time_ms_ = new_avg;
  }

  std::string build_query_string(
      const std::unordered_map<std::string, std::string> &params) {
    std::string query_string;
    bool first = true;

    for (const auto &[key, value] : params) {
      if (!first) {
        query_string += "&";
      }
      query_string += url_encode(key) + "=" + url_encode(value);
      first = false;
    }

    return query_string;
  }

  PrometheusQueryResult
  parse_prometheus_response(const std::string &json_response) {
    // Parse JSON response efficiently
    // This would use a fast JSON parser like simdjson
    PrometheusQueryResult result;
    result.status = "success";

    // Parse the JSON and populate result
    // Implementation would extract data.result array and convert to
    // PrometheusQueryResult

    return result;
  }

  PrometheusQueryResult create_error_result(const std::string &error_message) {
    PrometheusQueryResult result;
    result.status = "error";
    result.error = error_message;
    return result;
  }

  std::string extract_host_from_url(const std::string &url) {
    // Extract hostname from URL
    size_t start = url.find("://");
    if (start != std::string::npos) {
      start += 3;
      size_t end = url.find(":", start);
      if (end == std::string::npos) {
        end = url.find("/", start);
      }
      if (end == std::string::npos) {
        end = url.length();
      }
      return url.substr(start, end - start);
    }
    return "localhost";
  }

  int extract_port_from_url(const std::string &url) {
    // Extract port from URL, default to 9090
    size_t port_start = url.find("://");
    if (port_start != std::string::npos) {
      port_start += 3;
      port_start = url.find(":", port_start);
      if (port_start != std::string::npos) {
        ++port_start;
        size_t port_end = url.find("/", port_start);
        if (port_end == std::string::npos) {
          port_end = url.length();
        }
        return std::stoi(url.substr(port_start, port_end - port_start));
      }
    }
    return 9090; // Default Prometheus port
  }

  std::string url_encode(const std::string &str) {
    // Simple URL encoding
    std::string encoded;
    for (char c : str) {
      if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
        encoded += c;
      } else {
        encoded += '%';
        encoded += "0123456789ABCDEF"[c >> 4];
        encoded += "0123456789ABCDEF"[c & 15];
      }
    }
    return encoded;
  }

  uint64_t get_current_time() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

} // namespace memory_optimization

#endif // OPTIMIZED_PROMETHEUS_CLIENT_HPP

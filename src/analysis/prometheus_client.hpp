#ifndef PROMETHEUS_CLIENT_HPP
#define PROMETHEUS_CLIENT_HPP

#include <chrono>
#include <string>

// PrometheusClient configuration structure
struct PrometheusClientConfig {
  std::string endpoint_url; // e.g. "https://prometheus.example.com"
  std::string username;     // For basic auth
  std::string password;     // For basic auth
  std::string bearer_token; // For bearer token auth
  std::chrono::milliseconds timeout{5000}; // Request timeout
  int max_retries{3};                      // Retry count
  int circuit_breaker_threshold{5};        // Failures before opening circuit
  int connection_pool_size{4};             // Number of pooled connections
  // Additional TLS/SSL config fields as needed
};

// PrometheusClient: HTTP client for PromQL queries
class PrometheusClient {
public:
  // Construct with config
  explicit PrometheusClient(const PrometheusClientConfig &config);
  ~PrometheusClient();

  // Instant query: returns result as JSON string or throws on error
  std::string query(const std::string &promql);

  // Range query: returns result as JSON string or throws on error
  std::string query_range(const std::string &promql,
                          std::chrono::system_clock::time_point start,
                          std::chrono::system_clock::time_point end,
                          std::chrono::seconds step);

  // Error handling: throws PrometheusClientError on failure
  class PrometheusClientError : public std::exception {
  public:
    explicit PrometheusClientError(const std::string &msg);
    const char *what() const noexcept override;

  private:
    std::string message;
  };

  // Get current config
  const PrometheusClientConfig &get_config() const;

  // (Optional) Set new config at runtime
  void set_config(const PrometheusClientConfig &config);

private:
  PrometheusClientConfig config_;
  // Internal HTTP client, connection pool, circuit breaker state, etc.
  // ...
};

// Usage:
// PrometheusClient client(cfg);
// auto result = client.query("up");
// auto range = client.query_range("rate(http_requests_total[5m])", start, end,
// std::chrono::seconds(60));

#endif // PROMETHEUS_CLIENT_HPP
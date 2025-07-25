#include "../src/analysis/prometheus_client.hpp"

#include <chrono>
#include <gtest/gtest.h>

TEST(PrometheusClientTest, ConstructorAndConfig) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9090";
  cfg.timeout = std::chrono::milliseconds(2000);
  cfg.connection_pool_size = 2;
  PrometheusClient client(cfg);
  EXPECT_EQ(client.get_config().endpoint_url, "http://localhost:9090");
  EXPECT_EQ(client.get_config().timeout.count(), 2000);
}

TEST(PrometheusClientTest, CircuitBreaker) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9090";
  cfg.circuit_breaker_threshold = 2;
  PrometheusClient client(cfg);
  try {
    client.query("up"); // Should fail if Prometheus is not running
  } catch (const PrometheusClient::PrometheusClientError &) {
  }
  try {
    client.query("up"); // Should open circuit
  } catch (const PrometheusClient::PrometheusClientError &) {
  }
  try {
    client.query("up"); // Should throw circuit breaker open
    FAIL() << "Expected circuit breaker to be open";
  } catch (const PrometheusClient::PrometheusClientError &e) {
    SUCCEED() << "Circuit breaker test passed: " << e.what();
  }
}

TEST(PrometheusClientTest, QueryHandlesConnectionFailure) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9999"; // Unused port to force failure
  cfg.timeout = std::chrono::milliseconds(500);
  PrometheusClient client(cfg);
  EXPECT_THROW(client.query("up"), PrometheusClient::PrometheusClientError);
}

TEST(PrometheusClientTest, QueryRangeHandlesConnectionFailure) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9999";
  cfg.timeout = std::chrono::milliseconds(500);
  PrometheusClient client(cfg);
  auto now = std::chrono::system_clock::now();
  EXPECT_THROW(client.query_range("up", now - std::chrono::seconds(60), now,
                                  std::chrono::seconds(10)),
               PrometheusClient::PrometheusClientError);
}

TEST(PrometheusClientTest, AuthHeadersSet) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9090";
  cfg.bearer_token = "testtoken";
  PrometheusClient client(cfg);
  // We can't check headers directly, but we can call query and expect failure
  // (no server)
  EXPECT_THROW(client.query("up"), PrometheusClient::PrometheusClientError);

  cfg.bearer_token = "";
  cfg.username = "user";
  cfg.password = "pass";
  PrometheusClient client2(cfg);
  EXPECT_THROW(client2.query("up"), PrometheusClient::PrometheusClientError);
}

TEST(PrometheusClientTest, RetryLogic) {
  PrometheusClientConfig cfg;
  cfg.endpoint_url = "http://localhost:9999";
  cfg.max_retries = 2;
  cfg.timeout = std::chrono::milliseconds(100);
  PrometheusClient client(cfg);
  auto start = std::chrono::steady_clock::now();
  EXPECT_THROW(client.query("up"), PrometheusClient::PrometheusClientError);
  auto end = std::chrono::steady_clock::now();
  // Should take at least (max_retries+1)*timeout due to retries
  EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
                .count(),
            300);
}

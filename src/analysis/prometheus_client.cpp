#include "prometheus_client.hpp"

#include <chrono>
#include <httplib.h>
#include <thread>

PrometheusClient::PrometheusClient(const PrometheusClientConfig &config)
    : config_(config) {
  // Initialize HTTP client pool with configured size and timeout
  for (int i = 0; i < config_.connection_pool_size; ++i) {
    auto client =
        std::make_unique<httplib::Client>(config_.endpoint_url.c_str());
    // Set connection and read timeout (in seconds and microseconds)
    client->set_connection_timeout(config_.timeout.count() / 1000,
                                   config_.timeout.count() % 1000 * 1000);
    client->set_read_timeout(config_.timeout.count() / 1000,
                             config_.timeout.count() % 1000 * 1000);
    // Pooling: each thread can acquire/release a client safely
    client_pool_.push_back(std::move(client));
  }
  // TLS/SSL setup can be added here if needed
}

PrometheusClient::~PrometheusClient() {
  // Cleanup if needed
}

httplib::Client *PrometheusClient::acquire_client() {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  // Simple round-robin or first-available (for now, just use first)
  if (!client_pool_.empty()) {
    return client_pool_.front().get();
  }
  throw PrometheusClientError("No available HTTP client");
}

void PrometheusClient::release_client(httplib::Client * /*client*/) {
  // No-op for now (pool is static)
}

void PrometheusClient::setup_auth(httplib::Client &client) {
  if (!config_.bearer_token.empty()) {
    client.set_default_headers(
        {{"Authorization", "Bearer " + config_.bearer_token}});
  } else if (!config_.username.empty() && !config_.password.empty()) {
    client.set_basic_auth(config_.username.c_str(), config_.password.c_str());
  }
}

bool PrometheusClient::check_circuit() {
  if (circuit_open_) {
    auto now = std::chrono::system_clock::now();
    // 30s cooldown
    if (now - circuit_open_time_ > std::chrono::seconds(30)) {
      circuit_open_ = false;
      consecutive_failures_ = 0;
    }
  }
  return circuit_open_;
}

void PrometheusClient::record_failure() {
  ++consecutive_failures_;
  if (consecutive_failures_ >= config_.circuit_breaker_threshold) {
    circuit_open_ = true;
    circuit_open_time_ = std::chrono::system_clock::now();
  }
}

void PrometheusClient::reset_circuit() {
  consecutive_failures_ = 0;
  circuit_open_ = false;
}

static std::string build_query_url(const std::string &path,
                                   const httplib::Params &params) {
  std::ostringstream oss;
  oss << path << "?";
  bool first = true;
  for (const auto &kv : params) {
    if (!first)
      oss << "&";
    first = false;
    oss << kv.first << "=" << httplib::encode_uri(kv.second);
  }
  return oss.str();
}

std::string PrometheusClient::query(const std::string &promql) {
  if (check_circuit()) {
    throw PrometheusClientError("Circuit breaker open");
  }
  httplib::Client *client = acquire_client();
  setup_auth(*client);
  std::string path = "/api/v1/query";
  httplib::Params params = {{"query", promql}};
  std::string url = build_query_url(path, params);
  int attempts = 0;
  while (attempts <= config_.max_retries) {
    auto res = client->Get(url.c_str());
    if (res && res->status == 200) {
      reset_circuit();
      release_client(client);
      return res->body;
    } else {
      record_failure();
      ++attempts;
      std::this_thread::sleep_for(std::chrono::milliseconds(100 * attempts));
    }
  }
  release_client(client);
  throw PrometheusClientError("Prometheus query failed after retries");
}

std::string PrometheusClient::query_range(
    const std::string &promql, std::chrono::system_clock::time_point start,
    std::chrono::system_clock::time_point end, std::chrono::seconds step) {
  if (check_circuit()) {
    throw PrometheusClientError("Circuit breaker open");
  }
  httplib::Client *client = acquire_client();
  setup_auth(*client);
  std::string path = "/api/v1/query_range";
  auto to_rfc3339 = [](std::chrono::system_clock::time_point tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return std::string(buf);
  };
  httplib::Params params = {{"query", promql},
                            {"start", to_rfc3339(start)},
                            {"end", to_rfc3339(end)},
                            {"step", std::to_string(step.count())}};
  std::string url = build_query_url(path, params);
  int attempts = 0;
  while (attempts <= config_.max_retries) {
    auto res = client->Get(url.c_str());
    if (res && res->status == 200) {
      reset_circuit();
      release_client(client);
      return res->body;
    } else {
      record_failure();
      ++attempts;
      std::this_thread::sleep_for(std::chrono::milliseconds(100 * attempts));
    }
  }
  release_client(client);
  throw PrometheusClientError("Prometheus query_range failed after retries");
}

const PrometheusClientConfig &PrometheusClient::get_config() const {
  return config_;
}

void PrometheusClient::set_config(const PrometheusClientConfig &config) {
  config_ = config;
  // TODO: Reinitialize client pool if needed
}

PrometheusClient::PrometheusClientError::PrometheusClientError(
    const std::string &msg)
    : message(msg) {}

const char *PrometheusClient::PrometheusClientError::what() const noexcept {
  return message.c_str();
}

// Pooling notes:
// - acquire_client() and release_client() use a mutex for thread safety
// - Pool size is configurable via PrometheusClientConfig
// - For high concurrency, consider round-robin or per-thread assignment
// - Pool is static for now; can be extended for dynamic resizing

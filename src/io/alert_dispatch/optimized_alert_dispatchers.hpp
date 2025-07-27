#ifndef OPTIMIZED_ALERT_DISPATCHERS_HPP
#define OPTIMIZED_ALERT_DISPATCHERS_HPP

#include "../../core/memory_manager.hpp"
#include "../../utils/fast_string_formatting.hpp"
#include "../../utils/optimized_io_buffer_manager.hpp"
#include "base_dispatcher.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace anomaly_detector {

// Zero-copy HTTP dispatcher with connection pooling and keep-alive
class OptimizedHttpDispatcher : public IAlertDispatcher,
                                public memory::IMemoryManaged {
private:
  struct ConnectionInfo {
    int socket_fd = -1;
    std::chrono::steady_clock::time_point last_used;
    bool is_keep_alive = true;
    std::atomic<bool> in_use{false};

    ~ConnectionInfo() {
      if (socket_fd != -1) {
        close(socket_fd);
      }
    }
  };

  // Connection pool for reuse
  std::unordered_map<std::string, std::shared_ptr<ConnectionInfo>>
      connection_pool_;
  mutable std::mutex pool_mutex_;

  std::string host_;
  std::string path_;
  int port_;
  bool is_https_;

  // Pre-allocated buffers for zero-copy operations
  struct ZeroCopyBuffers {
    CircularBuffer<char> send_buffer{64 * 1024};
    CircularBuffer<char> recv_buffer{32 * 1024};
    std::vector<char> header_buffer;
    std::vector<char> json_buffer;

    ZeroCopyBuffers() {
      header_buffer.reserve(4096);
      json_buffer.reserve(16384);
    }
  };

  thread_local static ZeroCopyBuffers buffers_;

  // Template cache for repeated JSON formatting
  mutable std::unordered_map<std::string, StackStringBuilder::Template>
      json_templates_;
  mutable std::mutex template_mutex_;

  // Connection pooling and management
  std::shared_ptr<ConnectionInfo> get_connection() {
    std::string key = host_ + ":" + std::to_string(port_);
    std::lock_guard<std::mutex> lock(pool_mutex_);

    auto it = connection_pool_.find(key);
    if (it != connection_pool_.end()) {
      auto &conn = it->second;
      if (conn->socket_fd != -1 && !conn->in_use.load()) {
        // Check if connection is still valid
        if (is_connection_alive(conn->socket_fd)) {
          conn->in_use.store(true);
          conn->last_used = std::chrono::steady_clock::now();
          return conn;
        } else {
          // Connection is dead, remove it
          connection_pool_.erase(it);
        }
      }
    }

    // Create new connection
    auto new_conn = create_connection();
    if (new_conn && new_conn->socket_fd != -1) {
      new_conn->in_use.store(true);
      connection_pool_[key] = new_conn;
      return new_conn;
    }

    return nullptr;
  }

  void release_connection(std::shared_ptr<ConnectionInfo> conn) {
    if (conn) {
      conn->in_use.store(false);
      conn->last_used = std::chrono::steady_clock::now();
    }
  }

  std::shared_ptr<ConnectionInfo> create_connection() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      return nullptr;
    }

    // Set socket options for performance
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

    // Set non-blocking mode for timeout handling
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_);

    if (inet_pton(AF_INET, host_.c_str(), &server_addr.sin_addr) <= 0) {
      close(sock);
      return nullptr;
    }

    // Non-blocking connect with timeout
    int result =
        connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (result < 0 && errno != EINPROGRESS) {
      close(sock);
      return nullptr;
    }

    // Wait for connection with timeout
    if (result < 0) {
      fd_set write_fds;
      FD_ZERO(&write_fds);
      FD_SET(sock, &write_fds);

      struct timeval timeout;
      timeout.tv_sec = 5; // 5 second timeout
      timeout.tv_usec = 0;

      if (select(sock + 1, nullptr, &write_fds, nullptr, &timeout) <= 0) {
        close(sock);
        return nullptr;
      }

      // Check if connection succeeded
      int error;
      socklen_t len = sizeof(error);
      if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ||
          error != 0) {
        close(sock);
        return nullptr;
      }
    }

    // Set back to blocking mode
    fcntl(sock, F_SETFL, flags);

    auto conn = std::make_shared<ConnectionInfo>();
    conn->socket_fd = sock;
    conn->last_used = std::chrono::steady_clock::now();
    conn->is_keep_alive = true;

    return conn;
  }

  bool is_connection_alive(int sock) {
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;

    int result = poll(&pfd, 1, 0);
    if (result > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      return false;
    }

    return true;
  }

  // Zero-copy JSON formatting using templates
  size_t format_alert_json_zero_copy(const Alert &alert, char *buffer,
                                     size_t buffer_size) {
    // Get or create template for this alert type
    std::string template_key =
        "alert_" + std::to_string(static_cast<int>(alert.severity));

    StackStringBuilder::Template *tmpl = nullptr;
    {
      std::lock_guard<std::mutex> lock(template_mutex_);
      auto it = json_templates_.find(template_key);
      if (it == json_templates_.end()) {
        // Create new template
        StackStringBuilder::Template new_tmpl;
        new_tmpl.add_literal(R"({"timestamp":")");
        new_tmpl.add_placeholder("timestamp");
        new_tmpl.add_literal(R"(","severity":")");
        new_tmpl.add_placeholder("severity");
        new_tmpl.add_literal(R"(","source_ip":")");
        new_tmpl.add_placeholder("source_ip");
        new_tmpl.add_literal(R"(","message":")");
        new_tmpl.add_placeholder("message");
        new_tmpl.add_literal("\"}");

        json_templates_[template_key] = std::move(new_tmpl);
        tmpl = &json_templates_[template_key];
      } else {
        tmpl = &it->second;
      }
    }

    // Use stack string builder for zero-copy formatting
    StackStringBuilder builder(buffer, buffer_size);

    StackStringBuilder::Context ctx;
    ctx.add_value("timestamp", std::to_string(alert.timestamp_ms));
    ctx.add_value("severity", std::to_string(static_cast<int>(alert.severity)));
    ctx.add_value("source_ip", alert.source_ip);
    ctx.add_value("message", alert.message);

    return builder.format(*tmpl, ctx);
  }

  // Zero-copy HTTP request building
  size_t build_http_request_zero_copy(const char *json_body, size_t json_length,
                                      char *buffer, size_t buffer_size) {
    StackStringBuilder builder(buffer, buffer_size);

    builder.append("POST ");
    builder.append(path_);
    builder.append(" HTTP/1.1\r\n");
    builder.append("Host: ");
    builder.append(host_);
    builder.append("\r\n");
    builder.append("Content-Type: application/json\r\n");
    builder.append("Content-Length: ");
    builder.append(std::to_string(json_length));
    builder.append("\r\n");
    builder.append("Connection: keep-alive\r\n");
    builder.append("User-Agent: AnomalyDetector/1.0\r\n");
    builder.append("\r\n");

    // Append JSON body
    builder.append(json_body, json_length);

    return builder.size();
  }

public:
  explicit OptimizedHttpDispatcher(const std::string &webhook_url) {
    // Parse URL
    size_t proto_end = webhook_url.find("://");
    if (proto_end == std::string::npos) {
      throw std::invalid_argument("Invalid URL format");
    }

    std::string protocol = webhook_url.substr(0, proto_end);
    is_https_ = (protocol == "https");
    port_ = is_https_ ? 443 : 80;

    size_t host_start = proto_end + 3;
    size_t path_start = webhook_url.find('/', host_start);

    if (path_start == std::string::npos) {
      host_ = webhook_url.substr(host_start);
      path_ = "/";
    } else {
      host_ = webhook_url.substr(host_start, path_start - host_start);
      path_ = webhook_url.substr(path_start);
    }

    // Check for port in host
    size_t port_pos = host_.find(':');
    if (port_pos != std::string::npos) {
      port_ = std::stoi(host_.substr(port_pos + 1));
      host_ = host_.substr(0, port_pos);
    }

    // Pre-allocate template cache
    json_templates_.reserve(16);

    // Register with memory manager
    if (auto *mem_mgr = memory::MemoryManager::get_instance()) {
      mem_mgr->register_component(
          std::static_pointer_cast<memory::IMemoryManaged>(
              std::shared_ptr<OptimizedHttpDispatcher>(
                  this, [](OptimizedHttpDispatcher *) {})));
    }
  }

  ~OptimizedHttpDispatcher() override {
    // Close all connections
    std::lock_guard<std::mutex> lock(pool_mutex_);
    connection_pool_.clear();
  }

  bool dispatch(const Alert &alert) override {
    auto conn = get_connection();
    if (!conn) {
      return false;
    }

    bool success = false;

    try {
      // Format JSON using zero-copy approach
      size_t json_length = format_alert_json_zero_copy(
          alert, buffers_.json_buffer.data(), buffers_.json_buffer.capacity());

      if (json_length == 0) {
        release_connection(conn);
        return false;
      }

      // Build HTTP request using zero-copy
      size_t request_length = build_http_request_zero_copy(
          buffers_.json_buffer.data(), json_length,
          buffers_.header_buffer.data(), buffers_.header_buffer.capacity());

      if (request_length == 0) {
        release_connection(conn);
        return false;
      }

      // Send request using zero-copy
      ssize_t bytes_sent = send(conn->socket_fd, buffers_.header_buffer.data(),
                                request_length, MSG_NOSIGNAL);

      if (bytes_sent == static_cast<ssize_t>(request_length)) {
        // Read response (minimal - just check status)
        char response_buffer[1024];
        ssize_t bytes_received = recv(conn->socket_fd, response_buffer,
                                      sizeof(response_buffer) - 1, 0);

        if (bytes_received > 0) {
          response_buffer[bytes_received] = '\0';
          success = (strstr(response_buffer, "200 OK") != nullptr ||
                     strstr(response_buffer, "201 Created") != nullptr ||
                     strstr(response_buffer, "202 Accepted") != nullptr);
        }
      }

    } catch (const std::exception &e) {
      success = false;
    }

    release_connection(conn);
    return success;
  }

  const char *get_name() const override { return "OptimizedHttpDispatcher"; }

  std::string get_dispatcher_type() const override { return "optimized_http"; }

  // Connection pool management
  void cleanup_stale_connections() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto now = std::chrono::steady_clock::now();

    auto it = connection_pool_.begin();
    while (it != connection_pool_.end()) {
      auto &conn = it->second;
      auto age = std::chrono::duration_cast<std::chrono::minutes>(
          now - conn->last_used);

      if (age.count() > 5 || !is_connection_alive(conn->socket_fd)) {
        it = connection_pool_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    size_t usage = sizeof(*this);
    usage += connection_pool_.size() *
             (sizeof(ConnectionInfo) + 64); // Rough estimate
    usage += json_templates_.size() * 256;  // Template overhead
    return usage;
  }

  size_t compact() override {
    cleanup_stale_connections();

    std::lock_guard<std::mutex> lock(template_mutex_);
    if (json_templates_.size() > 32) {
      json_templates_.clear();
      return json_templates_.size() * 256;
    }
    return 0;
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 2) {
      cleanup_stale_connections();
      if (pressure_level >= 3) {
        std::lock_guard<std::mutex> lock(template_mutex_);
        json_templates_.clear();
      }
    }
  }

  bool can_evict() const override {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return connection_pool_.empty();
  }

  std::string get_component_name() const override {
    return "OptimizedHttpDispatcher";
  }

  int get_priority() const override {
    return 3; // Medium priority - important but can be recreated
  }
};

// Initialize thread-local buffers
thread_local OptimizedHttpDispatcher::ZeroCopyBuffers
    OptimizedHttpDispatcher::buffers_;

// Optimized Syslog dispatcher with connection pooling
class OptimizedSyslogDispatcher : public IAlertDispatcher,
                                  public memory::IMemoryManaged {
private:
  int syslog_socket_;
  struct sockaddr_in syslog_addr_;
  bool is_connected_;

  // Message formatting cache
  mutable std::unordered_map<int, StackStringBuilder::Template>
      message_templates_;
  mutable std::mutex template_mutex_;

  // Zero-copy message formatting
  size_t format_syslog_message_zero_copy(const Alert &alert, char *buffer,
                                         size_t buffer_size) {
    int priority =
        16 + static_cast<int>(alert.severity); // Local facility, severity

    StackStringBuilder builder(buffer, buffer_size);

    builder.append("<");
    builder.append(std::to_string(priority));
    builder.append(">");
    builder.append("AnomalyDetector[");
    builder.append(std::to_string(getpid()));
    builder.append("]: ");
    builder.append(alert.source_ip);
    builder.append(" - ");
    builder.append(alert.message);

    return builder.size();
  }

public:
  OptimizedSyslogDispatcher() : syslog_socket_(-1), is_connected_(false) {
    // Create UDP socket for syslog
    syslog_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (syslog_socket_ < 0) {
      throw std::runtime_error("Failed to create syslog socket");
    }

    // Configure local syslog address
    memset(&syslog_addr_, 0, sizeof(syslog_addr_));
    syslog_addr_.sin_family = AF_INET;
    syslog_addr_.sin_port = htons(514);
    syslog_addr_.sin_addr.s_addr = inet_addr("127.0.0.1");

    is_connected_ = true;

    // Register with memory manager
    if (auto *mem_mgr = memory::MemoryManager::get_instance()) {
      mem_mgr->register_component(
          std::static_pointer_cast<memory::IMemoryManaged>(
              std::shared_ptr<OptimizedSyslogDispatcher>(
                  this, [](OptimizedSyslogDispatcher *) {})));
    }
  }

  ~OptimizedSyslogDispatcher() override {
    if (syslog_socket_ != -1) {
      close(syslog_socket_);
    }
  }

  bool dispatch(const Alert &alert) override {
    if (!is_connected_) {
      return false;
    }

    char message_buffer[2048];
    size_t message_length = format_syslog_message_zero_copy(
        alert, message_buffer, sizeof(message_buffer));

    if (message_length == 0) {
      return false;
    }

    ssize_t bytes_sent =
        sendto(syslog_socket_, message_buffer, message_length, 0,
               (struct sockaddr *)&syslog_addr_, sizeof(syslog_addr_));

    return bytes_sent == static_cast<ssize_t>(message_length);
  }

  const char *get_name() const override { return "OptimizedSyslogDispatcher"; }

  std::string get_dispatcher_type() const override {
    return "optimized_syslog";
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    return sizeof(*this) + message_templates_.size() * 128;
  }

  size_t compact() override {
    std::lock_guard<std::mutex> lock(template_mutex_);
    if (message_templates_.size() > 16) {
      message_templates_.clear();
      return message_templates_.size() * 128;
    }
    return 0;
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 3) {
      std::lock_guard<std::mutex> lock(template_mutex_);
      message_templates_.clear();
    }
  }

  bool can_evict() const override {
    return false; // Syslog is typically critical
  }

  std::string get_component_name() const override {
    return "OptimizedSyslogDispatcher";
  }

  int get_priority() const override {
    return 2; // High priority - logging is important
  }
};

} // namespace anomaly_detector

#endif // OPTIMIZED_ALERT_DISPATCHERS_HPP

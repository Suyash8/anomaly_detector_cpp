#include "web_server.hpp"
#include "core/logger.hpp"

WebServer::WebServer(const std::string &host, int port)
    : host_(host), port_(port) {
  server_ = std::make_unique<httplib::Server>();
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Web server initialized for " << host_ << ":" << port_);
}

WebServer::~WebServer() {
  if (server_thread_.joinable()) {
    stop();
  }
}

void WebServer::start() {
  if (server_thread_.joinable()) {
    return; // Already running
  }
  server_thread_ = std::thread(&WebServer::run, this);
  server_thread_.detach(); // Run in the background
}

void WebServer::stop() {
  if (server_) {
    server_->stop();
  }
  // Note: Since we detach, we can't join. Stop is best-effort.
  LOG(LogLevel::INFO, LogComponent::CORE, "Web server stopping...");
}

void WebServer::run() {
  LOG(LogLevel::INFO, LogComponent::CORE,
      "Web server starting on a background thread...");
  if (!server_->listen(host_.c_str(), port_)) {
    LOG(LogLevel::FATAL, LogComponent::CORE,
        "Web server failed to listen on " << host_ << ":" << port_);
  }
}
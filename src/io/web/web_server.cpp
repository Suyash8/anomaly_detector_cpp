#include "web_server.hpp"
#include "core/logger.hpp"
#include "core/metrics_registry.hpp"
#include "utils/json_formatter.hpp"

#include <chrono>
#include <prometheus/gauge.h>
#include <prometheus/text_serializer.h>

WebServer::WebServer(const std::string &host, int port,
                     MetricsRegistry &metrics_registry,
                     AlertManager &alert_manager,
                     AnalysisEngine &analysis_engine,
                     prometheus::Gauge &memory_gauge)
    : host_(host), port_(port), metrics_registry_(metrics_registry),
      alert_manager_(alert_manager), analysis_engine_(analysis_engine),
      memory_gauge_(memory_gauge) {
  server_ = std::make_unique<httplib::Server>();

  const char *ui_path = "./src/io/web/ui/dist";
  if (!server_->set_mount_point("/", ui_path)) {
    LOG(LogLevel::WARN, LogComponent::CORE,
        "Failed to set mount point for UI. UI will not be available.");
  }

  server_->Get("/metrics", [this](const httplib::Request &req,
                                  httplib::Response &res) {
    LOG(LogLevel::DEBUG, LogComponent::CORE,
        "WebServer: Received request for /metrics from " << req.remote_addr);
    prometheus::TextSerializer serializer;
    auto collected_metrics = metrics_registry_.get_registry()->Collect();
    res.set_content(serializer.Serialize(collected_metrics),
                    "text/plain; version=0.0.4");
    LOG(LogLevel::DEBUG, LogComponent::CORE,
        "WebServer: Responded to /metrics");
  });

  server_->Get(
      "/api/v1/metrics/performance",
      [this](const httplib::Request &req, httplib::Response &res) {
        LOG(LogLevel::DEBUG, LogComponent::CORE,
            "WebServer: Received request for /api/v1/metrics/performance from "
                << req.remote_addr);
        res.set_content("{}", "application/json"); // Placeholder
        LOG(LogLevel::DEBUG, LogComponent::CORE,
            "WebServer: Responded to /api/v1/metrics/performance (deprecated)");
      });

  server_->Get("/api/v1/operations/alerts",
               [this](const httplib::Request &, httplib::Response &res) {
                 auto alerts = alert_manager_.get_recent_alerts(50);
                 nlohmann::json j = nlohmann::json::array();
                 for (const auto &alert : alerts) {
                   j.push_back(JsonFormatter::alert_to_json_object(alert));
                 }
                 res.set_content(j.dump(2), "application/json");
               });

  server_->Get("/api/v1/operations/state", [this](const httplib::Request &,
                                                  httplib::Response &res) {
    nlohmann::json j_state;

    auto top_active = analysis_engine_.get_top_n_by_metric(10, "request_rate");
    nlohmann::json j_top_active = nlohmann::json::array();
    for (const auto &info : top_active) {
      j_top_active.push_back({{"ip", info.ip}, {"value", info.value}});
    }
    j_state["top_active_ips"] = j_top_active;

    auto top_error = analysis_engine_.get_top_n_by_metric(10, "error_rate");
    nlohmann::json j_top_error = nlohmann::json::array();
    for (const auto &info : top_error) {
      j_top_error.push_back({{"ip", info.ip}, {"value", info.value}});
    }
    j_state["top_error_ips"] = j_top_error;

    res.set_content(j_state.dump(2), "application/json");
  });

  LOG(LogLevel::INFO, LogComponent::CORE,
      "Web server initialized for " << host_ << ":" << port_);
}

WebServer::~WebServer() {
  if (server_thread_.joinable() || memory_monitor_thread_.joinable())
    stop();
}

void WebServer::start() {
  if (server_thread_.joinable())
    return; // Already running

  server_thread_ = std::thread(&WebServer::run, this);
#if defined(__linux__)
  memory_monitor_thread_ = std::thread(&WebServer::monitor_memory, this);
#endif
  server_thread_.detach(); // Run in the background
}

void WebServer::stop() {
  shutdown_flag_ = true;
  if (server_)
    server_->stop();

  if (memory_monitor_thread_.joinable())
    memory_monitor_thread_.join();

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

#if defined(__linux__)
void WebServer::monitor_memory() {
  while (!shutdown_flag_) {
    std::ifstream statm("/proc/self/statm");
    if (statm.is_open()) {
      long long size, resident, share, text, lib, data, dt;
      statm >> size >> resident >> share >> text >> lib >> data >> dt;
      long page_size = getpagesize();
      memory_gauge_.Set(static_cast<double>(resident * page_size));
    }

    for (int i = 0; i < 150; ++i) {
      if (shutdown_flag_)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
}
#else
void WebServer::monitor_memory() {
  // No-op on non-Linux systems
}
#endif
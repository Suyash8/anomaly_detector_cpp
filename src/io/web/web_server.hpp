#ifndef WEB_SERVER_HPP
#define WEB_SERVER_HPP

#include "analysis/analysis_engine.hpp"
#include "core/alert_manager.hpp"
#include "core/metrics_registry.hpp"
#include "httplib.h"

#include <memory>
#include <prometheus/gauge.h>
#include <string>
#include <thread>

class WebServer {
public:
  WebServer(const std::string &host, int port,
            MetricsRegistry &metrics_registry, AlertManager &alert_manager,
            AnalysisEngine &analysis_engine, prometheus::Gauge &memory_gauge);
  ~WebServer();

  void start();
  void stop();

private:
  void run();
  void monitor_memory();

  std::unique_ptr<httplib::Server> server_;
  std::thread server_thread_;
  std::thread memory_monitor_thread_;
  std::atomic<bool> shutdown_flag_{false};
  std::string host_;
  int port_;
  MetricsRegistry &metrics_registry_;
  AlertManager &alert_manager_;
  AnalysisEngine &analysis_engine_;
  prometheus::Gauge &memory_gauge_;
};

#endif // WEB_SERVER_HPP
#ifndef WEB_SERVER_HPP
#define WEB_SERVER_HPP

#include "analysis/analysis_engine.hpp"
#include "core/alert_manager.hpp"
#include "core/metrics_manager.hpp"
#include "httplib.h"

#include <memory>
#include <string>
#include <thread>

class WebServer {
public:
  WebServer(const std::string &host, int port, MetricsManager &metrics_manager,
            AlertManager &alert_manager, AnalysisEngine &analysis_engine);
  ~WebServer();

  void start();
  void stop();

private:
  void run();

  std::unique_ptr<httplib::Server> server_;
  std::thread server_thread_;
  std::string host_;
  int port_;
  MetricsManager &metrics_manager_;
  AlertManager &alert_manager_;
  AnalysisEngine &analysis_engine_;
};

#endif // WEB_SERVER_HPP
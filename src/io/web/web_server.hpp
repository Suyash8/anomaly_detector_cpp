#ifndef WEB_SERVER_HPP
#define WEB_SERVER_HPP

#include "core/metrics_manager.hpp"
#include "httplib.h"

#include <memory>
#include <string>
#include <thread>

class WebServer {
public:
  WebServer(const std::string &host, int port, MetricsManager &metrics_manager);
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
};

#endif // WEB_SERVER_HPP
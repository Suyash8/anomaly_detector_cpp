#ifndef WEB_SERVER_HPP
#define WEB_SERVER_HPP

#include "httplib.h"
#include <memory>
#include <string>
#include <thread>

class WebServer {
public:
  WebServer(const std::string &host, int port);
  ~WebServer();

  void start();
  void stop();

private:
  void run();

  std::unique_ptr<httplib::Server> server_;
  std::thread server_thread_;
  std::string host_;
  int port_;
};

#endif // WEB_SERVER_HPP
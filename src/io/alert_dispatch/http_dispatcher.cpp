#include "../../io/alert_dispatch/http_dispatcher.hpp"
#include "../../../third_party/cpp-httplib/httplib.h"
#include "../../utils/json_formatter.hpp"
#include "http_dispatcher.hpp"

#include <iostream>
#include <regex>

HttpDispatcher::HttpDispatcher(const std::string &webhook_url) {
  // Regex to capture protocol, host, and path
  // Example: https://example.com/some/path
  // Group 1: https
  // Group 2: example.com
  // Group 3: /some/path
  std::regex url_regex(R"(^(https?):\/\/([^\/]+)(\/.*)?$)");
  std::smatch match;

  if (std::regex_match(webhook_url, match, url_regex)) {
    std::string protocol = match[1].str();
    host_ = match[2].str();
    path_ = match[3].matched ? match[3].str() : "/";
    is_https_ = (protocol == "https");
  } else {
    std::cerr
        << "Error: Invalid webhook URL format provided to HttpDispatcher: "
        << webhook_url << std::endl;
    // Set a default state to prevent crashes
    host_.clear();
    path_.clear();
  }
}

void HttpDispatcher::dispatch(const Alert &alert) {
  // If the URL was invalid during construction, don't try to send
  if (host_.empty() || path_.empty()) {
    return;
  }

  auto send_request = [&](auto &client) {
    // Disable certificate verification for ease of use.
    // This check ensures the method is only called if it exists (i.e., on
    // SSLClient)
    if constexpr (std::is_same_v<std::decay_t<decltype(client)>,
                                 httplib::SSLClient>) {
      client.set_ca_cert_path(nullptr);
      client.enable_server_certificate_verification(false);
    }

    std::string json_body = JsonFormatter::format_alert_to_json(alert);
    auto res = client.Post(path_.c_str(), json_body, "application/json");

    if (!res || res->status >= 400) {
      std::cerr << "Error: Failed to dispatch alert via HTTP to "
                << (is_https_ ? "https://" : "http://") << host_ << path_;
      if (res) {
        std::cerr << " | Status: " << res->status;
      }
      std::cerr << std::endl;
    }
  };

  if (is_https_) {
    httplib::SSLClient cli(host_);
    send_request(cli);
  } else {
    httplib::Client cli(host_);
    send_request(cli);
  }
}
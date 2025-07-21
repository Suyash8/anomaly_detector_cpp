#include "io/alert_dispatch/http_dispatcher.hpp"
#include "core/logger.hpp"
#include "http_dispatcher.hpp"
#include "httplib.h"
#include "utils/json_formatter.hpp"

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
    LOG(LogLevel::TRACE, LogComponent::IO_DISPATCH,
        "HttpDispatcher initialized with URL: "
            << webhook_url << " | Host: " << host_ << " | Path: " << path_
            << " | Protocol: " << (is_https_ ? "HTTPS" : "HTTP"));
  } else {
    LOG(LogLevel::ERROR, LogComponent::IO_DISPATCH,
        "Invalid webhook URL format provided to HttpDispatcher: "
            << webhook_url);
    // Set a default state to prevent crashes
    host_.clear();
    path_.clear();
  }
}

bool HttpDispatcher::dispatch(const Alert &alert) {
  // If the URL was invalid during construction, don't try to send
  if (host_.empty() || path_.empty()) {
    LOG(LogLevel::ERROR, LogComponent::IO_DISPATCH,
        "Cannot dispatch alert: Invalid host or path in HttpDispatcher.");
    return false;
  }

  bool success = false;
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

    if (res && res->status < 400) {
      LOG(LogLevel::TRACE, LogComponent::IO_DISPATCH,
          "Successfully dispatched alert via HTTP to "
              << (is_https_ ? "https://" : "http://") << host_ << path_
              << " | Status: " << res->status);
      success = true;
    } else {
      LOG(LogLevel::ERROR, LogComponent::IO_DISPATCH,
          "Failed to dispatch alert via HTTP to "
              << (is_https_ ? "https://" : "http://") << host_ << path_
              << " | Status: "
              << (res ? std::to_string(res->status) : "No response")
              << " | Body: " << (res ? res->body : "No response body"));
      success = false;
    }
  };

  if (is_https_) {
    httplib::SSLClient cli(host_);
    send_request(cli);
  } else {
    httplib::Client cli(host_);
    send_request(cli);
  }
  return success;
}
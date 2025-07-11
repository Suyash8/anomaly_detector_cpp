#include "intel_manager.hpp"
#include "core/logger.hpp"
#include "httplib.h"
#include "utils/utils.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <unordered_set>

IntelManager::IntelManager(const std::vector<std::string> &feed_urls,
                           uint32_t update_interval_seconds)
    : feed_urls_(feed_urls), update_interval_seconds_(update_interval_seconds),
      ip_blacklist_(std::make_unique<std::unordered_set<uint32_t>>()) {
  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "IntelManager created. Starting background thread for feed updates.");
  // Initial fetch on startup
  update_feeds();

  // Start the background thread
  background_thread_ = std::thread(&IntelManager::background_thread_func, this);
}

IntelManager::~IntelManager() {
  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "Shutting down IntelManager...");
  shutdown_flag_ = true;
  cv_.notify_one();

  if (background_thread_.joinable())
    background_thread_.join();

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL, "IntelManager shut down.");
}

bool IntelManager::is_blacklisted(uint32_t ip) const {
  std::lock_guard<std::mutex> lock(list_mutex_);
  if (!ip_blacklist_)
    return false;
  return ip_blacklist_->count(ip) > 0;
}

void IntelManager::background_thread_func() {
  while (!shutdown_flag_) {
    std::unique_lock<std::mutex> lock(cv_mutex_);
    cv_.wait_for(lock, std::chrono::seconds(update_interval_seconds_),
                 [this] { return shutdown_flag_.load(); });

    if (shutdown_flag_)
      break;

    LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
        "IntelManager: Running periodic threat feed update...");
    update_feeds();
  }
}

void IntelManager::update_feeds() {
  auto new_blacklist = std::make_unique<std::unordered_set<uint32_t>>();

  for (const auto &url_str : feed_urls_) {
    std::regex url_regex(R"(^(https?):\/\/([^\/]+)(\/.*)?$)");
    std::smatch match;
    if (!std::regex_match(url_str, match, url_regex)) {
      LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
          "IntelManager: Skipping invalid feed URL: " + url_str);
      continue;
    }
    std::string host = match[2].str();
    std::string path = match[3].matched ? match[3].str() : "/";
    bool is_https = (match[1].str() == "https");

    auto process_request = [&](auto &client) {
      auto res = client.Get(path.c_str());
      if (res && res->status == 200) {
        std::istringstream iss(res->body);
        std::string line;
        size_t count_before = new_blacklist->size();
        while (std::getline(iss, line)) {
          std::string trimmed_line = Utils::trim_copy(line);
          if (trimmed_line.empty() || trimmed_line[0] == '#') {
            continue;
          }
          uint32_t ip = Utils::ip_string_to_uint32(trimmed_line);
          if (ip != 0) {
            new_blacklist->insert(ip);
          }
        }
        LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
            "Fetched " << std::to_string(new_blacklist->size() - count_before)
                       << " IPs from " << url_str);
      } else {
        LOG(LogLevel::ERROR, LogComponent::IO_THREATINTEL,
            "IntelManager: Failed to fetch feed from "
                << url_str
                << (res ? " | Status: " + std::to_string(res->status) : ""));
      }
    };

    // Create the appropriate client
    if (is_https) {
      httplib::SSLClient cli(host);
      cli.enable_server_certificate_verification(false);
      process_request(cli);
    } else {
      httplib::Client cli(host);
      process_request(cli);
    }
  }

  size_t final_count = 0;
  {
    std::lock_guard<std::mutex> lock(list_mutex_);
    ip_blacklist_ = std::move(new_blacklist);
    if (ip_blacklist_)
      final_count = ip_blacklist_->size();
  }
  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "IntelManager: Threat intelligence feeds updated. Total blacklisted IPs: "
          << final_count);
}
#include "intel_manager.hpp"
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
  std::cout
      << "IntelManager created. Starting background thread for feed updates."
      << std::endl;
  // Initial fetch on startup
  update_feeds();

  // Start the background thread
  background_thread_ = std::thread(&IntelManager::background_thread_func, this);
}

IntelManager::~IntelManager() {
  std::cout << "Shutting down IntelManager..." << std::endl;
  shutdown_flag_ = true;
  cv_.notify_one();

  if (background_thread_.joinable())
    background_thread_.join();

  std::cout << "IntelManager shut down." << std::endl;
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

    std::cout << "IntelManager: Running periodic threat feed update..."
              << std::endl;
    update_feeds();
  }
}

void IntelManager::update_feeds() {
  auto new_blacklist = std::make_unique<std::unordered_set<uint32_t>>();

  for (const auto &url_str : feed_urls_) {
    std::regex url_regex(R"(^(https?):\/\/([^\/]+)(\/.*)?$)");
    std::smatch match;
    if (!std::regex_match(url_str, match, url_regex)) {
      std::cerr << "IntelManager: Skipping invalid feed URL: " << url_str
                << std::endl;
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
        std::cout << "  -> Fetched " << (new_blacklist->size() - count_before)
                  << " IPs from " << url_str << std::endl;
      } else {
        std::cerr << "IntelManager: Failed to fetch feed from " << url_str;
        if (res) {
          std::cerr << " | Status: " << res->status;
        }
        std::cerr << std::endl;
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
  std::cout << "IntelManager: Threat intelligence feeds updated. Total "
               "blacklisted IPs: "
            << final_count << std::endl;
}
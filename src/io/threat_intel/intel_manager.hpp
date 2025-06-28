#ifndef INTEL_MANAGER_HPP
#define INTEL_MANAGER_HPP

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

class IntelManager {
public:
  IntelManager(const std::vector<std::string> &feed_urls,
               uint32_t update_interval_seconds);
  ~IntelManager();
  bool is_blacklisted(uint32_t ip) const;

private:
  void update_feeds();
  void background_thread_func();

  std::vector<std::string> feed_urls_;
  uint32_t update_interval_seconds_;

  std::unique_ptr<std::unordered_set<uint32_t>> ip_blacklist_;
  mutable std::mutex list_mutex_;

  std::thread background_thread_;
  std::atomic<bool> shutdown_flag_{false};

  std::condition_variable cv_;
  std::mutex cv_mutex_;
};

#endif // INTEL_MANAGER_HPP
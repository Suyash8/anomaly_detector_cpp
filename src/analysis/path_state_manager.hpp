#ifndef PATH_STATE_MANAGER_HPP
#define PATH_STATE_MANAGER_HPP

#include "analysis/per_path_state.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

class PathStateManager {
public:
  PathStateManager() = default;

  PerPathState &get_or_create(const std::string &path,
                              uint64_t current_timestamp_ms);

  std::mutex &get_mutex() { return mutex_; }

  const std::unordered_map<std::string, PerPathState> &get_map() const {
    return path_activity_trackers_;
  }

private:
  std::unordered_map<std::string, PerPathState> path_activity_trackers_;
  std::mutex mutex_;
};

#endif // PATH_STATE_MANAGER_HPP
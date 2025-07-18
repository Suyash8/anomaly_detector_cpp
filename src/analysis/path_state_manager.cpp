#include "analysis/path_state_manager.hpp"
#include "analysis/per_path_state.hpp"
#include "core/logger.hpp"

PerPathState &PathStateManager::get_or_create(const std::string &path,
                                              uint64_t current_timestamp_ms) {
  // This assumes the caller has already locked the mutex
  auto it = path_activity_trackers_.find(path);
  if (it == path_activity_trackers_.end()) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "PathStateManager: Creating new PerPathState for Path: " << path);
    auto [inserted_it, success] = path_activity_trackers_.emplace(
        path, PerPathState(current_timestamp_ms));
    return inserted_it->second;
  } else {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "PathStateManager: Found existing PerPathState for Path: "
            << path << ". Updating last_seen timestamp.");
    it->second.last_seen_timestamp_ms = current_timestamp_ms;
    return it->second;
  }
}
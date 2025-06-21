#ifndef STATE_MANAGER_HPP
#define STATE_MANAGER_HPP

#include "../analysis_engine.hpp"
#include "lru_cache.hpp"
#include "persistence_manager.hpp"

#include <cstddef>
#include <memory>
#include <string>

class StateManager {
public:
  StateManager(std::string ip_state_dir, std::string path_state_dir,
               size_t cache_size, size_t num_shards);

  PerIpState &get_ip_state(const std::string &ip);
  PerPathState &get_path_state(const std::string &path);

  void shutdown();

private:
  void write_dirty_ip_state(const std::string &key, const PerIpState &state);
  void write_dirty_path_state(const std::string &key,
                              const PerPathState &state);

  std::unique_ptr<PersistenceManager> ip_persistence_;
  std::unique_ptr<PersistenceManager> path_persistence_;
  LRUCache<std::string, PerIpState> ip_cache_;
  LRUCache<std::string, PerPathState> path_cache_;
};

#endif // STATE_MANAGER_HPP
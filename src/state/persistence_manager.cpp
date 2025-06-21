#include "persistence_manager.hpp"
#include <cstddef>
#include <optional>

PersistenceManager::PersistenceManager(std::string base_dir, size_t num_shards)
    : base_dir_(std::move(base_dir)), num_shards_(num_shards) {}

bool PersistenceManager::write_state(const std::string &key,
                                     const std::vector<char> &data) {
  return false;
}

std::optional<std::vector<char>>
PersistenceManager::read_state(const std::string &key) {
  return std::nullopt;
}

std::string
PersistenceManager::get_shard_path_for_key(const std::string &key) const {
  return "";
}
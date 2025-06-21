#include "persistence_manager.hpp"
#include <cstddef>
#include <functional>
#include <optional>
#include <string>

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
  if (num_shards_ == 0)
    return "";

  std::hash<std::string> hasher;
  size_t shard_index = hasher(key) % num_shards_;

  return base_dir_ + "/shard_" + std::to_string(shard_index) + ".db";
}
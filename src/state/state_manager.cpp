#include "state_manager.hpp"
#include "persistence_manager.hpp"
#include "state_serializer.hpp"
#include <memory>
#include <utility>

StateManager::StateManager(std::string ip_state_dir, std::string path_state_dir,
                           size_t cache_size, size_t num_shards)
    : ip_persistence_(std::make_unique<PersistenceManager>(
          std::move(ip_state_dir), num_shards)),
      path_persistence_(std::make_unique<PersistenceManager>(
          std::move(path_state_dir), num_shards)),
      ip_cache_(cache_size), path_cache_(cache_size) {}

PerIpState &StateManager::get_ip_state(const std::string &ip) {
  // 1. Check the cache first
  auto cache_entry_ref = ip_cache_.get(ip);
  if (cache_entry_ref.has_value()) {
    cache_entry_ref->get().is_dirty = true;
    return cache_entry_ref->get().value;
  }

  // 2. Cache miss (Page fault): load from persistence layer
  auto serialized_data = ip_persistence_->read_state(ip);
  PerIpState state(0, 0, 0);
  if (serialized_data.has_value()) {
    auto deserialized_state =
        StateSerializer::deserialize_ip_state(*serialized_data);
    if (deserialized_state.has_value())
      state = std::move(*deserialized_state);
  }

  // 3. Put loaded/new state into cache
  auto evicted_item = ip_cache_.put(ip, std::move(state));

  // 4. If item was evicted, write it to disk
  if (evicted_item.has_value())
    write_dirty_ip_state(evicted_item->first, evicted_item->second);

  // 5. Item now in cache -> get it again and return
  auto new_cache_entry_ref = ip_cache_.get(ip);
  new_cache_entry_ref->get().is_dirty = true;
  return new_cache_entry_ref->get().value;
}

PerPathState &StateManager::get_path_state(const std::string &path) {
  // 1. Check the cache first
  auto cache_entry_ref = path_cache_.get(path);
  if (cache_entry_ref.has_value()) {
    cache_entry_ref->get().is_dirty = true;
    return cache_entry_ref->get().value;
  }

  // 2. Cache miss
  auto serialized_data = path_persistence_->read_state(path);
  PerPathState state(0);
  if (serialized_data.has_value()) {
    auto deserialized_state =
        StateSerializer::deserialize_path_state(*serialized_data);
    if (deserialized_state.has_value())
      state = std::move(*deserialized_state);
  }

  // 3. Put loaded/new state into cache
  auto evicted_item = path_cache_.put(path, std::move(state));
  if (evicted_item.has_value())
    write_dirty_path_state(evicted_item->first, evicted_item->second);

  auto new_cacle_entry_ref = path_cache_.get(path);
  new_cacle_entry_ref->get().is_dirty = true;
  return new_cacle_entry_ref->get().value;
}

void StateManager::shutdown() {
  // Flush IP cache
  for (const auto &item : ip_cache_.get_all_items())
    if (item.second.is_dirty)
      write_dirty_ip_state(item.first, item.second.value);

  // Flush Path cache
  for (const auto &item : path_cache_.get_all_items())
    if (item.second.is_dirty)
      write_dirty_path_state(item.first, item.second.value);
}

void StateManager::write_dirty_ip_state(const std::string &key,
                                        const PerIpState &state) {
  auto serialized_data = StateSerializer::serialize(state);
  ip_persistence_->write_state(key, serialized_data);
}

void StateManager::write_dirty_path_state(const std::string &key,
                                          const PerPathState &state) {
  auto serialized_data = StateSerializer::serialize(state);
  path_persistence_->write_state(key, serialized_data);
}
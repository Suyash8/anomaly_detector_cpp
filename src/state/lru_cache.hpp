#ifndef LRU_CACHE_HPP
#define LRU_CACHE_HPP

#include <cstddef>
#include <functional>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

template <typename Key, typename Value> class LRUCache {
public:
  struct CacheEntry {
    Value value;
    bool is_dirty = false;
  };

  explicit LRUCache(size_t max_size);

  std::optional<std::pair<Key, Value>> put(const Key &key, Value value);
  std::optional<std::reference_wrapper<CacheEntry>> get(const Key &key);
  size_t size() const;

  const std::list<std::pair<Key, CacheEntry>> &get_all_items() const;

private:
  using ListIterator = typename std::list<std::pair<Key, Value>>::iterator;

  std::list<std::pair<Key, Value>> items_list_;
  std::unordered_map<Key, ListIterator> items_map_;
  size_t max_size_;
};

// --- Implementation ---

template <typename Key, typename Value>

LRUCache<Key, Value>::LRUCache(size_t max_size) : max_size_(max_size) {
  if (max_size_ < 1)
    max_size_ = 1;
}

template <typename Key, typename Value>
void LRUCache<Key, Value>::put(const Key &key, Value value) {
  auto it = items_map_.find(key);

  // Case 1: Key already exists
  if (it != items_map_.end()) {
    it->second->second = std::move(value);
    items_list_.splice(items_list_.begin(), items_list_, it->second);
    return;
  }

  // Case 2: Key does not exist, and cache is full
  if (items_map_.size() >= max_size_) {
    Key lru_key = items_list_.back().first;
    items_map_.erase(lru_key);
    items_list_.pop_back();
  }

  // Case 3: Key does not exist, add it
  items_list_.emplace_front(key, std::move(value));
  items_map_[key] = items_list_.begin();
}

template <typename Key, typename Value>
std::optional<std::reference_wrapper<Value>>
LRUCache<Key, Value>::get(const Key &key) {
  auto it = items_map_.find(key);

  // Key not found
  if (it == items_map_.end())
    return std::nullopt;

  // Key found, move the accessed item to the front of the list
  items_list_.splice(items_list_.begin(), items_list_, it->second);

  return it->second->second;
}

template <typename Key, typename Value>
size_t LRUCache<Key, Value>::size() const {
  return items_map_.size();
}

#endif // LRU_CACHE_HPP
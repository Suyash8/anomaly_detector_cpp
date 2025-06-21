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
  explicit LRUCache(size_t max_size);

  void put(const Key &key, Value value);
  std::optional<std::reference_wrapper<Value>> get(const Key &key);
  size_t size() const;

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

#endif // LRU_CACHE_HPP
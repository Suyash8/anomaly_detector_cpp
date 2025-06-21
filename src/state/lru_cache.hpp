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

#endif // LRU_CACHE_HPP
#include "../src/state/lru_cache.hpp"

#include <cassert>
#include <iostream>

void test_put_and_get() {
  std::cout << "Running test_put_and_get..." << std::endl;
  LRUCache<int, std::string> cache(3);

  cache.put(1, "one");
  cache.put(2, "two");
  cache.put(3, "three");

  assert(cache.size() == 3);

  auto val1_ref = cache.get(1);
  assert(val1_ref.has_value() && val1_ref->get() == "one");

  auto val2_ref = cache.get(2);
  assert(val2_ref.has_value() && val2_ref->get() == "two");

  auto val_nonexistent = cache.get(99);
  assert(!val_nonexistent.has_value());

  // Update an existing key
  cache.put(1, "uno");
  auto val1_updated_ref = cache.get(1);
  assert(val1_updated_ref.has_value() && val1_updated_ref->get() == "uno");
  assert(cache.size() == 3); // Size should not change
  std::cout << "OK!" << std::endl;
}

void test_eviction_policy() {
  std::cout << "Running test_eviction_policy..." << std::endl;
  LRUCache<int, std::string> cache(3);

  cache.put(1, "one");
  cache.put(2, "two");
  cache.put(3, "three");

  // Adding a 4th item should evict item 1 (the LRU)
  cache.put(4, "four"); // 4, 3, 2

  assert(cache.size() == 3);
  assert(!cache.get(1).has_value());
  assert(cache.get(2).has_value());
  assert(cache.get(3).has_value());
  assert(cache.get(4).has_value());
  std::cout << "OK!" << std::endl;
}

void test_usage_order() {
  std::cout << "Running test_usage_order..." << std::endl;
  LRUCache<int, std::string> cache(3);

  cache.put(1, "one");
  cache.put(2, "two");
  cache.put(3, "three"); // 3, 2, 1

  cache.get(1); // Order is now: 1, 3, 2

  cache.put(4, "four"); // 4, 1, 3

  assert(cache.size() == 3);
  assert(!cache.get(2).has_value()); // 2 should be gone
  assert(cache.get(1).has_value());
  assert(cache.get(3).has_value());
  assert(cache.get(4).has_value());
  std::cout << "OK!" << std::endl;
}

int main() {
  std::cout << "--- Running LRU Cache Test ---" << std::endl;
  test_put_and_get();
  test_eviction_policy();
  test_usage_order();
  std::cout << "\n--- LRU Cache Test Initial Phase Passed! ---" << std::endl;
  return 0;
}
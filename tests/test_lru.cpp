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

int main() {
  std::cout << "--- Running LRU Cache Test ---" << std::endl;
  test_put_and_get();
  std::cout << "\n--- LRU Cache Test Initial Phase Passed! ---" << std::endl;
  return 0;
}
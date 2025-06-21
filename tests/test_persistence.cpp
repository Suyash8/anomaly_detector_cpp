#include "../src/state/persistence_manager.hpp"
#include "../src/state/state_serializer.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

void cleanup(const std::string &dir) {
  if (std::filesystem::exists(dir))
    std::filesystem::remove_all(dir);
}

int main() {
  const std::string test_dir = "./tmp_persistence_test";
  cleanup(test_dir);

  std::cout << "--- Running Persistence Manager Test ---" << std::endl;

  PersistenceManager pm(test_dir, 4);

  // 1. Create and serialize a state object
  PerPathState original_state(12345);
  original_state.bytes_sent_tracker.update(5000);
  auto serialized_data = StateSerializer::serialize(original_state);

  // 2. Write the state
  std::cout << "Writing state for key '/api/v1/users'..." << std::endl;
  bool success = pm.write_state("/api/v1/users", serialized_data);
  assert(success);

  // 3. Read the state back
  std::cout << "Reading state for key '/api/v1/users'..." << std::endl;
  auto read_data_opt = pm.read_state("/api/v1/users");
  assert(read_data_opt.has_value());
  assert(*read_data_opt == serialized_data);
  std::cout << "OK: Read matches write." << std::endl;

  // 4. Test non-existent key
  std::cout << "Reading non-existent key..." << std::endl;
  auto non_existent_data = pm.read_state("/does/not/exist");
  assert(!non_existent_data.has_value());
  std::cout << "OK: Non-existent key handled correctly." << std::endl;

  // 5. Update the state
  original_state.bytes_sent_tracker.update(9999);
  auto updated_serialized_data = StateSerializer::serialize(original_state);
  std::cout << "Updating state for key '/api/v1/users'..." << std::endl;
  success = pm.write_state("/api/v1/users", updated_serialized_data);
  assert(success);

  // 6. Read the updated state
  auto updated_read_data_opt = pm.read_state("/api/v1/users");
  assert(updated_read_data_opt.has_value());
  assert(*updated_read_data_opt == updated_serialized_data);
  assert(*updated_read_data_opt != serialized_data);
  std::cout << "OK: State update successful." << std::endl;

  // 7. Verify sharding by writing multiple keys
  pm.write_state("key1", {1});
  pm.write_state("key2", {2});
  pm.write_state("key3", {3});
  pm.write_state("key4", {4});
  pm.write_state("key5", {5});

  int file_count = 0;
  for (const auto &entry : std::filesystem::directory_iterator(test_dir)) {
    if (entry.is_regular_file())
      file_count++;
  }
  assert(file_count > 1 && file_count <= 4);
  std::cout << "OK: Data distributed across " << file_count << " shard files."
            << std::endl;

  std::cout << "\n--- Persistence Manager Test Passed! ---" << std::endl;
  cleanup(test_dir);
  return 0;
}
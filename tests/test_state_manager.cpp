#include "../src/state/state_manager.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

void cleanup(const std::string &dir) {
  if (std::filesystem::exists(dir))
    std::filesystem::remove_all(dir);
}

int main() {
  const std::string ip_dir = "./tmp_ip_state";
  const std::string path_dir = "./tmp_path_state";
  cleanup(ip_dir);
  cleanup(path_dir);

  std::cout << "--- Running State Manager Test ---" << std::endl;

  // Phase 1: Test cache miss and initial creation
  {
    std::cout << "Testing cache miss and creation..." << std::endl;
    StateManager sm(ip_dir, path_dir, 2, 1);
    PerIpState &ip_state = sm.get_ip_state("1.1.1.1");
    ip_state.ip_first_seen_timestamp_ms = 100;
    sm.shutdown(); // This should write the dirty state to disk
  }

  // Phase 2: Test cache miss with load from disk
  {
    std::cout << "Testing cache miss and load from disk..." << std::endl;
    StateManager sm(ip_dir, path_dir, 2, 1);
    PerIpState &ip_state = sm.get_ip_state("1.1.1.1");
    assert(ip_state.ip_first_seen_timestamp_ms == 100);
    std::cout << "OK: State loaded correctly from disk." << std::endl;
  }

  // Phase 3: Test eviction with write-back
  {
    std::cout << "Testing eviction with write-back..." << std::endl;
    StateManager sm(ip_dir, path_dir, 2, 1);

    sm.get_ip_state("1.1.1.1");
    PerIpState &ip2_state = sm.get_ip_state("2.2.2.2");
    ip2_state.last_seen_timestamp_ms = 200;

    // Load 3.3.3.3, this will evict 1.1.1.1 (which is not dirty yet)
    sm.get_ip_state("3.3.3.3");
    // Load 4.4.4.4, this will evict 2.2.2.2 (which IS dirty)
    // The eviction should trigger a write to disk for 2.2.2.2
    sm.get_ip_state("4.4.4.4");
  }

  // Phase 4: Verify the evicted item was saved
  {
    std::cout << "Verifying evicted item was saved..." << std::endl;
    StateManager sm(ip_dir, path_dir, 2, 1);
    PerIpState &ip2_state = sm.get_ip_state("2.2.2.2");
    assert(ip2_state.last_seen_timestamp_ms == 200);
    std::cout << "OK: Dirty evicted state was persisted." << std::endl;
  }

  std::cout << "\n--- State Manager Test Passed! ---" << std::endl;
  cleanup(ip_dir);
  cleanup(path_dir);
  return 0;
}
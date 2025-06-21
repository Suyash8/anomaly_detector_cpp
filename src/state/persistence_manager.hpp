#ifndef PERSISTENCE_MANAGER_HPP
#define PERSISTENCE_MANAGER_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

class PersistenceManager {
public:
  PersistenceManager(std::string base_dir, size_t num_shards);

  bool write_state(const std::string &key, const std::vector<char> &data);
  std::optional<std::vector<char>> read_state(const std::string &key);

private:
  std::string get_shard_path_for_key(const std::string &key) const;

  std::string base_dir_;
  size_t num_shards_;
};

#endif // PERSISTENCE_MANAGER_HPP
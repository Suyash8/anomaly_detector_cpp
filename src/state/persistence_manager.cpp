#include "persistence_manager.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

PersistenceManager::PersistenceManager(std::string base_dir, size_t num_shards)
    : base_dir_(std::move(base_dir)), num_shards_(num_shards) {
  if (!std::filesystem::exists(base_dir_))
    std::filesystem::create_directories(base_dir_);
}

bool PersistenceManager::write_state(const std::string &key,
                                     const std::vector<char> &data) {
  const std::string shard_path = get_shard_path_for_key(key);
  if (shard_path.empty())
    return false;

  // Read the whole shard into a map
  std::unordered_map<std::string, std::vector<char>> shard_data;
  std::ifstream in_file(shard_path, std::ios::binary);
  if (in_file.is_open()) {
    while (in_file.peek() != EOF) {
      uint32_t key_len, val_len;
      in_file.read(reinterpret_cast<char *>(&key_len), sizeof(key_len));
      std::string current_key(key_len, '\0');
      in_file.read(reinterpret_cast<char *>(current_key[0]), key_len);
      in_file.read(reinterpret_cast<char *>(&val_len), sizeof(val_len));
      std::vector<char> current_val(val_len);
      in_file.read(current_val.data(), val_len);
      shard_data[current_key] = current_val;
    }
    in_file.close();
  }

  // Update the map with the new data
  shard_data[key] = data;

  // ---- ATOMIC WRITE SEQUENCE ----
  const std::string temp_path = shard_path + ".tmp";

  // 1. Write the entire map back to a temporary file
  std::ofstream out_file(shard_path, std::ios::binary | std::ios::trunc);
  if (!out_file.is_open())
    return false;

  for (const auto &[k, v] : shard_data) {
    uint32_t key_len = k.length();
    uint32_t val_len = v.size();
    out_file.write(reinterpret_cast<const char *>(&key_len), sizeof(key_len));
    out_file.write(k.data(), key_len);
    out_file.write(reinterpret_cast<const char *>(&val_len), sizeof(val_len));
    out_file.write(v.data(), val_len);
  }

  out_file.close();
  if (!out_file)
    return false;

  // 2. Automatically replace the original file with the temporary one
  std::error_code ec;
  std::filesystem::rename(temp_path, shard_path, ec);

  return !ec;
}

std::optional<std::vector<char>>
PersistenceManager::read_state(const std::string &key) {
  const std::string shard_path = get_shard_path_for_key(key);
  if (shard_path.empty())
    return std::nullopt;

  std::ifstream file(shard_path, std::ios::binary);
  if (!file.is_open())
    return std::nullopt;

  while (file.peek() != EOF) {
    uint32_t key_len, val_len;
    file.read(reinterpret_cast<char *>(&key_len), sizeof(key));
    std::string current_key(key_len, '\0');
    file.read(reinterpret_cast<char *>(current_key[0]), key_len);
    file.read(reinterpret_cast<char *>(&val_len), sizeof(val_len));

    if (current_key == key) {
      std::vector<char> val(val_len);
      file.read(val.data(), val_len);
      return val;
    } else
      file.seekg(val_len, std::ios::cur);
  }

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
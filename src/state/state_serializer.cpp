#include "state_serializer.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace StateSerializer {

// Anonymous namespace for private helper functions
namespace {

// ================== WRITER HELPERS ==================
void write_bytes(std::vector<char> &buffer, const void *src, size_t size) {
  const char *bytes = static_cast<const char *>(src);
  buffer.insert(buffer.end(), bytes, bytes + size);
}

template <typename T> void write_primitive(std::vector<char> &buffer, T value) {
  write_bytes(buffer, &value, sizeof(T));
}

void write_string(std::vector<char> &buffer, const std::string &str) {
  write_primitive<uint32_t>(buffer, str.length());
  write_bytes(buffer, str.data(), str.length());
}

template <typename T>
void write_set(std::vector<char> &buffer,
               const std::unordered_set<T> &the_set) {
  write_primitive<uint32_t>(buffer, the_set.size());
  for (const auto &item : the_set)
    write_string(buffer, item);
}

// ================== READER HELPERS ==================
bool read_bytes(const std::vector<char> &buffer, size_t &offset, void *dest,
                size_t size) {
  if (offset + size > buffer.size())
    return false;
  std::memcpy(dest, buffer.data() + offset, size);
  offset += size;
  return true;
}

template <typename T>
bool read_primitive(const std::vector<char> &buffer, size_t &offset, T &value) {
  return read_bytes(buffer, offset, &value, sizeof(T));
}

bool read_string(const std::vector<char> &buffer, size_t &offset,
                 std::string &str) {
  uint32_t len;
  if (!read_primitive(buffer, offset, len))
    return false;
  if (offset + len > buffer.size())
    return false;
  str.assign(buffer.data() + offset, len);
  offset += len;
  return true;
}

template <typename T>
bool read_set(const std::vector<char> &buffer, size_t &offset,
              std::unordered_set<T> &the_set) {
  uint32_t count;
  if (!read_primitive(buffer, offset, count))
    return false;
  the_set.clear();
  the_set.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    std::string item;
    if (!read_string(buffer, offset, item))
      return false;
    the_set.insert(item);
  }
  return true;
}

} // namespace

// Empty stubs to allow compilation
std::vector<char> serialize(const PerIpState &state) { return {}; }
std::vector<char> serialize(const PerPathState &state) { return {}; }
std::optional<PerIpState> deserialize_ip_state(const std::vector<char> &data) {
  return std::nullopt;
}
std::optional<PerPathState>
deserialize_path_state(const std::vector<char> &data) {
  return std::nullopt;
}

} // namespace StateSerializer
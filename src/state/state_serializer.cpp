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

// Forward declare these to use them in the Accessor
void write_stats_tracker(std::vector<char> &buffer,
                         const StatsTracker &tracker);
void write_sliding_window_u64(std::vector<char> &buffer,
                              const SlidingWindow<uint64_t> &window);
void write_sliding_window_str(std::vector<char> &buffer,
                              const SlidingWindow<std::string> &window);

bool read_stats_tracker(const std::vector<char> &buffer, size_t &offset,
                        StatsTracker &tracker);
bool read_sliding_window_u64(const std::vector<char> &buffer, size_t &offset,
                             SlidingWindow<uint64_t> &window);
bool read_sliding_window_str(const std::vector<char> &buffer, size_t &offset,
                             SlidingWindow<std::string> &window);

} // namespace

class Accessor {
public:
  static void write_stats(std::vector<char> &buffer,
                          const StatsTracker &tracker) {
    write_primitive(buffer, tracker.count_);
    write_primitive(buffer, tracker.mean_);
    write_primitive(buffer, tracker.m2_);
  }

  static bool read_stats(const std::vector<char> &buffer, size_t &offset,
                         StatsTracker &tracker) {
    if (!read_primitive(buffer, offset, tracker.count_))
      return false;
    if (!read_primitive(buffer, offset, tracker.mean_))
      return false;
    if (!read_primitive(buffer, offset, tracker.m2_))
      return false;
    return true;
  }

  static void write_window_u64(std::vector<char> &buffer,
                               const SlidingWindow<uint64_t> &window) {
    write_primitive(buffer, window.configured_duration_ms);
    write_primitive(buffer, window.configured_max_elements);
    write_primitive<uint32_t>(buffer, window.window_data.size());
    for (const auto &pair : window.window_data) {
      write_primitive(buffer, pair.first);  // timestamp
      write_primitive(buffer, pair.second); // value
    }
  }

  static bool read_window_u64(const std::vector<char> &buffer, size_t &offset,
                              SlidingWindow<uint64_t> &window) {
    if (!read_primitive(buffer, offset, window.configured_duration_ms))
      return false;
    if (!read_primitive(buffer, offset, window.configured_max_elements))
      return false;
    uint32_t count;
    if (!read_primitive(buffer, offset, count))
      return false;
    window.window_data.clear();
    for (uint32_t i = 0; i < count; ++i) {
      uint64_t ts, val;
      if (!read_primitive(buffer, offset, ts))
        return false;
      if (!read_primitive(buffer, offset, val))
        return false;
      window.window_data.emplace_back(ts, val);
    }
    return true;
  }

  static void write_window_str(std::vector<char> &buffer,
                               const SlidingWindow<std::string> &window) {
    write_primitive(buffer, window.configured_duration_ms);
    write_primitive(buffer, window.configured_max_elements);
    write_primitive<uint32_t>(buffer, window.window_data.size());
    for (const auto &pair : window.window_data) {
      write_primitive(buffer, pair.first); // timestamp
      write_string(buffer, pair.second);   // value
    }
  }

  static bool read_window_str(const std::vector<char> &buffer, size_t &offset,
                              SlidingWindow<std::string> &window) {
    if (!read_primitive(buffer, offset, window.configured_duration_ms))
      return false;
    if (!read_primitive(buffer, offset, window.configured_max_elements))
      return false;
    uint32_t count;
    if (!read_primitive(buffer, offset, count))
      return false;
    window.window_data.clear();
    for (uint32_t i = 0; i < count; ++i) {
      uint64_t ts;
      std::string val;
      if (!read_primitive(buffer, offset, ts))
        return false;
      if (!read_string(buffer, offset, val))
        return false;
      window.window_data.emplace_back(ts, val);
    }
    return true;
  }
};

namespace {
// Connect helpers to the accessor
void write_stats_tracker(std::vector<char> &buffer,
                         const StatsTracker &tracker) {
  Accessor::write_stats(buffer, tracker);
}
bool read_stats_tracker(const std::vector<char> &buffer, size_t &offset,
                        StatsTracker &tracker) {
  return Accessor::read_stats(buffer, offset, tracker);
}
void write_sliding_window_u64(std::vector<char> &buffer,
                              const SlidingWindow<uint64_t> &window) {
  Accessor::write_window_u64(buffer, window);
}
bool read_sliding_window_u64(const std::vector<char> &buffer, size_t &offset,
                             SlidingWindow<uint64_t> &window) {
  return Accessor::read_window_u64(buffer, offset, window);
}
void write_sliding_window_str(std::vector<char> &buffer,
                              const SlidingWindow<std::string> &window) {
  Accessor::write_window_str(buffer, window);
}
bool read_sliding_window_str(const std::vector<char> &buffer, size_t &offset,
                             SlidingWindow<std::string> &window) {
  return Accessor::read_window_str(buffer, offset, window);
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
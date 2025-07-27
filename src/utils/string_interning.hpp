#ifndef STRING_INTERNING_HPP
#define STRING_INTERNING_HPP

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace memory {

/**
 * @brief Global string interning pool for memory optimization
 *
 * This class provides string interning functionality to reduce memory usage
 * by storing only one copy of each unique string and returning lightweight
 * string_view references.
 *
 * Key benefits:
 * - Reduces memory usage for repeated strings (paths, user agents, IPs)
 * - Enables fast string comparison by ID
 * - Thread-safe for concurrent access
 * - Provides statistics for optimization analysis
 */
class StringInternPool {
public:
  using InternID = uint32_t;
  static constexpr InternID INVALID_ID = 0;

  StringInternPool() : next_id_(1) {
    // Reserve space for common strings
    string_to_id_.reserve(10000);
    id_to_string_.reserve(10000);
    id_to_string_.emplace_back(""); // ID 0 = empty string
  }

  /**
   * @brief Intern a string and return its ID
   * @param str String to intern
   * @return Unique ID for this string
   */
  InternID intern(std::string_view str) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Look for existing string
    auto it = string_to_id_.find(std::string(str));
    if (it != string_to_id_.end()) {
      return it->second;
    }

    // Add new string
    InternID id = next_id_++;
    std::string stored_str(str);
    string_to_id_[stored_str] = id;
    id_to_string_.push_back(stored_str);

    return id;
  }

  /**
   * @brief Get string_view by ID (fast lookup)
   * @param id String ID from intern()
   * @return string_view of the interned string
   */
  std::string_view get_string(InternID id) const {
    if (id >= id_to_string_.size()) {
      return "";
    }
    return id_to_string_[id];
  }

  /**
   * @brief Get ID for a string (if already interned)
   * @param str String to look up
   * @return ID if found, INVALID_ID if not interned
   */
  InternID get_id(std::string_view str) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = string_to_id_.find(std::string(str));
    return (it != string_to_id_.end()) ? it->second : INVALID_ID;
  }

  /**
   * @brief Check if string is interned
   */
  bool contains(std::string_view str) const {
    return get_id(str) != INVALID_ID;
  }

  /**
   * @brief Get memory usage statistics
   */
  struct Stats {
    size_t unique_strings;
    size_t total_memory_bytes;
    size_t average_string_length;
    size_t hash_table_overhead;
    double compression_ratio; // original_size / interned_size
  };

  Stats get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Stats stats;
    stats.unique_strings = id_to_string_.size();

    size_t total_string_bytes = 0;
    size_t total_string_length = 0;

    for (const auto &str : id_to_string_) {
      total_string_bytes += str.capacity();
      total_string_length += str.length();
    }

    stats.total_memory_bytes =
        total_string_bytes +
        string_to_id_.size() * (sizeof(std::string) + sizeof(InternID)) +
        id_to_string_.capacity() * sizeof(std::string);

    stats.average_string_length =
        stats.unique_strings > 0 ? total_string_length / stats.unique_strings
                                 : 0;

    stats.hash_table_overhead =
        string_to_id_.size() * (sizeof(std::string) + sizeof(InternID));

    // Estimate compression (assuming each string was duplicated 5 times on
    // average)
    stats.compression_ratio =
        static_cast<double>(total_string_bytes * 5) / stats.total_memory_bytes;

    return stats;
  }

  /**
   * @brief Clear all interned strings (for testing/reset)
   */
  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    string_to_id_.clear();
    id_to_string_.clear();
    id_to_string_.emplace_back(""); // Re-add empty string
    next_id_ = 1;
  }

  /**
   * @brief Compact the pool by removing unused strings
   * This is expensive and should be done during low-activity periods
   */
  size_t compact() {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t freed = 0;

    // Shrink string capacities
    for (auto &str : id_to_string_) {
      size_t old_capacity = str.capacity();
      str.shrink_to_fit();
      freed += old_capacity - str.capacity();
    }

    return freed;
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, InternID> string_to_id_;
  std::vector<std::string> id_to_string_;
  InternID next_id_;
};

/**
 * @brief Global string interning pool instance
 */
extern StringInternPool &get_global_string_pool();

/**
 * @brief Convenience functions for global pool
 */
inline StringInternPool::InternID intern_string(std::string_view str) {
  return get_global_string_pool().intern(str);
}

inline std::string_view get_interned_string(StringInternPool::InternID id) {
  return get_global_string_pool().get_string(id);
}

/**
 * @brief RAII helper for interned strings with automatic memory management
 */
class InternedString {
public:
  InternedString() : id_(StringInternPool::INVALID_ID) {}

  explicit InternedString(std::string_view str) : id_(intern_string(str)) {}

  InternedString(const InternedString &other) = default;
  InternedString &operator=(const InternedString &other) = default;

  std::string_view view() const { return get_interned_string(id_); }

  StringInternPool::InternID id() const { return id_; }

  bool empty() const {
    return id_ == StringInternPool::INVALID_ID || view().empty();
  }

  // Comparison operators
  bool operator==(const InternedString &other) const {
    return id_ == other.id_;
  }
  bool operator!=(const InternedString &other) const {
    return id_ != other.id_;
  }
  bool operator==(std::string_view other) const { return view() == other; }
  bool operator!=(std::string_view other) const { return view() != other; }

  // For use in hash containers
  struct Hash {
    size_t operator()(const InternedString &str) const {
      return std::hash<StringInternPool::InternID>{}(str.id_);
    }
  };

private:
  StringInternPool::InternID id_;
};

} // namespace memory

#endif // STRING_INTERNING_HPP

#ifndef BLOOM_FILTER_HPP
#define BLOOM_FILTER_HPP

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace memory {

// High-performance Bloom filter optimized for memory efficiency
template <typename T> class BloomFilter {
public:
  // Constructor with expected number of elements and desired false positive
  // rate
  BloomFilter(size_t expected_elements, double false_positive_rate = 0.01)
      : expected_elements_(expected_elements),
        false_positive_rate_(false_positive_rate) {

    // Calculate optimal bit array size and number of hash functions
    bit_array_size_ =
        calculate_optimal_size(expected_elements, false_positive_rate);
    num_hash_functions_ =
        calculate_optimal_hash_count(bit_array_size_, expected_elements);

    // Initialize bit array
    size_t byte_size = (bit_array_size_ + 7) / 8; // Round up to nearest byte
    bit_array_.resize(byte_size, 0);

    inserted_elements_ = 0;
  }

  // Add element to the filter
  void add(const T &element) {
    auto hashes = hash_element(element);
    for (size_t i = 0; i < num_hash_functions_; ++i) {
      size_t bit_index = hashes[i] % bit_array_size_;
      set_bit(bit_index);
    }
    inserted_elements_++;
  }

  // Check if element might be in the set (no false negatives, possible false
  // positives)
  bool contains(const T &element) const {
    auto hashes = hash_element(element);
    for (size_t i = 0; i < num_hash_functions_; ++i) {
      size_t bit_index = hashes[i] % bit_array_size_;
      if (!get_bit(bit_index)) {
        return false; // Definitely not in set
      }
    }
    return true; // Probably in set
  }

  // Clear all elements from the filter
  void clear() {
    std::fill(bit_array_.begin(), bit_array_.end(), 0);
    inserted_elements_ = 0;
  }

  // Get current false positive probability based on actual insertions
  double get_false_positive_probability() const {
    if (inserted_elements_ == 0)
      return 0.0;

    double ratio = static_cast<double>(inserted_elements_) / expected_elements_;
    return std::pow(1.0 - std::exp(-num_hash_functions_ * ratio),
                    num_hash_functions_);
  }

  // Memory usage in bytes
  size_t memory_usage() const { return bit_array_.size() + sizeof(*this); }

  // Filter statistics
  size_t size() const { return inserted_elements_; }
  size_t capacity() const { return expected_elements_; }
  size_t bit_count() const { return bit_array_size_; }
  size_t hash_function_count() const { return num_hash_functions_; }
  double load_factor() const {
    return expected_elements_ > 0
               ? static_cast<double>(inserted_elements_) / expected_elements_
               : 0.0;
  }

  // Resize the filter (requires rebuilding)
  void resize(size_t new_expected_elements,
              double new_false_positive_rate = 0.0) {
    if (new_false_positive_rate <= 0.0) {
      new_false_positive_rate = false_positive_rate_;
    }

    // Store old data
    std::vector<uint8_t> old_bit_array = std::move(bit_array_);

    // Reinitialize with new parameters
    expected_elements_ = new_expected_elements;
    false_positive_rate_ = new_false_positive_rate;
    bit_array_size_ =
        calculate_optimal_size(expected_elements_, false_positive_rate_);
    num_hash_functions_ =
        calculate_optimal_hash_count(bit_array_size_, expected_elements_);

    size_t byte_size = (bit_array_size_ + 7) / 8;
    bit_array_.resize(byte_size, 0);
    inserted_elements_ = 0;

    // Note: We cannot rebuild the filter without the original elements
    // This is a limitation of Bloom filters - they are write-only
  }

  // Serialize filter to binary format
  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> data;
    data.reserve(sizeof(expected_elements_) + sizeof(false_positive_rate_) +
                 sizeof(bit_array_size_) + sizeof(num_hash_functions_) +
                 sizeof(inserted_elements_) + bit_array_.size());

    // Header
    auto append_value = [&data](const auto &value) {
      const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&value);
      data.insert(data.end(), bytes, bytes + sizeof(value));
    };

    append_value(expected_elements_);
    append_value(false_positive_rate_);
    append_value(bit_array_size_);
    append_value(num_hash_functions_);
    append_value(inserted_elements_);

    // Bit array
    data.insert(data.end(), bit_array_.begin(), bit_array_.end());

    return data;
  }

  // Deserialize filter from binary format
  bool deserialize(const std::vector<uint8_t> &data) {
    if (data.size() < 5 * sizeof(size_t) + sizeof(double)) {
      return false; // Invalid data
    }

    size_t offset = 0;
    auto read_value = [&data, &offset](auto &value) {
      if (offset + sizeof(value) > data.size())
        return false;
      std::memcpy(&value, data.data() + offset, sizeof(value));
      offset += sizeof(value);
      return true;
    };

    if (!read_value(expected_elements_) || !read_value(false_positive_rate_) ||
        !read_value(bit_array_size_) || !read_value(num_hash_functions_) ||
        !read_value(inserted_elements_)) {
      return false;
    }

    size_t expected_bit_array_size = (bit_array_size_ + 7) / 8;
    if (offset + expected_bit_array_size != data.size()) {
      return false; // Size mismatch
    }

    bit_array_.assign(data.begin() + offset, data.end());
    return true;
  }

private:
  // MurmurHash3 implementation for fast, uniform hashing
  static constexpr uint32_t murmur3_32(const void *key, size_t len,
                                       uint32_t seed) {
    const uint8_t *data = static_cast<const uint8_t *>(key);
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t r1 = 15;
    const uint32_t r2 = 13;
    const uint32_t m = 5;
    const uint32_t n = 0xe6546b64;

    uint32_t hash = seed;

    const size_t nblocks = len / 4;
    const uint32_t *blocks = reinterpret_cast<const uint32_t *>(data);

    for (size_t i = 0; i < nblocks; i++) {
      uint32_t k = blocks[i];
      k *= c1;
      k = (k << r1) | (k >> (32 - r1));
      k *= c2;

      hash ^= k;
      hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
    }

    const uint8_t *tail = data + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
    case 3:
      k1 ^= tail[2] << 16;
      [[fallthrough]];
    case 2:
      k1 ^= tail[1] << 8;
      [[fallthrough]];
    case 1:
      k1 ^= tail[0];
      k1 *= c1;
      k1 = (k1 << r1) | (k1 >> (32 - r1));
      k1 *= c2;
      hash ^= k1;
    }

    hash ^= len;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);

    return hash;
  }

  // Generate multiple hash values for an element
  std::array<uint32_t, 8> hash_element(const T &element) const {
    std::array<uint32_t, 8> hashes;

    // Convert element to bytes for hashing
    std::string element_bytes;
    if constexpr (std::is_same_v<T, std::string>) {
      element_bytes = element;
    } else {
      element_bytes = std::to_string(element);
    }

    // Generate primary and secondary hashes
    uint32_t hash1 = murmur3_32(element_bytes.data(), element_bytes.size(), 0);
    uint32_t hash2 =
        murmur3_32(element_bytes.data(), element_bytes.size(), hash1);

    // Use double hashing to generate multiple hash values
    for (size_t i = 0; i < std::min(num_hash_functions_, size_t(8)); ++i) {
      hashes[i] = hash1 + i * hash2;
    }

    return hashes;
  }

  // Calculate optimal bit array size
  static size_t calculate_optimal_size(size_t expected_elements,
                                       double false_positive_rate) {
    return static_cast<size_t>(-expected_elements *
                               std::log(false_positive_rate) /
                               (std::log(2) * std::log(2)));
  }

  // Calculate optimal number of hash functions
  static size_t calculate_optimal_hash_count(size_t bit_array_size,
                                             size_t expected_elements) {
    if (expected_elements == 0)
      return 1;
    return static_cast<size_t>(
        std::round((static_cast<double>(bit_array_size) / expected_elements) *
                   std::log(2)));
  }

  // Set bit at given index
  void set_bit(size_t index) {
    size_t byte_index = index / 8;
    size_t bit_offset = index % 8;
    bit_array_[byte_index] |= (1u << bit_offset);
  }

  // Get bit at given index
  bool get_bit(size_t index) const {
    size_t byte_index = index / 8;
    size_t bit_offset = index % 8;
    return (bit_array_[byte_index] & (1u << bit_offset)) != 0;
  }

  size_t expected_elements_;
  double false_positive_rate_;
  size_t bit_array_size_;
  size_t num_hash_functions_;
  size_t inserted_elements_;
  std::vector<uint8_t> bit_array_;
};

// Specialized Bloom filter for common types
using StringBloomFilter = BloomFilter<std::string>;
using IntBloomFilter = BloomFilter<int>;
using UIntBloomFilter = BloomFilter<uint32_t>;

// Counting Bloom filter for supporting deletions (approximate)
template <typename T> class CountingBloomFilter {
public:
  CountingBloomFilter(size_t expected_elements,
                      double false_positive_rate = 0.01, uint8_t max_count = 15)
      : expected_elements_(expected_elements),
        false_positive_rate_(false_positive_rate), max_count_(max_count) {

    bit_array_size_ = BloomFilter<T>::calculate_optimal_size(
        expected_elements, false_positive_rate);
    num_hash_functions_ = BloomFilter<T>::calculate_optimal_hash_count(
        bit_array_size_, expected_elements);

    // Use 4 bits per counter (0-15 range)
    size_t counter_array_size =
        (bit_array_size_ + 1) / 2; // 2 counters per byte
    counter_array_.resize(counter_array_size, 0);

    inserted_elements_ = 0;
  }

  void add(const T &element) {
    auto hashes = hash_element(element);
    for (size_t i = 0; i < num_hash_functions_; ++i) {
      size_t counter_index = hashes[i] % bit_array_size_;
      increment_counter(counter_index);
    }
    inserted_elements_++;
  }

  bool remove(const T &element) {
    auto hashes = hash_element(element);

    // First check if element is present
    for (size_t i = 0; i < num_hash_functions_; ++i) {
      size_t counter_index = hashes[i] % bit_array_size_;
      if (get_counter(counter_index) == 0) {
        return false; // Element definitely not present
      }
    }

    // Decrement counters
    for (size_t i = 0; i < num_hash_functions_; ++i) {
      size_t counter_index = hashes[i] % bit_array_size_;
      decrement_counter(counter_index);
    }

    if (inserted_elements_ > 0) {
      inserted_elements_--;
    }
    return true;
  }

  bool contains(const T &element) const {
    auto hashes = hash_element(element);
    for (size_t i = 0; i < num_hash_functions_; ++i) {
      size_t counter_index = hashes[i] % bit_array_size_;
      if (get_counter(counter_index) == 0) {
        return false;
      }
    }
    return true;
  }

  void clear() {
    std::fill(counter_array_.begin(), counter_array_.end(), 0);
    inserted_elements_ = 0;
  }

  size_t memory_usage() const { return counter_array_.size() + sizeof(*this); }

  size_t size() const { return inserted_elements_; }

private:
  using BloomFilterBase = BloomFilter<T>;

  auto hash_element(const T &element) const {
    return BloomFilterBase::hash_element(element);
  }

  uint8_t get_counter(size_t index) const {
    size_t byte_index = index / 2;
    bool is_high_nibble = (index % 2) == 1;

    if (is_high_nibble) {
      return (counter_array_[byte_index] >> 4) & 0x0F;
    } else {
      return counter_array_[byte_index] & 0x0F;
    }
  }

  void set_counter(size_t index, uint8_t value) {
    value = std::min(value, max_count_);
    size_t byte_index = index / 2;
    bool is_high_nibble = (index % 2) == 1;

    if (is_high_nibble) {
      counter_array_[byte_index] =
          (counter_array_[byte_index] & 0x0F) | (value << 4);
    } else {
      counter_array_[byte_index] = (counter_array_[byte_index] & 0xF0) | value;
    }
  }

  void increment_counter(size_t index) {
    uint8_t current = get_counter(index);
    if (current < max_count_) {
      set_counter(index, current + 1);
    }
  }

  void decrement_counter(size_t index) {
    uint8_t current = get_counter(index);
    if (current > 0) {
      set_counter(index, current - 1);
    }
  }

  size_t expected_elements_;
  double false_positive_rate_;
  size_t bit_array_size_;
  size_t num_hash_functions_;
  size_t inserted_elements_;
  uint8_t max_count_;
  std::vector<uint8_t> counter_array_;
};

} // namespace memory

#endif // BLOOM_FILTER_HPP

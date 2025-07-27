#pragma once

#include <bitset>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace core {

/**
 * Ultra-compact binary serialization system for maximum memory efficiency
 * Features:
 * - Variable-length integer encoding (varint)
 * - Dictionary compression for repeated strings
 * - Delta compression for time-series data
 * - Bit packing for boolean and enum fields
 * - Streaming serialization/deserialization
 */

// Forward declarations
class BinarySerializer;
class BinaryDeserializer;
class StringDictionary;

/**
 * Variable-length integer encoding utilities
 */
namespace varint {
// Encode unsigned integer as varint
size_t encode_uint64(uint64_t value, uint8_t *buffer);
size_t encode_uint32(uint32_t value, uint8_t *buffer);

// Decode varint from buffer
std::pair<uint64_t, size_t> decode_uint64(const uint8_t *buffer,
                                          size_t buffer_size);
std::pair<uint32_t, size_t> decode_uint32(const uint8_t *buffer,
                                          size_t buffer_size);

// Calculate encoded size without actually encoding
size_t encoded_size_uint64(uint64_t value);
size_t encoded_size_uint32(uint32_t value);
} // namespace varint

/**
 * String dictionary for compression of repeated strings
 */
class StringDictionary {
public:
  StringDictionary();

  // Add string to dictionary, returns ID
  uint32_t add_string(const std::string &str);

  // Get string by ID
  const std::string &get_string(uint32_t id) const;

  // Check if string exists, returns ID if found
  std::optional<uint32_t> find_string(const std::string &str) const;

  // Clear dictionary
  void clear();

  // Get dictionary size
  size_t size() const { return strings_.size(); }

  // Serialize dictionary itself
  size_t serialize(uint8_t *buffer, size_t buffer_size) const;
  size_t deserialize(const uint8_t *buffer, size_t buffer_size);

  // Calculate serialized size
  size_t serialized_size() const;

private:
  std::vector<std::string> strings_;
  std::unordered_map<std::string, uint32_t> string_to_id_;
  uint32_t next_id_;
};

/**
 * Bit packer for efficient boolean and small integer storage
 */
class BitPacker {
public:
  BitPacker() : bit_position_(0) {}

  // Pack boolean value
  void pack_bool(bool value);

  // Pack small integer (up to 32 bits)
  void pack_uint(uint32_t value, uint8_t bits);

  // Pack enum value
  template <typename E> void pack_enum(E value, uint8_t bits) {
    static_assert(std::is_enum_v<E>, "Type must be enum");
    pack_uint(static_cast<uint32_t>(value), bits);
  }

  // Get packed data
  const std::vector<uint8_t> &data() const { return data_; }
  size_t bit_size() const { return bit_position_; }
  size_t byte_size() const { return (bit_position_ + 7) / 8; }

  // Clear packer
  void clear();

private:
  std::vector<uint8_t> data_;
  size_t bit_position_;

  void ensure_capacity(size_t additional_bits);
};

/**
 * Bit unpacker for reading packed data
 */
class BitUnpacker {
public:
  BitUnpacker(const uint8_t *data, size_t size_bytes);

  // Unpack boolean value
  bool unpack_bool();

  // Unpack small integer
  uint32_t unpack_uint(uint8_t bits);

  // Unpack enum value
  template <typename E> E unpack_enum(uint8_t bits) {
    static_assert(std::is_enum_v<E>, "Type must be enum");
    return static_cast<E>(unpack_uint(bits));
  }

  // Check if more data available
  bool has_more() const { return bit_position_ < total_bits_; }

  // Get current position
  size_t bit_position() const { return bit_position_; }

private:
  const uint8_t *data_;
  size_t total_bits_;
  size_t bit_position_;
};

/**
 * Delta compression for time-series data
 */
class DeltaCompressor {
public:
  DeltaCompressor();

  // Add timestamp (will be delta-compressed)
  void add_timestamp(std::chrono::steady_clock::time_point timestamp);
  void add_timestamp_ms(uint64_t timestamp_ms);

  // Add counter value (will be delta-compressed)
  void add_counter(uint64_t value);

  // Get compressed data
  const std::vector<uint8_t> &data() const { return data_; }
  size_t size() const { return data_.size(); }

  // Clear compressor
  void clear();

  // Calculate compression ratio
  double compression_ratio() const;

private:
  std::vector<uint8_t> data_;
  uint64_t last_timestamp_ms_;
  uint64_t last_counter_;
  size_t value_count_;
  bool first_timestamp_;
  bool first_counter_;
};

/**
 * Delta decompressor for reading compressed time-series
 */
class DeltaDecompressor {
public:
  DeltaDecompressor(const uint8_t *data, size_t size);

  // Read next timestamp
  std::optional<std::chrono::steady_clock::time_point> next_timestamp();
  std::optional<uint64_t> next_timestamp_ms();

  // Read next counter value
  std::optional<uint64_t> next_counter();

  // Check if more data available
  bool has_more() const { return position_ < size_; }

private:
  const uint8_t *data_;
  size_t size_;
  size_t position_;
  uint64_t last_timestamp_ms_;
  uint64_t last_counter_;
  bool first_timestamp_;
  bool first_counter_;
};

/**
 * Main binary serializer with all compression features
 */
class BinarySerializer {
public:
  BinarySerializer(StringDictionary *dict = nullptr);

  // Basic types
  void write_bool(bool value);
  void write_uint8(uint8_t value);
  void write_uint16(uint16_t value);
  void write_uint32(uint32_t value);
  void write_uint64(uint64_t value);
  void write_varint32(uint32_t value);
  void write_varint64(uint64_t value);
  void write_float(float value);
  void write_double(double value);

  // Strings (with dictionary compression if available)
  void write_string(const std::string &str);
  void write_string_raw(const std::string &str); // No dictionary compression

  // Collections
  template <typename T> void write_vector(const std::vector<T> &vec) {
    write_varint32(static_cast<uint32_t>(vec.size()));
    for (const auto &item : vec) {
      write(item);
    }
  }

  // Time
  void write_timestamp(std::chrono::steady_clock::time_point timestamp);
  void write_duration(std::chrono::milliseconds duration);

  // Bit-packed data
  void write_bitset(const std::bitset<64> &bits);
  void write_flags(uint32_t flags, uint8_t flag_count);

  // Enums
  template <typename E> void write_enum(E value, uint8_t bits = 8) {
    static_assert(std::is_enum_v<E>, "Type must be enum");
    if (bits <= 8) {
      write_uint8(static_cast<uint8_t>(value));
    } else if (bits <= 16) {
      write_uint16(static_cast<uint16_t>(value));
    } else {
      write_uint32(static_cast<uint32_t>(value));
    }
  }

  // Get serialized data
  const std::vector<uint8_t> &data() const { return data_; }
  size_t size() const { return data_.size(); }

  // Clear serializer
  void clear();

  // Delta compression helpers
  void begin_delta_compression();
  void write_delta_timestamp(std::chrono::steady_clock::time_point timestamp);
  void write_delta_counter(uint64_t value);
  void end_delta_compression();

private:
  std::vector<uint8_t> data_;
  StringDictionary *dict_;
  std::unique_ptr<DeltaCompressor> delta_compressor_;

  void write_raw_bytes(const void *data, size_t size);

  // Template for writing any serializable type
  template <typename T> void write(const T &value) {
    if constexpr (std::is_same_v<T, bool>) {
      write_bool(value);
    } else if constexpr (std::is_same_v<T, uint8_t>) {
      write_uint8(value);
    } else if constexpr (std::is_same_v<T, uint16_t>) {
      write_uint16(value);
    } else if constexpr (std::is_same_v<T, uint32_t>) {
      write_uint32(value);
    } else if constexpr (std::is_same_v<T, uint64_t>) {
      write_uint64(value);
    } else if constexpr (std::is_same_v<T, float>) {
      write_float(value);
    } else if constexpr (std::is_same_v<T, double>) {
      write_double(value);
    } else if constexpr (std::is_same_v<T, std::string>) {
      write_string(value);
    } else {
      static_assert(false, "Unsupported type for serialization");
    }
  }
};

/**
 * Main binary deserializer
 */
class BinaryDeserializer {
public:
  BinaryDeserializer(const uint8_t *data, size_t size,
                     StringDictionary *dict = nullptr);

  // Basic types
  bool read_bool();
  uint8_t read_uint8();
  uint16_t read_uint16();
  uint32_t read_uint32();
  uint64_t read_uint64();
  uint32_t read_varint32();
  uint64_t read_varint64();
  float read_float();
  double read_double();

  // Strings
  std::string read_string();
  std::string read_string_raw();

  // Collections
  template <typename T> std::vector<T> read_vector() {
    uint32_t size = read_varint32();
    std::vector<T> result;
    result.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
      result.push_back(read<T>());
    }
    return result;
  }

  // Time
  std::chrono::steady_clock::time_point read_timestamp();
  std::chrono::milliseconds read_duration();

  // Bit-packed data
  std::bitset<64> read_bitset();
  uint32_t read_flags(uint8_t flag_count);

  // Enums
  template <typename E> E read_enum(uint8_t bits = 8) {
    static_assert(std::is_enum_v<E>, "Type must be enum");
    if (bits <= 8) {
      return static_cast<E>(read_uint8());
    } else if (bits <= 16) {
      return static_cast<E>(read_uint16());
    } else {
      return static_cast<E>(read_uint32());
    }
  }

  // Position management
  size_t position() const { return position_; }
  size_t remaining() const { return size_ - position_; }
  bool has_more() const { return position_ < size_; }

  // Delta compression helpers
  void begin_delta_decompression();
  std::chrono::steady_clock::time_point read_delta_timestamp();
  uint64_t read_delta_counter();
  void end_delta_decompression();

private:
  const uint8_t *data_;
  size_t size_;
  size_t position_;
  StringDictionary *dict_;
  std::unique_ptr<DeltaDecompressor> delta_decompressor_;

  void read_raw_bytes(void *dest, size_t size);
  void check_bounds(size_t bytes_needed);

  // Template for reading any deserializable type
  template <typename T> T read() {
    if constexpr (std::is_same_v<T, bool>) {
      return read_bool();
    } else if constexpr (std::is_same_v<T, uint8_t>) {
      return read_uint8();
    } else if constexpr (std::is_same_v<T, uint16_t>) {
      return read_uint16();
    } else if constexpr (std::is_same_v<T, uint32_t>) {
      return read_uint32();
    } else if constexpr (std::is_same_v<T, uint64_t>) {
      return read_uint64();
    } else if constexpr (std::is_same_v<T, float>) {
      return read_float();
    } else if constexpr (std::is_same_v<T, double>) {
      return read_double();
    } else if constexpr (std::is_same_v<T, std::string>) {
      return read_string();
    } else {
      static_assert(false, "Unsupported type for deserialization");
    }
  }
};

/**
 * Helper interface for serializable objects
 */
class ISerializable {
public:
  virtual ~ISerializable() = default;
  virtual size_t serialize(BinarySerializer &serializer) const = 0;
  virtual size_t deserialize(BinaryDeserializer &deserializer) = 0;
  virtual size_t serialized_size() const = 0;
};

/**
 * Convenience macros for implementing serialization
 */
#define DECLARE_SERIALIZABLE()                                                 \
  size_t serialize(BinarySerializer &serializer) const override;               \
  size_t deserialize(BinaryDeserializer &deserializer) override;               \
  size_t serialized_size() const override;

/**
 * Utility functions for common serialization patterns
 */
namespace serialization_utils {
// Calculate size of container
template <typename Container>
size_t container_size(const Container &container) {
  return varint::encoded_size_uint32(static_cast<uint32_t>(container.size()));
}

// Serialize map/unordered_map
template <typename Map>
void serialize_map(BinarySerializer &serializer, const Map &map) {
  serializer.write_varint32(static_cast<uint32_t>(map.size()));
  for (const auto &[key, value] : map) {
    serializer.write(key);
    serializer.write(value);
  }
}

// Deserialize map/unordered_map
template <typename Map> Map deserialize_map(BinaryDeserializer &deserializer) {
  uint32_t size = deserializer.read_varint32();
  Map result;
  for (uint32_t i = 0; i < size; ++i) {
    auto key = deserializer.read<typename Map::key_type>();
    auto value = deserializer.read<typename Map::mapped_type>();
    result.emplace(std::move(key), std::move(value));
  }
  return result;
}

// Calculate compression ratio
double compression_ratio(size_t original_size, size_t compressed_size);

// Validate serialization integrity
bool validate_serialization(const ISerializable &object);
} // namespace serialization_utils

} // namespace core

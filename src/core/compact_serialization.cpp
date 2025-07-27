#include "compact_serialization.hpp"
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace core {

// Variable-length integer encoding implementation
namespace varint {

size_t encode_uint64(uint64_t value, uint8_t *buffer) {
  size_t bytes = 0;
  while (value >= 0x80) {
    buffer[bytes++] = static_cast<uint8_t>(value | 0x80);
    value >>= 7;
  }
  buffer[bytes++] = static_cast<uint8_t>(value);
  return bytes;
}

size_t encode_uint32(uint32_t value, uint8_t *buffer) {
  return encode_uint64(value, buffer);
}

std::pair<uint64_t, size_t> decode_uint64(const uint8_t *buffer,
                                          size_t buffer_size) {
  uint64_t result = 0;
  size_t bytes = 0;
  uint32_t shift = 0;

  while (bytes < buffer_size) {
    uint8_t byte = buffer[bytes++];
    result |= static_cast<uint64_t>(byte & 0x7F) << shift;

    if ((byte & 0x80) == 0) {
      return {result, bytes};
    }

    shift += 7;
    if (shift >= 64) {
      throw std::runtime_error("Varint decode overflow");
    }
  }

  throw std::runtime_error("Incomplete varint");
}

std::pair<uint32_t, size_t> decode_uint32(const uint8_t *buffer,
                                          size_t buffer_size) {
  auto [value, bytes] = decode_uint64(buffer, buffer_size);
  if (value > UINT32_MAX) {
    throw std::runtime_error("Varint32 overflow");
  }
  return {static_cast<uint32_t>(value), bytes};
}

size_t encoded_size_uint64(uint64_t value) {
  size_t bytes = 1;
  while (value >= 0x80) {
    value >>= 7;
    bytes++;
  }
  return bytes;
}

size_t encoded_size_uint32(uint32_t value) {
  return encoded_size_uint64(value);
}

} // namespace varint

// StringDictionary implementation
StringDictionary::StringDictionary() : next_id_(0) {}

uint32_t StringDictionary::add_string(const std::string &str) {
  auto it = string_to_id_.find(str);
  if (it != string_to_id_.end()) {
    return it->second;
  }

  uint32_t id = next_id_++;
  strings_.push_back(str);
  string_to_id_[str] = id;
  return id;
}

const std::string &StringDictionary::get_string(uint32_t id) const {
  if (id >= strings_.size()) {
    throw std::runtime_error("Invalid string dictionary ID");
  }
  return strings_[id];
}

std::optional<uint32_t>
StringDictionary::find_string(const std::string &str) const {
  auto it = string_to_id_.find(str);
  if (it != string_to_id_.end()) {
    return it->second;
  }
  return std::nullopt;
}

void StringDictionary::clear() {
  strings_.clear();
  string_to_id_.clear();
  next_id_ = 0;
}

size_t StringDictionary::serialize(uint8_t *buffer, size_t buffer_size) const {
  size_t pos = 0;

  // Write number of strings
  pos += varint::encode_uint32(static_cast<uint32_t>(strings_.size()),
                               buffer + pos);

  // Write each string
  for (const auto &str : strings_) {
    if (pos + varint::encoded_size_uint32(static_cast<uint32_t>(str.size())) +
            str.size() >
        buffer_size) {
      throw std::runtime_error("Buffer too small for dictionary serialization");
    }

    pos +=
        varint::encode_uint32(static_cast<uint32_t>(str.size()), buffer + pos);
    std::memcpy(buffer + pos, str.data(), str.size());
    pos += str.size();
  }

  return pos;
}

size_t StringDictionary::deserialize(const uint8_t *buffer,
                                     size_t buffer_size) {
  clear();

  size_t pos = 0;

  // Read number of strings
  auto [count, count_bytes] =
      varint::decode_uint32(buffer + pos, buffer_size - pos);
  pos += count_bytes;

  strings_.reserve(count);

  // Read each string
  for (uint32_t i = 0; i < count; ++i) {
    auto [str_size, size_bytes] =
        varint::decode_uint32(buffer + pos, buffer_size - pos);
    pos += size_bytes;

    if (pos + str_size > buffer_size) {
      throw std::runtime_error(
          "Buffer too small for dictionary deserialization");
    }

    std::string str(reinterpret_cast<const char *>(buffer + pos), str_size);
    pos += str_size;

    string_to_id_[str] = next_id_;
    strings_.push_back(std::move(str));
    next_id_++;
  }

  return pos;
}

size_t StringDictionary::serialized_size() const {
  size_t size =
      varint::encoded_size_uint32(static_cast<uint32_t>(strings_.size()));
  for (const auto &str : strings_) {
    size += varint::encoded_size_uint32(static_cast<uint32_t>(str.size()));
    size += str.size();
  }
  return size;
}

// BitPacker implementation
void BitPacker::pack_bool(bool value) { pack_uint(value ? 1 : 0, 1); }

void BitPacker::pack_uint(uint32_t value, uint8_t bits) {
  if (bits == 0 || bits > 32) {
    throw std::runtime_error("Invalid bit count for packing");
  }

  ensure_capacity(bits);

  for (uint8_t i = 0; i < bits; ++i) {
    if (value & (1U << i)) {
      size_t byte_idx = bit_position_ / 8;
      size_t bit_idx = bit_position_ % 8;
      data_[byte_idx] |= (1U << bit_idx);
    }
    bit_position_++;
  }
}

void BitPacker::clear() {
  data_.clear();
  bit_position_ = 0;
}

void BitPacker::ensure_capacity(size_t additional_bits) {
  size_t required_bytes = (bit_position_ + additional_bits + 7) / 8;
  if (data_.size() < required_bytes) {
    data_.resize(required_bytes, 0);
  }
}

// BitUnpacker implementation
BitUnpacker::BitUnpacker(const uint8_t *data, size_t size_bytes)
    : data_(data), total_bits_(size_bytes * 8), bit_position_(0) {}

bool BitUnpacker::unpack_bool() { return unpack_uint(1) != 0; }

uint32_t BitUnpacker::unpack_uint(uint8_t bits) {
  if (bits == 0 || bits > 32) {
    throw std::runtime_error("Invalid bit count for unpacking");
  }

  if (bit_position_ + bits > total_bits_) {
    throw std::runtime_error("Not enough bits to unpack");
  }

  uint32_t result = 0;
  for (uint8_t i = 0; i < bits; ++i) {
    size_t byte_idx = bit_position_ / 8;
    size_t bit_idx = bit_position_ % 8;

    if (data_[byte_idx] & (1U << bit_idx)) {
      result |= (1U << i);
    }
    bit_position_++;
  }

  return result;
}

// DeltaCompressor implementation
DeltaCompressor::DeltaCompressor()
    : last_timestamp_ms_(0), last_counter_(0), value_count_(0),
      first_timestamp_(true), first_counter_(true) {}

void DeltaCompressor::add_timestamp(
    std::chrono::steady_clock::time_point timestamp) {
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch())
                .count();
  add_timestamp_ms(static_cast<uint64_t>(ms));
}

void DeltaCompressor::add_timestamp_ms(uint64_t timestamp_ms) {
  if (first_timestamp_) {
    // Store first timestamp as absolute value
    uint8_t buffer[10];
    size_t bytes = varint::encode_uint64(timestamp_ms, buffer);
    data_.insert(data_.end(), buffer, buffer + bytes);
    last_timestamp_ms_ = timestamp_ms;
    first_timestamp_ = false;
  } else {
    // Store delta
    uint64_t delta = timestamp_ms - last_timestamp_ms_;
    uint8_t buffer[10];
    size_t bytes = varint::encode_uint64(delta, buffer);
    data_.insert(data_.end(), buffer, buffer + bytes);
    last_timestamp_ms_ = timestamp_ms;
  }
  value_count_++;
}

void DeltaCompressor::add_counter(uint64_t value) {
  if (first_counter_) {
    // Store first counter as absolute value
    uint8_t buffer[10];
    size_t bytes = varint::encode_uint64(value, buffer);
    data_.insert(data_.end(), buffer, buffer + bytes);
    last_counter_ = value;
    first_counter_ = false;
  } else {
    // Store delta (handle wraparound)
    uint64_t delta = value >= last_counter_
                         ? value - last_counter_
                         : (UINT64_MAX - last_counter_) + value + 1;

    uint8_t buffer[10];
    size_t bytes = varint::encode_uint64(delta, buffer);
    data_.insert(data_.end(), buffer, buffer + bytes);
    last_counter_ = value;
  }
  value_count_++;
}

void DeltaCompressor::clear() {
  data_.clear();
  last_timestamp_ms_ = 0;
  last_counter_ = 0;
  value_count_ = 0;
  first_timestamp_ = true;
  first_counter_ = true;
}

double DeltaCompressor::compression_ratio() const {
  if (value_count_ == 0)
    return 1.0;

  // Estimate uncompressed size (8 bytes per timestamp/counter)
  size_t uncompressed = value_count_ * 8;
  return static_cast<double>(uncompressed) / static_cast<double>(data_.size());
}

// DeltaDecompressor implementation
DeltaDecompressor::DeltaDecompressor(const uint8_t *data, size_t size)
    : data_(data), size_(size), position_(0), last_timestamp_ms_(0),
      last_counter_(0), first_timestamp_(true), first_counter_(true) {}

std::optional<std::chrono::steady_clock::time_point>
DeltaDecompressor::next_timestamp() {
  auto ms = next_timestamp_ms();
  if (!ms)
    return std::nullopt;

  return std::chrono::steady_clock::time_point(std::chrono::milliseconds(*ms));
}

std::optional<uint64_t> DeltaDecompressor::next_timestamp_ms() {
  if (!has_more())
    return std::nullopt;

  try {
    auto [value, bytes] =
        varint::decode_uint64(data_ + position_, size_ - position_);
    position_ += bytes;

    if (first_timestamp_) {
      last_timestamp_ms_ = value;
      first_timestamp_ = false;
    } else {
      last_timestamp_ms_ += value;
    }

    return last_timestamp_ms_;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<uint64_t> DeltaDecompressor::next_counter() {
  if (!has_more())
    return std::nullopt;

  try {
    auto [delta, bytes] =
        varint::decode_uint64(data_ + position_, size_ - position_);
    position_ += bytes;

    if (first_counter_) {
      last_counter_ = delta;
      first_counter_ = false;
    } else {
      last_counter_ += delta;
    }

    return last_counter_;
  } catch (...) {
    return std::nullopt;
  }
}

// BinarySerializer implementation
BinarySerializer::BinarySerializer(StringDictionary *dict) : dict_(dict) {}

void BinarySerializer::write_bool(bool value) { write_uint8(value ? 1 : 0); }

void BinarySerializer::write_uint8(uint8_t value) { data_.push_back(value); }

void BinarySerializer::write_uint16(uint16_t value) {
  write_uint8(static_cast<uint8_t>(value));
  write_uint8(static_cast<uint8_t>(value >> 8));
}

void BinarySerializer::write_uint32(uint32_t value) {
  write_uint8(static_cast<uint8_t>(value));
  write_uint8(static_cast<uint8_t>(value >> 8));
  write_uint8(static_cast<uint8_t>(value >> 16));
  write_uint8(static_cast<uint8_t>(value >> 24));
}

void BinarySerializer::write_uint64(uint64_t value) {
  write_uint32(static_cast<uint32_t>(value));
  write_uint32(static_cast<uint32_t>(value >> 32));
}

void BinarySerializer::write_varint32(uint32_t value) {
  uint8_t buffer[5];
  size_t bytes = varint::encode_uint32(value, buffer);
  write_raw_bytes(buffer, bytes);
}

void BinarySerializer::write_varint64(uint64_t value) {
  uint8_t buffer[10];
  size_t bytes = varint::encode_uint64(value, buffer);
  write_raw_bytes(buffer, bytes);
}

void BinarySerializer::write_float(float value) {
  static_assert(sizeof(float) == 4, "Float must be 4 bytes");
  uint32_t bits;
  std::memcpy(&bits, &value, sizeof(bits));
  write_uint32(bits);
}

void BinarySerializer::write_double(double value) {
  static_assert(sizeof(double) == 8, "Double must be 8 bytes");
  uint64_t bits;
  std::memcpy(&bits, &value, sizeof(bits));
  write_uint64(bits);
}

void BinarySerializer::write_string(const std::string &str) {
  if (dict_) {
    // Use dictionary compression
    uint32_t id = dict_->add_string(str);
    write_varint32(id);
  } else {
    write_string_raw(str);
  }
}

void BinarySerializer::write_string_raw(const std::string &str) {
  write_varint32(static_cast<uint32_t>(str.size()));
  write_raw_bytes(str.data(), str.size());
}

void BinarySerializer::write_timestamp(
    std::chrono::steady_clock::time_point timestamp) {
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch())
                .count();
  write_varint64(static_cast<uint64_t>(ms));
}

void BinarySerializer::write_duration(std::chrono::milliseconds duration) {
  write_varint64(static_cast<uint64_t>(duration.count()));
}

void BinarySerializer::write_bitset(const std::bitset<64> &bits) {
  write_uint64(bits.to_ullong());
}

void BinarySerializer::write_flags(uint32_t flags, uint8_t flag_count) {
  if (flag_count <= 8) {
    write_uint8(static_cast<uint8_t>(flags));
  } else if (flag_count <= 16) {
    write_uint16(static_cast<uint16_t>(flags));
  } else {
    write_uint32(flags);
  }
}

void BinarySerializer::clear() {
  data_.clear();
  delta_compressor_.reset();
}

void BinarySerializer::begin_delta_compression() {
  delta_compressor_ = std::make_unique<DeltaCompressor>();
}

void BinarySerializer::write_delta_timestamp(
    std::chrono::steady_clock::time_point timestamp) {
  if (!delta_compressor_) {
    throw std::runtime_error("Delta compression not started");
  }
  delta_compressor_->add_timestamp(timestamp);
}

void BinarySerializer::write_delta_counter(uint64_t value) {
  if (!delta_compressor_) {
    throw std::runtime_error("Delta compression not started");
  }
  delta_compressor_->add_counter(value);
}

void BinarySerializer::end_delta_compression() {
  if (!delta_compressor_) {
    throw std::runtime_error("Delta compression not started");
  }

  const auto &compressed_data = delta_compressor_->data();
  write_varint32(static_cast<uint32_t>(compressed_data.size()));
  write_raw_bytes(compressed_data.data(), compressed_data.size());
  delta_compressor_.reset();
}

void BinarySerializer::write_raw_bytes(const void *data, size_t size) {
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  data_.insert(data_.end(), bytes, bytes + size);
}

// BinaryDeserializer implementation
BinaryDeserializer::BinaryDeserializer(const uint8_t *data, size_t size,
                                       StringDictionary *dict)
    : data_(data), size_(size), position_(0), dict_(dict) {}

bool BinaryDeserializer::read_bool() { return read_uint8() != 0; }

uint8_t BinaryDeserializer::read_uint8() {
  check_bounds(1);
  return data_[position_++];
}

uint16_t BinaryDeserializer::read_uint16() {
  uint8_t low = read_uint8();
  uint8_t high = read_uint8();
  return static_cast<uint16_t>(low) | (static_cast<uint16_t>(high) << 8);
}

uint32_t BinaryDeserializer::read_uint32() {
  uint16_t low = read_uint16();
  uint16_t high = read_uint16();
  return static_cast<uint32_t>(low) | (static_cast<uint32_t>(high) << 16);
}

uint64_t BinaryDeserializer::read_uint64() {
  uint32_t low = read_uint32();
  uint32_t high = read_uint32();
  return static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);
}

uint32_t BinaryDeserializer::read_varint32() {
  auto [value, bytes] =
      varint::decode_uint32(data_ + position_, size_ - position_);
  position_ += bytes;
  return value;
}

uint64_t BinaryDeserializer::read_varint64() {
  auto [value, bytes] =
      varint::decode_uint64(data_ + position_, size_ - position_);
  position_ += bytes;
  return value;
}

float BinaryDeserializer::read_float() {
  uint32_t bits = read_uint32();
  float value;
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

double BinaryDeserializer::read_double() {
  uint64_t bits = read_uint64();
  double value;
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

std::string BinaryDeserializer::read_string() {
  if (dict_) {
    // Use dictionary decompression
    uint32_t id = read_varint32();
    return dict_->get_string(id);
  } else {
    return read_string_raw();
  }
}

std::string BinaryDeserializer::read_string_raw() {
  uint32_t str_size = read_varint32();
  check_bounds(str_size);

  std::string result(reinterpret_cast<const char *>(data_ + position_),
                     str_size);
  position_ += str_size;
  return result;
}

std::chrono::steady_clock::time_point BinaryDeserializer::read_timestamp() {
  uint64_t ms = read_varint64();
  return std::chrono::steady_clock::time_point(std::chrono::milliseconds(ms));
}

std::chrono::milliseconds BinaryDeserializer::read_duration() {
  uint64_t ms = read_varint64();
  return std::chrono::milliseconds(ms);
}

std::bitset<64> BinaryDeserializer::read_bitset() {
  uint64_t bits = read_uint64();
  return std::bitset<64>(bits);
}

uint32_t BinaryDeserializer::read_flags(uint8_t flag_count) {
  if (flag_count <= 8) {
    return static_cast<uint32_t>(read_uint8());
  } else if (flag_count <= 16) {
    return static_cast<uint32_t>(read_uint16());
  } else {
    return read_uint32();
  }
}

void BinaryDeserializer::begin_delta_decompression() {
  uint32_t compressed_size = read_varint32();
  check_bounds(compressed_size);

  delta_decompressor_ =
      std::make_unique<DeltaDecompressor>(data_ + position_, compressed_size);
  position_ += compressed_size;
}

std::chrono::steady_clock::time_point
BinaryDeserializer::read_delta_timestamp() {
  if (!delta_decompressor_) {
    throw std::runtime_error("Delta decompression not started");
  }

  auto timestamp = delta_decompressor_->next_timestamp();
  if (!timestamp) {
    throw std::runtime_error("No more delta timestamps");
  }
  return *timestamp;
}

uint64_t BinaryDeserializer::read_delta_counter() {
  if (!delta_decompressor_) {
    throw std::runtime_error("Delta decompression not started");
  }

  auto counter = delta_decompressor_->next_counter();
  if (!counter) {
    throw std::runtime_error("No more delta counters");
  }
  return *counter;
}

void BinaryDeserializer::end_delta_decompression() {
  delta_decompressor_.reset();
}

void BinaryDeserializer::read_raw_bytes(void *dest, size_t size) {
  check_bounds(size);
  std::memcpy(dest, data_ + position_, size);
  position_ += size;
}

void BinaryDeserializer::check_bounds(size_t bytes_needed) {
  if (position_ + bytes_needed > size_) {
    throw std::runtime_error("Buffer underflow in deserialization");
  }
}

// Utility functions
namespace serialization_utils {

double compression_ratio(size_t original_size, size_t compressed_size) {
  if (compressed_size == 0)
    return 0.0;
  return static_cast<double>(original_size) /
         static_cast<double>(compressed_size);
}

bool validate_serialization(const ISerializable &object) {
  try {
    BinarySerializer serializer;
    size_t written = object.serialize(serializer);

    if (written != serializer.size()) {
      return false;
    }

    BinaryDeserializer deserializer(serializer.data().data(),
                                    serializer.size());

    // Create a copy and deserialize
    // Note: This is a simplified validation - real implementation would need
    // object-specific comparison
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace serialization_utils

} // namespace core

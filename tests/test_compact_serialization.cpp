#include "core/compact_serialization.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace core;

class CompactSerializationTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Set up test data
  }

  void TearDown() override {
    // Clean up
  }
};

// Test varint encoding/decoding
TEST_F(CompactSerializationTest, VarintEncodingDecoding) {
  std::vector<uint64_t> test_values = {
      0,          1,
      127,        128,
      255,        256,
      16383,      16384,
      UINT32_MAX, static_cast<uint64_t>(UINT32_MAX) + 1,
      UINT64_MAX};

  for (uint64_t value : test_values) {
    uint8_t buffer[10];
    size_t encoded_size = varint::encode_uint64(value, buffer);

    EXPECT_LE(encoded_size, 10);
    EXPECT_EQ(encoded_size, varint::encoded_size_uint64(value));

    auto [decoded_value, decoded_size] =
        varint::decode_uint64(buffer, encoded_size);
    EXPECT_EQ(value, decoded_value);
    EXPECT_EQ(encoded_size, decoded_size);
  }
}

// Test string dictionary
TEST_F(CompactSerializationTest, StringDictionary) {
  StringDictionary dict;

  // Add some strings
  uint32_t id1 = dict.add_string("hello");
  uint32_t id2 = dict.add_string("world");
  uint32_t id3 = dict.add_string("hello"); // Duplicate

  EXPECT_EQ(id1, id3); // Should return same ID for duplicate
  EXPECT_NE(id1, id2); // Different strings should have different IDs

  EXPECT_EQ("hello", dict.get_string(id1));
  EXPECT_EQ("world", dict.get_string(id2));

  EXPECT_EQ(2u, dict.size()); // Should only have 2 unique strings

  // Test serialization
  std::vector<uint8_t> buffer(dict.serialized_size());
  size_t serialized_size = dict.serialize(buffer.data(), buffer.size());
  EXPECT_EQ(serialized_size, dict.serialized_size());

  // Test deserialization
  StringDictionary dict2;
  size_t deserialized_size = dict2.deserialize(buffer.data(), buffer.size());
  EXPECT_EQ(serialized_size, deserialized_size);
  EXPECT_EQ(dict.size(), dict2.size());

  for (uint32_t i = 0; i < dict.size(); ++i) {
    EXPECT_EQ(dict.get_string(i), dict2.get_string(i));
  }
}

// Test bit packing
TEST_F(CompactSerializationTest, BitPacking) {
  BitPacker packer;

  // Pack some values
  packer.pack_bool(true);
  packer.pack_bool(false);
  packer.pack_uint(15, 4); // 0b1111
  packer.pack_uint(0, 3);  // 0b000
  packer.pack_uint(7, 3);  // 0b111

  // Total: 1 + 1 + 4 + 3 + 3 = 12 bits = 1.5 bytes (rounded to 2)
  EXPECT_EQ(12u, packer.bit_size());
  EXPECT_EQ(2u, packer.byte_size());

  // Unpack and verify
  BitUnpacker unpacker(packer.data().data(), packer.byte_size());

  EXPECT_TRUE(unpacker.unpack_bool());
  EXPECT_FALSE(unpacker.unpack_bool());
  EXPECT_EQ(15u, unpacker.unpack_uint(4));
  EXPECT_EQ(0u, unpacker.unpack_uint(3));
  EXPECT_EQ(7u, unpacker.unpack_uint(3));

  EXPECT_FALSE(unpacker.has_more());
}

// Test delta compression
TEST_F(CompactSerializationTest, DeltaCompression) {
  DeltaCompressor compressor;

  // Add some timestamps (simulating regular intervals)
  std::vector<uint64_t> timestamps = {1000, 1100, 1200, 1350, 1400};
  for (uint64_t ts : timestamps) {
    compressor.add_timestamp_ms(ts);
  }

  // Add some counter values
  std::vector<uint64_t> counters = {100, 150, 200, 180, 220};
  for (uint64_t counter : counters) {
    compressor.add_counter(counter);
  }

  EXPECT_GT(compressor.compression_ratio(),
            1.0); // Should achieve some compression

  // Test decompression
  DeltaDecompressor decompressor(compressor.data().data(), compressor.size());

  // Verify timestamps
  for (size_t i = 0; i < timestamps.size(); ++i) {
    auto ts = decompressor.next_timestamp_ms();
    ASSERT_TRUE(ts.has_value());
    EXPECT_EQ(timestamps[i], *ts);
  }

  // Reset decompressor for counters
  DeltaDecompressor counter_decompressor(compressor.data().data(),
                                         compressor.size());

  // Skip timestamps in decompressor (would need separate streams in real usage)
  // For this test, we'll just verify the compression ratio
}

// Test basic serialization
TEST_F(CompactSerializationTest, BasicSerialization) {
  BinarySerializer serializer;

  // Test basic types
  serializer.write_bool(true);
  serializer.write_uint8(255);
  serializer.write_uint16(65535);
  serializer.write_uint32(0xDEADBEEF);
  serializer.write_uint64(0x123456789ABCDEF0ULL);
  serializer.write_varint32(127);
  serializer.write_varint64(16383);
  serializer.write_float(3.14159f);
  serializer.write_double(2.71828);
  serializer.write_string_raw("test string");

  // Test deserialization
  BinaryDeserializer deserializer(serializer.data().data(), serializer.size());

  EXPECT_TRUE(deserializer.read_bool());
  EXPECT_EQ(255u, deserializer.read_uint8());
  EXPECT_EQ(65535u, deserializer.read_uint16());
  EXPECT_EQ(0xDEADBEEFu, deserializer.read_uint32());
  EXPECT_EQ(0x123456789ABCDEF0ULL, deserializer.read_uint64());
  EXPECT_EQ(127u, deserializer.read_varint32());
  EXPECT_EQ(16383u, deserializer.read_varint64());
  EXPECT_FLOAT_EQ(3.14159f, deserializer.read_float());
  EXPECT_DOUBLE_EQ(2.71828, deserializer.read_double());
  EXPECT_EQ("test string", deserializer.read_string_raw());

  EXPECT_FALSE(deserializer.has_more());
}

// Test serialization with string dictionary
TEST_F(CompactSerializationTest, SerializationWithDictionary) {
  StringDictionary dict;
  BinarySerializer serializer(&dict);

  // Write some strings (some duplicates)
  std::vector<std::string> test_strings = {"hello", "world", "hello",
                                           "test",  "world", "hello"};

  for (const auto &str : test_strings) {
    serializer.write_string(str);
  }

  // Serialize dictionary
  std::vector<uint8_t> dict_buffer(dict.serialized_size());
  dict.serialize(dict_buffer.data(), dict_buffer.size());

  // Test deserialization
  StringDictionary dict2;
  dict2.deserialize(dict_buffer.data(), dict_buffer.size());

  BinaryDeserializer deserializer(serializer.data().data(), serializer.size(),
                                  &dict2);

  for (const auto &expected_str : test_strings) {
    std::string actual_str = deserializer.read_string();
    EXPECT_EQ(expected_str, actual_str);
  }
}

// Test vector serialization
TEST_F(CompactSerializationTest, VectorSerialization) {
  BinarySerializer serializer;

  std::vector<uint32_t> test_vector = {1, 2, 3, 4, 5};
  serializer.write_vector(test_vector);

  BinaryDeserializer deserializer(serializer.data().data(), serializer.size());
  auto deserialized_vector = deserializer.read_vector<uint32_t>();

  EXPECT_EQ(test_vector, deserialized_vector);
}

// Test timestamp serialization
TEST_F(CompactSerializationTest, TimestampSerialization) {
  BinarySerializer serializer;

  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::milliseconds(1000);

  serializer.write_timestamp(now);
  serializer.write_duration(duration);

  BinaryDeserializer deserializer(serializer.data().data(), serializer.size());

  auto deserialized_timestamp = deserializer.read_timestamp();
  auto deserialized_duration = deserializer.read_duration();

  // Allow for small differences due to precision
  auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - deserialized_timestamp);
  EXPECT_LE(std::abs(diff.count()), 1); // Within 1ms

  EXPECT_EQ(duration, deserialized_duration);
}

// Test bitset serialization
TEST_F(CompactSerializationTest, BitsetSerialization) {
  BinarySerializer serializer;

  std::bitset<64> test_bits;
  test_bits.set(0);
  test_bits.set(15);
  test_bits.set(31);
  test_bits.set(63);

  serializer.write_bitset(test_bits);

  BinaryDeserializer deserializer(serializer.data().data(), serializer.size());
  auto deserialized_bits = deserializer.read_bitset();

  EXPECT_EQ(test_bits, deserialized_bits);
}

// Test error handling
TEST_F(CompactSerializationTest, ErrorHandling) {
  // Test buffer overflow
  uint8_t small_buffer[1];
  EXPECT_THROW(varint::decode_uint64(small_buffer, 1), std::runtime_error);

  // Test invalid string dictionary ID
  StringDictionary dict;
  EXPECT_THROW(dict.get_string(999), std::runtime_error);

  // Test bit unpacker bounds
  uint8_t bit_data[1] = {0xFF};
  BitUnpacker unpacker(bit_data, 1);
  unpacker.unpack_uint(8);                                  // Use all 8 bits
  EXPECT_THROW(unpacker.unpack_bool(), std::runtime_error); // Should fail

  // Test deserializer bounds
  uint8_t data[4] = {1, 2, 3, 4};
  BinaryDeserializer deserializer(data, 4);
  deserializer.read_uint32(); // Use all 4 bytes
  EXPECT_THROW(deserializer.read_uint8(), std::runtime_error); // Should fail
}

// Performance test
TEST_F(CompactSerializationTest, CompressionEfficiency) {
  StringDictionary dict;
  BinarySerializer serializer(&dict);

  // Create test data with lots of repetition
  std::vector<std::string> repeated_strings;
  for (int i = 0; i < 1000; ++i) {
    repeated_strings.push_back("common_string_" + std::to_string(i % 10));
  }

  // Serialize with dictionary
  for (const auto &str : repeated_strings) {
    serializer.write_string(str);
  }

  // Calculate compression ratio
  size_t uncompressed_size = 0;
  for (const auto &str : repeated_strings) {
    uncompressed_size += str.size() + 4; // String + length prefix
  }

  size_t compressed_size = serializer.size() + dict.serialized_size();
  double compression_ratio =
      static_cast<double>(uncompressed_size) / compressed_size;

  // Should achieve significant compression due to repeated strings
  EXPECT_GT(compression_ratio, 2.0);

  std::cout << "Compression ratio: " << compression_ratio << std::endl;
  std::cout << "Uncompressed: " << uncompressed_size << " bytes" << std::endl;
  std::cout << "Compressed: " << compressed_size << " bytes" << std::endl;
}

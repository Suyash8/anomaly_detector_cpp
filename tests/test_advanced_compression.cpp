#include "core/advanced_compression.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

using namespace core;

class AdvancedCompressionTest : public ::testing::Test {
protected:
  void SetUp() override { engine_ = std::make_unique<CompressionEngine>(); }

  void TearDown() override { engine_.reset(); }

  std::unique_ptr<CompressionEngine> engine_;
};

// Test basic compression functionality
TEST_F(AdvancedCompressionTest, BasicCompression) {
  std::string test_data =
      "Hello, World! This is a test string for compression. ";
  // Repeat to make it more compressible
  for (int i = 0; i < 10; ++i) {
    test_data += test_data;
  }

  std::vector<uint8_t> data(test_data.begin(), test_data.end());

  // Test LZ4 compression
  auto compressed_lz4 =
      engine_->compress(data.data(), data.size(), CompressionAlgorithm::LZ4);
  EXPECT_LT(compressed_lz4.size(), data.size()); // Should be smaller

  auto decompressed_lz4 = engine_->decompress(
      compressed_lz4.data(), compressed_lz4.size(), CompressionAlgorithm::LZ4);
  EXPECT_EQ(data.size(), decompressed_lz4.size());

  // Test Zstandard compression
  auto compressed_zstd =
      engine_->compress(data.data(), data.size(), CompressionAlgorithm::ZSTD);
  EXPECT_LT(compressed_zstd.size(), data.size());
  EXPECT_LT(compressed_zstd.size(),
            compressed_lz4.size()); // ZSTD should be better

  auto decompressed_zstd =
      engine_->decompress(compressed_zstd.data(), compressed_zstd.size(),
                          CompressionAlgorithm::ZSTD);
  EXPECT_EQ(data.size(), decompressed_zstd.size());
}

// Test compression with metadata
TEST_F(AdvancedCompressionTest, CompressionWithMetadata) {
  std::vector<uint8_t> data(1024, 0xAB); // Repeated pattern

  auto [compressed, metadata] = engine_->compress_with_metadata(
      data.data(), data.size(), CompressionAlgorithm::ZSTD,
      CompressionLevel::DEFAULT);

  EXPECT_EQ(metadata.algorithm, CompressionAlgorithm::ZSTD);
  EXPECT_EQ(metadata.level, CompressionLevel::DEFAULT);
  EXPECT_EQ(metadata.original_size, data.size());
  EXPECT_EQ(metadata.compressed_size, compressed.size());
  EXPECT_GT(metadata.compression_ratio, 1.0);
  EXPECT_GT(metadata.checksum, 0u);

  // Test decompression with validation
  auto decompressed = engine_->decompress_with_validation(
      compressed.data(), compressed.size(), metadata);

  EXPECT_EQ(data, decompressed);
}

// Test compression statistics
TEST_F(AdvancedCompressionTest, CompressionStatistics) {
  engine_->reset_stats();

  std::vector<uint8_t> data(512, 0x42);

  // Perform several compressions
  for (int i = 0; i < 5; ++i) {
    auto compressed = engine_->compress(data.data(), data.size());
    engine_->decompress(compressed.data(), compressed.size(),
                        CompressionAlgorithm::LZ4);
  }

  auto stats = engine_->get_stats();
  EXPECT_EQ(stats.total_compressions, 5u);
  EXPECT_EQ(stats.total_decompressions, 5u);
  EXPECT_EQ(stats.total_original_bytes, 5u * data.size());
  EXPECT_GT(stats.average_compression_ratio, 1.0);
  EXPECT_GT(stats.total_compression_time.count(), 0);
}

// Test incremental serialization
TEST_F(AdvancedCompressionTest, IncrementalSerialization) {
  IncrementalSerializer serializer;

  // Initialize with base snapshot
  std::vector<uint8_t> base_data = {1, 2, 3, 4, 5};
  serializer.initialize_base_snapshot(base_data);

  // Add some changes
  std::vector<uint8_t> change1 = {10, 20, 30};
  std::vector<uint8_t> change2 = {40, 50};

  serializer.add_change(100, change1);
  serializer.add_change(200, change2);
  serializer.remove_object(300);

  // Create incremental snapshot
  auto snapshot = serializer.create_incremental_snapshot();
  EXPECT_GT(snapshot.size(), 0u);

  // Test metadata
  auto metadata = serializer.get_metadata();
  EXPECT_EQ(metadata.base_snapshot_size, base_data.size());
  EXPECT_EQ(metadata.incremental_count, 3u); // 2 changes + 1 removal
  EXPECT_EQ(metadata.total_objects, 3u);

  // Test applying snapshot
  IncrementalSerializer serializer2;
  serializer2.initialize_base_snapshot(base_data);
  serializer2.apply_incremental_snapshot(snapshot);

  auto metadata2 = serializer2.get_metadata();
  EXPECT_EQ(metadata2.incremental_count, metadata.incremental_count);
}

// Test copy-on-write functionality
TEST_F(AdvancedCompressionTest, CopyOnWrite) {
  CopyOnWriteManager cow_manager;

  // Create initial data
  std::vector<int> initial_data = {1, 2, 3, 4, 5};
  auto handle1 = cow_manager.create(std::move(initial_data));

  // Check initial state
  EXPECT_EQ(handle1.use_count(), 1);
  EXPECT_TRUE(handle1.is_unique());

  // Read access should work fine
  EXPECT_EQ(handle1.read().size(), 5u);
  EXPECT_EQ(handle1.read()[0], 1);

  // Write access should trigger copy if needed
  auto &writable = handle1.write();
  writable[0] = 99;

  // Verify the change
  EXPECT_EQ(handle1.read()[0], 99);
  EXPECT_EQ(handle1.read().size(), 5u);

  // Commit changes
  auto new_shared = handle1.commit();
  EXPECT_EQ(new_shared.use_count(), 1);
}

// Test background compressor
TEST_F(AdvancedCompressionTest, BackgroundCompressor) {
  BackgroundCompressor compressor(engine_.get());

  // Configure for quick testing
  BackgroundCompressor::Config config;
  config.idle_threshold = std::chrono::minutes(1); // Very short for testing
  config.scan_interval = std::chrono::milliseconds(50);
  config.min_size_threshold = 64;

  compressor.configure(config);
  compressor.start();

  // Register some data
  auto data1 = std::make_shared<std::vector<uint8_t>>(1024, 0xAA);
  auto data2 = std::make_shared<std::vector<uint8_t>>(2048, 0xBB);

  uint64_t handle1 = compressor.register_data("test1", data1);
  uint64_t handle2 = compressor.register_data("test2", data2);

  // Wait for background compression
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Data should still be retrievable
  auto retrieved1 = compressor.get_data(handle1);
  auto retrieved2 = compressor.get_data(handle2);

  EXPECT_TRUE(retrieved1 != nullptr);
  EXPECT_TRUE(retrieved2 != nullptr);
  EXPECT_EQ(retrieved1->size(), 1024u);
  EXPECT_EQ(retrieved2->size(), 2048u);

  // Check stats
  auto stats = compressor.get_stats();
  EXPECT_EQ(stats.registered_objects, 2u);

  compressor.stop();
}

// Test compressed memory store
TEST_F(AdvancedCompressionTest, CompressedMemoryStore) {
  CompressedMemoryStore store(engine_.get());

  // Configure store
  CompressedMemoryStore::Config config;
  config.compression_threshold = 100;
  config.min_compression_ratio = 1.1;
  store.configure(config);

  // Store small data (should not be compressed)
  std::vector<uint8_t> small_data = {1, 2, 3, 4, 5};
  uint64_t handle1 = store.store("small", small_data);

  // Store large data (should be compressed)
  std::vector<uint8_t> large_data(1024, 0x42);
  uint64_t handle2 = store.store("large", large_data);

  // Retrieve data
  auto retrieved_small = store.retrieve(handle1);
  auto retrieved_large = store.retrieve(handle2);

  EXPECT_EQ(small_data, retrieved_small);
  EXPECT_EQ(large_data, retrieved_large);

  // Check stats
  auto stats = store.get_stats();
  EXPECT_EQ(stats.total_objects, 2u);
  EXPECT_GE(stats.compressed_objects,
            1u); // At least large data should be compressed

  // Test key-based access
  EXPECT_TRUE(store.exists("small"));
  EXPECT_TRUE(store.exists("large"));
  EXPECT_FALSE(store.exists("nonexistent"));

  auto retrieved_by_key = store.retrieve("large");
  EXPECT_EQ(large_data, retrieved_by_key);
}

// Test compression algorithm selection
TEST_F(AdvancedCompressionTest, AlgorithmSelection) {
  std::vector<uint8_t> data(1024, 0x55);

  // Test different algorithms
  auto lz4_compressed =
      engine_->compress(data.data(), data.size(), CompressionAlgorithm::LZ4);
  auto zstd_compressed =
      engine_->compress(data.data(), data.size(), CompressionAlgorithm::ZSTD);

  // ZSTD should generally achieve better compression
  EXPECT_LE(zstd_compressed.size(), lz4_compressed.size());

  // Test estimation
  double lz4_estimate = engine_->estimate_compression_ratio(
      data.data(), data.size(), CompressionAlgorithm::LZ4);
  double zstd_estimate = engine_->estimate_compression_ratio(
      data.data(), data.size(), CompressionAlgorithm::ZSTD);

  EXPECT_GT(lz4_estimate, 1.0);
  EXPECT_GT(zstd_estimate, 1.0);
  EXPECT_GE(zstd_estimate,
            lz4_estimate); // ZSTD should estimate better compression
}

// Test compression utility functions
TEST_F(AdvancedCompressionTest, UtilityFunctions) {
  // Test checksum calculation
  std::vector<uint8_t> data = {1, 2, 3, 4, 5};
  uint32_t checksum1 =
      compression_utils::calculate_checksum(data.data(), data.size());
  uint32_t checksum2 =
      compression_utils::calculate_checksum(data.data(), data.size());

  EXPECT_EQ(checksum1, checksum2); // Should be deterministic
  EXPECT_NE(checksum1, 0u);        // Should not be zero for this data

  // Test algorithm selection
  auto small_algo =
      compression_utils::select_optimal_algorithm(data.data(), data.size());

  std::vector<uint8_t> large_data(100 * 1024, 0x77);
  auto large_algo = compression_utils::select_optimal_algorithm(
      large_data.data(), large_data.size());

  // Should recommend different algorithms for different sizes
  EXPECT_TRUE(small_algo == CompressionAlgorithm::LZ4 ||
              small_algo == CompressionAlgorithm::ZSTD);
  EXPECT_TRUE(large_algo == CompressionAlgorithm::LZ4 ||
              large_algo == CompressionAlgorithm::ZSTD);

  // Test recommendations
  auto realtime_rec = compression_utils::recommend_for_realtime();
  auto storage_rec = compression_utils::recommend_for_storage();
  auto network_rec = compression_utils::recommend_for_network();
  auto archival_rec = compression_utils::recommend_for_archival();

  EXPECT_FALSE(realtime_rec.reasoning.empty());
  EXPECT_FALSE(storage_rec.reasoning.empty());
  EXPECT_FALSE(network_rec.reasoning.empty());
  EXPECT_FALSE(archival_rec.reasoning.empty());

  // Archival should use maximum compression
  EXPECT_EQ(archival_rec.level, CompressionLevel::MAXIMUM);
}

// Test error handling
TEST_F(AdvancedCompressionTest, ErrorHandling) {
  // Test compression with null data
  EXPECT_NO_THROW({
    auto result = engine_->compress(nullptr, 0);
    EXPECT_TRUE(result.empty());
  });

  // Test decompression with null data
  EXPECT_NO_THROW({
    auto result = engine_->decompress(nullptr, 0, CompressionAlgorithm::LZ4);
    EXPECT_TRUE(result.empty());
  });

  // Test invalid compression metadata
  CompressionMetadata invalid_metadata;
  invalid_metadata.checksum = 0x12345678; // Wrong checksum
  invalid_metadata.original_size = 100;

  std::vector<uint8_t> test_data = {1, 2, 3, 4, 5};
  auto compressed = engine_->compress(test_data.data(), test_data.size());

  EXPECT_THROW(
      {
        engine_->decompress_with_validation(
            compressed.data(), compressed.size(), invalid_metadata);
      },
      std::runtime_error);
}

// Performance test
TEST_F(AdvancedCompressionTest, PerformanceTest) {
  // Create test data with various patterns
  std::vector<uint8_t> uniform_data(64 * 1024, 0x42); // Highly compressible
  std::vector<uint8_t> random_data(64 * 1024);        // Less compressible

  // Fill with pseudo-random data
  for (size_t i = 0; i < random_data.size(); ++i) {
    random_data[i] = static_cast<uint8_t>(i * 31 + 17); // Pseudo-random pattern
  }

  auto start = std::chrono::high_resolution_clock::now();

  // Test compression performance
  auto uniform_compressed = engine_->compress(
      uniform_data.data(), uniform_data.size(), CompressionAlgorithm::LZ4);
  auto random_compressed = engine_->compress(
      random_data.data(), random_data.size(), CompressionAlgorithm::LZ4);

  auto end = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  // Uniform data should compress much better
  double uniform_ratio =
      static_cast<double>(uniform_data.size()) / uniform_compressed.size();
  double random_ratio =
      static_cast<double>(random_data.size()) / random_compressed.size();

  EXPECT_GT(uniform_ratio, 5.0); // Should achieve significant compression
  EXPECT_LT(random_ratio, 2.0);  // Random data compresses poorly
  EXPECT_GT(uniform_ratio, random_ratio);

  std::cout << "Compression performance test:" << std::endl;
  std::cout << "  Duration: " << duration.count() << " ms" << std::endl;
  std::cout << "  Uniform data ratio: " << uniform_ratio << std::endl;
  std::cout << "  Random data ratio: " << random_ratio << std::endl;

  // Test throughput
  size_t total_bytes = uniform_data.size() + random_data.size();
  double throughput_mbps = (static_cast<double>(total_bytes) / (1024 * 1024)) /
                           (static_cast<double>(duration.count()) / 1000.0);

  std::cout << "  Throughput: " << throughput_mbps << " MB/s" << std::endl;

  // Should achieve reasonable throughput (this is implementation dependent)
  EXPECT_GT(throughput_mbps, 1.0); // At least 1 MB/s
}

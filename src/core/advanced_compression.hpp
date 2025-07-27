#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace core {

/**
 * Advanced compression system for state snapshots and data storage
 * Features:
 * - LZ4/Zstandard compression for state snapshots
 * - Incremental serialization to avoid full dumps
 * - Copy-on-write for shared data structures
 * - Background compression of cold data
 * - Compressed in-memory representations
 */

// Forward declarations
class CompressionEngine;
class IncrementalSerializer;
class CopyOnWriteManager;
class BackgroundCompressor;

/**
 * Compression algorithms supported
 */
enum class CompressionAlgorithm : uint8_t {
  NONE = 0,
  LZ4 = 1,
  ZSTD = 2,
  LZ4_HC = 3, // High compression LZ4
  ZSTD_FAST = 4,
  ZSTD_MAX = 5
};

/**
 * Compression level settings
 */
enum class CompressionLevel : uint8_t {
  FASTEST = 1,
  FAST = 3,
  DEFAULT = 6,
  BEST = 9,
  MAXIMUM = 22 // For Zstandard only
};

/**
 * Compression metadata for tracking
 */
struct CompressionMetadata {
  CompressionAlgorithm algorithm;
  CompressionLevel level;
  size_t original_size;
  size_t compressed_size;
  std::chrono::steady_clock::time_point timestamp;
  uint32_t checksum;
  double compression_ratio;
  std::chrono::milliseconds compression_time;
};

/**
 * Main compression engine interface
 */
class CompressionEngine {
public:
  CompressionEngine();
  ~CompressionEngine();

  // Compress data using specified algorithm
  std::vector<uint8_t>
  compress(const void *data, size_t size,
           CompressionAlgorithm algorithm = CompressionAlgorithm::LZ4,
           CompressionLevel level = CompressionLevel::DEFAULT);

  // Decompress data
  std::vector<uint8_t> decompress(const void *compressed_data,
                                  size_t compressed_size,
                                  CompressionAlgorithm algorithm);

  // Compress with metadata tracking
  std::pair<std::vector<uint8_t>, CompressionMetadata> compress_with_metadata(
      const void *data, size_t size,
      CompressionAlgorithm algorithm = CompressionAlgorithm::LZ4,
      CompressionLevel level = CompressionLevel::DEFAULT);

  // Decompress with validation
  std::vector<uint8_t>
  decompress_with_validation(const void *compressed_data,
                             size_t compressed_size,
                             const CompressionMetadata &metadata);

  // Estimate compression ratio without actually compressing
  double estimate_compression_ratio(const void *data, size_t size,
                                    CompressionAlgorithm algorithm) const;

  // Get compression statistics
  struct CompressionStats {
    size_t total_compressions;
    size_t total_decompressions;
    size_t total_original_bytes;
    size_t total_compressed_bytes;
    double average_compression_ratio;
    std::chrono::milliseconds total_compression_time;
    std::chrono::milliseconds total_decompression_time;
  };

  CompressionStats get_stats() const;
  void reset_stats();

private:
  mutable std::mutex stats_mutex_;
  CompressionStats stats_;
};

/**
 * Incremental serialization system to avoid full dumps
 */
class IncrementalSerializer {
public:
  IncrementalSerializer();
  ~IncrementalSerializer();

  // Initialize with base snapshot
  void initialize_base_snapshot(const std::vector<uint8_t> &base_data);

  // Add incremental change
  void add_change(uint32_t object_id, const std::vector<uint8_t> &delta_data);

  // Remove object
  void remove_object(uint32_t object_id);

  // Create incremental snapshot (only changes since last snapshot)
  std::vector<uint8_t> create_incremental_snapshot();

  // Create full snapshot (base + all incremental changes)
  std::vector<uint8_t> create_full_snapshot();

  // Apply incremental snapshot to restore state
  void apply_incremental_snapshot(const std::vector<uint8_t> &snapshot_data);

  // Compact history (merge old incremental changes into base)
  void compact_history(size_t max_incremental_snapshots = 10);

  // Get current snapshot metadata
  struct SnapshotMetadata {
    size_t base_snapshot_size;
    size_t incremental_count;
    size_t total_objects;
    std::chrono::steady_clock::time_point last_snapshot_time;
    double compression_efficiency;
  };

  SnapshotMetadata get_metadata() const;

private:
  struct Change {
    enum Type { ADD, MODIFY, REMOVE };
    Type type;
    uint32_t object_id;
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point timestamp;
  };

  std::vector<uint8_t> base_snapshot_;
  std::vector<Change> incremental_changes_;
  std::unordered_map<uint32_t, size_t> object_to_change_index_;
  mutable std::mutex mutex_;
  size_t next_snapshot_id_;
};

/**
 * Copy-on-write manager for shared data structures
 */
class CopyOnWriteManager {
public:
  // Handle for COW data
  template <typename T> class COWHandle {
  public:
    COWHandle(std::shared_ptr<const T> data)
        : data_(data), unique_copy_(nullptr) {}

    // Read access (always safe)
    const T &read() const { return *data_; }
    const T *operator->() const { return data_.get(); }
    const T &operator*() const { return *data_; }

    // Write access (triggers copy if shared)
    T &write() {
      if (!unique_copy_ && data_.use_count() > 1) {
        unique_copy_ = std::make_unique<T>(*data_);
      }
      return unique_copy_ ? *unique_copy_ : const_cast<T &>(*data_);
    }

    // Commit changes (creates new shared version)
    std::shared_ptr<const T> commit() {
      if (unique_copy_) {
        data_ = std::shared_ptr<const T>(std::move(unique_copy_));
        unique_copy_.reset();
      }
      return data_;
    }

    // Check if this handle has exclusive access
    bool is_unique() const { return data_.use_count() == 1; }

    // Get reference count
    long use_count() const { return data_.use_count(); }

  private:
    std::shared_ptr<const T> data_;
    std::unique_ptr<T> unique_copy_;
  };

  // Create new COW handle
  template <typename T> COWHandle<T> create(T &&initial_data) {
    return COWHandle<T>(
        std::make_shared<const T>(std::forward<T>(initial_data)));
  }

  // Create COW handle from existing data
  template <typename T> COWHandle<T> create(const T &initial_data) {
    return COWHandle<T>(std::make_shared<const T>(initial_data));
  }

  // Statistics
  struct COWStats {
    size_t total_handles;
    size_t total_copies_made;
    size_t memory_saved_bytes;
    double copy_efficiency;
  };

  COWStats get_stats() const;
};

/**
 * Background compressor for cold data
 */
class BackgroundCompressor {
public:
  BackgroundCompressor(CompressionEngine *engine);
  ~BackgroundCompressor();

  // Configuration for background compression
  struct Config {
    std::chrono::minutes idle_threshold{30}; // Compress data idle for this long
    CompressionAlgorithm algorithm{CompressionAlgorithm::ZSTD};
    CompressionLevel level{CompressionLevel::BEST};
    size_t min_size_threshold{1024}; // Don't compress smaller data
    size_t max_parallel_jobs{2};
    std::chrono::milliseconds scan_interval{
        60000}; // Check for cold data every minute
  };

  void configure(const Config &config);

  // Register data for potential background compression
  uint64_t register_data(const std::string &identifier,
                         std::shared_ptr<std::vector<uint8_t>> data);

  // Mark data as accessed (resets idle timer)
  void mark_accessed(uint64_t handle);

  // Unregister data
  void unregister_data(uint64_t handle);

  // Get compressed data (may trigger decompression)
  std::shared_ptr<std::vector<uint8_t>> get_data(uint64_t handle);

  // Force compression of specific data
  void force_compress(uint64_t handle);

  // Start/stop background compression thread
  void start();
  void stop();

  // Statistics
  struct BackgroundStats {
    size_t registered_objects;
    size_t compressed_objects;
    size_t total_original_size;
    size_t total_compressed_size;
    size_t compression_jobs_completed;
    size_t decompression_requests;
    double average_compression_ratio;
    std::chrono::milliseconds total_compression_time;
  };

  BackgroundStats get_stats() const;

private:
  struct DataEntry {
    std::string identifier;
    std::shared_ptr<std::vector<uint8_t>> original_data;
    std::shared_ptr<std::vector<uint8_t>> compressed_data;
    CompressionMetadata compression_metadata;
    std::chrono::steady_clock::time_point last_accessed;
    std::atomic<bool> is_compressed{false};
    std::atomic<bool> compression_in_progress{false};
    mutable std::mutex mutex;
  };

  CompressionEngine *compression_engine_;
  Config config_;
  std::unordered_map<uint64_t, std::unique_ptr<DataEntry>> data_entries_;
  std::atomic<uint64_t> next_handle_{1};
  std::atomic<bool> running_{false};
  std::thread background_thread_;
  mutable std::mutex entries_mutex_;

  // Background compression worker
  void background_worker();
  void scan_and_compress();
  void compress_entry(DataEntry &entry);
};

/**
 * Compressed memory representations
 */
class CompressedMemoryStore {
public:
  CompressedMemoryStore(CompressionEngine *engine);
  ~CompressedMemoryStore();

  // Store data with automatic compression decision
  uint64_t store(const std::string &key, const std::vector<uint8_t> &data,
                 bool force_compression = false);

  // Retrieve data (automatically decompressed if needed)
  std::vector<uint8_t> retrieve(uint64_t handle);
  std::vector<uint8_t> retrieve(const std::string &key);

  // Check if data exists
  bool exists(uint64_t handle) const;
  bool exists(const std::string &key) const;

  // Remove data
  void remove(uint64_t handle);
  void remove(const std::string &key);

  // Get compression info
  std::optional<CompressionMetadata>
  get_compression_info(uint64_t handle) const;

  // Configuration
  struct Config {
    size_t compression_threshold{512}; // Compress data larger than this
    CompressionAlgorithm default_algorithm{CompressionAlgorithm::LZ4};
    CompressionLevel default_level{CompressionLevel::FAST};
    double min_compression_ratio{
        1.1}; // Only keep compressed if better than this ratio
    size_t max_memory_usage{100 * 1024 * 1024}; // 100MB max
  };

  void configure(const Config &config);

  // Statistics and management
  struct MemoryStats {
    size_t total_objects;
    size_t compressed_objects;
    size_t uncompressed_objects;
    size_t total_memory_used;
    size_t memory_saved;
    double average_compression_ratio;
    double memory_efficiency;
  };

  MemoryStats get_stats() const;
  void cleanup_expired(); // Remove old/unused data

private:
  struct StoredData {
    std::string key;
    std::vector<uint8_t> data;
    bool is_compressed;
    CompressionMetadata metadata;
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point last_accessed;
  };

  CompressionEngine *compression_engine_;
  Config config_;
  std::unordered_map<uint64_t, StoredData> data_by_handle_;
  std::unordered_map<std::string, uint64_t> handle_by_key_;
  std::atomic<uint64_t> next_handle_{1};
  mutable std::mutex mutex_;

  bool should_compress(const std::vector<uint8_t> &data) const;
  uint64_t store_internal(const std::string &key,
                          const std::vector<uint8_t> &data,
                          bool force_compression);
};

/**
 * Utility functions for compression operations
 */
namespace compression_utils {
// Calculate optimal compression algorithm for data type
CompressionAlgorithm select_optimal_algorithm(const void *data, size_t size);

// Calculate checksum for data integrity
uint32_t calculate_checksum(const void *data, size_t size);

// Validate compressed data integrity
bool validate_compressed_data(const void *compressed_data,
                              size_t compressed_size,
                              const CompressionMetadata &metadata);

// Benchmark compression algorithms
struct BenchmarkResult {
  CompressionAlgorithm algorithm;
  CompressionLevel level;
  double compression_ratio;
  std::chrono::microseconds compression_time;
  std::chrono::microseconds decompression_time;
  double throughput_mbps;
};

std::vector<BenchmarkResult> benchmark_algorithms(const void *data,
                                                  size_t size);

// Get recommended settings for different use cases
struct CompressionRecommendation {
  CompressionAlgorithm algorithm;
  CompressionLevel level;
  std::string reasoning;
};

CompressionRecommendation recommend_for_realtime();
CompressionRecommendation recommend_for_storage();
CompressionRecommendation recommend_for_network();
CompressionRecommendation recommend_for_archival();
} // namespace compression_utils

} // namespace core

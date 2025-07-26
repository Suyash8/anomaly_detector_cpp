#include "advanced_compression.hpp"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <thread>

namespace core {

// Simulated compression implementations
namespace compression_impl {

size_t lz4_compress_bound(size_t input_size) {
  return input_size + sizeof(uint32_t); // Add space for size prefix
}

// Note: In a real implementation, we would include LZ4 and Zstandard libraries
// For this implementation, we'll create stub implementations that simulate
// compression

namespace core {

// Simulation of LZ4/Zstandard compression for demonstration
namespace compression_impl {
// Simulate LZ4 compression
size_t lz4_compress_bound(size_t input_size) {
  return input_size + sizeof(uint32_t); // Add space for size prefix
}

size_t lz4_compress(const void *src, void *dst, size_t src_size,
                    size_t dst_capacity, int level) {
  // Simulation: prepend original size, then copy data with simple compression
  (void)level; // Suppress unused parameter warning

  // We need at least 4 bytes for original size + compressed data
  size_t compressed_data_size = src_size; // For simulation, keep original size
  size_t total_size = sizeof(uint32_t) + compressed_data_size;

  if (total_size > dst_capacity)
    return 0;

  // Store original size in first 4 bytes
  uint32_t orig_size = static_cast<uint32_t>(src_size);
  std::memcpy(dst, &orig_size, sizeof(uint32_t));

  // Copy the data (in real LZ4, this would be compressed)
  std::memcpy(static_cast<char *>(dst) + sizeof(uint32_t), src, src_size);

  return total_size;
}

size_t lz4_decompress(const void *src, void *dst, size_t compressed_size,
                      size_t max_decompressed_size) {
  // Simulation: read original size from first 4 bytes, then copy data
  if (compressed_size < sizeof(uint32_t))
    return 0;

  uint32_t original_size;
  std::memcpy(&original_size, src, sizeof(uint32_t));

  if (original_size > max_decompressed_size)
    return 0;

  size_t data_size = compressed_size - sizeof(uint32_t);
  if (data_size < original_size)
    return 0;

  std::memcpy(dst, static_cast<const char *>(src) + sizeof(uint32_t),
              original_size);
  return original_size;
}

// Simulate Zstandard compression
size_t zstd_compress_bound(size_t input_size) {
  return input_size + sizeof(uint32_t); // Add space for size prefix
}

size_t zstd_compress(const void *src, void *dst, size_t src_size,
                     size_t dst_capacity, int level) {
  // Simulation: prepend original size, then copy data (representing ZSTD
  // compression)
  (void)level; // Suppress unused parameter warning

  // We need at least 4 bytes for original size + compressed data
  size_t compressed_data_size = src_size; // For simulation, keep original size
  size_t total_size = sizeof(uint32_t) + compressed_data_size;

  if (total_size > dst_capacity)
    return 0;

  // Store original size in first 4 bytes
  uint32_t orig_size = static_cast<uint32_t>(src_size);
  std::memcpy(dst, &orig_size, sizeof(uint32_t));

  // Copy the data (in real ZSTD, this would be compressed)
  std::memcpy(static_cast<char *>(dst) + sizeof(uint32_t), src, src_size);

  return total_size;
}

size_t zstd_decompress(const void *src, void *dst, size_t compressed_size,
                       size_t max_decompressed_size) {
  // Simulation: read original size from first 4 bytes, then copy data
  if (compressed_size < sizeof(uint32_t))
    return 0;

  uint32_t original_size;
  std::memcpy(&original_size, src, sizeof(uint32_t));

  if (original_size > max_decompressed_size)
    return 0;

  size_t data_size = compressed_size - sizeof(uint32_t);
  if (data_size < original_size)
    return 0;

  std::memcpy(dst, static_cast<const char *>(src) + sizeof(uint32_t),
              original_size);
  return original_size;
}
} // namespace compression_impl

// CompressionEngine implementation
struct CompressionEngine::Impl {
  mutable std::mutex stats_mutex;
  CompressionStats stats{};

  void update_compression_stats(size_t original_size, size_t compressed_size,
                                std::chrono::milliseconds duration) {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_compressions++;
    stats.total_original_bytes += original_size;
    stats.total_compressed_bytes += compressed_size;
    stats.total_compression_time += duration;

    if (stats.total_compressed_bytes > 0) {
      stats.average_compression_ratio =
          static_cast<double>(stats.total_original_bytes) /
          stats.total_compressed_bytes;
    }
  }

  void update_decompression_stats(std::chrono::milliseconds duration) {
    std::lock_guard<std::mutex> lock(stats_mutex);
    stats.total_decompressions++;
    stats.total_decompression_time += duration;
  }
};

CompressionEngine::CompressionEngine() : impl_(std::make_unique<Impl>()) {}

CompressionEngine::~CompressionEngine() = default;

std::vector<uint8_t> CompressionEngine::compress(const void *data, size_t size,
                                                 CompressionAlgorithm algorithm,
                                                 CompressionLevel level) {
  auto start_time = std::chrono::steady_clock::now();

  if (!data || size == 0) {
    return {};
  }

  std::vector<uint8_t> result;
  size_t compressed_size = 0;

  switch (algorithm) {
  case CompressionAlgorithm::LZ4:
  case CompressionAlgorithm::LZ4_HC: {
    size_t max_size = compression_impl::lz4_compress_bound(size);
    result.resize(max_size);

    compressed_size = compression_impl::lz4_compress(
        data, result.data(), size, max_size, static_cast<int>(level));
    break;
  }

  case CompressionAlgorithm::ZSTD:
  case CompressionAlgorithm::ZSTD_FAST:
  case CompressionAlgorithm::ZSTD_MAX: {
    size_t max_size = compression_impl::zstd_compress_bound(size);
    result.resize(max_size);

    compressed_size = compression_impl::zstd_compress(
        data, result.data(), size, max_size, static_cast<int>(level));
    break;
  }

  case CompressionAlgorithm::NONE:
  default:
    result.assign(static_cast<const uint8_t *>(data),
                  static_cast<const uint8_t *>(data) + size);
    compressed_size = size;
    break;
  }

  if (compressed_size == 0) {
    throw std::runtime_error("Compression failed");
  }

  result.resize(compressed_size);

  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  impl_->update_compression_stats(size, compressed_size, duration);

  return result;
}

std::vector<uint8_t>
CompressionEngine::decompress(const void *compressed_data,
                              size_t compressed_size,
                              CompressionAlgorithm algorithm) {
  auto start_time = std::chrono::steady_clock::now();

  if (!compressed_data || compressed_size == 0) {
    return {};
  }

  // Estimate original size (this would come from metadata in real
  // implementation)
  size_t estimated_original_size = compressed_size * 3; // Conservative estimate
  std::vector<uint8_t> result(estimated_original_size);

  size_t decompressed_size = 0;

  switch (algorithm) {
  case CompressionAlgorithm::LZ4:
  case CompressionAlgorithm::LZ4_HC: {
    decompressed_size = compression_impl::lz4_decompress(
        compressed_data, result.data(), compressed_size,
        estimated_original_size);
    break;
  }

  case CompressionAlgorithm::ZSTD:
  case CompressionAlgorithm::ZSTD_FAST:
  case CompressionAlgorithm::ZSTD_MAX: {
    decompressed_size = compression_impl::zstd_decompress(
        compressed_data, result.data(), compressed_size,
        estimated_original_size);
    break;
  }

  case CompressionAlgorithm::NONE:
  default:
    result.assign(static_cast<const uint8_t *>(compressed_data),
                  static_cast<const uint8_t *>(compressed_data) +
                      compressed_size);
    decompressed_size = compressed_size;
    break;
  }

  if (decompressed_size == 0) {
    throw std::runtime_error("Decompression failed");
  }

  result.resize(decompressed_size);

  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  impl_->update_decompression_stats(duration);

  return result;
}

std::pair<std::vector<uint8_t>, CompressionMetadata>
CompressionEngine::compress_with_metadata(const void *data, size_t size,
                                          CompressionAlgorithm algorithm,
                                          CompressionLevel level) {
  auto start_time = std::chrono::steady_clock::now();

  auto compressed_data = compress(data, size, algorithm, level);

  auto end_time = std::chrono::steady_clock::now();
  auto compression_time = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  CompressionMetadata metadata;
  metadata.algorithm = algorithm;
  metadata.level = level;
  metadata.original_size = size;
  metadata.compressed_size = compressed_data.size();
  metadata.timestamp = std::chrono::steady_clock::now();
  metadata.checksum = compression_utils::calculate_checksum(data, size);
  metadata.compression_ratio =
      static_cast<double>(size) / compressed_data.size();
  metadata.compression_time = compression_time;

  return {std::move(compressed_data), metadata};
}

std::vector<uint8_t> CompressionEngine::decompress_with_validation(
    const void *compressed_data, size_t compressed_size,
    const CompressionMetadata &metadata) {

  auto result =
      decompress(compressed_data, compressed_size, metadata.algorithm);

  // Validate decompressed data
  if (result.size() != metadata.original_size) {
    throw std::runtime_error("Decompressed size mismatch");
  }

  uint32_t checksum =
      compression_utils::calculate_checksum(result.data(), result.size());
  if (checksum != metadata.checksum) {
    throw std::runtime_error("Checksum validation failed");
  }

  return result;
}

double CompressionEngine::estimate_compression_ratio(
    const void *data, size_t size, CompressionAlgorithm algorithm) const {
  // Simple heuristic based on data entropy (simplified)
  if (size == 0)
    return 1.0;

  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  std::unordered_map<uint8_t, size_t> frequency;

  // Sample first 1KB for estimation
  size_t sample_size = std::min(size, size_t(1024));
  for (size_t i = 0; i < sample_size; ++i) {
    frequency[bytes[i]]++;
  }

  // Calculate entropy
  double entropy = 0.0;
  for (const auto &[byte, count] : frequency) {
    double p = static_cast<double>(count) / sample_size;
    if (p > 0) {
      entropy -= p * std::log2(p);
    }
  }

  // Estimate compression ratio based on entropy and algorithm
  double base_ratio = 8.0 / std::max(entropy, 1.0);

  switch (algorithm) {
  case CompressionAlgorithm::LZ4:
  case CompressionAlgorithm::LZ4_HC:
    return std::min(base_ratio * 0.8, 3.0);
  case CompressionAlgorithm::ZSTD:
  case CompressionAlgorithm::ZSTD_FAST:
  case CompressionAlgorithm::ZSTD_MAX:
    return std::min(base_ratio, 4.0);
  default:
    return 1.0;
  }
}

CompressionEngine::CompressionStats CompressionEngine::get_stats() const {
  std::lock_guard<std::mutex> lock(impl_->stats_mutex);
  return impl_->stats;
}

void CompressionEngine::reset_stats() {
  std::lock_guard<std::mutex> lock(impl_->stats_mutex);
  impl_->stats = {};
}

// IncrementalSerializer implementation
IncrementalSerializer::IncrementalSerializer() : next_snapshot_id_(1) {}

IncrementalSerializer::~IncrementalSerializer() = default;

void IncrementalSerializer::initialize_base_snapshot(
    const std::vector<uint8_t> &base_data) {
  std::lock_guard<std::mutex> lock(mutex_);
  base_snapshot_ = base_data;
  incremental_changes_.clear();
  object_to_change_index_.clear();
}

void IncrementalSerializer::add_change(uint32_t object_id,
                                       const std::vector<uint8_t> &delta_data) {
  std::lock_guard<std::mutex> lock(mutex_);

  Change change;
  change.type = Change::MODIFY;
  change.object_id = object_id;
  change.data = delta_data;
  change.timestamp = std::chrono::steady_clock::now();

  // Update existing change or add new one
  auto it = object_to_change_index_.find(object_id);
  if (it != object_to_change_index_.end()) {
    incremental_changes_[it->second] = std::move(change);
  } else {
    object_to_change_index_[object_id] = incremental_changes_.size();
    incremental_changes_.push_back(std::move(change));
  }
}

void IncrementalSerializer::remove_object(uint32_t object_id) {
  std::lock_guard<std::mutex> lock(mutex_);

  Change change;
  change.type = Change::REMOVE;
  change.object_id = object_id;
  change.timestamp = std::chrono::steady_clock::now();

  auto it = object_to_change_index_.find(object_id);
  if (it != object_to_change_index_.end()) {
    incremental_changes_[it->second] = std::move(change);
  } else {
    object_to_change_index_[object_id] = incremental_changes_.size();
    incremental_changes_.push_back(std::move(change));
  }
}

std::vector<uint8_t> IncrementalSerializer::create_incremental_snapshot() {
  std::lock_guard<std::mutex> lock(mutex_);

  std::vector<uint8_t> snapshot;

  // Simple serialization format:
  // [snapshot_id:4][change_count:4][changes...]

  uint32_t snapshot_id = next_snapshot_id_++;
  uint32_t change_count = static_cast<uint32_t>(incremental_changes_.size());

  snapshot.resize(8);
  std::memcpy(snapshot.data(), &snapshot_id, 4);
  std::memcpy(snapshot.data() + 4, &change_count, 4);

  for (const auto &change : incremental_changes_) {
    // [type:1][object_id:4][data_size:4][data...]
    snapshot.push_back(static_cast<uint8_t>(change.type));

    uint32_t object_id = change.object_id;
    snapshot.insert(snapshot.end(),
                    reinterpret_cast<const uint8_t *>(&object_id),
                    reinterpret_cast<const uint8_t *>(&object_id) + 4);

    uint32_t data_size = static_cast<uint32_t>(change.data.size());
    snapshot.insert(snapshot.end(),
                    reinterpret_cast<const uint8_t *>(&data_size),
                    reinterpret_cast<const uint8_t *>(&data_size) + 4);

    snapshot.insert(snapshot.end(), change.data.begin(), change.data.end());
  }

  return snapshot;
}

std::vector<uint8_t> IncrementalSerializer::create_full_snapshot() {
  std::lock_guard<std::mutex> lock(mutex_);

  // For simplicity, just return base snapshot + incremental changes
  // In a real implementation, this would merge the changes properly
  auto base = base_snapshot_;
  auto incremental = create_incremental_snapshot();

  base.insert(base.end(), incremental.begin(), incremental.end());
  return base;
}

void IncrementalSerializer::apply_incremental_snapshot(
    const std::vector<uint8_t> &snapshot_data) {
  if (snapshot_data.size() < 8) {
    throw std::runtime_error("Invalid snapshot format");
  }

  // Parse header
  uint32_t snapshot_id, change_count;
  std::memcpy(&snapshot_id, snapshot_data.data(), 4);
  std::memcpy(&change_count, snapshot_data.data() + 4, 4);

  size_t pos = 8;
  for (uint32_t i = 0; i < change_count && pos < snapshot_data.size(); ++i) {
    if (pos + 9 > snapshot_data.size())
      break;

    uint8_t type = snapshot_data[pos++];

    uint32_t object_id, data_size;
    std::memcpy(&object_id, snapshot_data.data() + pos, 4);
    pos += 4;
    std::memcpy(&data_size, snapshot_data.data() + pos, 4);
    pos += 4;

    if (pos + data_size > snapshot_data.size())
      break;

    std::vector<uint8_t> data(snapshot_data.begin() + pos,
                              snapshot_data.begin() + pos + data_size);
    pos += data_size;

    // Apply change based on type
    switch (static_cast<Change::Type>(type)) {
    case Change::MODIFY:
      add_change(object_id, data);
      break;
    case Change::REMOVE:
      remove_object(object_id);
      break;
    default:
      break;
    }
  }
}

void IncrementalSerializer::compact_history(size_t max_incremental_snapshots) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (incremental_changes_.size() <= max_incremental_snapshots) {
    return;
  }

  // In a real implementation, this would merge old changes into the base
  // snapshot For simplicity, we'll just keep the most recent changes
  size_t keep_count = max_incremental_snapshots;
  if (incremental_changes_.size() > keep_count) {
    incremental_changes_.erase(incremental_changes_.begin(),
                               incremental_changes_.end() - keep_count);

    // Rebuild object index
    object_to_change_index_.clear();
    for (size_t i = 0; i < incremental_changes_.size(); ++i) {
      object_to_change_index_[incremental_changes_[i].object_id] = i;
    }
  }
}

IncrementalSerializer::SnapshotMetadata
IncrementalSerializer::get_metadata() const {
  std::lock_guard<std::mutex> lock(mutex_);

  SnapshotMetadata metadata;
  metadata.base_snapshot_size = base_snapshot_.size();
  metadata.incremental_count = incremental_changes_.size();
  metadata.total_objects = object_to_change_index_.size();
  metadata.last_snapshot_time = std::chrono::steady_clock::now();

  // Calculate compression efficiency
  size_t total_incremental_size = 0;
  for (const auto &change : incremental_changes_) {
    total_incremental_size += change.data.size();
  }

  if (total_incremental_size > 0) {
    metadata.compression_efficiency =
        static_cast<double>(base_snapshot_.size()) /
        (base_snapshot_.size() + total_incremental_size);
  } else {
    metadata.compression_efficiency = 1.0;
  }

  return metadata;
}

// BackgroundCompressor implementation
BackgroundCompressor::BackgroundCompressor(CompressionEngine *engine)
    : compression_engine_(engine) {}

BackgroundCompressor::~BackgroundCompressor() { stop(); }

void BackgroundCompressor::configure(const Config &config) { config_ = config; }

uint64_t BackgroundCompressor::register_data(
    const std::string &identifier, std::shared_ptr<std::vector<uint8_t>> data) {
  std::lock_guard<std::mutex> lock(entries_mutex_);

  uint64_t handle = next_handle_++;
  auto entry = std::make_unique<DataEntry>();
  entry->identifier = identifier;
  entry->original_data = data;
  entry->last_accessed = std::chrono::steady_clock::now();

  data_entries_[handle] = std::move(entry);

  return handle;
}

void BackgroundCompressor::mark_accessed(uint64_t handle) {
  std::lock_guard<std::mutex> lock(entries_mutex_);

  auto it = data_entries_.find(handle);
  if (it != data_entries_.end()) {
    it->second->last_accessed = std::chrono::steady_clock::now();
  }
}

void BackgroundCompressor::unregister_data(uint64_t handle) {
  std::lock_guard<std::mutex> lock(entries_mutex_);
  data_entries_.erase(handle);
}

std::shared_ptr<std::vector<uint8_t>>
BackgroundCompressor::get_data(uint64_t handle) {
  std::lock_guard<std::mutex> lock(entries_mutex_);

  auto it = data_entries_.find(handle);
  if (it == data_entries_.end()) {
    return nullptr;
  }

  auto &entry = *it->second;
  mark_accessed(handle);

  if (!entry.is_compressed) {
    return entry.original_data;
  }

  // Decompress on demand
  std::lock_guard<std::mutex> entry_lock(entry.mutex);
  if (entry.compressed_data && compression_engine_) {
    try {
      auto decompressed = compression_engine_->decompress_with_validation(
          entry.compressed_data->data(), entry.compressed_data->size(),
          entry.compression_metadata);

      return std::make_shared<std::vector<uint8_t>>(std::move(decompressed));
    } catch (const std::exception &e) {
      // Fallback to original data if decompression fails
      return entry.original_data;
    }
  }

  return entry.original_data;
}

void BackgroundCompressor::start() {
  if (running_.exchange(true)) {
    return; // Already running
  }

  background_thread_ =
      std::thread(&BackgroundCompressor::background_worker, this);
}

void BackgroundCompressor::stop() {
  if (!running_.exchange(false)) {
    return; // Already stopped
  }

  if (background_thread_.joinable()) {
    background_thread_.join();
  }
}

void BackgroundCompressor::background_worker() {
  while (running_) {
    try {
      scan_and_compress();
    } catch (const std::exception &e) {
      // Log error and continue
    }

    std::this_thread::sleep_for(config_.scan_interval);
  }
}

void BackgroundCompressor::scan_and_compress() {
  std::vector<uint64_t> candidates;
  auto now = std::chrono::steady_clock::now();

  // Find compression candidates
  {
    std::lock_guard<std::mutex> lock(entries_mutex_);
    for (const auto &[handle, entry] : data_entries_) {
      if (!entry->is_compressed && !entry->compression_in_progress &&
          entry->original_data &&
          entry->original_data->size() >= config_.min_size_threshold &&
          (now - entry->last_accessed) >= config_.idle_threshold) {

        candidates.push_back(handle);
      }
    }
  }

  // Compress candidates (limit parallel jobs)
  size_t active_jobs = 0;
  for (uint64_t handle : candidates) {
    if (active_jobs >= config_.max_parallel_jobs) {
      break;
    }

    std::lock_guard<std::mutex> lock(entries_mutex_);
    auto it = data_entries_.find(handle);
    if (it != data_entries_.end()) {
      auto &entry = *it->second;
      if (!entry.compression_in_progress.exchange(true)) {
        // Launch compression in background
        std::thread([this, handle]() {
          try {
            std::lock_guard<std::mutex> lock(entries_mutex_);
            auto it = data_entries_.find(handle);
            if (it != data_entries_.end()) {
              compress_entry(*it->second);
            }
          } catch (...) {
            // Error handling
          }
        }).detach();

        active_jobs++;
      }
    }
  }
}

void BackgroundCompressor::compress_entry(DataEntry &entry) {
  if (!entry.original_data || !compression_engine_) {
    entry.compression_in_progress = false;
    return;
  }

  try {
    auto [compressed_data, metadata] =
        compression_engine_->compress_with_metadata(
            entry.original_data->data(), entry.original_data->size(),
            config_.algorithm, config_.level);

    // Only keep compressed version if it's actually smaller
    if (metadata.compression_ratio > 1.1) {
      std::lock_guard<std::mutex> entry_lock(entry.mutex);
      entry.compressed_data =
          std::make_shared<std::vector<uint8_t>>(std::move(compressed_data));
      entry.compression_metadata = metadata;
      entry.is_compressed = true;

      // Release original data to save memory
      entry.original_data.reset();
    }
  } catch (const std::exception &e) {
    // Compression failed, keep original data
  }

  entry.compression_in_progress = false;
}

BackgroundCompressor::BackgroundStats BackgroundCompressor::get_stats() const {
  std::lock_guard<std::mutex> lock(entries_mutex_);

  BackgroundStats stats{};
  stats.registered_objects = data_entries_.size();

  for (const auto &[handle, entry] : data_entries_) {
    if (entry->is_compressed) {
      stats.compressed_objects++;
      stats.total_compressed_size +=
          entry->compressed_data ? entry->compressed_data->size() : 0;
      stats.total_original_size += entry->compression_metadata.original_size;
    } else if (entry->original_data) {
      stats.total_original_size += entry->original_data->size();
    }
  }

  if (stats.total_compressed_size > 0) {
    stats.average_compression_ratio =
        static_cast<double>(stats.total_original_size) /
        stats.total_compressed_size;
  }

  return stats;
}

// CompressedMemoryStore implementation
CompressedMemoryStore::CompressedMemoryStore(CompressionEngine *engine)
    : compression_engine_(engine) {}

CompressedMemoryStore::~CompressedMemoryStore() = default;

uint64_t CompressedMemoryStore::store(const std::string &key,
                                      const std::vector<uint8_t> &data,
                                      bool force_compression) {
  return store_internal(key, data, force_compression);
}

std::vector<uint8_t> CompressedMemoryStore::retrieve(uint64_t handle) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = data_by_handle_.find(handle);
  if (it == data_by_handle_.end()) {
    throw std::runtime_error("Handle not found");
  }

  auto &stored_data = it->second;
  stored_data.last_accessed = std::chrono::steady_clock::now();

  if (!stored_data.is_compressed) {
    return stored_data.data;
  }

  // Decompress
  if (compression_engine_) {
    return compression_engine_->decompress_with_validation(
        stored_data.data.data(), stored_data.data.size(), stored_data.metadata);
  }

  return stored_data.data;
}

bool CompressedMemoryStore::should_compress(
    const std::vector<uint8_t> &data) const {
  return data.size() >= config_.compression_threshold;
}

uint64_t CompressedMemoryStore::store_internal(const std::string &key,
                                               const std::vector<uint8_t> &data,
                                               bool force_compression) {
  std::lock_guard<std::mutex> lock(mutex_);

  uint64_t handle = next_handle_++;

  StoredData stored_data;
  stored_data.key = key;
  stored_data.created = std::chrono::steady_clock::now();
  stored_data.last_accessed = stored_data.created;

  if ((force_compression || should_compress(data)) && compression_engine_) {
    try {
      auto [compressed, metadata] = compression_engine_->compress_with_metadata(
          data.data(), data.size(), config_.default_algorithm,
          config_.default_level);

      if (metadata.compression_ratio >= config_.min_compression_ratio) {
        stored_data.data = std::move(compressed);
        stored_data.metadata = metadata;
        stored_data.is_compressed = true;
      } else {
        // Compression not worthwhile
        stored_data.data = data;
        stored_data.is_compressed = false;
      }
    } catch (const std::exception &e) {
      // Compression failed, store uncompressed
      stored_data.data = data;
      stored_data.is_compressed = false;
    }
  } else {
    stored_data.data = data;
    stored_data.is_compressed = false;
  }

  data_by_handle_[handle] = std::move(stored_data);
  handle_by_key_[key] = handle;

  return handle;
}

CompressedMemoryStore::MemoryStats CompressedMemoryStore::get_stats() const {
  std::lock_guard<std::mutex> lock(mutex_);

  MemoryStats stats{};
  stats.total_objects = data_by_handle_.size();

  size_t total_compressed_original_size = 0;

  for (const auto &[handle, stored_data] : data_by_handle_) {
    stats.total_memory_used += stored_data.data.size();

    if (stored_data.is_compressed) {
      stats.compressed_objects++;
      total_compressed_original_size += stored_data.metadata.original_size;
      stats.memory_saved +=
          (stored_data.metadata.original_size - stored_data.data.size());
    } else {
      stats.uncompressed_objects++;
    }
  }

  if (stats.compressed_objects > 0) {
    stats.average_compression_ratio =
        static_cast<double>(total_compressed_original_size) /
        (total_compressed_original_size - stats.memory_saved);
  }

  if (stats.total_memory_used + stats.memory_saved > 0) {
    stats.memory_efficiency = static_cast<double>(stats.memory_saved) /
                              (stats.total_memory_used + stats.memory_saved);
  }

  return stats;
}

// Utility functions
namespace compression_utils {

CompressionAlgorithm select_optimal_algorithm(const void *data, size_t size) {
  (void)data; // Suppress unused parameter warning
  if (size < 1024) {
    return CompressionAlgorithm::LZ4; // Fast for small data
  }

  // Simple heuristic: use Zstandard for larger data
  return (size > 64 * 1024) ? CompressionAlgorithm::ZSTD
                            : CompressionAlgorithm::LZ4;
}

uint32_t calculate_checksum(const void *data, size_t size) {
  // Simple FNV-1a hash
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  uint32_t hash = 2166136261u;

  for (size_t i = 0; i < size; ++i) {
    hash ^= bytes[i];
    hash *= 16777619u;
  }

  return hash;
}

bool validate_compressed_data(const void *compressed_data,
                              size_t compressed_size,
                              const CompressionMetadata &metadata) {
  if (!compressed_data || compressed_size != metadata.compressed_size) {
    return false;
  }

  // Additional validation could be added here
  return true;
}

CompressionRecommendation recommend_for_realtime() {
  return {CompressionAlgorithm::LZ4, CompressionLevel::FAST,
          "Fast compression for real-time processing"};
}

CompressionRecommendation recommend_for_storage() {
  return {CompressionAlgorithm::ZSTD, CompressionLevel::DEFAULT,
          "Balanced compression for storage efficiency"};
}

CompressionRecommendation recommend_for_network() {
  return {CompressionAlgorithm::LZ4, CompressionLevel::DEFAULT,
          "Fast compression optimized for network transmission"};
}

CompressionRecommendation recommend_for_archival() {
  return {CompressionAlgorithm::ZSTD, CompressionLevel::MAXIMUM,
          "Maximum compression for long-term archival"};
}

} // namespace compression_utils

// ============================================================================
// CompressedMemoryStore Implementation
// ============================================================================

void CompressedMemoryStore::configure(const Config &config) {
  config_ = config;
}

std::vector<uint8_t> CompressedMemoryStore::retrieve(const std::string &key) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = handle_by_key_.find(key);
  if (it == handle_by_key_.end()) {
    return {}; // Empty vector if not found
  }

  return retrieve(it->second);
}

bool CompressedMemoryStore::exists(const std::string &key) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return handle_by_key_.find(key) != handle_by_key_.end();
}

} // namespace core

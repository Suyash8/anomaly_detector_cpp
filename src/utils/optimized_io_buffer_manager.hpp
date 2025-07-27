#ifndef OPTIMIZED_IO_BUFFER_MANAGER_HPP
#define OPTIMIZED_IO_BUFFER_MANAGER_HPP

#include "core/memory_manager.hpp"
#include "utils/string_interning.hpp"

#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string_view>
#include <vector>

namespace optimized_io {

/**
 * @brief High-performance circular buffer for streaming data
 *
 * Optimized for zero-copy operations and cache-friendly access patterns.
 * Uses memory-mapped approach for large data sets.
 */
template <size_t BufferSize = 1024 * 1024> // 1MB default
class CircularBuffer {
public:
  CircularBuffer() : read_pos_(0), write_pos_(0), size_(0) {
    static_assert(BufferSize > 0 && (BufferSize & (BufferSize - 1)) == 0,
                  "BufferSize must be a power of 2");
  }

  // Zero-copy write interface
  struct WriteRegion {
    char *data;
    size_t size;
    bool is_contiguous;
    char *data2; // Second region if wrapping
    size_t size2;
  };

  // Get writable region without copying
  WriteRegion get_write_region(size_t requested_size) {
    WriteRegion region{};

    size_t available = BufferSize - size_;
    if (requested_size > available) {
      requested_size = available;
    }

    size_t write_pos = write_pos_.load(std::memory_order_acquire);
    size_t end_space = BufferSize - write_pos;

    if (requested_size <= end_space) {
      // Contiguous write
      region.data = buffer_.data() + write_pos;
      region.size = requested_size;
      region.is_contiguous = true;
    } else {
      // Split write (wrapping)
      region.data = buffer_.data() + write_pos;
      region.size = end_space;
      region.data2 = buffer_.data();
      region.size2 = requested_size - end_space;
      region.is_contiguous = false;
    }

    return region;
  }

  // Commit written data
  void commit_write(size_t bytes_written) {
    write_pos_.store((write_pos_.load() + bytes_written) & (BufferSize - 1),
                     std::memory_order_release);
    size_.fetch_add(bytes_written, std::memory_order_acq_rel);
  }

  // Zero-copy read interface
  struct ReadRegion {
    const char *data;
    size_t size;
    bool is_contiguous;
    const char *data2;
    size_t size2;
  };

  ReadRegion get_read_region(size_t requested_size) const {
    ReadRegion region{};

    size_t available = size_.load(std::memory_order_acquire);
    if (requested_size > available) {
      requested_size = available;
    }

    size_t read_pos = read_pos_.load(std::memory_order_acquire);
    size_t end_space = BufferSize - read_pos;

    if (requested_size <= end_space) {
      // Contiguous read
      region.data = buffer_.data() + read_pos;
      region.size = requested_size;
      region.is_contiguous = true;
    } else {
      // Split read (wrapping)
      region.data = buffer_.data() + read_pos;
      region.size = end_space;
      region.data2 = buffer_.data();
      region.size2 = requested_size - end_space;
      region.is_contiguous = false;
    }

    return region;
  }

  // Commit read data (mark as consumed)
  void commit_read(size_t bytes_read) {
    read_pos_.store((read_pos_.load() + bytes_read) & (BufferSize - 1),
                    std::memory_order_release);
    size_.fetch_sub(bytes_read, std::memory_order_acq_rel);
  }

  // Utility methods
  size_t available_write_space() const {
    return BufferSize - size_.load(std::memory_order_acquire);
  }

  size_t available_read_data() const {
    return size_.load(std::memory_order_acquire);
  }

  bool is_empty() const { return size_.load(std::memory_order_acquire) == 0; }

  bool is_full() const {
    return size_.load(std::memory_order_acquire) == BufferSize;
  }

  void clear() {
    read_pos_.store(0, std::memory_order_release);
    write_pos_.store(0, std::memory_order_release);
    size_.store(0, std::memory_order_release);
  }

private:
  alignas(64) std::array<char, BufferSize> buffer_; // Cache-line aligned
  std::atomic<size_t> read_pos_;
  std::atomic<size_t> write_pos_;
  std::atomic<size_t> size_;
};

/**
 * @brief Memory pool for HTTP response buffers and temporary allocations
 *
 * Reduces allocation overhead for frequently created/destroyed buffers.
 */
class BufferPool : public memory::IMemoryManaged {
public:
  struct PooledBuffer {
    std::vector<char> data;
    size_t used_size;

    PooledBuffer(size_t capacity = 4096) : used_size(0) {
      data.reserve(capacity);
    }

    void reset() {
      used_size = 0;
      // Don't shrink, just reset size
    }

    char *get_data() { return data.data(); }
    size_t capacity() const { return data.capacity(); }
    size_t size() const { return used_size; }

    void resize(size_t new_size) {
      if (new_size > data.capacity()) {
        data.reserve(new_size);
      }
      used_size = new_size;
    }
  };

  explicit BufferPool(size_t pool_size = 100, size_t buffer_capacity = 4096)
      : pool_size_(pool_size), buffer_capacity_(buffer_capacity) {

    // Pre-allocate buffers
    for (size_t i = 0; i < pool_size; ++i) {
      available_buffers_.emplace_back(
          std::make_unique<PooledBuffer>(buffer_capacity));
    }
  }

  // RAII buffer acquisition
  class BufferHandle {
  public:
    BufferHandle(std::unique_ptr<PooledBuffer> buffer, BufferPool *pool)
        : buffer_(std::move(buffer)), pool_(pool) {}

    ~BufferHandle() {
      if (buffer_ && pool_) {
        pool_->return_buffer(std::move(buffer_));
      }
    }

    // Move-only
    BufferHandle(const BufferHandle &) = delete;
    BufferHandle &operator=(const BufferHandle &) = delete;

    BufferHandle(BufferHandle &&other) noexcept
        : buffer_(std::move(other.buffer_)), pool_(other.pool_) {
      other.pool_ = nullptr;
    }

    BufferHandle &operator=(BufferHandle &&other) noexcept {
      if (this != &other) {
        if (buffer_ && pool_) {
          pool_->return_buffer(std::move(buffer_));
        }
        buffer_ = std::move(other.buffer_);
        pool_ = other.pool_;
        other.pool_ = nullptr;
      }
      return *this;
    }

    PooledBuffer *operator->() { return buffer_.get(); }
    PooledBuffer &operator*() { return *buffer_; }
    PooledBuffer *get() { return buffer_.get(); }

    explicit operator bool() const { return buffer_ != nullptr; }

  private:
    std::unique_ptr<PooledBuffer> buffer_;
    BufferPool *pool_;
  };

  BufferHandle acquire_buffer() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!available_buffers_.empty()) {
      auto buffer = std::move(available_buffers_.back());
      available_buffers_.pop_back();
      buffer->reset();
      return BufferHandle(std::move(buffer), this);
    }

    // Pool exhausted, create new buffer
    ++total_allocated_;
    return BufferHandle(std::make_unique<PooledBuffer>(buffer_capacity_), this);
  }

  void return_buffer(std::unique_ptr<PooledBuffer> buffer) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (available_buffers_.size() < pool_size_) {
      buffer->reset();
      available_buffers_.push_back(std::move(buffer));
    }
    // Otherwise let it be destroyed (pool is full)
  }

  // Statistics
  size_t get_pool_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return available_buffers_.size();
  }

  size_t get_total_allocated() const { return total_allocated_.load(); }

  // memory::IMemoryManaged interface
  size_t get_memory_usage() const override {
    std::lock_guard<std::mutex> lock(mutex_);
    return available_buffers_.size() * buffer_capacity_ + sizeof(*this);
  }

  size_t compact() override {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t freed = 0;

    // Shrink buffers to actual usage
    for (auto &buffer : available_buffers_) {
      size_t old_capacity = buffer->data.capacity();
      buffer->data.shrink_to_fit();
      freed += old_capacity - buffer->data.capacity();
    }

    return freed;
  }

  void on_memory_pressure(size_t pressure_level) override {
    std::lock_guard<std::mutex> lock(mutex_);

    // Reduce pool size under memory pressure
    size_t reduction = (pressure_level * available_buffers_.size()) / 4;
    if (reduction > 0 && reduction < available_buffers_.size()) {
      available_buffers_.resize(available_buffers_.size() - reduction);
    }
  }

  bool can_evict() const override { return true; }
  std::string get_component_name() const override { return "BufferPool"; }
  int get_priority() const override { return 7; } // Medium-low priority

private:
  std::vector<std::unique_ptr<PooledBuffer>> available_buffers_;
  size_t pool_size_;
  size_t buffer_capacity_;
  std::atomic<size_t> total_allocated_{0};
  mutable std::mutex mutex_;
};

/**
 * @brief Zero-copy log line parser with string interning
 *
 * Optimized for high-throughput log processing without string allocations.
 */
class ZeroCopyLogParser {
public:
  struct ParsedLogLine {
    std::string_view timestamp;
    std::string_view ip_address;
    std::string_view method;
    std::string_view path;
    std::string_view user_agent;
    std::string_view status_code;
    std::string_view bytes_sent;

    // Interned versions for storage
    memory::StringInternPool::InternID ip_id = 0;
    memory::StringInternPool::InternID path_id = 0;
    memory::StringInternPool::InternID user_agent_id = 0;

    bool is_valid = false;
  };

  // Parse a log line without copying strings (works on raw buffer data)
  ParsedLogLine parse_line(std::string_view line_data) {
    ParsedLogLine result{};

    // Fast path: check if line looks like valid log format
    if (line_data.size() < 50 || line_data[0] == '#') {
      return result; // Invalid or comment line
    }

    // Use fixed-field parsing for performance (assuming Apache Common Log
    // Format)
    size_t pos = 0;

    // Parse IP address (first field)
    size_t space_pos = line_data.find(' ', pos);
    if (space_pos == std::string_view::npos)
      return result;
    result.ip_address = line_data.substr(pos, space_pos - pos);
    pos = space_pos + 1;

    // Skip identd and userid fields (usually "-")
    for (int i = 0; i < 2; ++i) {
      space_pos = line_data.find(' ', pos);
      if (space_pos == std::string_view::npos)
        return result;
      pos = space_pos + 1;
    }

    // Parse timestamp [dd/MMM/yyyy:HH:mm:ss +0000]
    if (pos >= line_data.size() || line_data[pos] != '[')
      return result;
    size_t timestamp_end = line_data.find(']', pos);
    if (timestamp_end == std::string_view::npos)
      return result;
    result.timestamp = line_data.substr(pos + 1, timestamp_end - pos - 1);
    pos = timestamp_end + 2; // Skip "] "

    // Parse request "METHOD /path HTTP/1.1"
    if (pos >= line_data.size() || line_data[pos] != '"')
      return result;
    size_t request_end = line_data.find('"', pos + 1);
    if (request_end == std::string_view::npos)
      return result;

    std::string_view request = line_data.substr(pos + 1, request_end - pos - 1);
    parse_request_line(request, result);
    pos = request_end + 2; // Skip '" '

    // Parse status code
    space_pos = line_data.find(' ', pos);
    if (space_pos == std::string_view::npos)
      return result;
    result.status_code = line_data.substr(pos, space_pos - pos);
    pos = space_pos + 1;

    // Parse bytes sent
    space_pos = line_data.find(' ', pos);
    if (space_pos == std::string_view::npos) {
      // Last field, might not have trailing space
      result.bytes_sent = line_data.substr(pos);
    } else {
      result.bytes_sent = line_data.substr(pos, space_pos - pos);
      pos = space_pos + 1;
    }

    // Parse user agent (if present)
    if (pos < line_data.size()) {
      // Skip referrer field
      if (line_data[pos] == '"') {
        size_t ref_end = line_data.find('"', pos + 1);
        if (ref_end != std::string_view::npos) {
          pos = ref_end + 3; // Skip '" "'

          // Parse user agent
          if (pos < line_data.size() && line_data[pos] == '"') {
            size_t ua_end = line_data.find('"', pos + 1);
            if (ua_end != std::string_view::npos) {
              result.user_agent = line_data.substr(pos + 1, ua_end - pos - 1);
            }
          }
        }
      }
    }

    // Intern frequently used strings
    if (!result.ip_address.empty()) {
      result.ip_id = memory::intern_string(result.ip_address);
    }
    if (!result.path.empty()) {
      result.path_id = memory::intern_string(result.path);
    }
    if (!result.user_agent.empty()) {
      result.user_agent_id = memory::intern_string(result.user_agent);
    }

    result.is_valid = true;
    return result;
  }

private:
  void parse_request_line(std::string_view request, ParsedLogLine &result) {
    // Parse "METHOD /path HTTP/1.1"
    size_t first_space = request.find(' ');
    if (first_space == std::string_view::npos)
      return;

    result.method = request.substr(0, first_space);

    size_t second_space = request.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) {
      // No HTTP version, just method and path
      result.path = request.substr(first_space + 1);
    } else {
      result.path =
          request.substr(first_space + 1, second_space - first_space - 1);
    }
  }
};

/**
 * @brief Global buffer pool instances for different use cases
 */
class GlobalBufferManager {
public:
  static GlobalBufferManager &instance() {
    static GlobalBufferManager instance_;
    return instance_;
  }

  // Different pools for different buffer sizes
  BufferPool &get_small_buffer_pool() {
    return small_buffer_pool_;
  } // 4KB buffers
  BufferPool &get_medium_buffer_pool() {
    return medium_buffer_pool_;
  } // 64KB buffers
  BufferPool &get_large_buffer_pool() {
    return large_buffer_pool_;
  } // 1MB buffers

  // HTTP response buffer pool
  BufferPool &get_http_response_pool() { return http_response_pool_; }

  // Log parsing buffer pool
  BufferPool &get_log_buffer_pool() { return log_buffer_pool_; }

private:
  GlobalBufferManager()
      : small_buffer_pool_(200, 4 * 1024) // 200 × 4KB = 800KB
        ,
        medium_buffer_pool_(50, 64 * 1024) // 50 × 64KB = 3.2MB
        ,
        large_buffer_pool_(10, 1024 * 1024) // 10 × 1MB = 10MB
        ,
        http_response_pool_(100, 8 * 1024) // 100 × 8KB = 800KB
        ,
        log_buffer_pool_(50, 16 * 1024) // 50 × 16KB = 800KB
  {}

  BufferPool small_buffer_pool_;
  BufferPool medium_buffer_pool_;
  BufferPool large_buffer_pool_;
  BufferPool http_response_pool_;
  BufferPool log_buffer_pool_;
};

// Convenience functions
inline BufferPool::BufferHandle acquire_small_buffer() {
  return GlobalBufferManager::instance()
      .get_small_buffer_pool()
      .acquire_buffer();
}

inline BufferPool::BufferHandle acquire_medium_buffer() {
  return GlobalBufferManager::instance()
      .get_medium_buffer_pool()
      .acquire_buffer();
}

inline BufferPool::BufferHandle acquire_large_buffer() {
  return GlobalBufferManager::instance()
      .get_large_buffer_pool()
      .acquire_buffer();
}

inline BufferPool::BufferHandle acquire_http_response_buffer() {
  return GlobalBufferManager::instance()
      .get_http_response_pool()
      .acquire_buffer();
}

inline BufferPool::BufferHandle acquire_log_buffer() {
  return GlobalBufferManager::instance().get_log_buffer_pool().acquire_buffer();
}

} // namespace optimized_io

#endif // OPTIMIZED_IO_BUFFER_MANAGER_HPP

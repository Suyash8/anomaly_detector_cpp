#ifndef OPTIMIZED_FILE_LOG_READER_HPP
#define OPTIMIZED_FILE_LOG_READER_HPP

#include "../../core/memory_manager.hpp"
#include "../../utils/optimized_io_buffer_manager.hpp"
#include "base_log_reader.hpp"
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <regex>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace anomaly_detector {

// Memory-mapped file reader for high-performance log processing
class OptimizedFileLogReader : public ILogReader,
                               public memory::IMemoryManaged {
private:
  struct MemoryMappedFile {
    int fd = -1;
    void *mapped_memory = nullptr;
    size_t file_size = 0;

    ~MemoryMappedFile() { cleanup(); }

    void cleanup() {
      if (mapped_memory && mapped_memory != MAP_FAILED) {
        munmap(mapped_memory, file_size);
        mapped_memory = nullptr;
      }
      if (fd != -1) {
        close(fd);
        fd = -1;
      }
    }

    bool map_file(const std::string &filepath) {
      cleanup();

      fd = open(filepath.c_str(), O_RDONLY);
      if (fd == -1) {
        return false;
      }

      struct stat st;
      if (fstat(fd, &st) == -1) {
        close(fd);
        fd = -1;
        return false;
      }

      file_size = st.st_size;
      if (file_size == 0) {
        // Empty file, but not an error
        return true;
      }

      mapped_memory = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
      if (mapped_memory == MAP_FAILED) {
        close(fd);
        fd = -1;
        mapped_memory = nullptr;
        return false;
      }

      // Advise kernel about access pattern
      madvise(mapped_memory, file_size, MADV_SEQUENTIAL);

      return true;
    }
  };

  MemoryMappedFile mapped_file_;
  const char *current_pos_;
  const char *end_pos_;
  uint64_t line_number_;
  std::string filepath_;

  // Fallback for non-mappable files or streaming
  std::unique_ptr<std::ifstream> fallback_stream_;
  bool use_fallback_;

  // Line parsing cache and optimization
  static constexpr size_t BATCH_SIZE = 2048;
  static constexpr size_t MAX_LINE_LENGTH = 8192;

  // Compiled regex cache for log parsing
  struct RegexCache {
    std::regex compiled_regex;
    bool is_valid = false;
  };

  mutable std::unordered_map<std::string, RegexCache> regex_cache_;

  // Buffer for line processing
  std::vector<char> line_buffer_;

  // Performance optimizations
  struct ParsedLineCache {
    std::vector<LogEntry> cached_entries;
    size_t cache_hits = 0;
    size_t cache_misses = 0;
  };

  mutable ParsedLineCache parse_cache_;

  // Fast line finding using SIMD-like operations
  const char *find_next_line(const char *start) const {
    const char *pos = start;
    while (pos < end_pos_ && *pos != '\n') {
      // Vectorized search for newline could be added here
      pos++;
    }
    return (pos < end_pos_) ? pos + 1 : end_pos_;
  }

  // Extract line without allocation for most cases
  std::string_view extract_line(const char *start, const char *end) const {
    return std::string_view(start, end - start - 1); // -1 to skip \n
  }

  bool initialize_memory_mapping() {
    if (mapped_file_.map_file(filepath_)) {
      current_pos_ = static_cast<const char *>(mapped_file_.mapped_memory);
      end_pos_ = current_pos_ + mapped_file_.file_size;
      use_fallback_ = false;
      return true;
    }

    // Fall back to traditional file I/O
    fallback_stream_ = std::make_unique<std::ifstream>(filepath_);
    use_fallback_ = !fallback_stream_->is_open();
    return !use_fallback_;
  }

  std::vector<LogEntry> read_batch_memory_mapped() {
    std::vector<LogEntry> batch;
    batch.reserve(BATCH_SIZE);

    while (batch.size() < BATCH_SIZE && current_pos_ < end_pos_) {
      const char *line_start = current_pos_;
      const char *line_end = find_next_line(current_pos_);

      if (line_end > line_start) {
        std::string_view line_view = extract_line(line_start, line_end);

        if (!line_view.empty()) {
          line_number_++;

          // Parse the line - could be optimized further with custom parsing
          std::string line_str(line_view);
          if (auto entry_opt = LogEntry::parse_from_string(
                  std::move(line_str), line_number_, false)) {
            batch.push_back(*entry_opt);
          }
        }
      }

      current_pos_ = line_end;
    }

    return batch;
  }

  std::vector<LogEntry> read_batch_fallback() {
    std::vector<LogEntry> batch;
    batch.reserve(BATCH_SIZE);

    if (!fallback_stream_ || !fallback_stream_->is_open()) {
      return batch;
    }

    std::string line;
    while (batch.size() < BATCH_SIZE && std::getline(*fallback_stream_, line)) {
      if (!line.empty()) {
        line_number_++;
        if (auto entry_opt = LogEntry::parse_from_string(std::move(line),
                                                         line_number_, false)) {
          batch.push_back(*entry_opt);
        }
      }
    }

    // Handle EOF for live monitoring
    if (fallback_stream_->eof()) {
      fallback_stream_->clear();
    }

    return batch;
  }

public:
  explicit OptimizedFileLogReader(const std::string &filepath)
      : filepath_(filepath), current_pos_(nullptr), end_pos_(nullptr),
        line_number_(0), use_fallback_(false) {

    line_buffer_.reserve(MAX_LINE_LENGTH);

    if (!initialize_memory_mapping()) {
      throw std::runtime_error("Failed to open log file: " + filepath);
    }

    // Register with memory manager
    if (auto *mem_mgr = memory::MemoryManager::get_instance()) {
      mem_mgr->register_component(
          std::static_pointer_cast<memory::IMemoryManaged>(
              std::shared_ptr<OptimizedFileLogReader>(
                  this, [](OptimizedFileLogReader *) {})));
    }
  }

  ~OptimizedFileLogReader() override { mapped_file_.cleanup(); }

  std::vector<LogEntry> get_next_batch() override {
    if (use_fallback_) {
      return read_batch_fallback();
    } else {
      return read_batch_memory_mapped();
    }
  }

  bool is_open() const {
    if (use_fallback_) {
      return fallback_stream_ && fallback_stream_->is_open();
    }
    return mapped_file_.mapped_memory != nullptr || mapped_file_.file_size == 0;
  }

  // Additional optimized methods
  size_t get_file_size() const { return mapped_file_.file_size; }

  double get_progress() const {
    if (use_fallback_ || mapped_file_.file_size == 0) {
      return 0.0;
    }
    size_t bytes_read =
        current_pos_ - static_cast<const char *>(mapped_file_.mapped_memory);
    return static_cast<double>(bytes_read) / mapped_file_.file_size;
  }

  void prefetch_next_chunk(size_t chunk_size = 64 * 1024) {
    if (!use_fallback_ && current_pos_ &&
        current_pos_ + chunk_size <= end_pos_) {
// Prefetch next chunk into CPU cache
#ifdef __builtin_prefetch
      __builtin_prefetch(current_pos_, 0,
                         1); // Read hint, low temporal locality
#endif
    }
  }

  // Performance statistics
  struct Statistics {
    size_t total_lines_read = 0;
    size_t total_bytes_read = 0;
    size_t cache_hits = 0;
    size_t cache_misses = 0;
    double avg_line_length = 0.0;
  };

  Statistics get_statistics() const {
    Statistics stats;
    stats.total_lines_read = line_number_;
    stats.total_bytes_read =
        use_fallback_ ? 0
                      : (current_pos_ -
                         static_cast<const char *>(mapped_file_.mapped_memory));
    stats.cache_hits = parse_cache_.cache_hits;
    stats.cache_misses = parse_cache_.cache_misses;
    stats.avg_line_length = stats.total_lines_read > 0
                                ? static_cast<double>(stats.total_bytes_read) /
                                      stats.total_lines_read
                                : 0.0;
    return stats;
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    size_t usage = sizeof(*this);
    usage += line_buffer_.capacity();
    usage += parse_cache_.cached_entries.capacity() * sizeof(LogEntry);
    usage += regex_cache_.size() * (sizeof(std::string) + sizeof(RegexCache));

    if (use_fallback_ && fallback_stream_) {
      usage += sizeof(std::ifstream);
    } else {
      usage += mapped_file_.file_size; // Memory mapped area
    }

    return usage;
  }

  size_t compact() override {
    size_t freed = 0;

    // Clear parsing caches
    parse_cache_.cached_entries.clear();
    parse_cache_.cached_entries.shrink_to_fit();
    freed += parse_cache_.cached_entries.capacity() * sizeof(LogEntry);

    // Clear regex cache
    regex_cache_.clear();
    freed += regex_cache_.size() * (sizeof(std::string) + sizeof(RegexCache));

    return freed;
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 2) {
      // Clear caches under medium pressure
      parse_cache_.cached_entries.clear();
      if (pressure_level >= 3) {
        regex_cache_.clear();
        line_buffer_.shrink_to_fit();
      }
    }
  }

  bool can_evict() const override {
    return false; // File readers are typically not evictable during active use
  }

  std::string get_component_name() const override {
    return "OptimizedFileLogReader";
  }

  int get_priority() const override {
    return 2; // High priority - I/O components are critical
  }
};

} // namespace anomaly_detector

#endif // OPTIMIZED_FILE_LOG_READER_HPP

#ifndef BATCH_PROCESSOR_HPP
#define BATCH_PROCESSOR_HPP

#include "analysis/analyzed_event.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "core/resource_pool_manager.hpp"
#include <algorithm>
#include <chrono>
#include <functional>
#include <future>
#include <thread>
#include <vector>

namespace resource {

// Performance metrics for batch processing
struct BatchProcessingMetrics {
  std::chrono::duration<double> total_processing_time{0};
  std::chrono::duration<double> allocation_time{0};
  std::chrono::duration<double> processing_time{0};
  std::chrono::duration<double> cleanup_time{0};
  size_t total_batches_processed = 0;
  size_t total_items_processed = 0;
  size_t average_batch_size = 0;
  double items_per_second = 0.0;

  void update_rates() {
    if (total_processing_time.count() > 0) {
      items_per_second = total_items_processed / total_processing_time.count();
    }
    if (total_batches_processed > 0) {
      average_batch_size = total_items_processed / total_batches_processed;
    }
  }
};

// Configuration for batch processing behavior
struct BatchProcessingConfig {
  size_t optimal_batch_size = 100;
  size_t max_batch_size = 1000;
  size_t min_batch_size = 10;
  std::chrono::milliseconds max_wait_time{
      50}; // Max time to wait for batch to fill
  bool enable_parallel_processing = true;
  size_t thread_pool_size = std::thread::hardware_concurrency();
  bool enable_memory_optimization = true;
  bool enable_profiling = false;
};

// High-performance batch processor for log entries
class BatchProcessor {
public:
  explicit BatchProcessor(
      ResourcePoolManager &pool_manager,
      const BatchProcessingConfig &config = BatchProcessingConfig{})
      : pool_manager_(pool_manager), config_(config) {

    LOG(LogLevel::INFO, LogComponent::MEMORY,
        "BatchProcessor initialized with batch_size: "
            << config_.optimal_batch_size
            << ", parallel: " << config_.enable_parallel_processing
            << ", threads: " << config_.thread_pool_size);
  }

  // Process a batch of raw log lines into AnalyzedEvents
  template <typename InputContainer, typename ProcessorFunc>
  void process_log_batch(const InputContainer &raw_log_lines,
                         ProcessorFunc &&processor) {
    auto start_time = std::chrono::high_resolution_clock::now();

    // Phase 1: Parse log entries (with pooling)
    auto parse_start = std::chrono::high_resolution_clock::now();
    std::vector<PooledObject<LogEntry>> log_entries;
    log_entries.reserve(raw_log_lines.size());

    for (const auto &raw_line : raw_log_lines) {
      auto pooled_entry = pool_manager_.acquire_log_entry();
      if (auto parsed =
              LogEntry::parse_from_string(std::string(raw_line), 0, false)) {
        *pooled_entry = std::move(*parsed);
        log_entries.emplace_back(std::move(pooled_entry));
      }
    }
    auto parse_end = std::chrono::high_resolution_clock::now();

    // Phase 2: Create AnalyzedEvents (with pooling)
    auto analysis_start = std::chrono::high_resolution_clock::now();
    std::vector<PooledObject<AnalyzedEvent>> analyzed_events;
    analyzed_events.reserve(log_entries.size());

    for (const auto &log_entry : log_entries) {
      analyzed_events.emplace_back(
          pool_manager_.acquire_analyzed_event(*log_entry));
    }
    auto analysis_end = std::chrono::high_resolution_clock::now();

    // Phase 3: Process in parallel if enabled
    auto process_start = std::chrono::high_resolution_clock::now();
    if (config_.enable_parallel_processing &&
        analyzed_events.size() > config_.min_batch_size) {
      process_parallel(analyzed_events, std::forward<ProcessorFunc>(processor));
    } else {
      process_sequential(analyzed_events,
                         std::forward<ProcessorFunc>(processor));
    }
    auto process_end = std::chrono::high_resolution_clock::now();

    // Update metrics
    auto total_time = process_end - start_time;
    metrics_.total_processing_time += total_time;
    metrics_.allocation_time += (analysis_end - parse_start);
    metrics_.processing_time += (process_end - process_start);
    metrics_.total_batches_processed++;
    metrics_.total_items_processed += analyzed_events.size();
    metrics_.update_rates();

    if (config_.enable_profiling) {
      LOG(LogLevel::DEBUG, LogComponent::MEMORY,
          "Batch processed: {} items in {:.2f}ms (parse: {:.2f}ms, analysis: "
          "{:.2f}ms, process: {:.2f}ms)",
          analyzed_events.size(), total_time.count() * 1000.0,
          (parse_end - parse_start).count() * 1000.0,
          (analysis_end - analysis_start).count() * 1000.0,
          (process_end - process_start).count() * 1000.0);
    }

    // Memory pressure handling
    if (config_.enable_memory_optimization) {
      pool_manager_.handle_memory_pressure();
    }
  }

  // Process pre-parsed LogEntries
  template <typename ProcessorFunc>
  void process_analyzed_events(std::vector<PooledObject<AnalyzedEvent>> &events,
                               ProcessorFunc &&processor) {
    auto start_time = std::chrono::high_resolution_clock::now();

    if (config_.enable_parallel_processing &&
        events.size() > config_.min_batch_size) {
      process_parallel(events, std::forward<ProcessorFunc>(processor));
    } else {
      process_sequential(events, std::forward<ProcessorFunc>(processor));
    }

    auto total_time = std::chrono::high_resolution_clock::now() - start_time;
    metrics_.processing_time += total_time;
    metrics_.total_items_processed += events.size();
    metrics_.update_rates();
  }

  // Adaptive batch sizing based on performance
  size_t get_optimal_batch_size() const {
    if (metrics_.items_per_second > 1000.0) {
      // High throughput, increase batch size
      return std::min(config_.max_batch_size, config_.optimal_batch_size * 2);
    } else if (metrics_.items_per_second < 100.0) {
      // Low throughput, decrease batch size
      return std::max(config_.min_batch_size, config_.optimal_batch_size / 2);
    }
    return config_.optimal_batch_size;
  }

  const BatchProcessingMetrics &get_metrics() const { return metrics_; }

  void reset_metrics() { metrics_ = BatchProcessingMetrics{}; }

  void update_config(const BatchProcessingConfig &new_config) {
    config_ = new_config;
    LOG(LogLevel::INFO, LogComponent::MEMORY,
        "BatchProcessor config updated: batch_size={}, parallel={}",
        config_.optimal_batch_size, config_.enable_parallel_processing);
  }

private:
  template <typename ProcessorFunc>
  void process_sequential(std::vector<PooledObject<AnalyzedEvent>> &events,
                          ProcessorFunc &&processor) {
    for (auto &event : events) {
      processor(std::move(event));
    }
  }

  template <typename ProcessorFunc>
  void process_parallel(std::vector<PooledObject<AnalyzedEvent>> &events,
                        ProcessorFunc &&processor) {
    const size_t num_threads =
        std::min(config_.thread_pool_size, events.size());
    const size_t items_per_thread = events.size() / num_threads;

    std::vector<std::future<void>> futures;
    futures.reserve(num_threads);

    for (size_t i = 0; i < num_threads; ++i) {
      size_t start_idx = i * items_per_thread;
      size_t end_idx =
          (i == num_threads - 1) ? events.size() : (i + 1) * items_per_thread;

      futures.emplace_back(
          std::async(std::launch::async, [&, start_idx, end_idx]() {
            for (size_t j = start_idx; j < end_idx; ++j) {
              processor(std::move(events[j]));
            }
          }));
    }

    // Wait for all threads to complete
    for (auto &future : futures) {
      future.wait();
    }
  }

  ResourcePoolManager &pool_manager_;
  BatchProcessingConfig config_;
  BatchProcessingMetrics metrics_;
};

// Streaming batch collector that accumulates items and processes when threshold
// is reached
template <typename ItemType> class StreamingBatchCollector {
public:
  StreamingBatchCollector(
      BatchProcessor &processor,
      std::function<void(std::vector<PooledObject<AnalyzedEvent>> &)>
          batch_handler,
      size_t batch_size = 100)
      : processor_(processor), batch_handler_(std::move(batch_handler)),
        target_batch_size_(batch_size) {

    batch_.reserve(batch_size);
  }

  void add_item(ItemType &&item) {
    std::lock_guard<std::mutex> lock(mutex_);
    batch_.emplace_back(std::forward<ItemType>(item));

    if (batch_.size() >= target_batch_size_) {
      flush_batch_locked();
    }
  }

  void flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!batch_.empty()) {
      flush_batch_locked();
    }
  }

  size_t pending_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return batch_.size();
  }

private:
  void flush_batch_locked() {
    if (!batch_.empty()) {
      batch_handler_(batch_);
      batch_.clear();
    }
  }

  BatchProcessor &processor_;
  std::function<void(std::vector<PooledObject<AnalyzedEvent>> &)>
      batch_handler_;
  size_t target_batch_size_;
  std::vector<ItemType> batch_;
  mutable std::mutex mutex_;
};

} // namespace resource

#endif // BATCH_PROCESSOR_HPP

#ifndef ADVANCED_THREADING_HPP
#define ADVANCED_THREADING_HPP

#include <array>
#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

namespace memory::threading {

/**
 * Lock-free single-producer, single-consumer queue
 * Extremely fast for one-to-one communication
 */
template <typename T, size_t Capacity = 1024> class SPSCQueue {
private:
  static_assert((Capacity & (Capacity - 1)) == 0,
                "Capacity must be power of 2");

  alignas(64) std::array<T, Capacity> buffer_;
  alignas(64) std::atomic<size_t> head_{0}; // Consumer index
  alignas(64) std::atomic<size_t> tail_{0}; // Producer index

  static constexpr size_t mask_ = Capacity - 1;

public:
  /**
   * Non-blocking enqueue (producer side)
   */
  bool try_enqueue(const T &item) {
    const size_t current_tail = tail_.load(std::memory_order_relaxed);
    const size_t next_tail = (current_tail + 1) & mask_;

    if (next_tail == head_.load(std::memory_order_acquire)) {
      return false; // Queue is full
    }

    buffer_[current_tail] = item;
    tail_.store(next_tail, std::memory_order_release);
    return true;
  }

  /**
   * Non-blocking enqueue with move semantics
   */
  bool try_enqueue(T &&item) {
    const size_t current_tail = tail_.load(std::memory_order_relaxed);
    const size_t next_tail = (current_tail + 1) & mask_;

    if (next_tail == head_.load(std::memory_order_acquire)) {
      return false; // Queue is full
    }

    buffer_[current_tail] = std::move(item);
    tail_.store(next_tail, std::memory_order_release);
    return true;
  }

  /**
   * Non-blocking dequeue (consumer side)
   */
  bool try_dequeue(T &item) {
    const size_t current_head = head_.load(std::memory_order_relaxed);

    if (current_head == tail_.load(std::memory_order_acquire)) {
      return false; // Queue is empty
    }

    item = std::move(buffer_[current_head]);
    head_.store((current_head + 1) & mask_, std::memory_order_release);
    return true;
  }

  /**
   * Check if queue is empty
   */
  bool empty() const {
    return head_.load(std::memory_order_acquire) ==
           tail_.load(std::memory_order_acquire);
  }

  /**
   * Get approximate size
   */
  size_t size() const {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    return (tail - head) & mask_;
  }
};

/**
 * Work-stealing queue for thread pool implementations
 */
template <typename T> class WorkStealingQueue {
private:
  std::deque<T> queue_;
  mutable std::mutex mutex_;

public:
  WorkStealingQueue() = default;

  // Non-copyable, non-movable
  WorkStealingQueue(const WorkStealingQueue &) = delete;
  WorkStealingQueue &operator=(const WorkStealingQueue &) = delete;

  /**
   * Push work item (owner thread)
   */
  void push(T item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push_front(std::move(item));
  }

  /**
   * Try to pop work item from front (owner thread)
   */
  bool try_pop(T &item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return false;
    }

    item = std::move(queue_.front());
    queue_.pop_front();
    return true;
  }

  /**
   * Try to steal work item from back (other threads)
   */
  bool try_steal(T &item) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return false;
    }

    item = std::move(queue_.back());
    queue_.pop_back();
    return true;
  }

  /**
   * Check if queue is empty
   */
  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

  /**
   * Get queue size
   */
  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }
};

/**
 * Thread affinity manager for CPU-specific binding
 */
class ThreadAffinityManager {
private:
  static constexpr unsigned MAX_CPUS = 256;
  std::vector<unsigned> available_cpus_;
  std::atomic<unsigned> next_cpu_{0};

public:
  ThreadAffinityManager() { discover_available_cpus(); }

  /**
   * Bind current thread to specific CPU
   */
  bool bind_to_cpu(unsigned cpu_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) ==
           0;
#else
    return false; // Not supported on this platform
#endif
  }

  /**
   * Bind current thread to next available CPU (round-robin)
   */
  bool bind_to_next_cpu() {
    if (available_cpus_.empty()) {
      return false;
    }

    unsigned index = next_cpu_.fetch_add(1, std::memory_order_relaxed) %
                     available_cpus_.size();
    return bind_to_cpu(available_cpus_[index]);
  }

  /**
   * Get number of available CPUs
   */
  size_t cpu_count() const { return available_cpus_.size(); }

  /**
   * Get list of available CPU IDs
   */
  const std::vector<unsigned> &get_available_cpus() const {
    return available_cpus_;
  }

private:
  void discover_available_cpus() {
#ifdef __linux__
    cpu_set_t cpuset;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &cpuset) == 0) {
      for (unsigned i = 0; i < MAX_CPUS; ++i) {
        if (CPU_ISSET(i, &cpuset)) {
          available_cpus_.push_back(i);
        }
      }
    }
#else
    // Fallback - assume all logical CPUs are available
    unsigned cpu_count = std::thread::hardware_concurrency();
    for (unsigned i = 0; i < cpu_count; ++i) {
      available_cpus_.push_back(i);
    }
#endif
  }
};

/**
 * Double-buffered state manager
 * Allows lock-free reading while writing to alternate buffer
 */
template <typename T> class DoubleBufferedState {
private:
  alignas(64) std::array<T, 2> buffers_;
  alignas(64) std::atomic<unsigned> active_buffer_{0};
  std::mutex write_mutex_;

public:
  DoubleBufferedState() = default;

  explicit DoubleBufferedState(const T &initial_state) {
    buffers_[0] = initial_state;
    buffers_[1] = initial_state;
  }

  /**
   * Get current state for reading (lock-free)
   */
  const T &read() const {
    return buffers_[active_buffer_.load(std::memory_order_acquire)];
  }

  /**
   * Update state (blocking for writes, non-blocking for reads)
   */
  template <typename UpdateFunc> void update(UpdateFunc &&func) {
    std::lock_guard<std::mutex> lock(write_mutex_);

    const unsigned current = active_buffer_.load(std::memory_order_relaxed);
    const unsigned next = 1 - current;

    // Update inactive buffer
    if constexpr (std::is_copy_assignable_v<T>) {
      buffers_[next] = buffers_[current];
    }
    func(buffers_[next]);

    // Atomically switch active buffer
    active_buffer_.store(next, std::memory_order_release);
  }

  /**
   * Set new state
   */
  void set(const T &new_state) {
    update([&new_state](T &state) { state = new_state; });
  }

  /**
   * Set new state with move semantics
   */
  void set(T &&new_state) {
    update([&new_state](T &state) { state = std::move(new_state); });
  }
};

/**
 * High-performance circular buffer for streaming data
 */
template <typename T, size_t Capacity = 4096> class CircularBuffer {
private:
  static_assert((Capacity & (Capacity - 1)) == 0,
                "Capacity must be power of 2");

  alignas(64) std::array<T, Capacity> buffer_;
  alignas(64) std::atomic<size_t> write_pos_{0};
  alignas(64) std::atomic<size_t> read_pos_{0};

  static constexpr size_t mask_ = Capacity - 1;

public:
  /**
   * Write data to buffer (producer)
   */
  bool write(const T &item) {
    const size_t current_write = write_pos_.load(std::memory_order_relaxed);
    const size_t next_write = (current_write + 1) & mask_;

    if (next_write == read_pos_.load(std::memory_order_acquire)) {
      return false; // Buffer full
    }

    buffer_[current_write] = item;
    write_pos_.store(next_write, std::memory_order_release);
    return true;
  }

  /**
   * Read data from buffer (consumer)
   */
  bool read(T &item) {
    const size_t current_read = read_pos_.load(std::memory_order_relaxed);

    if (current_read == write_pos_.load(std::memory_order_acquire)) {
      return false; // Buffer empty
    }

    item = buffer_[current_read];
    read_pos_.store((current_read + 1) & mask_, std::memory_order_release);
    return true;
  }

  /**
   * Batch write operation
   */
  size_t write_batch(const T *items, size_t count) {
    size_t written = 0;
    const size_t read_pos = read_pos_.load(std::memory_order_acquire);
    size_t write_pos = write_pos_.load(std::memory_order_relaxed);

    for (size_t i = 0; i < count; ++i) {
      const size_t next_write = (write_pos + 1) & mask_;
      if (next_write == read_pos) {
        break; // Buffer full
      }

      buffer_[write_pos] = items[i];
      write_pos = next_write;
      ++written;
    }

    if (written > 0) {
      write_pos_.store(write_pos, std::memory_order_release);
    }

    return written;
  }

  /**
   * Batch read operation
   */
  size_t read_batch(T *items, size_t max_count) {
    size_t read_count = 0;
    const size_t write_pos = write_pos_.load(std::memory_order_acquire);
    size_t read_pos = read_pos_.load(std::memory_order_relaxed);

    for (size_t i = 0; i < max_count; ++i) {
      if (read_pos == write_pos) {
        break; // Buffer empty
      }

      items[i] = buffer_[read_pos];
      read_pos = (read_pos + 1) & mask_;
      ++read_count;
    }

    if (read_count > 0) {
      read_pos_.store(read_pos, std::memory_order_release);
    }

    return read_count;
  }

  /**
   * Get available space for writing
   */
  size_t available_write() const {
    const size_t write_pos = write_pos_.load(std::memory_order_acquire);
    const size_t read_pos = read_pos_.load(std::memory_order_acquire);
    return (read_pos - write_pos - 1) & mask_;
  }

  /**
   * Get available data for reading
   */
  size_t available_read() const {
    const size_t write_pos = write_pos_.load(std::memory_order_acquire);
    const size_t read_pos = read_pos_.load(std::memory_order_acquire);
    return (write_pos - read_pos) & mask_;
  }
};

} // namespace memory::threading

#endif // ADVANCED_THREADING_HPP

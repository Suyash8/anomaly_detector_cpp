#ifndef OPTIMIZED_THREAD_SAFE_QUEUE_HPP
#define OPTIMIZED_THREAD_SAFE_QUEUE_HPP

#include "../core/memory_manager.hpp"
#include <array>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

namespace anomaly_detector {

// Lock-free single-producer-single-consumer queue for high performance
// scenarios
template <typename T, size_t Capacity = 4096>
class LockFreeSPSCQueue : public memory::IMemoryManaged {
private:
  struct alignas(64) Node {
    std::atomic<T *> data{nullptr};
    char padding[64 - sizeof(std::atomic<T *>)]; // Cache line padding
  };

  static constexpr size_t CAPACITY = Capacity;
  static_assert((CAPACITY & (CAPACITY - 1)) == 0,
                "Capacity must be power of 2");

  std::array<Node, CAPACITY> buffer_;
  alignas(64) std::atomic<size_t> write_index_{0};
  alignas(64) std::atomic<size_t> read_index_{0};
  alignas(64) std::atomic<bool> shutdown_{false};

  // Memory pool for T objects to avoid frequent allocation
  std::array<T, CAPACITY> object_pool_;
  std::atomic<size_t> pool_index_{0};

public:
  LockFreeSPSCQueue() = default;

  ~LockFreeSPSCQueue() {
    shutdown();
    // Clean up any remaining items
    while (auto item = try_pop()) {
      // Items automatically cleaned up
    }
  }

  // Producer side - lock-free push
  bool push(T &&value) {
    if (shutdown_.load(std::memory_order_acquire)) {
      return false;
    }

    const size_t write_idx = write_index_.load(std::memory_order_relaxed);
    const size_t next_write = (write_idx + 1) & (CAPACITY - 1);

    // Check if queue is full
    if (next_write == read_index_.load(std::memory_order_acquire)) {
      return false; // Queue full
    }

    // Get object from pool
    size_t pool_idx =
        pool_index_.fetch_add(1, std::memory_order_relaxed) & (CAPACITY - 1);
    object_pool_[pool_idx] = std::move(value);

    // Store pointer to the object
    buffer_[write_idx].data.store(&object_pool_[pool_idx],
                                  std::memory_order_release);
    write_index_.store(next_write, std::memory_order_release);

    return true;
  }

  // Consumer side - lock-free pop
  std::optional<T> try_pop() {
    const size_t read_idx = read_index_.load(std::memory_order_relaxed);

    if (read_idx == write_index_.load(std::memory_order_acquire)) {
      return std::nullopt; // Queue empty
    }

    T *data_ptr = buffer_[read_idx].data.load(std::memory_order_acquire);
    if (!data_ptr) {
      return std::nullopt;
    }

    T result = std::move(*data_ptr);
    buffer_[read_idx].data.store(nullptr, std::memory_order_release);
    read_index_.store((read_idx + 1) & (CAPACITY - 1),
                      std::memory_order_release);

    return result;
  }

  void shutdown() { shutdown_.store(true, std::memory_order_release); }

  bool is_shutdown() const { return shutdown_.load(std::memory_order_acquire); }

  size_t size() const {
    const size_t write_idx = write_index_.load(std::memory_order_acquire);
    const size_t read_idx = read_index_.load(std::memory_order_acquire);
    return (write_idx - read_idx) & (CAPACITY - 1);
  }

  bool empty() const {
    return read_index_.load(std::memory_order_acquire) ==
           write_index_.load(std::memory_order_acquire);
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    return sizeof(*this) + (sizeof(T) * CAPACITY) + (sizeof(Node) * CAPACITY);
  }

  size_t compact() override {
    // Lock-free queue can't be compacted without breaking lock-free guarantees
    return 0;
  }

  void on_memory_pressure(size_t pressure_level) override {
    // For lock-free queues, we can only signal shutdown under extreme pressure
    if (pressure_level >= 4) { // Critical pressure
      shutdown();
    }
  }

  bool can_evict() const override { return empty() && is_shutdown(); }

  std::string get_component_name() const override {
    return "LockFreeSPSCQueue";
  }

  int get_priority() const override {
    return 1; // High priority - critical infrastructure
  }
};

// Lock-free multi-producer-single-consumer queue using hazard pointers
template <typename T, size_t Capacity = 4096>
class LockFreeMPSCQueue : public memory::IMemoryManaged {
private:
  struct Node {
    std::atomic<T *> data{nullptr};
    std::atomic<Node *> next{nullptr};

    Node() = default;
    Node(T *d) : data(d) {}
  };

  alignas(64) std::atomic<Node *> head_{nullptr};
  alignas(64) std::atomic<Node *> tail_{nullptr};
  alignas(64) std::atomic<bool> shutdown_{false};

  // Node pool for memory efficiency
  std::array<Node, Capacity> node_pool_;
  std::atomic<size_t> node_pool_index_{0};

  // Object pool for T instances
  std::array<T, Capacity> object_pool_;
  std::atomic<size_t> object_pool_index_{0};

  Node *allocate_node() {
    size_t idx =
        node_pool_index_.fetch_add(1, std::memory_order_relaxed) % Capacity;
    return &node_pool_[idx];
  }

  T *allocate_object() {
    size_t idx =
        object_pool_index_.fetch_add(1, std::memory_order_relaxed) % Capacity;
    return &object_pool_[idx];
  }

public:
  LockFreeMPSCQueue() {
    Node *dummy = allocate_node();
    head_.store(dummy, std::memory_order_relaxed);
    tail_.store(dummy, std::memory_order_relaxed);
  }

  ~LockFreeMPSCQueue() {
    shutdown();
    while (auto item = try_pop()) {
      // Clean up remaining items
    }
  }

  // Multi-producer push
  bool push(T &&value) {
    if (shutdown_.load(std::memory_order_acquire)) {
      return false;
    }

    T *obj = allocate_object();
    *obj = std::move(value);

    Node *new_node = allocate_node();
    new_node->data.store(obj, std::memory_order_relaxed);
    new_node->next.store(nullptr, std::memory_order_relaxed);

    Node *prev_tail = tail_.exchange(new_node, std::memory_order_acq_rel);
    prev_tail->next.store(new_node, std::memory_order_release);

    return true;
  }

  // Single-consumer pop
  std::optional<T> try_pop() {
    Node *head = head_.load(std::memory_order_relaxed);
    Node *next = head->next.load(std::memory_order_acquire);

    if (!next) {
      return std::nullopt; // Queue empty
    }

    T *data = next->data.load(std::memory_order_relaxed);
    if (!data) {
      return std::nullopt;
    }

    T result = std::move(*data);
    head_.store(next, std::memory_order_release);

    return result;
  }

  void shutdown() { shutdown_.store(true, std::memory_order_release); }

  bool is_shutdown() const { return shutdown_.load(std::memory_order_acquire); }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    return sizeof(*this) + (sizeof(Node) * Capacity) + (sizeof(T) * Capacity);
  }

  size_t compact() override {
    return 0; // Cannot compact lock-free structures safely
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 4) {
      shutdown();
    }
  }

  bool can_evict() const override { return is_shutdown(); }

  std::string get_component_name() const override {
    return "LockFreeMPSCQueue";
  }

  int get_priority() const override {
    return 1; // High priority
  }
};

// Optimized blocking queue with better performance characteristics
template <typename T>
class OptimizedThreadSafeQueue : public memory::IMemoryManaged {
private:
  mutable std::mutex mutex_;
  std::queue<T> queue_;
  std::condition_variable cond_;
  std::atomic<bool> shutdown_requested_{false};

  // Pre-allocated batch processing
  static constexpr size_t BATCH_SIZE = 32;
  std::array<T, BATCH_SIZE> batch_buffer_;

public:
  OptimizedThreadSafeQueue() = default;

  ~OptimizedThreadSafeQueue() { shutdown(); }

  void push(T value) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      queue_.push(std::move(value));
    }
    cond_.notify_one();
  }

  // Batch push for better throughput
  template <typename Iterator> void push_batch(Iterator begin, Iterator end) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto it = begin; it != end; ++it) {
        queue_.push(std::move(*it));
      }
    }
    cond_.notify_all();
  }

  std::optional<T> wait_and_pop() {
    std::unique_lock<std::mutex> lock(mutex_);
    cond_.wait(lock, [this] {
      return !queue_.empty() ||
             shutdown_requested_.load(std::memory_order_acquire);
    });

    if (shutdown_requested_.load(std::memory_order_acquire) && queue_.empty()) {
      return std::nullopt;
    }

    T value = std::move(queue_.front());
    queue_.pop();
    return value;
  }

  std::optional<T> try_pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return std::nullopt;
    }

    T value = std::move(queue_.front());
    queue_.pop();
    return value;
  }

  // Batch pop for better throughput
  size_t try_pop_batch(T *output, size_t max_items) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t popped = 0;

    while (popped < max_items && !queue_.empty()) {
      output[popped] = std::move(queue_.front());
      queue_.pop();
      ++popped;
    }

    return popped;
  }

  void shutdown() {
    shutdown_requested_.store(true, std::memory_order_release);
    cond_.notify_all();
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

  // IMemoryManaged interface
  size_t get_memory_usage() const override {
    std::lock_guard<std::mutex> lock(mutex_);
    return sizeof(*this) + (queue_.size() * sizeof(T));
  }

  size_t compact() override {
    // Cannot compact std::queue efficiently
    return 0;
  }

  void on_memory_pressure(size_t pressure_level) override {
    if (pressure_level >= 3) {
      // Clear queue under high memory pressure
      std::lock_guard<std::mutex> lock(mutex_);
      std::queue<T> empty_queue;
      queue_.swap(empty_queue);
    }
  }

  bool can_evict() const override { return empty(); }

  std::string get_component_name() const override {
    return "OptimizedThreadSafeQueue";
  }

  int get_priority() const override {
    return 2; // Medium-high priority
  }
};

} // namespace anomaly_detector

#endif // OPTIMIZED_THREAD_SAFE_QUEUE_HPP

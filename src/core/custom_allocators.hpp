#ifndef CUSTOM_ALLOCATORS_HPP
#define CUSTOM_ALLOCATORS_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#ifdef __linux__
#include <numa.h>
#include <numaif.h>
#include <sched.h>
#endif

namespace memory {

/**
 * Slab allocator for fixed-size objects
 * Provides O(1) allocation/deallocation with excellent cache locality
 */
template <typename T, size_t SlabSize = 4096> class SlabAllocator {
private:
  struct Slab {
    alignas(T) uint8_t data[SlabSize];
    std::atomic<size_t> free_count{SlabSize / sizeof(T)};
    std::atomic<void *> free_list{nullptr};
    std::atomic<Slab *> next{nullptr};

    Slab() {
      // Initialize free list
      size_t object_count = SlabSize / sizeof(T);
      void **current = reinterpret_cast<void **>(data);

      for (size_t i = 0; i < object_count - 1; ++i) {
        void *next_ptr = reinterpret_cast<uint8_t *>(current) + sizeof(T);
        *current = next_ptr;
        current = reinterpret_cast<void **>(next_ptr);
      }
      *current = nullptr; // Last element
      free_list.store(data, std::memory_order_release);
    }
  };

  std::atomic<Slab *> current_slab_{nullptr};
  std::atomic<Slab *> slab_list_{nullptr};
  std::mutex allocation_mutex_;

  static constexpr size_t objects_per_slab = SlabSize / sizeof(T);

public:
  SlabAllocator() { allocate_new_slab(); }

  ~SlabAllocator() {
    Slab *slab = slab_list_.load();
    while (slab) {
      Slab *next = slab->next.load();
      delete slab;
      slab = next;
    }
  }

  /**
   * Allocate a single object
   */
  T *allocate() {
    Slab *slab = current_slab_.load(std::memory_order_acquire);

    while (slab) {
      void *free_ptr = slab->free_list.load(std::memory_order_acquire);

      if (free_ptr) {
        void *next_free = *reinterpret_cast<void **>(free_ptr);

        if (slab->free_list.compare_exchange_weak(free_ptr, next_free,
                                                  std::memory_order_acq_rel,
                                                  std::memory_order_relaxed)) {

          slab->free_count.fetch_sub(1, std::memory_order_relaxed);
          return reinterpret_cast<T *>(free_ptr);
        }
        continue; // Retry on CAS failure
      }

      // Current slab is full, try to allocate new one
      if (allocate_new_slab()) {
        slab = current_slab_.load(std::memory_order_acquire);
        continue;
      }

      return nullptr; // Out of memory
    }

    return nullptr;
  }

  /**
   * Deallocate a single object
   */
  void deallocate(T *ptr) {
    if (!ptr)
      return;

    // Find which slab this pointer belongs to
    Slab *slab = find_slab_for_pointer(ptr);
    if (!slab)
      return;

    // Add to free list
    void *old_head = slab->free_list.load(std::memory_order_relaxed);
    do {
      *reinterpret_cast<void **>(ptr) = old_head;
    } while (!slab->free_list.compare_exchange_weak(
        old_head, ptr, std::memory_order_release, std::memory_order_relaxed));

    slab->free_count.fetch_add(1, std::memory_order_relaxed);
  }

  /**
   * Get memory usage statistics
   */
  struct Stats {
    size_t total_slabs;
    size_t total_objects;
    size_t free_objects;
    size_t memory_usage;
  };

  Stats get_stats() const {
    Stats stats{0, 0, 0, 0};

    Slab *slab = slab_list_.load();
    while (slab) {
      stats.total_slabs++;
      stats.total_objects += objects_per_slab;
      stats.free_objects += slab->free_count.load();
      stats.memory_usage += SlabSize;
      slab = slab->next.load();
    }

    return stats;
  }

private:
  bool allocate_new_slab() {
    std::lock_guard<std::mutex> lock(allocation_mutex_);

    try {
      Slab *new_slab = new Slab();

      // Add to slab list
      new_slab->next.store(slab_list_.load());
      slab_list_.store(new_slab);

      // Update current slab
      current_slab_.store(new_slab);

      return true;
    } catch (const std::bad_alloc &) {
      return false;
    }
  }

  Slab *find_slab_for_pointer(T *ptr) {
    Slab *slab = slab_list_.load();
    const uint8_t *byte_ptr = reinterpret_cast<const uint8_t *>(ptr);

    while (slab) {
      const uint8_t *slab_start = slab->data;
      const uint8_t *slab_end = slab_start + SlabSize;

      if (byte_ptr >= slab_start && byte_ptr < slab_end) {
        return slab;
      }

      slab = slab->next.load();
    }

    return nullptr;
  }
};

/**
 * Bump allocator for temporary calculations
 * Extremely fast allocation with bulk deallocation
 */
class BumpAllocator {
private:
  uint8_t *memory_;
  size_t size_;
  std::atomic<size_t> offset_{0};

public:
  explicit BumpAllocator(size_t size) : size_(size) {
    memory_ = static_cast<uint8_t *>(std::aligned_alloc(64, size));
    if (!memory_) {
      throw std::bad_alloc();
    }
  }

  ~BumpAllocator() { std::free(memory_); }

  /**
   * Allocate memory with specified alignment
   */
  void *allocate(size_t bytes, size_t alignment = 8) {
    size_t current_offset = offset_.load(std::memory_order_relaxed);
    size_t aligned_offset = (current_offset + alignment - 1) & ~(alignment - 1);
    size_t new_offset = aligned_offset + bytes;

    if (new_offset > size_) {
      return nullptr; // Out of space
    }

    while (!offset_.compare_exchange_weak(current_offset, new_offset,
                                          std::memory_order_acq_rel,
                                          std::memory_order_relaxed)) {

      aligned_offset = (current_offset + alignment - 1) & ~(alignment - 1);
      new_offset = aligned_offset + bytes;

      if (new_offset > size_) {
        return nullptr;
      }
    }

    return memory_ + aligned_offset;
  }

  /**
   * Reset allocator (bulk deallocation)
   */
  void reset() { offset_.store(0, std::memory_order_release); }

  /**
   * Get current usage
   */
  size_t bytes_used() const { return offset_.load(std::memory_order_acquire); }

  /**
   * Get remaining space
   */
  size_t bytes_remaining() const { return size_ - bytes_used(); }

  /**
   * Check if pointer belongs to this allocator
   */
  bool owns(void *ptr) const {
    const uint8_t *byte_ptr = static_cast<const uint8_t *>(ptr);
    return byte_ptr >= memory_ && byte_ptr < memory_ + size_;
  }
};

} // namespace memory

#endif // CUSTOM_ALLOCATORS_HPP

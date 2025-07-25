#include "utils/advanced_threading.hpp"
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

using namespace memory::threading;

class AdvancedThreadingTest : public ::testing::Test {
protected:
  void SetUp() override {}
  void TearDown() override {}
};

// Test SPSC Queue functionality
TEST_F(AdvancedThreadingTest, SPSCQueueBasicOperations) {
  SPSCQueue<int, 16> queue;

  // Test enqueue
  EXPECT_TRUE(queue.try_enqueue(42));
  EXPECT_TRUE(queue.try_enqueue(100));

  // Test dequeue
  int value;
  EXPECT_TRUE(queue.try_dequeue(value));
  EXPECT_EQ(value, 42);

  EXPECT_TRUE(queue.try_dequeue(value));
  EXPECT_EQ(value, 100);

  // Queue should be empty now
  EXPECT_FALSE(queue.try_dequeue(value));
}

TEST_F(AdvancedThreadingTest, SPSCQueueConcurrency) {
  SPSCQueue<int, 1024> queue;
  std::atomic<int> produced{0};
  std::atomic<int> consumed{0};
  const int total_items = 10000;

  // Producer thread
  std::thread producer([&]() {
    for (int i = 0; i < total_items; ++i) {
      while (!queue.try_enqueue(i)) {
        std::this_thread::yield();
      }
      produced++;
    }
  });

  // Consumer thread
  std::thread consumer([&]() {
    int value;
    while (consumed < total_items) {
      if (queue.try_dequeue(value)) {
        EXPECT_EQ(value, consumed.load());
        consumed++;
      } else {
        std::this_thread::yield();
      }
    }
  });

  producer.join();
  consumer.join();

  EXPECT_EQ(produced.load(), total_items);
  EXPECT_EQ(consumed.load(), total_items);
}

// Test Work Stealing Queue
TEST_F(AdvancedThreadingTest, WorkStealingQueueBasicOperations) {
  WorkStealingQueue<std::function<void()>> queue;

  std::atomic<int> counter{0};
  auto task = [&counter]() { counter++; };

  // Test push and pop
  queue.push(task);

  std::function<void()> stolen_task;
  EXPECT_TRUE(queue.try_steal(stolen_task));
  stolen_task();

  EXPECT_EQ(counter.load(), 1);
}

// Test Circular Buffer
TEST_F(AdvancedThreadingTest, CircularBufferOperations) {
  CircularBuffer<int, 8> buffer;

  // Test write and read
  EXPECT_TRUE(buffer.write(42));
  EXPECT_TRUE(buffer.write(100));

  int value;
  EXPECT_TRUE(buffer.read(value));
  EXPECT_EQ(value, 42);

  EXPECT_TRUE(buffer.read(value));
  EXPECT_EQ(value, 100);

  // Buffer should be empty
  EXPECT_FALSE(buffer.read(value));
}

TEST_F(AdvancedThreadingTest, CircularBufferWraparound) {
  CircularBuffer<int, 8> buffer;

  // Fill the buffer (capacity - 1 due to full/empty distinction)
  for (int i = 0; i < 7; ++i) {
    EXPECT_TRUE(buffer.write(i));
  }

  // Buffer should be full
  EXPECT_FALSE(buffer.write(999));

  // Read one item
  int value;
  EXPECT_TRUE(buffer.read(value));
  EXPECT_EQ(value, 0);

  // Now we should be able to write one more
  EXPECT_TRUE(buffer.write(999));

  // Read remaining items
  for (int i = 1; i < 7; ++i) {
    EXPECT_TRUE(buffer.read(value));
    EXPECT_EQ(value, i);
  }

  EXPECT_TRUE(buffer.read(value));
  EXPECT_EQ(value, 999);
}

// Test Double Buffered State
TEST_F(AdvancedThreadingTest, DoubleBufferedStateOperations) {
  DoubleBufferedState<std::string> state;

  // Test write and read
  state.set("Hello World");

  const std::string &result = state.read();
  EXPECT_EQ(result, "Hello World");
}

TEST_F(AdvancedThreadingTest, DoubleBufferedStateConcurrency) {
  DoubleBufferedState<std::atomic<int>> state;
  std::atomic<bool> stop{false};

  // Writer thread
  std::thread writer([&]() {
    int counter = 0;
    while (!stop.load()) {
      state.update(
          [&counter](std::atomic<int> &atom) { atom.store(++counter); });
      std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
  });

  // Reader thread
  std::thread reader([&]() {
    int last_value = 0;
    for (int i = 0; i < 100; ++i) {
      const auto &atom = state.read();
      int current_value = atom.load();
      EXPECT_GE(current_value, last_value);
      last_value = current_value;
      std::this_thread::sleep_for(std::chrono::microseconds(15));
    }
  });

  reader.join();
  stop = true;
  writer.join();
}

// Test Thread Affinity Manager (Linux-specific)
#ifdef __linux__
TEST_F(AdvancedThreadingTest, ThreadAffinityManagerBasic) {
  ThreadAffinityManager affinity_mgr;

  // Should be able to get CPU count
  EXPECT_GT(affinity_mgr.cpu_count(), 0);

  // Should be able to get available CPUs
  const auto &cpus = affinity_mgr.get_available_cpus();
  EXPECT_FALSE(cpus.empty());
}
#endif

// Performance test to demonstrate lock-free benefits
TEST_F(AdvancedThreadingTest, PerformanceComparison) {
  const int iterations = 100000;

  // Test SPSC queue performance
  auto start = std::chrono::high_resolution_clock::now();
  {
    SPSCQueue<int, 1024> queue;
    std::atomic<bool> done{false};

    std::thread producer([&]() {
      for (int i = 0; i < iterations; ++i) {
        while (!queue.try_enqueue(i)) {
          std::this_thread::yield();
        }
      }
      done = true;
    });

    std::thread consumer([&]() {
      int consumed = 0;
      int value;
      while (consumed < iterations || !done.load()) {
        if (queue.try_dequeue(value)) {
          consumed++;
        }
      }
    });

    producer.join();
    consumer.join();
  }
  auto end = std::chrono::high_resolution_clock::now();
  auto spsc_duration =
      std::chrono::duration_cast<std::chrono::microseconds>(end - start);

  // The test passes if we complete without deadlock
  EXPECT_GT(spsc_duration.count(), 0);
}

#ifndef THREAD_SAFE_QUEUE_HPP
#define THREAD_SAFE_QUEUE_HPP

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

template <typename T> class ThreadSafeQueue {
public:
  void push(T value) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(std::move(value));
    cond_.notify_one();
  }

  // A non-blocking try_pop
  std::optional<T> try_pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty())
      return std::nullopt;
    T value = std::move(queue_.front());
    queue_.pop();
    return value;
  }

  // A blocking wait_and_pop that returns false on shutdown
  bool wait_and_pop(T &value) {
    std::unique_lock<std::mutex> lock(mutex_);
    cond_.wait(lock, [this] { return !queue_.empty() || shutdown_requested_; });
    if (shutdown_requested_ && queue_.empty())
      return false;

    value = std::move(queue_.front());
    queue_.pop();
    return true;
  }

  // Notify all waiting threads to wake up for shutdown
  void shutdown() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      shutdown_requested_ = true;
    }
    cond_.notify_all();
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
  }

private:
  mutable std::mutex mutex_;
  std::queue<T> queue_;
  std::condition_variable cond_;
  bool shutdown_requested_ = false;
};

#endif // THREAD_SAFE_QUEUE_HPP
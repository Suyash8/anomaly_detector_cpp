#ifndef SLIDING_WINDOW_HPP
#define SLIDING_WINDOW_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>
template <typename ValueType> class SlidingWindow {
public:
  SlidingWindow(uint64_t duration_ms, size_t max_elements_limit = 0)
      : configured_duration_ms(duration_ms),
        configured_max_elements(max_elements_limit) {};

  void add_event(uint64_t event_timestamp_ms, const ValueType &value) {
    // Always add, then prune. This ensures the current event is considered.
    window_data.emplace_back(event_timestamp_ms, value);
    prune_old_events(event_timestamp_ms);
  }

  void add_event(uint64_t event_timestamp_ms, ValueType &&value) {
    window_data.emplace_back(event_timestamp_ms, std::move(value));
    prune_old_events(event_timestamp_ms);
  }

  // Remove events that are older than the window duration relative to
  // 'current_time_ms'
  // Also enforces max_elements if set
  void prune_old_events(uint64_t current_time_ms) {
    // 1. Time based pruning
    if (configured_duration_ms > 0) {
      // Calculate the cutoff: events strictly older than this are removed
      // T_event must be >= (current_time_ms - configured_duration_ms)
      // So, remove if T_event < (current_time_ms - configured_duration_ms)
      uint64_t cutoff_timestamp = 0;
      if (current_time_ms >= configured_duration_ms) // Avoid underflow
        cutoff_timestamp = current_time_ms - configured_duration_ms;

      // Else, cutoff_timestamp is 0, meaning if current_time_ms is small, no
      // time-based pruning happens yet, which is fine.

      while (!window_data.empty() &&
             window_data.front().first < cutoff_timestamp)
        window_data.pop_front();
    }

    // 2. Size based pruning
    if (configured_max_elements > 0)
      while (window_data.size() > configured_max_elements)
        window_data.pop_front();
  }

  size_t get_event_count() const { return window_data.size(); }

  bool is_empty() const { return window_data.size(); }

  std::vector<ValueType> get_all_values_in_window() const {
    std::vector<ValueType> values;
    values.reserve(window_data.size());
    for (const auto &pair : window_data)
      values.push_back(pair.second);
    return values;
  }

  const std::deque<std::pair<uint64_t, ValueType>> &
  get_raw_window_data() const {
    return window_data;
  }

  void reconfigure(uint64_t new_duration_ms, size_t new_max_elements = 0) {
    configured_duration_ms = new_duration_ms;
    configured_max_elements = new_max_elements;
  }

private:
  std::deque<std::pair<uint64_t, ValueType>> window_data;
  uint64_t configured_duration_ms;
  size_t configured_max_elements; // 0 means no limit
};

#endif // SLIDING_WINDOW_HPP
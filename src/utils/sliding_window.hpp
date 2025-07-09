#ifndef SLIDING_WINDOW_HPP
#define SLIDING_WINDOW_HPP

#include "utils.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

template <typename ValueType> class SlidingWindow {
public:
  SlidingWindow(uint64_t duration_ms, size_t max_elements_limit = 0)
      : configured_duration_ms(duration_ms),
        configured_max_elements(max_elements_limit) {};

  void add_event(uint64_t event_timestamp_ms, const ValueType &value) {
    window_data.emplace_back(event_timestamp_ms, value);
  }

  void add_event(uint64_t event_timestamp_ms, ValueType &&value) {
    window_data.emplace_back(event_timestamp_ms, std::move(value));
  }

  void prune_old_events(uint64_t current_time_ms) {
    // 1. Time based pruning
    if (configured_duration_ms > 0 && !window_data.empty()) {
      uint64_t cutoff_timestamp = 0;
      // Avoid underflow if current_time_ms is less than the duration
      if (current_time_ms >= configured_duration_ms)
        cutoff_timestamp = current_time_ms - configured_duration_ms;

      auto first_to_keep = std::lower_bound(
          window_data.begin(), window_data.end(), cutoff_timestamp,
          [](const std::pair<uint64_t, ValueType> &element, uint64_t time) {
            return element.first < time;
          });

      window_data.erase(window_data.begin(), first_to_keep);
    }

    // 2. Size based pruning
    if (configured_max_elements > 0)
      while (window_data.size() > configured_max_elements)
        window_data.pop_front();
  }

  size_t get_event_count() const { return window_data.size(); }

  bool is_empty() const { return window_data.empty(); }

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

  void save(std::ofstream &out) const {
    size_t size = window_data.size();
    out.write(reinterpret_cast<const char *>(&size), sizeof(size));

    for (const auto &pair : window_data) {
      out.write(reinterpret_cast<const char *>(&pair.first),
                sizeof(pair.first));

      if constexpr (std::is_same_v<ValueType, std::string>)
        Utils::save_string(out, pair.second);
      else
        out.write(reinterpret_cast<const char *>(&pair.second),
                  sizeof(pair.second));
    }
  }

  void load(std::ifstream &in) {
    window_data.clear();
    size_t size = 0;
    in.read(reinterpret_cast<char *>(&size), sizeof(size));

    for (size_t i = 0; i < size; ++i) {
      uint64_t timestamp;
      ValueType value;

      in.read(reinterpret_cast<char *>(&timestamp), sizeof(timestamp));

      if constexpr (std::is_same_v<ValueType, std::string>)
        value = Utils::load_string(in);
      else
        in.read(reinterpret_cast<char *>(&value), sizeof(value));

      window_data.emplace_back(timestamp, std::move(value));
    }
  }

private:
  std::deque<std::pair<uint64_t, ValueType>> window_data;
  uint64_t configured_duration_ms;
  size_t configured_max_elements; // 0 means no limit
};

#endif // SLIDING_WINDOW_HPP
#include "../src/state/state_serializer.hpp"

#include <cassert>
#include <cmath>
#include <iostream>

void assert_stats_equal(const StatsTracker &s1, const StatsTracker &s2,
                        const std::string &name) {
  assert(s1.get_count() == s2.get_count());
  assert(std::abs(s1.get_mean() - s2.get_mean()) < 1e-9);
  assert(std::abs(s1.get_variance() - s2.get_variance()) < 1e-9);
  std::cout << "OK: StatsTracker '" << name << "' matches." << std::endl;
}

template <typename T>
void assert_windows_equal(const SlidingWindow<T> &w1,
                          const SlidingWindow<T> &w2, const std::string &name) {
  assert(w1.get_event_count() == w2.get_event_count());
  const auto &d1 = w1.get_raw_window_data();
  const auto &d2 = w2.get_raw_window_data();
  assert(d1 == d2);
  std::cout << "OK: SlidingWindow '" << name << "' matches." << std::endl;
}

int main() {
  std::cout << "--- Running Serialization Test ---" << std::endl;

  // 1. Test PerIpState
  std::cout << "\nTesting PerIpState..." << std::endl;
  PerIpState original_ip_state(60000, 60000, 0);
  original_ip_state.last_seen_timestamp_ms = 123456789;
  original_ip_state.ip_first_seen_timestamp_ms = 100000000;
  original_ip_state.request_timestamps_window.add_event(123, 123);
  original_ip_state.paths_seen_by_ip.insert("/index.html");
  original_ip_state.paths_seen_by_ip.insert("/api/data");
  original_ip_state.last_known_user_agent = "Mozilla/5.0";
  original_ip_state.historical_user_agents.insert("Mozilla/5.0");
  original_ip_state.historical_user_agents.insert("Chrome/101");
  original_ip_state.recent_unique_ua_window.add_event(1234, "TestUA/1.0");
  original_ip_state.request_time_tracker.update(0.1);
  original_ip_state.request_time_tracker.update(0.2);
  original_ip_state.bytes_sent_tracker.update(1024);
  original_ip_state.error_rate_tracker.update(1.0);
  original_ip_state.requests_in_window_count_tracker.update(50);

  auto serialized_ip = StateSerializer::serialize(original_ip_state);
  std::cout << "PerIpState serialized to " << serialized_ip.size() << " bytes."
            << std::endl;
  auto deserialized_ip_opt =
      StateSerializer::deserialize_ip_state(serialized_ip);

  assert(deserialized_ip_opt.has_value());
  const auto &new_ip_state = *deserialized_ip_opt;

  assert(original_ip_state.last_seen_timestamp_ms ==
         new_ip_state.last_seen_timestamp_ms);
  std::cout << "OK: last_seen_timestamp_ms matches." << std::endl;
  assert(original_ip_state.ip_first_seen_timestamp_ms ==
         new_ip_state.ip_first_seen_timestamp_ms);
  std::cout << "OK: ip_first_seen_timestamp_ms matches." << std::endl;
  assert(original_ip_state.paths_seen_by_ip == new_ip_state.paths_seen_by_ip);
  std::cout << "OK: paths_seen_by_ip matches." << std::endl;
  assert(original_ip_state.last_known_user_agent ==
         new_ip_state.last_known_user_agent);
  std::cout << "OK: last_known_user_agent matches." << std::endl;
  assert(original_ip_state.historical_user_agents ==
         new_ip_state.historical_user_agents);
  std::cout << "OK: historical_user_agents matches." << std::endl;

  assert_stats_equal(original_ip_state.request_time_tracker,
                     new_ip_state.request_time_tracker,
                     "ip.request_time_tracker");
  assert_stats_equal(original_ip_state.bytes_sent_tracker,
                     new_ip_state.bytes_sent_tracker, "ip.bytes_sent_tracker");
  assert_windows_equal(original_ip_state.request_timestamps_window,
                       new_ip_state.request_timestamps_window,
                       "ip.request_timestamps_window");
  assert_windows_equal(original_ip_state.recent_unique_ua_window,
                       new_ip_state.recent_unique_ua_window,
                       "ip.recent_unique_ua_window");

  // 2. Test PerPathState
  std::cout << "\nTesting PerPathState..." << std::endl;
  PerPathState original_path_state(987654321);
  original_path_state.request_time_tracker.update(0.5);
  original_path_state.request_time_tracker.update(0.6);
  original_path_state.bytes_sent_tracker.update(2048);
  original_path_state.bytes_sent_tracker.update(4096);

  auto serialized_path = StateSerializer::serialize(original_path_state);
  std::cout << "PerPathState serialized to " << serialized_path.size()
            << " bytes." << std::endl;
  auto deserialized_path_opt =
      StateSerializer::deserialize_path_state(serialized_path);

  assert(deserialized_path_opt.has_value());
  const auto &new_path_state = *deserialized_path_opt;

  assert(original_path_state.last_seen_timestamp_ms ==
         new_path_state.last_seen_timestamp_ms);
  std::cout << "OK: path.last_seen_timestamp_ms matches." << std::endl;
  assert_stats_equal(original_path_state.request_time_tracker,
                     new_path_state.request_time_tracker,
                     "path.request_time_tracker");
  assert_stats_equal(original_path_state.bytes_sent_tracker,
                     new_path_state.bytes_sent_tracker,
                     "path.bytes_sent_tracker");

  std::cout << "\n--- Serialization Test Passed! ---" << std::endl;
  return 0;
}
#include "utils/sliding_window.hpp"

#include <gtest/gtest.h>

TEST(SlidingWindowTest, PrunesCorrectly) {
  // Test that pruning correctly removes old items based on timestamp
  SlidingWindow<int> window(1000, 0); // 1-second window

  // Add events inside and outside the future window
  window.add_event(100, 1);
  window.add_event(200, 2);
  window.add_event(1100, 3);
  window.add_event(1200, 4);

  // Current time is 1150ms
  // Cutoff should be 150ms
  // Events at 100 should be pruned
  window.prune_old_events(1150);
  ASSERT_EQ(window.get_event_count(), 3)
      << "Should keep events at 200, 1100, 1200";

  auto raw_data = window.get_raw_window_data();
  ASSERT_EQ(raw_data.front().second,
            2); // Check that the first element is correct

  // Current time is 2100ms
  // Cutoff should be 1100ms
  // Event at 200 should be pruned
  window.prune_old_events(2100);
  ASSERT_EQ(window.get_event_count(), 2) << "Should keep events at 1100, 1200";
  raw_data = window.get_raw_window_data();
  ASSERT_EQ(raw_data.front().second, 3);

  // Current time is 3000ms
  // Cutoff is 2000ms
  // All events should be pruned
  window.prune_old_events(3000);
  ASSERT_EQ(window.get_event_count(), 0);
  ASSERT_TRUE(window.is_empty());
}

TEST(SlidingWindowTest, HandlesEmptyWindow) {
  SlidingWindow<int> window(1000, 0);
  // Pruning an empty window should not crash or cause issues
  ASSERT_NO_THROW(window.prune_old_events(5000));
  ASSERT_EQ(window.get_event_count(), 0);
}
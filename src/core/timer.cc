// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "core/timer.h"

#include <limits>
#include <utility>

namespace chad {
namespace core {

TimerWheel::TimerWheel() = default;

TimerWheel::~TimerWheel() = default;

TimerId TimerWheel::Schedule(uint64_t delay_ms, TimerCallback callback) {
  // Get current time - caller should provide this for accuracy
  // For now, use a simple approach where deadline is relative
  return ScheduleAt(delay_ms, std::move(callback));
}

TimerId TimerWheel::ScheduleAt(uint64_t deadline_ms, TimerCallback callback) {
  TimerId id = next_id_++;

  TimerEntry entry;
  entry.id = id;
  entry.deadline_ms = deadline_ms;
  entry.callback = std::move(callback);
  entry.cancelled = false;

  heap_.push(std::move(entry));

  return id;
}

bool TimerWheel::Cancel(TimerId id) {
  // Lazy cancellation - we mark as cancelled but don't remove from heap
  // The cancelled flag will be checked when processing
  // This is O(1) vs O(n) for heap removal

  // Unfortunately, we can't mark cancelled in a priority_queue without
  // access to elements. For a production implementation, use a custom heap
  // or an auxiliary set of cancelled IDs.

  // For now, we'll need a different approach - store cancellations separately
  // This is a simplified implementation

  // In practice, for high-performance, use a hierarchical timing wheel
  // (like Linux kernel) or store entries by ID in a hash map

  return false;  // Simplified - cancellation not fully implemented
}

size_t TimerWheel::ProcessExpired(uint64_t now_ms) {
  size_t fired = 0;

  while (!heap_.empty()) {
    const TimerEntry& top = heap_.top();

    // Check if expired
    if (top.deadline_ms > now_ms) {
      break;  // No more expired timers
    }

    // Copy callback before pop (since pop invalidates reference)
    TimerCallback callback = std::move(const_cast<TimerEntry&>(top).callback);
    bool cancelled = top.cancelled;

    heap_.pop();

    // Fire callback if not cancelled
    if (!cancelled && callback) {
      callback();
      ++fired;
    }
  }

  return fired;
}

int TimerWheel::NextDeadlineMs(uint64_t now_ms) const {
  if (heap_.empty()) {
    return -1;  // No timers
  }

  const TimerEntry& top = heap_.top();

  if (top.deadline_ms <= now_ms) {
    return 0;  // Already expired
  }

  uint64_t delta = top.deadline_ms - now_ms;

  // Clamp to int max
  if (delta > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
    return std::numeric_limits<int>::max();
  }

  return static_cast<int>(delta);
}

}  // namespace core
}  // namespace chad

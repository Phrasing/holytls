// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_CORE_TIMER_H_
#define CHAD_CORE_TIMER_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <queue>
#include <vector>

namespace chad {
namespace core {

// Timer ID for cancellation
using TimerId = uint64_t;

// Timer callback
using TimerCallback = std::function<void()>;

// Timer entry
struct TimerEntry {
  TimerId id;
  uint64_t deadline_ms;
  TimerCallback callback;
  bool cancelled;

  // For priority queue ordering (min-heap by deadline)
  bool operator>(const TimerEntry& other) const {
    return deadline_ms > other.deadline_ms;
  }
};

// Simple timer wheel for efficient timeout management
// Optimized for the common case of many timeouts with similar durations
class TimerWheel {
 public:
  TimerWheel();
  ~TimerWheel();

  // Non-copyable, non-movable
  TimerWheel(const TimerWheel&) = delete;
  TimerWheel& operator=(const TimerWheel&) = delete;
  TimerWheel(TimerWheel&&) = delete;
  TimerWheel& operator=(TimerWheel&&) = delete;

  // Schedule a one-shot timer
  // Returns timer ID for cancellation
  TimerId Schedule(uint64_t delay_ms, TimerCallback callback);

  // Schedule at absolute time
  TimerId ScheduleAt(uint64_t deadline_ms, TimerCallback callback);

  // Cancel a timer
  // Returns true if timer was found and cancelled
  bool Cancel(TimerId id);

  // Process expired timers
  // Call this periodically with current time
  // Returns number of timers fired
  size_t ProcessExpired(uint64_t now_ms);

  // Get time until next timer fires (for epoll timeout)
  // Returns -1 if no timers, 0 if timer already expired
  int NextDeadlineMs(uint64_t now_ms) const;

  // Number of pending timers (including cancelled)
  size_t Size() const { return heap_.size(); }

  // Check if empty
  bool Empty() const { return heap_.empty(); }

 private:
  TimerId next_id_ = 1;

  // Min-heap ordered by deadline
  std::priority_queue<TimerEntry, std::vector<TimerEntry>,
                      std::greater<TimerEntry>>
      heap_;
};

// RAII timer guard - cancels timer on destruction
class TimerGuard {
 public:
  TimerGuard() : wheel_(nullptr), id_(0) {}
  TimerGuard(TimerWheel* wheel, TimerId id) : wheel_(wheel), id_(id) {}

  ~TimerGuard() { Cancel(); }

  // Move-only
  TimerGuard(TimerGuard&& other) noexcept
      : wheel_(other.wheel_), id_(other.id_) {
    other.wheel_ = nullptr;
    other.id_ = 0;
  }

  TimerGuard& operator=(TimerGuard&& other) noexcept {
    if (this != &other) {
      Cancel();
      wheel_ = other.wheel_;
      id_ = other.id_;
      other.wheel_ = nullptr;
      other.id_ = 0;
    }
    return *this;
  }

  TimerGuard(const TimerGuard&) = delete;
  TimerGuard& operator=(const TimerGuard&) = delete;

  // Cancel the timer
  void Cancel() {
    if (wheel_ != nullptr && id_ != 0) {
      wheel_->Cancel(id_);
      wheel_ = nullptr;
      id_ = 0;
    }
  }

  // Release ownership without cancelling
  TimerId Release() {
    TimerId released = id_;
    wheel_ = nullptr;
    id_ = 0;
    return released;
  }

  // Check if valid
  bool Valid() const { return wheel_ != nullptr && id_ != 0; }

  TimerId id() const { return id_; }

 private:
  TimerWheel* wheel_;
  TimerId id_;
};

}  // namespace core
}  // namespace chad

#endif  // CHAD_CORE_TIMER_H_

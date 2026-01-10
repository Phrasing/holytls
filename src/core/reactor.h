// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_CORE_REACTOR_H_
#define CHAD_CORE_REACTOR_H_

// Include platform.h first for Windows compatibility
#include "util/platform.h"

#include <uv.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "base/types.h"

namespace chad {
namespace core {

// Maximum file descriptors supported (can be adjusted)
inline constexpr size_t kMaxFds = 65536;

// Event types (portable, libuv-compatible)
enum class EventType : uint32_t {
  kNone = 0,
  kRead = UV_READABLE,
  kWrite = UV_WRITABLE,
  kReadWrite = UV_READABLE | UV_WRITABLE,
  kDisconnect = UV_DISCONNECT,
  kPrioritized = UV_PRIORITIZED,
};

// Bitwise operators for EventType
inline EventType operator|(EventType a, EventType b) {
  return static_cast<EventType>(static_cast<uint32_t>(a) |
                                static_cast<uint32_t>(b));
}

inline EventType operator&(EventType a, EventType b) {
  return static_cast<EventType>(static_cast<uint32_t>(a) &
                                static_cast<uint32_t>(b));
}

inline EventType& operator|=(EventType& a, EventType b) {
  a = a | b;
  return a;
}

inline bool HasEvent(EventType events, EventType check) {
  return (static_cast<uint32_t>(events) & static_cast<uint32_t>(check)) != 0;
}

// Event handler interface - connection objects implement this
class EventHandler {
 public:
  virtual ~EventHandler() = default;

  // Called when socket is readable
  virtual void OnReadable() = 0;

  // Called when socket is writable
  virtual void OnWritable() = 0;

  // Called on error or hangup
  virtual void OnError(int error_code) = 0;

  // Called on connection close
  virtual void OnClose() = 0;

  // Get the file descriptor
  virtual int fd() const = 0;
};

// Reactor configuration
struct ReactorConfig {
  int max_events = 1024;          // Hint for max concurrent handlers
  int epoll_timeout_ms = 100;     // Timer resolution (for compatibility)
  bool use_edge_trigger = true;   // Ignored in libuv (uses level-triggered)
};

// Internal poll handle data
struct PollData {
  uv_poll_t handle;
  EventHandler* handler;
  class Reactor* reactor;
};

// Reactor - single-threaded libuv event loop
// Optimized with FdTable for O(1) handler lookup
class Reactor {
 public:
  explicit Reactor(const ReactorConfig& config = {});
  ~Reactor();

  // Non-copyable, non-movable
  Reactor(const Reactor&) = delete;
  Reactor& operator=(const Reactor&) = delete;
  Reactor(Reactor&&) = delete;
  Reactor& operator=(Reactor&&) = delete;

  // Register a handler for events
  bool Add(EventHandler* handler, EventType events);

  // Modify events for an existing handler
  bool Modify(EventHandler* handler, EventType events);

  // Remove handler from reactor
  bool Remove(EventHandler* handler);

  // Check if handler is registered
  bool Contains(int fd) const;

  // Run the event loop
  void Run();          // Run forever until Stop()
  void RunOnce();      // Process events once and return
  void RunFor(int timeout_ms);  // Run for specified duration

  // Stop the event loop
  void Stop();

  // Check if running
  bool running() const { return running_.load(std::memory_order_acquire); }

  // Get current monotonic time in milliseconds (cached per iteration)
  uint64_t now_ms() const { return now_ms_; }

  // Schedule a callback to run on next iteration
  void Post(std::function<void()> callback);

  // Get number of registered handlers
  size_t handler_count() const { return fd_table_.Count(); }

  // Access the underlying loop (for advanced use)
  uv_loop_t* loop() { return loop_; }

 private:
  void UpdateTime();
  void ProcessPostedCallbacks();

  static void OnPollEvent(uv_poll_t* handle, int status, int events);
  static void OnTimerCallback(uv_timer_t* handle);
  static void OnAsyncCallback(uv_async_t* handle);
  static void OnCloseCallback(uv_handle_t* handle);

  uv_loop_t* loop_;
  uv_async_t async_;           // For cross-thread wakeup
  uv_timer_t run_timer_;       // For RunFor()
  ReactorConfig config_;
  std::atomic<bool> running_{false};
  uint64_t now_ms_ = 0;

  // O(1) fd -> PollData lookup (replaces unordered_map)
  FdTable<PollData, kMaxFds> fd_table_;

  // Posted callbacks (thread-safe addition, processed on event loop thread)
  std::mutex posted_mutex_;
  std::vector<std::function<void()>> posted_callbacks_;
  std::vector<std::function<void()>> pending_callbacks_;
  std::atomic<bool> has_posted_{false};
};

}  // namespace core
}  // namespace chad

#endif  // CHAD_CORE_REACTOR_H_

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/core/reactor.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "holytls/memory/slab_allocator.h"

namespace holytls {
namespace core {

namespace {
// Slab allocator for PollData - avoids per-fd heap allocations
memory::SlabAllocator<PollData, 256> g_poll_data_allocator;
}  // namespace

Reactor::Reactor(const ReactorConfig& config) : config_(config) {
  // Allocate and initialize a new event loop
  loop_ = new uv_loop_t;
  if (uv_loop_init(loop_) != 0) {
    delete loop_;
    throw std::runtime_error("Failed to initialize libuv loop");
  }

  // Initialize async handle for cross-thread wakeup
  if (uv_async_init(loop_, &async_, OnAsyncCallback) != 0) {
    uv_loop_close(loop_);
    delete loop_;
    throw std::runtime_error("Failed to initialize async handle");
  }
  async_.data = this;

  // Initialize timer for RunFor()
  if (uv_timer_init(loop_, &run_timer_) != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&async_), nullptr);
    uv_loop_close(loop_);
    delete loop_;
    throw std::runtime_error("Failed to initialize timer");
  }
  run_timer_.data = this;

  // Initialize time
  UpdateTime();
}

Reactor::~Reactor() {
  // Stop and close all poll handles
  for (size_t fd = 0; fd < kMaxFds; ++fd) {
    PollData* poll_data = fd_table_.Get(static_cast<int>(fd));
    if (poll_data) {
      uv_poll_stop(&poll_data->handle);
      uv_close(reinterpret_cast<uv_handle_t*>(&poll_data->handle),
               OnCloseCallback);
    }
  }
  fd_table_.Clear();

  // Stop and close the timer
  uv_timer_stop(&run_timer_);
  uv_close(reinterpret_cast<uv_handle_t*>(&run_timer_), nullptr);

  // Close the async handle
  uv_close(reinterpret_cast<uv_handle_t*>(&async_), nullptr);

  // Run the loop one more time to process close callbacks (including PollData
  // deallocation)
  uv_run(loop_, UV_RUN_DEFAULT);

  // Close and free the loop
  uv_loop_close(loop_);
  delete loop_;
}

bool Reactor::Add(EventHandler* handler, EventType events) {
  if (handler == nullptr || handler->fd() < 0) {
    return false;
  }

  int fd = handler->fd();

  // Check bounds and if already registered
  if (static_cast<size_t>(fd) >= kMaxFds || fd_table_.Contains(fd)) {
    return false;
  }

  // Allocate poll data from slab allocator
  PollData* poll_data = g_poll_data_allocator.Allocate();
  poll_data->handler = handler;
  poll_data->reactor = this;

  // Initialize poll handle
  // Windows requires uv_poll_init_socket() for socket handles
  // Unix uses uv_poll_init() for file descriptors
#ifdef _WIN32
  if (uv_poll_init_socket(loop_, &poll_data->handle, fd) != 0) {
#else
  if (uv_poll_init(loop_, &poll_data->handle, fd) != 0) {
#endif
    g_poll_data_allocator.Deallocate(poll_data);
    return false;
  }
  poll_data->handle.data = poll_data;

  // Start polling
  int uv_events = static_cast<int>(events);
  if (uv_poll_start(&poll_data->handle, uv_events, OnPollEvent) != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&poll_data->handle), nullptr);
    g_poll_data_allocator.Deallocate(poll_data);
    return false;
  }

  fd_table_.Set(fd, poll_data);
  return true;
}

bool Reactor::Modify(EventHandler* handler, EventType events) {
  if (handler == nullptr || handler->fd() < 0) {
    return false;
  }

  int fd = handler->fd();
  PollData* poll_data = fd_table_.Get(fd);
  if (!poll_data) {
    return false;
  }

  // Modify the poll events
  // On Windows, we must stop before re-starting with new events
  // Otherwise event notifications are lost
#ifdef _WIN32
  uv_poll_stop(&poll_data->handle);
#endif
  int uv_events = static_cast<int>(events);
  return uv_poll_start(&poll_data->handle, uv_events, OnPollEvent) == 0;
}

bool Reactor::Remove(EventHandler* handler) {
  if (handler == nullptr || handler->fd() < 0) {
    return false;
  }

  int fd = handler->fd();
  PollData* poll_data = fd_table_.Get(fd);
  if (!poll_data) {
    return false;
  }

  // Stop polling and close the handle
  uv_poll_stop(&poll_data->handle);
  uv_close(reinterpret_cast<uv_handle_t*>(&poll_data->handle), OnCloseCallback);

  fd_table_.Remove(fd);
  // Note: PollData is deallocated in OnCloseCallback after uv_close completes
  return true;
}

bool Reactor::Contains(int fd) const { return fd_table_.Contains(fd); }

void Reactor::Run() {
  running_.store(true, std::memory_order_release);

  while (running_.load(std::memory_order_acquire)) {
    UpdateTime();
    ProcessPostedCallbacks();
    uv_run(loop_, UV_RUN_ONCE);
    UpdateTime();
  }
}

void Reactor::RunOnce() {
  UpdateTime();
  ProcessPostedCallbacks();
  uv_run(loop_, UV_RUN_NOWAIT);
  UpdateTime();
}

void Reactor::RunFor(int timeout_ms) {
  running_.store(true, std::memory_order_release);

  // Start a one-shot timer
  uv_timer_start(&run_timer_, OnTimerCallback,
                 static_cast<uint64_t>(timeout_ms), 0);

  while (running_.load(std::memory_order_acquire)) {
    UpdateTime();
    ProcessPostedCallbacks();
    uv_run(loop_, UV_RUN_ONCE);
    UpdateTime();
  }

  // Stop the timer in case we exited early
  uv_timer_stop(&run_timer_);
}

void Reactor::Stop() {
  running_.store(false, std::memory_order_release);
  // Wake up the loop if it's blocked
  uv_async_send(&async_);
}

void Reactor::Post(std::function<void()> callback) {
  {
    std::lock_guard<std::mutex> lock(posted_mutex_);
    posted_callbacks_.push_back(std::move(callback));
  }
  has_posted_.store(true, std::memory_order_release);
  // Wake up the loop to process the callback
  uv_async_send(&async_);
}

void Reactor::UpdateTime() {
  uv_update_time(loop_);
  now_ms_ = uv_now(loop_);
}

void Reactor::ProcessPostedCallbacks() {
  if (!has_posted_.load(std::memory_order_acquire)) {
    return;
  }

  // Swap under lock, then process without holding lock
  {
    std::lock_guard<std::mutex> lock(posted_mutex_);
    pending_callbacks_.swap(posted_callbacks_);
    posted_callbacks_.clear();
    has_posted_.store(false, std::memory_order_release);
  }

  for (auto& callback : pending_callbacks_) {
    callback();
  }
  pending_callbacks_.clear();
}

void Reactor::OnPollEvent(uv_poll_t* handle, int status, int events) {
  auto* poll_data = static_cast<PollData*>(handle->data);
  if (!poll_data || !poll_data->handler) {
    return;
  }

  EventHandler* handler = poll_data->handler;

  // Handle error
  if (status < 0) {
    handler->OnError(-status);
    return;
  }

  // Handle readable
  if ((events & UV_READABLE) != 0) {
    handler->OnReadable();
  }

  // Handle writable
  if ((events & UV_WRITABLE) != 0) {
    handler->OnWritable();
  }

  // Handle disconnect
  if ((events & UV_DISCONNECT) != 0) {
    handler->OnClose();
  }
}

void Reactor::OnTimerCallback(uv_timer_t* handle) {
  auto* reactor = static_cast<Reactor*>(handle->data);
  if (reactor) {
    reactor->Stop();
  }
}

void Reactor::OnAsyncCallback(uv_async_t* handle) {
  auto* reactor = static_cast<Reactor*>(handle->data);
  if (reactor) {
    reactor->ProcessPostedCallbacks();
  }
}

void Reactor::OnCloseCallback(uv_handle_t* handle) {
  // Deallocate PollData after uv_close completes (must be deferred, not
  // immediate)
  auto* poll_data = static_cast<PollData*>(handle->data);
  if (poll_data) {
    g_poll_data_allocator.Deallocate(poll_data);
  }
}

}  // namespace core
}  // namespace holytls

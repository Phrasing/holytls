// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "core/reactor.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace chad {
namespace core {

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
  // Stop all poll handles
  for (auto& pair : handlers_) {
    uv_poll_stop(&pair.second->handle);
  }
  handlers_.clear();

  // Stop and close the timer
  uv_timer_stop(&run_timer_);
  uv_close(reinterpret_cast<uv_handle_t*>(&run_timer_), nullptr);

  // Close the async handle
  uv_close(reinterpret_cast<uv_handle_t*>(&async_), nullptr);

  // Run the loop one more time to process close callbacks
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

  // Check if already registered
  if (handlers_.find(fd) != handlers_.end()) {
    return false;
  }

  // Create poll data
  auto poll_data = std::make_unique<PollData>();
  poll_data->handler = handler;
  poll_data->reactor = this;

  // Initialize poll handle
  if (uv_poll_init(loop_, &poll_data->handle, fd) != 0) {
    return false;
  }
  poll_data->handle.data = poll_data.get();

  // Start polling
  int uv_events = static_cast<int>(events);
  if (uv_poll_start(&poll_data->handle, uv_events, OnPollEvent) != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&poll_data->handle), nullptr);
    return false;
  }

  handlers_[fd] = std::move(poll_data);
  return true;
}

bool Reactor::Modify(EventHandler* handler, EventType events) {
  if (handler == nullptr || handler->fd() < 0) {
    return false;
  }

  int fd = handler->fd();

  // Check if registered
  auto it = handlers_.find(fd);
  if (it == handlers_.end()) {
    return false;
  }

  // Modify the poll events
  int uv_events = static_cast<int>(events);
  return uv_poll_start(&it->second->handle, uv_events, OnPollEvent) == 0;
}

bool Reactor::Remove(EventHandler* handler) {
  if (handler == nullptr || handler->fd() < 0) {
    return false;
  }

  int fd = handler->fd();

  auto it = handlers_.find(fd);
  if (it == handlers_.end()) {
    return false;
  }

  // Stop polling and close the handle
  uv_poll_stop(&it->second->handle);
  uv_close(reinterpret_cast<uv_handle_t*>(&it->second->handle), OnCloseCallback);

  handlers_.erase(it);
  return true;
}

bool Reactor::Contains(int fd) const {
  return handlers_.find(fd) != handlers_.end();
}

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
  uv_timer_start(&run_timer_, OnTimerCallback, static_cast<uint64_t>(timeout_ms), 0);

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
  posted_callbacks_.push_back(std::move(callback));
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

  // Swap to process callbacks without holding any locks
  pending_callbacks_.swap(posted_callbacks_);
  posted_callbacks_.clear();
  has_posted_.store(false, std::memory_order_release);

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

void Reactor::OnCloseCallback(uv_handle_t* /*handle*/) {
  // Handle is automatically freed when the PollData unique_ptr is destroyed
}

}  // namespace core
}  // namespace chad

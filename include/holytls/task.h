// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TASK_H_
#define HOLYTLS_TASK_H_

#include <coroutine>
#include <cstdlib>
#include <optional>
#include <utility>
#include <variant>

#include "holytls/error.h"

namespace holytls {

// Forward declaration
template <typename T>
class Task;

namespace detail {

// Promise base with common functionality
template <typename T>
struct TaskPromiseBase {
  std::coroutine_handle<> continuation_;

  auto initial_suspend() noexcept { return std::suspend_always{}; }

  // Coroutines should not throw - terminate if they do
  [[noreturn]] void unhandled_exception() noexcept { std::abort(); }
};

// Promise for Task<T> where T is not void
template <typename T>
struct TaskPromise : TaskPromiseBase<T> {
  std::optional<T> value_;

  Task<T> get_return_object() noexcept;

  auto final_suspend() noexcept {
    struct FinalAwaiter {
      bool await_ready() noexcept { return false; }

      std::coroutine_handle<> await_suspend(
          std::coroutine_handle<TaskPromise<T>> h) noexcept {
        if (h.promise().continuation_) {
          return h.promise().continuation_;
        }
        return std::noop_coroutine();
      }

      void await_resume() noexcept {}
    };
    return FinalAwaiter{};
  }

  void return_value(T value) noexcept(std::is_nothrow_move_constructible_v<T>) {
    value_.emplace(std::move(value));
  }

  T& result() & { return *value_; }
  T&& result() && { return std::move(*value_); }
};

// Promise for Task<void>
template <>
struct TaskPromise<void> : TaskPromiseBase<void> {
  Task<void> get_return_object() noexcept;

  auto final_suspend() noexcept {
    struct FinalAwaiter {
      bool await_ready() noexcept { return false; }

      std::coroutine_handle<> await_suspend(
          std::coroutine_handle<TaskPromise<void>> h) noexcept {
        if (h.promise().continuation_) {
          return h.promise().continuation_;
        }
        return std::noop_coroutine();
      }

      void await_resume() noexcept {}
    };
    return FinalAwaiter{};
  }

  void return_void() noexcept {}
  void result() noexcept {}
};

}  // namespace detail

// Task<T> - a coroutine return type representing an async operation
//
// Usage:
//   Task<Response> FetchData() {
//     Response resp = co_await client.GetAsync("https://example.com");
//     co_return resp;
//   }
//
template <typename T = void>
class Task {
 public:
  using promise_type = detail::TaskPromise<T>;
  using handle_type = std::coroutine_handle<promise_type>;

  Task() noexcept : handle_(nullptr) {}

  explicit Task(handle_type h) noexcept : handle_(h) {}

  Task(Task&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }

  Task& operator=(Task&& other) noexcept {
    if (this != &other) {
      if (handle_) {
        handle_.destroy();
      }
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }

  // Non-copyable
  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;

  ~Task() {
    if (handle_) {
      handle_.destroy();
    }
  }

  // Check if task is valid
  explicit operator bool() const noexcept { return handle_ != nullptr; }

  // Awaiter for co_await support
  auto operator co_await() const& noexcept {
    struct Awaiter {
      handle_type handle_;

      bool await_ready() noexcept { return false; }

      std::coroutine_handle<> await_suspend(
          std::coroutine_handle<> continuation) noexcept {
        handle_.promise().continuation_ = continuation;
        return handle_;
      }

      decltype(auto) await_resume() {
        return std::move(handle_.promise()).result();
      }
    };
    return Awaiter{handle_};
  }

  // Start the coroutine and block until completion (for sync contexts)
  // WARNING: This will block the calling thread!
  T sync_wait() {
    struct SyncWaiter {
      std::coroutine_handle<> handle_;
      bool done_ = false;

      bool await_ready() noexcept { return false; }

      void await_suspend(std::coroutine_handle<> h) noexcept { handle_ = h; }

      void await_resume() noexcept {}
    };

    // Create a wrapper coroutine that signals completion
    struct Runner {
      Task& task_;
      bool& done_;

      struct promise_type {
        Runner get_return_object() noexcept {
          return Runner{*static_cast<Task*>(nullptr),
                        *static_cast<bool*>(nullptr)};
        }
        auto initial_suspend() noexcept { return std::suspend_never{}; }
        auto final_suspend() noexcept { return std::suspend_never{}; }
        void return_void() noexcept {}
        void unhandled_exception() { std::terminate(); }
      };
    };

    // Simple blocking implementation
    bool done = false;
    auto wrapper = [](Task task, bool* done_ptr) -> Task<T> {
      auto result = co_await std::move(task);
      *done_ptr = true;
      co_return result;
    };

    auto wrapped = wrapper(std::move(*this), &done);
    wrapped.handle_.resume();

    // Spin until done (not ideal, but works for simple cases)
    while (!done && !wrapped.handle_.done()) {
      // In a real implementation, you'd integrate with an event loop
    }

    return std::move(wrapped.handle_.promise()).result();
  }

  // Resume the coroutine (for manual control)
  void resume() {
    if (handle_ && !handle_.done()) {
      handle_.resume();
    }
  }

  // Check if coroutine is done
  bool done() const noexcept { return handle_ && handle_.done(); }

 private:
  handle_type handle_;

  template <typename U>
  friend class Task;
};

// Implementation of get_return_object
namespace detail {

template <typename T>
Task<T> TaskPromise<T>::get_return_object() noexcept {
  return Task<T>{std::coroutine_handle<TaskPromise<T>>::from_promise(*this)};
}

inline Task<void> TaskPromise<void>::get_return_object() noexcept {
  return Task<void>{
      std::coroutine_handle<TaskPromise<void>>::from_promise(*this)};
}

}  // namespace detail

// Result type for async operations that can fail
// Holds either a value or an error
template <typename T>
class AsyncResult {
 public:
  AsyncResult(T value) : data_(std::move(value)) {}
  AsyncResult(Error error) : data_(std::move(error)) {}

  bool ok() const { return std::holds_alternative<T>(data_); }
  bool has_error() const { return std::holds_alternative<Error>(data_); }

  explicit operator bool() const { return ok(); }

  T& value() & { return std::get<T>(data_); }
  const T& value() const& { return std::get<T>(data_); }
  T&& value() && { return std::get<T>(std::move(data_)); }

  Error& error() & { return std::get<Error>(data_); }
  const Error& error() const& { return std::get<Error>(data_); }

  // Map - transform the value if present
  template <typename F>
  auto map(F&& f) -> AsyncResult<decltype(f(std::declval<T>()))> {
    using U = decltype(f(std::declval<T>()));
    if (ok()) {
      return AsyncResult<U>(f(std::move(value())));
    }
    return AsyncResult<U>(error());
  }

 private:
  std::variant<T, Error> data_;
};

// Specialization for void
template <>
class AsyncResult<void> {
 public:
  AsyncResult() : error_(std::nullopt) {}
  AsyncResult(Error error) : error_(std::move(error)) {}

  bool ok() const { return !error_.has_value(); }
  bool has_error() const { return error_.has_value(); }

  explicit operator bool() const { return ok(); }

  Error& error() & { return *error_; }
  const Error& error() const& { return *error_; }

 private:
  std::optional<Error> error_;
};

}  // namespace holytls

#endif  // HOLYTLS_TASK_H_

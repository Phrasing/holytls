// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_ASYNC_H_
#define HOLYTLS_ASYNC_H_

#include <coroutine>
#include <functional>
#include <memory>
#include <utility>

#include "holytls/client.h"
#include "holytls/error.h"
#include "holytls/task.h"

namespace holytls {

namespace detail {

// Shared state for callback-based awaitable
// Must be heap-allocated to survive across await suspension
template <typename T>
struct CallbackState {
  std::optional<AsyncResult<T>> result;
  std::coroutine_handle<> continuation;
};

// Awaitable that wraps a callback-based async operation
// Converts SendAsync(request, callback) into co_await SendAsync(request)
template <typename T>
class CallbackAwaitable {
 public:
  using ResultType = AsyncResult<T>;
  using CallbackType = std::function<void(std::function<void(T, Error)>)>;

  explicit CallbackAwaitable(CallbackType initiator)
      : initiator_(std::move(initiator)),
        state_(std::make_shared<CallbackState<T>>()) {}

  bool await_ready() noexcept { return false; }

  void await_suspend(std::coroutine_handle<> continuation) {
    state_->continuation = continuation;

    // Capture state by shared_ptr so it survives after this object is destroyed
    auto state = state_;
    initiator_([state](T value, Error error) mutable {
      if (error) {
        state->result = ResultType(std::move(error));
      } else {
        state->result = ResultType(std::move(value));
      }
      if (state->continuation) {
        // Resume the coroutine - this is called from reactor thread
        state->continuation.resume();
      }
    });
  }

  ResultType await_resume() { return std::move(*state_->result); }

 private:
  CallbackType initiator_;
  std::shared_ptr<CallbackState<T>> state_;
};

}  // namespace detail

// Async wrapper around HttpClient that provides coroutine-based API
//
// Usage:
//   AsyncClient client;
//
//   Task<void> FetchData() {
//     auto result = co_await client.Get("https://example.com");
//     if (result) {
//       std::cout << "Status: " << result.value().status_code << "\n";
//     } else {
//       std::cerr << "Error: " << result.error().message << "\n";
//     }
//   }
//
class AsyncClient {
 public:
  explicit AsyncClient(
      const ClientConfig& config = ClientConfig::ChromeLatest())
      : client_(std::make_shared<HttpClient>(config)) {}

  // Construct from existing HttpClient (takes ownership)
  explicit AsyncClient(std::unique_ptr<HttpClient> client)
      : client_(std::move(client)) {}

  // Send a request asynchronously - returns awaitable
  auto SendAsync(Request request) {
    return detail::CallbackAwaitable<Response>(
        [this, request = std::move(request)](
            std::function<void(Response, Error)> callback) mutable {
          client_->SendAsync(std::move(request), std::move(callback));
        });
  }

  // Convenience methods that return awaitables

  auto Get(std::string url) {
    Request req;
    req.method = Method::kGet;
    req.url = std::move(url);
    return SendAsync(std::move(req));
  }

  auto Get(std::string url, Headers headers) {
    Request req;
    req.method = Method::kGet;
    req.url = std::move(url);
    req.headers = std::move(headers);
    return SendAsync(std::move(req));
  }

  auto Post(std::string url, std::vector<uint8_t> body) {
    Request req;
    req.method = Method::kPost;
    req.url = std::move(url);
    req.body = std::move(body);
    return SendAsync(std::move(req));
  }

  auto Post(std::string url, std::string_view body) {
    Request req;
    req.method = Method::kPost;
    req.url = std::move(url);
    req.SetBody(body);
    return SendAsync(std::move(req));
  }

  auto Post(std::string url, Headers headers, std::vector<uint8_t> body) {
    Request req;
    req.method = Method::kPost;
    req.url = std::move(url);
    req.headers = std::move(headers);
    req.body = std::move(body);
    return SendAsync(std::move(req));
  }

  auto Put(std::string url, std::vector<uint8_t> body) {
    Request req;
    req.method = Method::kPut;
    req.url = std::move(url);
    req.body = std::move(body);
    return SendAsync(std::move(req));
  }

  auto Delete(std::string url) {
    Request req;
    req.method = Method::kDelete;
    req.url = std::move(url);
    return SendAsync(std::move(req));
  }

  auto Patch(std::string url, std::vector<uint8_t> body) {
    Request req;
    req.method = Method::kPatch;
    req.url = std::move(url);
    req.body = std::move(body);
    return SendAsync(std::move(req));
  }

  auto Head(std::string url) {
    Request req;
    req.method = Method::kHead;
    req.url = std::move(url);
    return SendAsync(std::move(req));
  }

  auto Options(std::string url) {
    Request req;
    req.method = Method::kOptions;
    req.url = std::move(url);
    return SendAsync(std::move(req));
  }

  // Event loop control (delegates to underlying HttpClient)
  void Run() { client_->Run(); }
  void RunOnce() { client_->RunOnce(); }
  void Stop() { client_->Stop(); }
  bool IsRunning() const { return client_->IsRunning(); }

  // Statistics
  ClientStats GetStats() const { return client_->GetStats(); }
  ChromeVersion GetChromeVersion() const { return client_->GetChromeVersion(); }

  // Access underlying client
  HttpClient& client() { return *client_; }
  const HttpClient& client() const { return *client_; }

 private:
  std::shared_ptr<HttpClient> client_;
};

// Helper to run a coroutine on the client's event loop
// This is the main entry point for running async code
//
// Usage:
//   AsyncClient client;
//
//   Task<void> FetchData(AsyncClient& c) {
//     auto result = co_await c.Get("https://example.com");
//     std::cout << result.value().status_code << "\n";
//   }
//
//   // In main():
//   RunAsync(client, FetchData(client));
//
template <typename T>
void RunAsync(AsyncClient& client, Task<T> task) {
  // Start the task
  task.resume();

  // Run the event loop until the task completes
  while (!task.done()) {
    client.RunOnce();
  }
}

// Overload for multiple tasks - runs all concurrently
template <typename... Tasks>
void RunAsync(AsyncClient& client, Tasks&&... tasks) {
  // Start all tasks
  (tasks.resume(), ...);

  // Create a check function
  auto all_done = [&]() { return (tasks.done() && ...); };

  // Run until all complete
  while (!all_done()) {
    client.RunOnce();
  }
}

// WhenAll - wait for multiple tasks to complete
// Returns a Task that completes when all input tasks complete
template <typename... Ts>
Task<std::tuple<AsyncResult<Ts>...>> WhenAll(Task<AsyncResult<Ts>>... tasks);

// WhenAny - wait for any task to complete
// Returns a Task that completes when any input task completes

}  // namespace holytls

#endif  // HOLYTLS_ASYNC_H_

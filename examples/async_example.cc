// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Using the coroutine-based async API
//
// This example demonstrates the modern C++20 coroutine API for making
// HTTP requests with holytls. Instead of callbacks, you can use co_await
// for clean, sequential async code.
//
// Usage: ./async_example

#include <atomic>
#include <print>
#include <string>
#include <thread>

#include "holytls/async.h"
#include "holytls/client.h"
#include "holytls/config.h"

using namespace holytls;

// Main coroutine that makes sequential requests
Task<void> RunAll(AsyncClient& client, std::atomic<bool>& done) {
  std::println("=== holytls Coroutine Example ===");
  std::println("Chrome version: {}", static_cast<int>(client.GetChromeVersion()));

  // TLS Fingerprint Check
  std::println("\n=== TLS Fingerprint Check ===");
  auto result1 = co_await client.Get("https://tls.peet.ws/api/all");
  if (result1) {
    std::println("Fingerprint check: {} ({} bytes)", result1.value().status_code,
                 result1.value().body.size());
  } else {
    std::println("Fingerprint check failed: {}", result1.error().message);
  }

  // Sequential Requests
  std::println("\n=== Sequential Requests ===");

  auto result2 = co_await client.Get("https://httpbin.org/get");
  if (result2) {
    std::println("Request 1: {} ({} bytes)", result2.value().status_code,
                 result2.value().body.size());
  } else {
    std::println("Request 1 failed: {}", result2.error().message);
  }

  auto result3 = co_await client.Get("https://httpbin.org/ip");
  if (result3) {
    std::println("Request 2: {} ({} bytes)", result3.value().status_code,
                 result3.value().body.size());
    std::println("  Response: {}", result3.value().body_string());
  } else {
    std::println("Request 2 failed: {}", result3.error().message);
  }

  std::println("\n=== Done ===");
  done.store(true, std::memory_order_release);
  co_return;
}

int main() {
  std::println("Creating AsyncClient...");
  AsyncClient client(ClientConfig::Chrome143());

  std::atomic<bool> done{false};

  std::println("Creating and starting task...");
  auto task = RunAll(client, done);
  task.resume();

  std::println("Running event loop...");
  int count = 0;
  while (!done.load(std::memory_order_acquire) && count < 1000) {
    client.RunOnce();
    count++;
    if (count % 100 == 0) {
      std::println("Event loop iteration {}, task.done()={}", count, task.done());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  std::println("Event loop finished, count={}", count);

  // Print stats
  auto stats = client.GetStats();
  std::println("\nStats:");
  std::println("  Requests sent: {}", stats.requests_sent);
  std::println("  Requests completed: {}", stats.requests_completed);
  std::println("  Requests failed: {}", stats.requests_failed);
  std::println("  Connections created: {}", stats.connections_created);
  std::println("  Connections reused: {}", stats.connections_reused);

  return 0;
}

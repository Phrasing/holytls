// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Using the coroutine-based async API
//
// This example demonstrates the modern C++23 coroutine API for making
// HTTP requests with holytls. Instead of callbacks, you can use co_await
// for clean, sequential async code.
//
// Usage: ./async_example

#include <print>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

// Main coroutine that makes sequential requests
Task<void> RunAll(AsyncClient& client) {
  std::println("=== holytls Coroutine Example ===");
  std::println("Chrome version: {}", static_cast<int>(client.GetChromeVersion()));

  // TLS Fingerprint Check
  std::println("\n=== TLS Fingerprint Check ===");
  auto result1 = co_await client.Get("https://tls.peet.ws/api/all");
  if (result1) {
    std::println("Fingerprint check: {} ({} bytes)",
                 result1.value().status_code, result1.value().body.size());
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

  // Print stats
  auto stats = client.GetStats();
  std::println("\n=== Stats ===");
  std::println("Requests sent: {}", stats.requests_sent);
  std::println("Requests completed: {}", stats.requests_completed);
  std::println("Requests failed: {}", stats.requests_failed);
  std::println("Connections created: {}", stats.connections_created);
  std::println("Connections reused: {}", stats.connections_reused);

  std::println("\n=== Done ===");
}

int main() {
  std::println("Creating AsyncClient with Chrome 143...");
  AsyncClient client(ClientConfig::Chrome143());

  // RunAsync handles the event loop - clean C++23 pattern
  RunAsync(client, RunAll(client));

  return 0;
}

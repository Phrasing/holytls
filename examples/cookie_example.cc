// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Cookie Jar usage with holytls
//
// This example demonstrates automatic cookie handling:
// 1. First request to httpbin.org/cookies/set sets cookies
// 2. Second request to httpbin.org/cookies shows the cookies are sent back
//
// Usage: ./cookie_example

#include <print>

#include "holytls/async.h"
#include "holytls/client.h"
#include "holytls/http/cookie_jar.h"

using namespace holytls;

Task<void> TestCookies(AsyncClient& client, http::CookieJar& jar) {
  std::println("=== Cookie Jar Test ===\n");

  // Step 1: Set some cookies via httpbin
  std::println("1. Setting cookies via httpbin.org/cookies/set...");
  auto set_result = co_await client.Get(
      "https://httpbin.org/cookies/set?session_id=abc123&user=testuser");

  if (set_result) {
    std::println("   Status: {}", set_result.value().status_code);
    std::println("   Cookies stored: {}\n", jar.Size());
  } else {
    std::println(stderr, "   Error: {}", set_result.error().message);
    co_return;
  }

  // Step 2: Verify cookies are sent back
  std::println("2. Fetching httpbin.org/cookies to verify cookies sent...");
  auto get_result = co_await client.Get("https://httpbin.org/cookies");

  if (get_result) {
    const auto& response = get_result.value();
    std::println("   Status: {}", response.status_code);
    std::println("   Response body:");
    std::println("{}\n", response.body_string());
  } else {
    std::println(stderr, "   Error: {}", get_result.error().message);
    co_return;
  }

  // Step 3: Show all cookies in the jar
  std::println("3. All cookies in jar:");
  auto cookies = jar.GetAllCookies();
  for (const auto& cookie : cookies) {
    std::println("   - {}={} (domain: {})", cookie.name, cookie.value,
                 cookie.domain);
  }

  std::println("\n=== Test Complete ===");
}

int main() {
  // Create a cookie jar
  http::CookieJar cookie_jar;

  // Configure client with cookie jar
  ClientConfig config = ClientConfig::ChromeLatest();
  config.cookie_jar = &cookie_jar;

  // Create async client
  AsyncClient client(config);

  // RunAsync handles the event loop - clean C++23 pattern
  RunAsync(client, TestCookies(client, cookie_jar));

  return 0;
}

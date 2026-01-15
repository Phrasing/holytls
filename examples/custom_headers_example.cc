// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Custom Header Order with HTTP/2
//
// Three modes:
// 1. Auto - Chrome headers auto-generated
// 2. Append - Custom headers added after Chrome headers
// 3. Full control - User specifies exact header order

#include <print>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

// Auto mode: Chrome headers are fully auto-generated
Task<void> DemoAutoMode(AsyncClient& client) {
  std::println("=== Auto mode ===");
  auto result = co_await client.Get("https://httpbin.org/headers");
  std::println("{}\n",
               result ? result.value().body_string() : result.error().message);
}

// Append mode: Custom headers added after Chrome's standard headers
Task<void> DemoAppendMode(AsyncClient& client) {
  std::println("=== Append mode ===");
  Headers custom = {
      {"x-custom-header", "my-value"},
      {"referer", "https://example.com/"},
  };

  auto result = co_await client.Get("https://httpbin.org/headers", custom);
  std::println("{}\n",
               result ? result.value().body_string() : result.error().message);
}

// Full control mode: User specifies exact header order
Task<void> DemoFullControlMode(AsyncClient& client) {
  std::println("=== Full control mode ===");

  // Define exact order (static, zero allocation)
  static constexpr std::string_view kHeaderOrder[] = {
      "accept",           "accept-encoding",    "accept-language", "sec-ch-ua",
      "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent",      "x-custom",
  };

  Request req;
  req.method = Method::kGet;
  req.url = "https://httpbin.org/headers";
  req.headers = {
      {"accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
      {"accept-encoding", "gzip, deflate, br"},
      {"accept-language", "en-US,en;q=0.9"},
      {"sec-ch-ua", R"("Chrome";v="143")"},
      {"sec-ch-ua-mobile", "?0"},
      {"sec-ch-ua-platform", R"("Windows")"},
      {"user-agent", "Mozilla/5.0 Chrome/143.0.0.0"},
      {"x-custom", "value"},
  };
  req.header_order = kHeaderOrder;

  auto result = co_await client.SendAsync(std::move(req));
  std::println("{}\n",
               result ? result.value().body_string() : result.error().message);
}

Task<void> RunAll(AsyncClient& client) {
  co_await DemoAutoMode(client);
  co_await DemoAppendMode(client);
  co_await DemoFullControlMode(client);
}

int main() {
  AsyncClient client(ClientConfig::Chrome143());
  RunAsync(client, RunAll(client));
  return 0;
}

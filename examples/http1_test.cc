// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Simple test for HTTP/1.1 client
// Forces HTTP/1.1 by only advertising it in ALPN

#include <print>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

Task<void> Run(AsyncClient& client) {
  std::println("Making request with HTTP/1.1 forced...\n");

  auto result = co_await client.Get("https://tls.peet.ws/api/all");

  if (!result) {
    std::println("Error: {}", result.error().message);
    co_return;
  }

  std::println("Status: {}", result.value().status_code);
  std::println("Body length: {} bytes\n", result.value().body.size());

  // Check the http_version in the response
  auto body = result.value().body_string();
  auto pos = body.find("\"http_version\"");
  if (pos != std::string::npos) {
    auto end = body.find(',', pos);
    if (end != std::string::npos) {
      std::println("Server saw: {}", body.substr(pos, end - pos));
    }
  }

  std::println("\n=== Done ===");
}

int main() {
  std::println("=== HTTP/1.1 Test ===\n");

  // Create config with force_http1 enabled
  auto config = ClientConfig::Chrome143();
  config.tls.force_http1 = true;

  AsyncClient client(config);
  RunAsync(client, Run(client));

  return 0;
}

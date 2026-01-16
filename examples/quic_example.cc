// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// HTTP/3 (QUIC) example using the coroutine-based async API
//
// This example demonstrates protocol-agnostic HTTP using coroutines:
// - Same API for HTTP/1.1, HTTP/2, and HTTP/3
// - Protocol selection via ClientConfig
// - Clean async/await syntax with C++23 coroutines
//
// Build with: cmake -DHOLYTLS_BUILD_QUIC=ON
// Usage: ./quic_example [url] [--http2]

#include <cstdlib>
#include <print>
#include <string>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

// Global exit code (set by coroutine)
static int g_exit_code = 1;

// Main coroutine that makes HTTP/3 request
Task<void> RunRequest(AsyncClient& client, const std::string& url) {
  std::println("=== HTTP/3 (QUIC) Example ===");
  std::println("URL: {}", url);
  std::println("Chrome version: {}", static_cast<int>(client.GetChromeVersion()));

  std::println("\nSending request...");
  auto result = co_await client.Get(url);

  if (result) {
    const auto& response = result.value();
    std::println("\nResponse Status: {}", response.status_code);

    std::println("Headers:");
    for (const auto& header : response.headers) {
      std::println("  {}: {}", header.name, header.value);
    }

    std::println("\nBody size: {} bytes", response.body.size());
    if (response.body.size() < 1000) {
      std::println("Body:\n{}", response.body_string());
    } else {
      std::println("Body (first 500 chars):\n{:.500}...", response.body_string());
    }

    if (response.status_code >= 200 && response.status_code < 400) {
      std::println("\nSUCCESS: Got response with status {}", response.status_code);
      g_exit_code = 0;
    } else {
      std::println("\nFAILED: Unexpected status code {}", response.status_code);
    }
  } else {
    std::println("Request failed: {}", result.error().message);
  }

  // Print stats
  auto stats = client.GetStats();
  std::println("\nStats:");
  std::println("  Requests sent: {}", stats.requests_sent);
  std::println("  Requests completed: {}", stats.requests_completed);
  std::println("  Requests failed: {}", stats.requests_failed);
}

int main(int argc, char* argv[]) {
  const char* url = argc > 1 ? argv[1] : "https://cloudflare.com/";
  bool use_http3 = true;
  if (argc > 2 && std::string(argv[2]) == "--http2") {
    use_http3 = false;
  }

  std::println("HTTP/{} Example (Coroutine API)", use_http3 ? "3" : "2");
  std::println("================================");
  std::println("Protocol: {}\n", use_http3 ? "HTTP/3 (QUIC)" : "HTTP/2 (TCP)");

  // Create client config with protocol preference
  ClientConfig config = ClientConfig::Chrome143();
  if (use_http3) {
    config.protocol = ProtocolPreference::kHttp3Only;
  } else {
    config.protocol = ProtocolPreference::kHttp2Preferred;
  }

  // Create async client
  AsyncClient client(config);

  // RunAsync handles the event loop - clean C++23 pattern
  std::string url_copy = url;
  RunAsync(client, RunRequest(client, url_copy));

  // Force exit due to QUIC timer cleanup issue
  _exit(g_exit_code);
}

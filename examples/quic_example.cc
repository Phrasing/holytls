// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// HTTP/3 (QUIC) example using the coroutine-based async API
//
// This example demonstrates protocol-agnostic HTTP using coroutines:
// - Same API for HTTP/1.1, HTTP/2, and HTTP/3
// - Protocol selection via ClientConfig
// - Clean async/await syntax with C++20 coroutines
//
// Build with: cmake -DHOLYTLS_BUILD_QUIC=ON
// Usage: ./quic_example [url] [--http2]

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

#include "holytls/async.h"
#include "holytls/client.h"
#include "holytls/config.h"

using namespace holytls;

// Main coroutine that makes HTTP/3 request
Task<void> RunRequest(AsyncClient& client, const std::string& url,
                      std::atomic<bool>& done, int& exit_code) {
  printf("=== HTTP/3 (QUIC) Example ===\n");
  printf("URL: %s\n", url.c_str());
  printf("Chrome version: %d\n", static_cast<int>(client.GetChromeVersion()));

  printf("\nSending request...\n");
  auto result = co_await client.Get(url);

  if (result) {
    const auto& response = result.value();
    printf("\nResponse Status: %d\n", response.status_code);

    printf("Headers:\n");
    for (const auto& header : response.headers) {
      printf("  %s: %s\n", header.name.c_str(), header.value.c_str());
    }

    printf("\nBody size: %zu bytes\n", response.body.size());
    if (response.body.size() < 1000) {
      printf("Body:\n%s\n", response.body_string().data());
    } else {
      printf("Body (first 500 chars):\n%.500s...\n",
             response.body_string().data());
    }

    if (response.status_code >= 200 && response.status_code < 400) {
      printf("\nSUCCESS: Got HTTP/3 response with status %d\n",
             response.status_code);
      exit_code = 0;
    } else {
      printf("\nFAILED: Unexpected status code %d\n", response.status_code);
    }
  } else {
    printf("Request failed: %s\n", result.error().message.c_str());
  }

  done.store(true, std::memory_order_release);
  co_return;
}

int main(int argc, char* argv[]) {
  setbuf(stdout, nullptr);
  setbuf(stderr, nullptr);

  const char* url = argc > 1 ? argv[1] : "https://cloudflare.com/";
  bool use_http3 = true;
  if (argc > 2 && std::string(argv[2]) == "--http2") {
    use_http3 = false;
  }

  printf("HTTP/%s Example (Coroutine API)\n", use_http3 ? "3" : "2");
  printf("================================\n");
  printf("Protocol: %s\n\n", use_http3 ? "HTTP/3 (QUIC)" : "HTTP/2 (TCP)");

  // Create client config with protocol preference
  ClientConfig config = ClientConfig::Chrome143();
  if (use_http3) {
    config.protocol = ProtocolPreference::kHttp3Only;
  } else {
    config.protocol = ProtocolPreference::kHttp2Preferred;
  }

  // Create async client
  AsyncClient client(config);

  std::atomic<bool> done{false};
  int exit_code = 1;

  // Create and start the coroutine (copy url to ensure it stays valid)
  std::string url_copy = url;
  auto task = RunRequest(client, url_copy, done, exit_code);
  task.resume();

  // Run event loop with timeout
  constexpr int kMaxIterations = 1000;  // 10 seconds at 10ms per iteration
  int count = 0;
  while (!done.load(std::memory_order_acquire) && count < kMaxIterations) {
    client.RunOnce();
    count++;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  if (count >= kMaxIterations) {
    fprintf(stderr, "Timeout: no response received within 10 seconds\n");
  }

  // Print stats
  auto stats = client.GetStats();
  printf("\nStats:\n");
  printf("  Requests sent: %zu\n", stats.requests_sent);
  printf("  Requests completed: %zu\n", stats.requests_completed);
  printf("  Requests failed: %zu\n", stats.requests_failed);

  // Force exit due to QUIC timer cleanup issue
  _exit(exit_code);
}

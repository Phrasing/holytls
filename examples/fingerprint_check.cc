// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Check TLS fingerprint against multiple services
//
// This example demonstrates the coroutine-based async API by making
// requests to fingerprint checking services:
//   - tls.peet.ws/api/all
//   - tls.browserleaks.com/tls?minify=1
//
// Usage: ./fingerprint_check [chrome_version]
//   chrome_version: 120, 125, 130, 131, or 143 (default: 143)

#include <print>
#include <string>

#include "holytls/async.h"
#include "holytls/client.h"
#include "holytls/config.h"

using namespace holytls;

namespace {

void PrintUsage(const char* prog) {
  std::println(stderr, "Usage: {} [ignored]", prog);
  std::println(stderr, "  (Defaults to Chrome 143)");
}

ChromeVersion ParseChromeVersion(const std::string& /*arg*/) {
  return ChromeVersion::kChrome143;
}

// Test a single fingerprint endpoint
Task<bool> TestEndpoint(AsyncClient& client, std::string_view url,
                        std::string_view label) {
  std::println("\n=== Testing {} ===", label);
  std::println("URL: {}", url);

  auto result = co_await client.Get(std::string(url));

  if (!result) {
    std::println(stderr, "Request failed: {}", result.error().message);
    co_return false;
  }

  std::println("\n=== {} Response ===", label);
  std::println("Status: {}", result.value().status_code);
  std::println("Body length: {} bytes\n", result.value().body.size());
  std::println("=== {} Fingerprint Data ===", label);
  std::println("{}", result.value().body_string());

  co_return result.value().status_code == 200;
}

}  // namespace

// Global to track results for return code
static int g_exit_code = 0;

Task<void> Run(AsyncClient& client) {
  std::println("Chrome version: {}",
               static_cast<int>(client.GetChromeVersion()));

  // Test peet.ws
  if (!co_await TestEndpoint(client, "https://tls.peet.ws/api/all",
                             "Peet.ws")) {
    g_exit_code = 1;
  }

  // Test browserleaks
  if (!co_await TestEndpoint(client,
                             "https://tls.browserleaks.com/tls?minify=1",
                             "BrowserLeaks")) {
    g_exit_code = 1;
  }

  // Test session resumption by making a second request to the same host
  std::println("\n=== Testing Session Resumption ===");
  std::println("Making second request to tls.peet.ws...");
  if (!co_await TestEndpoint(client, "https://tls.peet.ws/api/all",
                             "Peet.ws (Resumption)")) {
    g_exit_code = 1;
  }

  // Print stats
  auto stats = client.GetStats();
  std::println("\n=== Connection Stats ===");
  std::println("Requests sent: {}", stats.requests_sent);
  std::println("Requests completed: {}", stats.requests_completed);
  std::println("Requests failed: {}", stats.requests_failed);
  std::println("Connections created: {}", stats.connections_created);
  std::println("Connections reused: {}", stats.connections_reused);

  std::println("\n=== Done ===");
}

int main(int argc, char* argv[]) {
  // Parse command line
  ChromeVersion version = ChromeVersion::kChrome143;
  if (argc > 1) {
    std::string arg = argv[1];
    if (arg == "-h" || arg == "--help") {
      PrintUsage(argv[0]);
      return 0;
    }
    version = ParseChromeVersion(arg);
  }

  std::println("=== TLS Fingerprint Check ===");
  std::println("Impersonating Chrome {}", static_cast<int>(version));
  std::println("Targets:");
  std::println("  - https://tls.peet.ws/api/all");
  std::println("  - https://tls.browserleaks.com/tls?minify=1");

  // Create client config for the requested Chrome version
  ClientConfig config;
  config.tls.chrome_version = version;
  config.http2.chrome_version = version;

  AsyncClient client(config);
  RunAsync(client, Run(client));

  return g_exit_code;
}

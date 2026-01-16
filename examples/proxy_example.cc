// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Using proxies with holytls
//
// This example demonstrates how to configure HTTP and SOCKS proxies.
// Supports HTTP CONNECT, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h.
//
// Usage: ./proxy_example <proxy_type> <proxy_host> <proxy_port> [username] [password]

#include <cstdlib>
#include <print>
#include <string>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

// Test URL to fetch through proxy
constexpr const char* kTestUrl = "https://httpbin.org/ip";

Task<void> FetchThroughProxy(AsyncClient& client) {
  std::println("Fetching {} through proxy...", kTestUrl);

  auto result = co_await client.Get(kTestUrl);

  if (result) {
    const auto& response = result.value();
    std::println("Status: {}", response.status_code);
    std::println("Body: {}", response.body_string());
  } else {
    std::println(stderr, "Error: {}", result.error().message);
  }
}

ProxyType ParseProxyType(const std::string& type_str) {
  if (type_str == "http") return ProxyType::kHttp;
  if (type_str == "socks4") return ProxyType::kSocks4;
  if (type_str == "socks4a") return ProxyType::kSocks4a;
  if (type_str == "socks5") return ProxyType::kSocks5;
  if (type_str == "socks5h") return ProxyType::kSocks5h;
  return ProxyType::kNone;
}

const char* ProxyTypeToString(ProxyType type) {
  switch (type) {
    case ProxyType::kHttp: return "HTTP";
    case ProxyType::kSocks4: return "SOCKS4";
    case ProxyType::kSocks4a: return "SOCKS4a";
    case ProxyType::kSocks5: return "SOCKS5";
    case ProxyType::kSocks5h: return "SOCKS5h";
    default: return "Unknown";
  }
}

void PrintUsage(const char* prog) {
  std::println(stderr, "Usage: {} <proxy_type> <proxy_host> <proxy_port> [username] [password]", prog);
  std::println(stderr, "\nProxy types:");
  std::println(stderr, "  http     - HTTP CONNECT proxy");
  std::println(stderr, "  socks4   - SOCKS4 (requires client-side DNS resolution)");
  std::println(stderr, "  socks4a  - SOCKS4a (proxy resolves DNS)");
  std::println(stderr, "  socks5   - SOCKS5 (requires client-side DNS resolution)");
  std::println(stderr, "  socks5h  - SOCKS5h (proxy resolves DNS) - RECOMMENDED");
  std::println(stderr, "\nExamples:");
  std::println(stderr, "  {} http 127.0.0.1 8080", prog);
  std::println(stderr, "  {} socks5h 127.0.0.1 1080", prog);
  std::println(stderr, "  {} socks5 proxy.example.com 1080 myuser mypass", prog);
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    PrintUsage(argv[0]);
    return 1;
  }

  // Parse command line arguments
  ProxyType proxy_type = ParseProxyType(argv[1]);
  if (proxy_type == ProxyType::kNone) {
    std::println(stderr, "Error: Unknown proxy type '{}'\n", argv[1]);
    PrintUsage(argv[0]);
    return 1;
  }

  std::string proxy_host = argv[2];
  uint16_t proxy_port = static_cast<uint16_t>(std::stoi(argv[3]));
  std::string proxy_user = (argc > 4) ? argv[4] : "";
  std::string proxy_pass = (argc > 5) ? argv[5] : "";

  std::print("Proxy: {}:{} ({})", proxy_host, proxy_port, ProxyTypeToString(proxy_type));
  if (!proxy_user.empty()) {
    std::print(" (with authentication)");
  }
  std::println("\n");

  // Configure client with proxy
  ClientConfig config = ClientConfig::ChromeLatest();
  config.proxy.type = proxy_type;
  config.proxy.host = proxy_host;
  config.proxy.port = proxy_port;
  config.proxy.username = proxy_user;
  config.proxy.password = proxy_pass;

  // Create async client with proxy configuration
  AsyncClient client(config);

  // RunAsync handles the event loop - clean C++23 pattern
  RunAsync(client, FetchThroughProxy(client));

  return 0;
}

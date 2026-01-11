// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Check TLS fingerprint against multiple services
//
// This example demonstrates the full TLS + HTTP/2 stack by making
// requests to fingerprint checking services:
//   - tls.peet.ws/api/all
//   - tls.browserleaks.com/tls?minify=1
//
// Usage: ./fingerprint_check [chrome_version]
//   chrome_version: 120, 125, 130, 131, or 143 (default: 143)

#include <memory>
#include <print>
#include <string>

#include "holytls/config.h"
#include "holytls/core/connection.h"
#include "holytls/core/reactor.h"
#include "holytls/tls/session_cache.h"
#include "holytls/tls/tls_context.h"
#include "holytls/util/dns_resolver.h"
#include "holytls/util/platform.h"

namespace {

void PrintUsage(const char* prog) {
  std::println(stderr, "Usage: {} [chrome_version]", prog);
  std::println(stderr, "  chrome_version: 120, 125, 130, 131, or 143 (default: 143)");
}

holytls::ChromeVersion ParseChromeVersion(const std::string& arg) {
  if (arg == "120") return holytls::ChromeVersion::kChrome120;
  if (arg == "125") return holytls::ChromeVersion::kChrome125;
  if (arg == "130") return holytls::ChromeVersion::kChrome130;
  if (arg == "131") return holytls::ChromeVersion::kChrome131;
  if (arg == "143") return holytls::ChromeVersion::kChrome143;
  return holytls::ChromeVersion::kChrome143;
}

// Test a single fingerprint endpoint
void TestEndpoint(holytls::core::Reactor& reactor,
                  holytls::tls::TlsContextFactory& tls_factory,
                  holytls::util::DnsResolver& resolver, const std::string& host,
                  const std::string& path, const std::string& label) {
  std::unique_ptr<holytls::core::Connection> conn;

  std::println("\n=== Testing {} ===", label);
  std::println("Resolving {}...", host);

  resolver.ResolveAsync(
      host, [&](const std::vector<holytls::util::ResolvedAddress>& addresses,
                const std::string& error) {
        if (!error.empty() || addresses.empty()) {
          std::println(stderr, "DNS resolution failed: {}", error);
          reactor.Stop();
          return;
        }

        std::print("Resolved to: {}", addresses[0].ip);
        if (addresses[0].is_ipv6) {
          std::print(" (IPv6)");
        }
        std::println("");

        conn = std::make_unique<holytls::core::Connection>(&reactor, &tls_factory,
                                                        host, 443);

        // Stop reactor when connection becomes idle (request complete)
        conn->idle_callback =
            [&reactor](holytls::core::Connection*) { reactor.Stop(); };

        std::println("Connecting...");
        if (!conn->Connect(addresses[0].ip, addresses[0].is_ipv6)) {
          std::println(stderr, "Connection failed");
          reactor.Stop();
          return;
        }

        // Chrome headers are now auto-generated with proper ordering
        // and GREASE sec-ch-ua randomization. Pass empty list for defaults.
        conn->SendRequest(
            "GET", path, {},  // Chrome headers are auto-generated
            [&label](const holytls::core::Response& response) {
              std::println("\n=== {} Response ===", label);
              std::println("Status: {}", response.status_code);
              std::println("Body length: {} bytes\n", response.body.size());
              std::println("=== {} Fingerprint Data ===", label);
              std::println("{}", response.body_string());
            },
            [](const std::string& err) {
              std::println(stderr, "Request error: {}", err);
            });
      });

  reactor.Run();
}

}  // namespace

int main(int argc, char* argv[]) {
  // Initialize platform-specific networking (Winsock on Windows)
  if (!holytls::util::InitializeNetworking()) {
    std::println(stderr, "Failed to initialize networking");
    return 1;
  }

  // Parse command line
  holytls::ChromeVersion version = holytls::ChromeVersion::kChrome143;
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

  // Create reactor
  holytls::core::Reactor reactor;

  // Create TLS context with Chrome profile
  holytls::TlsConfig tls_config;
  tls_config.chrome_version = version;
  tls_config.verify_certificates = true;
  holytls::tls::TlsContextFactory tls_factory(tls_config);
  std::println("\nTLS context created for Chrome {}", static_cast<int>(version));

  // Create DNS resolver
  holytls::util::DnsResolver resolver(reactor.loop());

  // Test peet.ws
  TestEndpoint(reactor, tls_factory, resolver, "tls.peet.ws", "/api/all",
               "Peet.ws");

  // Test browserleaks
  TestEndpoint(reactor, tls_factory, resolver, "tls.browserleaks.com",
               "/tls?minify=1", "BrowserLeaks");

  // Test session resumption by making a second request to the same host
  std::println("\n=== Testing Session Resumption ===");
  std::println("Making second request to tls.peet.ws...");
  TestEndpoint(reactor, tls_factory, resolver, "tls.peet.ws", "/api/all",
               "Peet.ws (Resumption)");

  // Print DNS cache stats
  std::println("\n=== DNS Cache Stats ===");
  std::println("Cache hits: {}", resolver.CacheHits());
  std::println("Cache misses: {}", resolver.CacheMisses());

  // Print TLS session cache stats
  if (auto* cache = tls_factory.session_cache()) {
    std::println("\n=== TLS Session Cache Stats ===");
    std::println("Session cache hits: {}", cache->Hits());
    std::println("Session cache misses: {}", cache->Misses());
    std::println("Cached sessions: {}", cache->Size());
  }

  std::println("\n=== Done ===");

  // Cleanup platform-specific networking
  holytls::util::CleanupNetworking();

  return 0;
}

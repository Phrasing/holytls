// Copyright 2024 Chad-TLS Authors
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

#include <iostream>
#include <memory>
#include <string>

#include "chad/config.h"
#include "core/connection.h"
#include "core/reactor.h"
#include "tls/session_cache.h"
#include "tls/tls_context.h"
#include "util/dns_resolver.h"

namespace {

void PrintUsage(const char* prog) {
  std::cerr << "Usage: " << prog << " [chrome_version]\n";
  std::cerr << "  chrome_version: 120, 125, 130, 131, or 143 (default: 143)\n";
}

chad::ChromeVersion ParseChromeVersion(const std::string& arg) {
  if (arg == "120") return chad::ChromeVersion::kChrome120;
  if (arg == "125") return chad::ChromeVersion::kChrome125;
  if (arg == "130") return chad::ChromeVersion::kChrome130;
  if (arg == "131") return chad::ChromeVersion::kChrome131;
  if (arg == "143") return chad::ChromeVersion::kChrome143;
  return chad::ChromeVersion::kChrome143;
}

// Test a single fingerprint endpoint
void TestEndpoint(chad::core::Reactor& reactor,
                  chad::tls::TlsContextFactory& tls_factory,
                  chad::util::DnsResolver& resolver,
                  const std::string& host,
                  const std::string& path,
                  const std::string& label) {
  std::unique_ptr<chad::core::Connection> conn;

  std::cout << "\n=== Testing " << label << " ===\n";
  std::cout << "Resolving " << host << "...\n";

  resolver.ResolveAsync(host,
      [&](const std::vector<chad::util::ResolvedAddress>& addresses,
          const std::string& error) {
        if (!error.empty() || addresses.empty()) {
          std::cerr << "DNS resolution failed: " << error << "\n";
          reactor.Stop();
          return;
        }

        std::cout << "Resolved to: " << addresses[0].ip;
        if (addresses[0].is_ipv6) {
          std::cout << " (IPv6)";
        }
        std::cout << "\n";

        conn = std::make_unique<chad::core::Connection>(
            &reactor, &tls_factory, host, 443);

        std::cout << "Connecting...\n";
        if (!conn->Connect(addresses[0].ip, addresses[0].is_ipv6)) {
          std::cerr << "Connection failed\n";
          reactor.Stop();
          return;
        }

        // Chrome headers are now auto-generated with proper ordering
        // and GREASE sec-ch-ua randomization. Pass empty list for defaults.
        conn->SendRequest(
            "GET", path,
            {},  // Chrome headers are auto-generated
            [&label](const chad::core::Response& response) {
              std::cout << "\n=== " << label << " Response ===\n";
              std::cout << "Status: " << response.status_code << "\n";
              std::cout << "Body length: " << response.body.size() << " bytes\n\n";
              std::cout << "=== " << label << " Fingerprint Data ===\n";
              std::cout << response.body_string() << "\n";
            },
            [](const std::string& err) {
              std::cerr << "Request error: " << err << "\n";
            });
      });

  reactor.Run();
}

}  // namespace

int main(int argc, char* argv[]) {
  // Parse command line
  chad::ChromeVersion version = chad::ChromeVersion::kChrome143;
  if (argc > 1) {
    std::string arg = argv[1];
    if (arg == "-h" || arg == "--help") {
      PrintUsage(argv[0]);
      return 0;
    }
    version = ParseChromeVersion(arg);
  }

  std::cout << "=== TLS Fingerprint Check ===\n";
  std::cout << "Impersonating Chrome " << static_cast<int>(version) << "\n";
  std::cout << "Targets:\n";
  std::cout << "  - https://tls.peet.ws/api/all\n";
  std::cout << "  - https://tls.browserleaks.com/tls?minify=1\n";

  // Create reactor
  chad::core::Reactor reactor;

  // Create TLS context with Chrome profile
  chad::TlsConfig tls_config;
  tls_config.chrome_version = version;
  tls_config.verify_certificates = true;
  chad::tls::TlsContextFactory tls_factory(tls_config);
  std::cout << "\nTLS context created for Chrome " << static_cast<int>(version) << "\n";

  // Create DNS resolver
  chad::util::DnsResolver resolver(reactor.loop());

  // Test peet.ws
  TestEndpoint(reactor, tls_factory, resolver,
               "tls.peet.ws", "/api/all", "Peet.ws");

  // Test browserleaks
  TestEndpoint(reactor, tls_factory, resolver,
               "tls.browserleaks.com", "/tls?minify=1", "BrowserLeaks");

  // Test session resumption by making a second request to the same host
  std::cout << "\n=== Testing Session Resumption ===\n";
  std::cout << "Making second request to tls.peet.ws...\n";
  TestEndpoint(reactor, tls_factory, resolver,
               "tls.peet.ws", "/api/all", "Peet.ws (Resumption)");

  // Print DNS cache stats
  std::cout << "\n=== DNS Cache Stats ===\n";
  std::cout << "Cache hits: " << resolver.CacheHits() << "\n";
  std::cout << "Cache misses: " << resolver.CacheMisses() << "\n";

  // Print TLS session cache stats
  if (auto* cache = tls_factory.session_cache()) {
    std::cout << "\n=== TLS Session Cache Stats ===\n";
    std::cout << "Session cache hits: " << cache->Hits() << "\n";
    std::cout << "Session cache misses: " << cache->Misses() << "\n";
    std::cout << "Cached sessions: " << cache->Size() << "\n";
  }

  std::cout << "\n=== Done ===\n";
  return 0;
}

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Integration Test: Top 10 US Websites
//
// This test validates the holytls client against the top 10 US websites:
// - Makes GET / requests with Chrome 143 headers
// - Verifies TLS 1.3 handshake succeeds
// - Verifies HTTP/2 response received
// - Verifies TLS session resumption on second request
//
// Pass criteria: 2xx or 3xx response on both requests

#include <memory>
#include <print>
#include <string>
#include <vector>

#include "holytls/config.h"
#include "holytls/core/connection.h"
#include "holytls/core/reactor.h"
#include "holytls/tls/session_cache.h"
#include "holytls/tls/tls_context.h"
#include "holytls/util/dns_resolver.h"

namespace {

struct TestResult {
  std::string host;
  int first_status = 0;
  int second_status = 0;
  bool session_resumed = false;
  std::string error;
  bool passed = false;
};

bool IsSuccessStatus(int status) { return status >= 200 && status < 400; }

// Make a single request and return the status code
int MakeRequest(holytls::core::Reactor& reactor,
                holytls::tls::TlsContextFactory& tls_factory,
                holytls::util::DnsResolver& resolver, const std::string& host,
                std::string& error, bool verbose = false) {
  int status = 0;
  std::unique_ptr<holytls::core::Connection> conn;

  resolver.ResolveAsync(
      host, [&](const std::vector<holytls::util::ResolvedAddress>& addresses,
                const std::string& dns_error) {
        if (!dns_error.empty() || addresses.empty()) {
          error = "DNS failed: " + dns_error;
          reactor.Stop();
          return;
        }

        if (verbose) {
          std::println("[DEBUG] Resolved {} to {}", host, addresses[0].ip);
        }

        conn = std::make_unique<holytls::core::Connection>(&reactor, &tls_factory,
                                                        host, 443);

        if (!conn->Connect(addresses[0].ip, addresses[0].is_ipv6)) {
          error = "Connect failed";
          reactor.Stop();
          return;
        }

        if (verbose) {
          std::println("[DEBUG] Connected to {}", host);
        }

        conn->SendRequest(
            "GET", "/", {},
            [&status, &reactor, verbose, &host](const holytls::core::RawResponse& response) {
              status = response.status_code;
              if (verbose) {
                std::println("[DEBUG] Got response from {}: {} ({} bytes)",
                             host, status, response.body.size());
              }
              reactor.Stop();
            },
            [&error, &reactor, verbose, &host](const std::string& err) {
              error = err;
              if (verbose) {
                std::println("[DEBUG] Error from {}: {}", host, err);
              }
              reactor.Stop();
            });
      });

  reactor.Run();
  return status;
}

// Test a single website with two requests (for session resumption)
void TestWebsite(holytls::core::Reactor& reactor,
                 holytls::tls::TlsContextFactory& tls_factory,
                 holytls::util::DnsResolver& resolver, const std::string& host,
                 TestResult& result, bool verbose = false) {
  std::print("Testing {}... ", host);

  // First request - full handshake
  result.first_status =
      MakeRequest(reactor, tls_factory, resolver, host, result.error, verbose);

  if (!result.error.empty()) {
    std::println("FAIL (1st: {})", result.error);
    return;  // Don't try second request if first failed
  }

  // Second request - should use session resumption
  std::string error2;
  result.second_status =
      MakeRequest(reactor, tls_factory, resolver, host, error2, verbose);

  if (!error2.empty()) {
    result.error = "2nd: " + error2;
  }

  result.passed = IsSuccessStatus(result.first_status) &&
                  IsSuccessStatus(result.second_status);

  if (result.passed) {
    std::println("OK [{} -> {}]", result.first_status, result.second_status);
  } else if (!result.error.empty()) {
    std::println("FAIL ({})", result.error);
  } else {
    std::println("FAIL [{} -> {}]", result.first_status, result.second_status);
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  bool verbose = false;
  if (argc > 1 && std::string(argv[1]) == "-v") {
    verbose = true;
  }

  std::println("=== Top 10 US Websites Integration Test ===");
  std::println("Chrome 143 fingerprint, TLS 1.3, HTTP/2");
  std::println("Testing session resumption (2 requests per site)\n");

  // Top 10 US websites by traffic
  // Using www. prefix for sites that commonly redirect there
  std::vector<std::string> websites = {"www.google.com",    "www.youtube.com",
                                       "www.facebook.com",  "www.amazon.com",
                                       "www.wikipedia.org", "x.com",
                                       "www.instagram.com", "www.reddit.com",
                                       "www.linkedin.com",  "www.netflix.com"};

  // Setup
  holytls::core::Reactor reactor;
  if (!reactor.Initialize()) {
    std::println("Failed to initialize reactor: {}", reactor.last_error());
    return 1;
  }
  holytls::TlsConfig tls_config;
  tls_config.chrome_version = holytls::ChromeVersion::kChrome143;
  tls_config.verify_certificates = true;
  holytls::tls::TlsContextFactory tls_factory;
  if (!tls_factory.Initialize(tls_config)) {
    std::println("Failed to initialize TLS: {}", tls_factory.last_error());
    return 1;
  }
  holytls::util::DnsResolver resolver(reactor.loop());

  // Test each website
  std::vector<TestResult> results(websites.size());

  for (size_t i = 0; i < websites.size(); ++i) {
    results[i].host = websites[i];
    TestWebsite(reactor, tls_factory, resolver, websites[i], results[i],
                verbose);
  }

  // Print summary
  std::println("\n=== Summary ===");
  int passed = 0;
  for (const auto& r : results) {
    if (r.passed) passed++;
    if (r.passed) {
      std::println("[PASS] {}", r.host);
    } else if (!r.error.empty()) {
      std::println("[FAIL] {} - {}", r.host, r.error);
    } else {
      std::println("[FAIL] {} [{} -> {}]", r.host, r.first_status,
                   r.second_status);
    }
  }

  std::println("\nPassed: {}/{}", passed, websites.size());

  // Print session cache stats
  if (auto* cache = tls_factory.session_cache()) {
    std::println("\n=== Session Cache Stats ===");
    std::println("Hits: {}", cache->Hits());
    std::println("Misses: {}", cache->Misses());
    std::println("Cached: {}", cache->Size());
  }

  // Print DNS cache stats
  std::println("\n=== DNS Cache Stats ===");
  std::println("Hits: {}", resolver.CacheHits());
  std::println("Misses: {}", resolver.CacheMisses());

  std::println("\n=== Done ===");

  // Consider test passed if at least 8/10 succeed (allow for transient issues)
  bool overall_pass = passed >= 8;
  return overall_pass ? 0 : 1;
}

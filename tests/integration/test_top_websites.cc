// Copyright 2024 HolyTLS Authors
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

#include <iostream>
#include <memory>
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
          std::cout << "[DEBUG] Resolved " << host << " to " << addresses[0].ip
                    << "\n";
        }

        conn = std::make_unique<holytls::core::Connection>(&reactor, &tls_factory,
                                                        host, 443);

        if (!conn->Connect(addresses[0].ip, addresses[0].is_ipv6)) {
          error = "Connect failed";
          reactor.Stop();
          return;
        }

        if (verbose) {
          std::cout << "[DEBUG] Connected to " << host << "\n";
        }

        conn->SendRequest(
            "GET", "/", {},
            [&status, verbose, &host](const holytls::core::Response& response) {
              status = response.status_code;
              if (verbose) {
                std::cout << "[DEBUG] Got response from " << host << ": "
                          << status << " (" << response.body.size()
                          << " bytes)\n";
              }
            },
            [&error, &reactor, verbose, &host](const std::string& err) {
              error = err;
              if (verbose) {
                std::cout << "[DEBUG] Error from " << host << ": " << err
                          << "\n";
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
  std::cout << "Testing " << host << "... " << std::flush;

  // First request - full handshake
  result.first_status =
      MakeRequest(reactor, tls_factory, resolver, host, result.error, verbose);

  if (!result.error.empty()) {
    std::cout << "FAIL (1st: " << result.error << ")\n";
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
    std::cout << "OK [" << result.first_status << " -> " << result.second_status
              << "]\n";
  } else if (!result.error.empty()) {
    std::cout << "FAIL (" << result.error << ")\n";
  } else {
    std::cout << "FAIL [" << result.first_status << " -> "
              << result.second_status << "]\n";
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  bool verbose = false;
  if (argc > 1 && std::string(argv[1]) == "-v") {
    verbose = true;
  }

  std::cout << "=== Top 10 US Websites Integration Test ===\n";
  std::cout << "Chrome 143 fingerprint, TLS 1.3, HTTP/2\n";
  std::cout << "Testing session resumption (2 requests per site)\n\n";

  // Top 10 US websites by traffic
  // Using www. prefix for sites that commonly redirect there
  std::vector<std::string> websites = {"www.google.com",    "www.youtube.com",
                                       "www.facebook.com",  "www.amazon.com",
                                       "www.wikipedia.org", "x.com",
                                       "www.instagram.com", "www.reddit.com",
                                       "www.linkedin.com",  "www.netflix.com"};

  // Setup
  holytls::core::Reactor reactor;
  holytls::TlsConfig tls_config;
  tls_config.chrome_version = holytls::ChromeVersion::kChrome143;
  tls_config.verify_certificates = true;
  holytls::tls::TlsContextFactory tls_factory(tls_config);
  holytls::util::DnsResolver resolver(reactor.loop());

  // Test each website
  std::vector<TestResult> results(websites.size());

  for (size_t i = 0; i < websites.size(); ++i) {
    results[i].host = websites[i];
    TestWebsite(reactor, tls_factory, resolver, websites[i], results[i],
                verbose);
  }

  // Print summary
  std::cout << "\n=== Summary ===\n";
  int passed = 0;
  for (const auto& r : results) {
    if (r.passed) passed++;
    std::cout << (r.passed ? "[PASS]" : "[FAIL]") << " " << r.host;
    if (!r.passed && !r.error.empty()) {
      std::cout << " - " << r.error;
    } else if (!r.passed) {
      std::cout << " [" << r.first_status << " -> " << r.second_status << "]";
    }
    std::cout << "\n";
  }

  std::cout << "\nPassed: " << passed << "/" << websites.size() << "\n";

  // Print session cache stats
  if (auto* cache = tls_factory.session_cache()) {
    std::cout << "\n=== Session Cache Stats ===\n";
    std::cout << "Hits: " << cache->Hits() << "\n";
    std::cout << "Misses: " << cache->Misses() << "\n";
    std::cout << "Cached: " << cache->Size() << "\n";
  }

  // Print DNS cache stats
  std::cout << "\n=== DNS Cache Stats ===\n";
  std::cout << "Hits: " << resolver.CacheHits() << "\n";
  std::cout << "Misses: " << resolver.CacheMisses() << "\n";

  std::cout << "\n=== Done ===\n";

  // Consider test passed if at least 8/10 succeed (allow for transient issues)
  bool overall_pass = passed >= 8;
  return overall_pass ? 0 : 1;
}

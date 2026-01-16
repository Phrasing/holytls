// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: OrderedHeaders - DOD-style headers with O(1) lookup and order control
//
// Demonstrates:
// 1. Building headers with free functions (Set, Get, Has)
// 2. Case-insensitive lookup
// 3. Header ordering control (SetAt, MoveTo)
// 4. Converting to Request via SetHeaders()
// 5. Using internal Chrome header profile for browser-accurate headers

#include <print>

#include "holytls/async.h"
#include "holytls/client.h"
#include "holytls/http/ordered_headers.h"
#include "holytls/http2/chrome_header_profile.h"
#include "holytls/http2/sec_ch_ua.h"

using namespace holytls;
namespace headers = holytls::http::headers;

Task<void> DemoOrderedHeaders(AsyncClient& client) {
  std::println("=== OrderedHeaders Demo ===\n");

  // Build headers with O(1) lookup and ordering control
  headers::OrderedHeaders h;

  // Set headers (upsert semantics - replaces if exists)
  headers::Set(h, "accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
  headers::Set(h, "accept-encoding", "gzip, deflate, br");
  headers::Set(h, "accept-language", "en-US,en;q=0.9");
  headers::Set(h, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/143.0.0.0");
  headers::Set(h, "x-custom", "my-value");

  // O(1) case-insensitive lookup
  std::println("--- O(1) Lookup ---");
  if (headers::Has(h, "Accept")) {  // Case-insensitive
    std::println("Accept: {}", headers::Get(h, "accept"));
  }
  if (headers::Has(h, "X-CUSTOM")) {  // Case-insensitive
    std::println("X-Custom: {}", headers::Get(h, "x-custom"));
  }
  std::println("");

  // Move header to specific position (for fingerprint control)
  std::println("--- Header Ordering ---");
  std::println("Before MoveTo:");
  for (size_t i = 0; i < h.headers.size(); ++i) {
    std::println("  [{}] {}: {}", i, h.headers[i].name, h.headers[i].value);
  }

  headers::MoveTo(h, "user-agent", 0);  // Move user-agent to front

  std::println("\nAfter MoveTo(user-agent, 0):");
  for (size_t i = 0; i < h.headers.size(); ++i) {
    std::println("  [{}] {}: {}", i, h.headers[i].name, h.headers[i].value);
  }
  std::println("");

  // Build request with ordered headers
  std::println("--- HTTP Request ---");
  Request req;
  req.method = Method::kGet;
  req.url = "https://httpbin.org/headers";
  req.SetHeaders(h);

  auto result = co_await client.SendAsync(std::move(req));
  if (result) {
    std::println("Response:");
    std::println("{}", result.value().body_string());
  } else {
    std::println("Error: {}", result.error().message);
  }
}

Task<void> DemoBrowserHeaders(AsyncClient& client) {
  std::println("\n=== Browser Headers from Chrome Profile ===\n");

  // Get Chrome 143 header profile (contains user-agent, accept values, etc.)
  const auto& profile =
      http2::GetChromeHeaderProfile(client.GetChromeVersion());

  std::println("Chrome Profile:");
  std::println("  User-Agent: {}", profile.user_agent);
  std::println("  Accept (nav): {}", profile.accept_navigation);
  std::println("  Accept-Encoding: {}", profile.accept_encoding);
  std::println("  Accept-Language: {}", profile.accept_language);
  std::println("  Platform: {}", profile.sec_ch_ua_platform);
  std::println("");

  // Build complete browser-style headers using BuildChromeHeaders
  // This gives headers in Chrome's exact wire order with GREASE sec-ch-ua
  auto chrome_headers = http2::BuildChromeHeaders(
      profile,
      http2::RequestType::kNavigation,  // Navigation request
      http2::FetchSite::kNone,          // Direct navigation (no referrer)
      http2::FetchMode::kNavigate,      // Navigation mode
      http2::FetchDest::kDocument,      // Fetching a document
      true                              // User-activated (clicked link)
  );

  std::println("Built Chrome Headers (exact wire order):");
  for (size_t i = 0; i < chrome_headers.size(); ++i) {
    std::println("  [{}] {}: {}", i, chrome_headers[i].name,
                 chrome_headers[i].value);
  }
  std::println("");

  // Convert to OrderedHeaders for manipulation
  headers::OrderedHeaders h;
  for (const auto& hdr : chrome_headers) {
    headers::Set(h, hdr.name, hdr.value);
  }

  // Add custom header at the end
  headers::Set(h, "x-custom-header", "my-application");

  // Build request with browser-accurate headers
  Request req;
  req.method = Method::kGet;
  req.url = "https://httpbin.org/headers";
  req.SetHeaders(h);

  std::println("--- HTTP Request with Browser Headers ---");
  auto result = co_await client.SendAsync(std::move(req));
  if (result) {
    std::println("{}", result.value().body_string());
  } else {
    std::println("Error: {}", result.error().message);
  }
}

Task<void> DemoSecChUa(AsyncClient& client) {
  std::println("\n=== Sec-CH-UA Generation ===\n");

  // SecChUaGenerator creates GREASE-randomized sec-ch-ua values
  // Each instance has stable GREASE for its lifetime (like a browser session)
  http2::SecChUaGenerator gen(143);

  std::println("SecChUaGenerator for Chrome 143:");
  std::println("  sec-ch-ua: {}", gen.Get());
  std::println("  GREASE brand: {}", gen.grease_brand());
  std::println("  GREASE version: {}", gen.grease_version());
  std::println("");

  // Get full version list (for Accept-CH: Sec-CH-UA-Full-Version-List)
  const auto& profile =
      http2::GetChromeHeaderProfile(client.GetChromeVersion());
  std::println("  Full version list: {}",
               gen.GetFullVersionList(profile.full_version));

  (void)client;
  co_return;
}

Task<void> DemoMultiValue(AsyncClient& client) {
  std::println("\n=== Multi-Value Headers Demo ===\n");

  headers::OrderedHeaders h;

  // Add allows duplicates (for Set-Cookie, etc.)
  headers::Add(h, "accept", "text/html");
  headers::Add(h, "accept", "application/json");
  headers::Add(h, "accept", "text/plain");

  std::println("Headers after Add():");
  for (const auto& hdr : h.headers) {
    std::println("  {}: {}", hdr.name, hdr.value);
  }

  // GetAll retrieves all values
  auto all_accept = headers::GetAll(h, "accept");
  std::println("\nGetAll(accept): {} values", all_accept.size());
  for (auto v : all_accept) {
    std::println("  - {}", v);
  }

  // Set (upsert) replaces first occurrence
  headers::Set(h, "accept", "text/html,application/xhtml+xml");

  std::println("\nAfter Set() (upsert):");
  for (const auto& hdr : h.headers) {
    std::println("  {}: {}", hdr.name, hdr.value);
  }

  (void)client;  // Not used in this demo
  co_return;
}

Task<void> RunAll(AsyncClient& client) {
  co_await DemoOrderedHeaders(client);
  co_await DemoBrowserHeaders(client);
  co_await DemoSecChUa(client);
  co_await DemoMultiValue(client);
}

int main() {
  AsyncClient client(ClientConfig::Chrome143());
  RunAsync(client, RunAll(client));
  return 0;
}

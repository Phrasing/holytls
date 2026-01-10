// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "chad/config.h"
#include "http2/chrome_header_builder.h"
#include "http2/chrome_header_profile.h"
#include "http2/sec_ch_ua.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string_view>

using namespace chad::http2;
using chad::ChromeVersion;

// Helper to get header name as string_view
std::string_view GetHeaderName(const nghttp2_nv& nv) {
  return std::string_view(reinterpret_cast<const char*>(nv.name), nv.namelen);
}

// Helper to get header value as string_view
std::string_view GetHeaderValue(const nghttp2_nv& nv) {
  return std::string_view(reinterpret_cast<const char*>(nv.value), nv.valuelen);
}

// Helper to find header position (-1 if not found)
int FindHeaderPosition(const std::vector<nghttp2_nv>& headers,
                       std::string_view name) {
  for (size_t i = 0; i < headers.size(); ++i) {
    if (GetHeaderName(headers[i]) == name) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

void TestBasicHeaderOrder() {
  std::cout << "Testing basic header order... ";

  const auto& profile = GetChromeHeaderProfile(ChromeVersion::kChrome143);
  SecChUaGenerator sec_ch_ua(143);

  ChromeHeaderBuilder builder(profile, sec_ch_ua);
  builder.SetMethod("GET")
      .SetAuthority("example.com")
      .SetPath("/")
      .SetRequestType(RequestType::kNavigation)
      .SetFetchMetadata(FetchSite::kNone, FetchMode::kNavigate,
                        FetchDest::kDocument)
      .SetUserActivated(true);

  auto headers = builder.Build();

  // Verify pseudo-headers are first (indices 0-3)
  assert(GetHeaderName(headers[0]) == ":method");
  assert(GetHeaderName(headers[1]) == ":authority");
  assert(GetHeaderName(headers[2]) == ":scheme");
  assert(GetHeaderName(headers[3]) == ":path");

  // Verify client hints come next
  assert(GetHeaderName(headers[4]) == "sec-ch-ua");
  assert(GetHeaderName(headers[5]) == "sec-ch-ua-mobile");
  assert(GetHeaderName(headers[6]) == "sec-ch-ua-platform");

  // Verify upgrade-insecure-requests for navigation
  assert(GetHeaderName(headers[7]) == "upgrade-insecure-requests");
  assert(GetHeaderValue(headers[7]) == "1");

  // Verify user-agent comes after
  assert(GetHeaderName(headers[8]) == "user-agent");

  std::cout << "PASSED\n";
}

void TestHighEntropyHeaderPlacement() {
  std::cout << "Testing high-entropy header placement... ";

  const auto& profile = GetChromeHeaderProfile(ChromeVersion::kChrome143);
  SecChUaGenerator sec_ch_ua(143);

  ChromeHeaderBuilder builder(profile, sec_ch_ua);
  builder.SetMethod("GET")
      .SetAuthority("example.com")
      .SetPath("/")
      .SetRequestType(RequestType::kNavigation)
      .SetFetchMetadata(FetchSite::kNone, FetchMode::kNavigate,
                        FetchDest::kDocument);

  // Simulate warm connection with Accept-CH response
  AcceptChHints hints;
  hints.full_version_list = true;
  hints.arch = true;
  hints.bitness = true;
  builder.AddHighEntropyHeaders(hints);

  auto headers = builder.Build();

  // Find positions of key headers
  int platform_pos = FindHeaderPosition(headers, "sec-ch-ua-platform");
  int full_version_pos =
      FindHeaderPosition(headers, "sec-ch-ua-full-version-list");
  int arch_pos = FindHeaderPosition(headers, "sec-ch-ua-arch");
  int bitness_pos = FindHeaderPosition(headers, "sec-ch-ua-bitness");
  int upgrade_pos = FindHeaderPosition(headers, "upgrade-insecure-requests");
  int user_agent_pos = FindHeaderPosition(headers, "user-agent");

  // All headers must be present
  assert(platform_pos >= 0);
  assert(full_version_pos >= 0);
  assert(arch_pos >= 0);
  assert(bitness_pos >= 0);
  assert(upgrade_pos >= 0);
  assert(user_agent_pos >= 0);

  // CRITICAL: High-entropy headers MUST come after sec-ch-ua-platform
  // and BEFORE upgrade-insecure-requests/user-agent
  assert(full_version_pos > platform_pos);
  assert(arch_pos > platform_pos);
  assert(bitness_pos > platform_pos);

  assert(full_version_pos < upgrade_pos);
  assert(arch_pos < upgrade_pos);
  assert(bitness_pos < upgrade_pos);

  assert(full_version_pos < user_agent_pos);
  assert(arch_pos < user_agent_pos);
  assert(bitness_pos < user_agent_pos);

  // High-entropy headers should be in order: full_version_list, arch, bitness
  assert(full_version_pos < arch_pos);
  assert(arch_pos < bitness_pos);

  std::cout << "PASSED\n";
}

void TestHighEntropyWithoutNavigation() {
  std::cout << "Testing high-entropy headers without navigation... ";

  const auto& profile = GetChromeHeaderProfile(ChromeVersion::kChrome143);
  SecChUaGenerator sec_ch_ua(143);

  ChromeHeaderBuilder builder(profile, sec_ch_ua);
  builder.SetMethod("GET")
      .SetAuthority("api.example.com")
      .SetPath("/data")
      .SetRequestType(RequestType::kXhr)  // XHR, not navigation
      .SetFetchMetadata(FetchSite::kSameOrigin, FetchMode::kCors,
                        FetchDest::kEmpty);

  AcceptChHints hints;
  hints.full_version_list = true;
  builder.AddHighEntropyHeaders(hints);

  auto headers = builder.Build();

  // XHR requests don't have upgrade-insecure-requests
  int upgrade_pos = FindHeaderPosition(headers, "upgrade-insecure-requests");
  assert(upgrade_pos == -1);

  // But high-entropy should still be placed correctly
  int platform_pos = FindHeaderPosition(headers, "sec-ch-ua-platform");
  int full_version_pos =
      FindHeaderPosition(headers, "sec-ch-ua-full-version-list");
  int user_agent_pos = FindHeaderPosition(headers, "user-agent");

  assert(platform_pos >= 0);
  assert(full_version_pos >= 0);
  assert(user_agent_pos >= 0);

  assert(full_version_pos > platform_pos);
  assert(full_version_pos < user_agent_pos);

  std::cout << "PASSED\n";
}

void TestNoHighEntropyHeaders() {
  std::cout << "Testing without high-entropy headers... ";

  const auto& profile = GetChromeHeaderProfile(ChromeVersion::kChrome143);
  SecChUaGenerator sec_ch_ua(143);

  ChromeHeaderBuilder builder(profile, sec_ch_ua);
  builder.SetMethod("GET")
      .SetAuthority("example.com")
      .SetPath("/")
      .SetRequestType(RequestType::kNavigation)
      .SetFetchMetadata(FetchSite::kNone, FetchMode::kNavigate,
                        FetchDest::kDocument);

  // No AddHighEntropyHeaders call

  auto headers = builder.Build();

  // High-entropy headers should not be present
  assert(FindHeaderPosition(headers, "sec-ch-ua-full-version-list") == -1);
  assert(FindHeaderPosition(headers, "sec-ch-ua-arch") == -1);

  // Standard headers should be present and in order
  int platform_pos = FindHeaderPosition(headers, "sec-ch-ua-platform");
  int upgrade_pos = FindHeaderPosition(headers, "upgrade-insecure-requests");
  int user_agent_pos = FindHeaderPosition(headers, "user-agent");

  assert(platform_pos >= 0);
  assert(upgrade_pos >= 0);
  assert(user_agent_pos >= 0);

  // upgrade-insecure-requests should immediately follow sec-ch-ua-platform
  assert(upgrade_pos == platform_pos + 1);

  std::cout << "PASSED\n";
}

void TestCustomHeadersAtEnd() {
  std::cout << "Testing custom headers at end... ";

  const auto& profile = GetChromeHeaderProfile(ChromeVersion::kChrome143);
  SecChUaGenerator sec_ch_ua(143);

  ChromeHeaderBuilder builder(profile, sec_ch_ua);
  builder.SetMethod("GET")
      .SetAuthority("example.com")
      .SetPath("/")
      .SetRequestType(RequestType::kNavigation)
      .SetFetchMetadata(FetchSite::kNone, FetchMode::kNavigate,
                        FetchDest::kDocument)
      .AddCustomHeader("x-custom-header", "custom-value")
      .AddCustomHeader("authorization", "Bearer token123");

  AcceptChHints hints;
  hints.full_version_list = true;
  builder.AddHighEntropyHeaders(hints);

  auto headers = builder.Build();

  int accept_lang_pos = FindHeaderPosition(headers, "accept-language");
  int custom_pos = FindHeaderPosition(headers, "x-custom-header");
  int auth_pos = FindHeaderPosition(headers, "authorization");

  assert(accept_lang_pos >= 0);
  assert(custom_pos >= 0);
  assert(auth_pos >= 0);

  // Custom headers must come after accept-language (the last standard header)
  assert(custom_pos > accept_lang_pos);
  assert(auth_pos > accept_lang_pos);

  std::cout << "PASSED\n";
}

void TestParseAcceptCh() {
  std::cout << "Testing ParseAcceptCh... ";

  // Test single hint
  AcceptChHints hints1 = ParseAcceptCh("Sec-CH-UA-Full-Version-List");
  assert(hints1.full_version_list == true);
  assert(hints1.arch == false);

  // Test multiple hints with different casing
  AcceptChHints hints2 = ParseAcceptCh(
      "sec-ch-ua-full-version-list, SEC-CH-UA-ARCH, Sec-CH-UA-Bitness");
  assert(hints2.full_version_list == true);
  assert(hints2.arch == true);
  assert(hints2.bitness == true);
  assert(hints2.model == false);

  // Test with whitespace
  AcceptChHints hints3 =
      ParseAcceptCh("  Sec-CH-UA-Model  ,  Sec-CH-UA-WoW64  ");
  assert(hints3.model == true);
  assert(hints3.wow64 == true);
  assert(hints3.full_version_list == false);

  // Test form-factors
  AcceptChHints hints4 = ParseAcceptCh("Sec-CH-UA-Form-Factors");
  assert(hints4.form_factors == true);

  // Test empty string
  AcceptChHints hints5 = ParseAcceptCh("");
  assert(hints5.full_version_list == false);
  assert(hints5.arch == false);

  std::cout << "PASSED\n";
}

void TestAllHighEntropyHeaders() {
  std::cout << "Testing all high-entropy headers... ";

  const auto& profile = GetChromeHeaderProfile(ChromeVersion::kChrome143);
  SecChUaGenerator sec_ch_ua(143);

  ChromeHeaderBuilder builder(profile, sec_ch_ua);
  builder.SetMethod("GET")
      .SetAuthority("example.com")
      .SetPath("/")
      .SetRequestType(RequestType::kNavigation)
      .SetFetchMetadata(FetchSite::kNone, FetchMode::kNavigate,
                        FetchDest::kDocument);

  // Enable all high-entropy headers
  AcceptChHints hints;
  hints.full_version_list = true;
  hints.arch = true;
  hints.bitness = true;
  hints.model = true;
  hints.wow64 = true;
  hints.form_factors = true;
  builder.AddHighEntropyHeaders(hints);

  auto headers = builder.Build();

  // All high-entropy headers should be present
  assert(FindHeaderPosition(headers, "sec-ch-ua-full-version-list") >= 0);
  assert(FindHeaderPosition(headers, "sec-ch-ua-arch") >= 0);
  assert(FindHeaderPosition(headers, "sec-ch-ua-bitness") >= 0);
  assert(FindHeaderPosition(headers, "sec-ch-ua-model") >= 0);
  assert(FindHeaderPosition(headers, "sec-ch-ua-wow64") >= 0);
  assert(FindHeaderPosition(headers, "sec-ch-ua-form-factors") >= 0);

  // Verify order: all between platform and upgrade-insecure-requests
  int platform_pos = FindHeaderPosition(headers, "sec-ch-ua-platform");
  int upgrade_pos = FindHeaderPosition(headers, "upgrade-insecure-requests");

  int full_version_pos =
      FindHeaderPosition(headers, "sec-ch-ua-full-version-list");
  int form_factors_pos = FindHeaderPosition(headers, "sec-ch-ua-form-factors");

  assert(full_version_pos > platform_pos);
  assert(form_factors_pos < upgrade_pos);

  std::cout << "PASSED\n";
}

int main() {
  std::cout << "=== ChromeHeaderBuilder Unit Tests ===\n\n";

  TestBasicHeaderOrder();
  TestHighEntropyHeaderPlacement();
  TestHighEntropyWithoutNavigation();
  TestNoHighEntropyHeaders();
  TestCustomHeadersAtEnd();
  TestParseAcceptCh();
  TestAllHighEntropyHeaders();

  std::cout << "\nAll ChromeHeaderBuilder tests passed!\n";
  return 0;
}

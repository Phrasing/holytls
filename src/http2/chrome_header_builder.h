// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_HTTP2_CHROME_HEADER_BUILDER_H_
#define CHAD_HTTP2_CHROME_HEADER_BUILDER_H_

// Include platform.h first for Windows compatibility and standard types
#include "util/platform.h"

#include <nghttp2/nghttp2.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "http2/chrome_header_profile.h"
#include "http2/sec_ch_ua.h"

namespace chad {
namespace http2 {

// High-entropy Client Hints requested via Accept-CH header
struct AcceptChHints {
  bool full_version_list = false;  // Sec-CH-UA-Full-Version-List
  bool arch = false;               // Sec-CH-UA-Arch
  bool bitness = false;            // Sec-CH-UA-Bitness
  bool model = false;              // Sec-CH-UA-Model (mobile only)
  bool wow64 = false;              // Sec-CH-UA-WoW64 (Windows only)
  bool form_factors = false;       // Sec-CH-UA-Form-Factors
};

// Parse Accept-CH header value into hints struct
AcceptChHints ParseAcceptCh(std::string_view accept_ch);

// Builds HTTP/2 headers in Chrome 143's exact wire order.
//
// Chrome 143 uses a strict header ordering that fingerprinting systems detect.
// This class constructs headers with hardcoded indices to prevent any
// alphabetical sorting by the compiler, standard library, or nghttp2.
//
// Usage:
//   ChromeHeaderBuilder builder(profile, sec_ch_ua_gen);
//   builder.SetMethod("GET")
//          .SetAuthority("example.com")
//          .SetPath("/api/data")
//          .SetRequestType(RequestType::kNavigation)
//          .SetFetchMetadata(FetchSite::kNone, FetchMode::kNavigate, FetchDest::kDocument);
//   auto nva = builder.Build();
//
class ChromeHeaderBuilder {
 public:
  // Create builder with Chrome profile and sec-ch-ua generator
  ChromeHeaderBuilder(const ChromeHeaderProfile& profile,
                      const SecChUaGenerator& sec_ch_ua);

  // Set pseudo-headers (indices 0-3)
  ChromeHeaderBuilder& SetMethod(std::string_view method);
  ChromeHeaderBuilder& SetAuthority(std::string_view authority);
  ChromeHeaderBuilder& SetPath(std::string_view path);
  ChromeHeaderBuilder& SetScheme(std::string_view scheme);  // default: "https"

  // Set request context
  ChromeHeaderBuilder& SetRequestType(RequestType type);
  ChromeHeaderBuilder& SetFetchMetadata(FetchSite site, FetchMode mode, FetchDest dest);
  ChromeHeaderBuilder& SetUserActivated(bool activated);

  // Add high-entropy headers (from Accept-CH response)
  ChromeHeaderBuilder& AddHighEntropyHeaders(const AcceptChHints& hints);

  // Override specific headers (replaces default values)
  ChromeHeaderBuilder& SetUserAgent(std::string_view ua);
  ChromeHeaderBuilder& SetAccept(std::string_view accept);
  ChromeHeaderBuilder& SetAcceptLanguage(std::string_view lang);

  // Add custom header at the end (after standard Chrome headers)
  ChromeHeaderBuilder& AddCustomHeader(std::string_view name, std::string_view value);

  // Build final nghttp2_nv array
  // IMPORTANT: Returned vector must outlive the nghttp2 call!
  std::vector<nghttp2_nv> Build();

  // Get header count (for pre-allocation)
  size_t HeaderCount() const;

 private:
  // Chrome 143 header indices - NEVER change these!
  // The order is critical for fingerprint matching.
  enum HeaderIndex : size_t {
    // Pseudo-headers (always first, in this exact order)
    kMethod = 0,
    kAuthority = 1,
    kScheme = 2,
    kPath = 3,

    // Standard headers in Chrome 143 order
    kSecChUa = 4,
    kSecChUaMobile = 5,
    kSecChUaPlatform = 6,
    kUpgradeInsecureRequests = 7,
    kUserAgent = 8,
    kAccept = 9,
    kSecFetchSite = 10,
    kSecFetchMode = 11,
    kSecFetchUser = 12,
    kSecFetchDest = 13,
    kAcceptEncoding = 14,
    kAcceptLanguage = 15,

    // Marker for base header count
    kBaseHeaderCount = 16
  };

  // Static header names (lowercase, must match HTTP/2 spec)
  static constexpr const char* kHeaderNames[] = {
      ":method",                    // 0
      ":authority",                 // 1
      ":scheme",                    // 2
      ":path",                      // 3
      "sec-ch-ua",                  // 4
      "sec-ch-ua-mobile",           // 5
      "sec-ch-ua-platform",         // 6
      "upgrade-insecure-requests",  // 7
      "user-agent",                 // 8
      "accept",                     // 9
      "sec-fetch-site",             // 10
      "sec-fetch-mode",             // 11
      "sec-fetch-user",             // 12
      "sec-fetch-dest",             // 13
      "accept-encoding",            // 14
      "accept-language",            // 15
  };

  // Create nghttp2_nv with NO_COPY flags (caller owns memory)
  static nghttp2_nv MakeNv(const char* name, size_t name_len,
                           const std::string& value);

  // Profile and generator references
  const ChromeHeaderProfile& profile_;
  const SecChUaGenerator& sec_ch_ua_;

  // Header values storage (indices match HeaderIndex enum)
  std::array<std::string, kBaseHeaderCount> values_;

  // Flags for conditional headers
  bool include_upgrade_insecure_requests_ = false;
  bool include_sec_fetch_user_ = false;

  // High-entropy headers (added after base headers)
  std::vector<std::pair<std::string, std::string>> high_entropy_headers_;

  // Custom headers (added at the end)
  std::vector<std::pair<std::string, std::string>> custom_headers_;

  // Request type for conditional header inclusion
  RequestType request_type_ = RequestType::kNavigation;
};

}  // namespace http2
}  // namespace chad

#endif  // CHAD_HTTP2_CHROME_HEADER_BUILDER_H_

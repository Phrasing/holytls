// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_HTTP2_CHROME_HEADER_PROFILE_H_
#define HOLYTLS_HTTP2_CHROME_HEADER_PROFILE_H_

#include <string>
#include <string_view>
#include <vector>

#include "holytls/config.h"

namespace holytls {
namespace http2 {

// Request type affects which headers are sent and their order
enum class RequestType {
  kNavigation,   // Document navigation (user-initiated)
  kSubresource,  // Script, CSS, image, etc.
  kXhr,          // XMLHttpRequest / fetch()
  kWebSocket,    // WebSocket upgrade
};

// Sec-Fetch-Site values
enum class FetchSite {
  kNone,        // Direct navigation (typed URL, bookmark)
  kSameOrigin,  // Same origin request
  kSameSite,    // Same site but different origin
  kCrossSite,   // Cross-site request
};

// Sec-Fetch-Mode values
enum class FetchMode {
  kNavigate,    // Navigation request
  kCors,        // CORS request
  kNoCors,      // No-CORS request
  kSameOrigin,  // Same-origin only
  kWebSocket,   // WebSocket
};

// Sec-Fetch-Dest values
enum class FetchDest {
  kDocument,  // Main document
  kEmbed,     // <embed>
  kFont,      // Font
  kImage,     // Image
  kManifest,  // Web manifest
  kMedia,     // Audio/video
  kObject,    // <object>
  kScript,    // Script
  kStyle,     // Stylesheet
  kWorker,    // Web worker
  kXslt,      // XSLT
  kEmpty,     // fetch(), XHR
};

// Chrome header profile - defines default headers and their order
struct ChromeHeaderProfile {
  ChromeVersion version;

  // User-Agent string (reduced format per Chrome's UA reduction)
  std::string user_agent;

  // Accept header for navigation requests
  std::string accept_navigation;

  // Accept header for XHR/fetch
  std::string accept_xhr;

  // Accept-Encoding (includes zstd in Chrome 123+)
  std::string accept_encoding;

  // Accept-Language
  std::string accept_language;

  // Platform for sec-ch-ua-platform
  std::string sec_ch_ua_platform;

  // Mobile flag for sec-ch-ua-mobile
  bool sec_ch_ua_mobile;

  // Full version string (e.g., "143.0.7499.192")
  std::string full_version;
};

// Get Chrome header profile for version
const ChromeHeaderProfile& GetChromeHeaderProfile(ChromeVersion version);

// Convert fetch metadata enums to string values
std::string_view FetchSiteToString(FetchSite site);
std::string_view FetchModeToString(FetchMode mode);
std::string_view FetchDestToString(FetchDest dest);

// Header entry for ordered header list
struct HeaderEntry {
  std::string name;
  std::string value;
};

// Build ordered header list for a request
// Headers are returned in Chrome's exact wire order
std::vector<HeaderEntry> BuildChromeHeaders(
    const ChromeHeaderProfile& profile, RequestType request_type,
    FetchSite fetch_site, FetchMode fetch_mode, FetchDest fetch_dest,
    bool user_activated, const std::vector<HeaderEntry>& custom_headers = {});

// Chrome 143 HTTP/2 Connection Preface Constants
// These values define the exact SETTINGS and WINDOW_UPDATE frames Chrome sends.
namespace chrome143 {

// SETTINGS frame parameters (sent in connection preface)
// Chrome 143 sends exactly 4 settings, in this order:
//   SETTINGS_HEADER_TABLE_SIZE (0x1)
//   SETTINGS_ENABLE_PUSH (0x2)
//   SETTINGS_INITIAL_WINDOW_SIZE (0x4)
//   SETTINGS_MAX_HEADER_LIST_SIZE (0x6)

// HPACK dynamic table size (default 4096, Chrome uses 65536)
inline constexpr uint32_t kSettingsHeaderTableSize = 65536;

// Server push disabled (Chrome 143+ disables push)
inline constexpr uint32_t kSettingsEnablePush = 0;

// Stream-level initial window size (6MB = 6291456 bytes)
inline constexpr uint32_t kSettingsInitialWindowSize = 6291456;

// Maximum header list size (256KB = 262144 bytes)
inline constexpr uint32_t kSettingsMaxHeaderListSize = 262144;

// Connection-level WINDOW_UPDATE increment
// Chrome targets 15MB connection window: 15728640 bytes
// Increment = target - default (65535) = 15663105
inline constexpr uint32_t kConnectionWindowIncrement = 15663105;

// Chrome 143 does NOT send these settings (uses defaults):
// - SETTINGS_MAX_CONCURRENT_STREAMS (0x3) - default unlimited
// - SETTINGS_MAX_FRAME_SIZE (0x5) - default 16384

}  // namespace chrome143

}  // namespace http2
}  // namespace holytls

#endif  // HOLYTLS_HTTP2_CHROME_HEADER_PROFILE_H_

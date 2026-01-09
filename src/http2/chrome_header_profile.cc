// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "http2/chrome_header_profile.h"

#include "http2/sec_ch_ua.h"

namespace chad {
namespace http2 {

namespace {

// Chrome 143 profile (latest)
ChromeHeaderProfile CreateChrome143Profile() {
  ChromeHeaderProfile profile;
  profile.version = ChromeVersion::kChrome143;
  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";
  profile.accept_navigation =
      "text/html,application/xhtml+xml,application/xml;q=0.9,"
      "image/avif,image/webp,image/apng,*/*;q=0.8,"
      "application/signed-exchange;v=b3;q=0.7";
  profile.accept_xhr = "*/*";
  profile.accept_encoding = "gzip, deflate, br, zstd";
  profile.accept_language = "en-US,en;q=0.9";
  profile.sec_ch_ua_platform = "\"Windows\"";
  profile.sec_ch_ua_mobile = false;
  profile.full_version = "143.0.7499.192";
  return profile;
}

// Chrome 131 profile
ChromeHeaderProfile CreateChrome131Profile() {
  ChromeHeaderProfile profile;
  profile.version = ChromeVersion::kChrome131;
  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
  profile.accept_navigation =
      "text/html,application/xhtml+xml,application/xml;q=0.9,"
      "image/avif,image/webp,image/apng,*/*;q=0.8,"
      "application/signed-exchange;v=b3;q=0.7";
  profile.accept_xhr = "*/*";
  profile.accept_encoding = "gzip, deflate, br, zstd";
  profile.accept_language = "en-US,en;q=0.9";
  profile.sec_ch_ua_platform = "\"Windows\"";
  profile.sec_ch_ua_mobile = false;
  profile.full_version = "131.0.6778.139";
  return profile;
}

// Chrome 130 profile
ChromeHeaderProfile CreateChrome130Profile() {
  ChromeHeaderProfile profile;
  profile.version = ChromeVersion::kChrome130;
  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
  profile.accept_navigation =
      "text/html,application/xhtml+xml,application/xml;q=0.9,"
      "image/avif,image/webp,image/apng,*/*;q=0.8,"
      "application/signed-exchange;v=b3;q=0.7";
  profile.accept_xhr = "*/*";
  profile.accept_encoding = "gzip, deflate, br, zstd";
  profile.accept_language = "en-US,en;q=0.9";
  profile.sec_ch_ua_platform = "\"Windows\"";
  profile.sec_ch_ua_mobile = false;
  profile.full_version = "130.0.6723.116";
  return profile;
}

// Chrome 125 profile
ChromeHeaderProfile CreateChrome125Profile() {
  ChromeHeaderProfile profile;
  profile.version = ChromeVersion::kChrome125;
  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
  profile.accept_navigation =
      "text/html,application/xhtml+xml,application/xml;q=0.9,"
      "image/avif,image/webp,image/apng,*/*;q=0.8,"
      "application/signed-exchange;v=b3;q=0.7";
  profile.accept_xhr = "*/*";
  profile.accept_encoding = "gzip, deflate, br";  // No zstd before Chrome 123
  profile.accept_language = "en-US,en;q=0.9";
  profile.sec_ch_ua_platform = "\"Windows\"";
  profile.sec_ch_ua_mobile = false;
  profile.full_version = "125.0.6422.112";
  return profile;
}

// Chrome 120 profile
ChromeHeaderProfile CreateChrome120Profile() {
  ChromeHeaderProfile profile;
  profile.version = ChromeVersion::kChrome120;
  profile.user_agent =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
  profile.accept_navigation =
      "text/html,application/xhtml+xml,application/xml;q=0.9,"
      "image/avif,image/webp,image/apng,*/*;q=0.8,"
      "application/signed-exchange;v=b3;q=0.7";
  profile.accept_xhr = "*/*";
  profile.accept_encoding = "gzip, deflate, br";  // No zstd before Chrome 123
  profile.accept_language = "en-US,en;q=0.9";
  profile.sec_ch_ua_platform = "\"Windows\"";
  profile.sec_ch_ua_mobile = false;
  profile.full_version = "120.0.6099.109";
  return profile;
}

// Static profile instances
const ChromeHeaderProfile kProfileChrome120 = CreateChrome120Profile();
const ChromeHeaderProfile kProfileChrome125 = CreateChrome125Profile();
const ChromeHeaderProfile kProfileChrome130 = CreateChrome130Profile();
const ChromeHeaderProfile kProfileChrome131 = CreateChrome131Profile();
const ChromeHeaderProfile kProfileChrome143 = CreateChrome143Profile();

}  // namespace

const ChromeHeaderProfile& GetChromeHeaderProfile(ChromeVersion version) {
  switch (version) {
    case ChromeVersion::kChrome120:
      return kProfileChrome120;
    case ChromeVersion::kChrome125:
      return kProfileChrome125;
    case ChromeVersion::kChrome130:
      return kProfileChrome130;
    case ChromeVersion::kChrome131:
      return kProfileChrome131;
    default:
      return kProfileChrome143;
  }
}

std::string_view FetchSiteToString(FetchSite site) {
  switch (site) {
    case FetchSite::kNone:
      return "none";
    case FetchSite::kSameOrigin:
      return "same-origin";
    case FetchSite::kSameSite:
      return "same-site";
    case FetchSite::kCrossSite:
      return "cross-site";
  }
  return "none";
}

std::string_view FetchModeToString(FetchMode mode) {
  switch (mode) {
    case FetchMode::kNavigate:
      return "navigate";
    case FetchMode::kCors:
      return "cors";
    case FetchMode::kNoCors:
      return "no-cors";
    case FetchMode::kSameOrigin:
      return "same-origin";
    case FetchMode::kWebSocket:
      return "websocket";
  }
  return "navigate";
}

std::string_view FetchDestToString(FetchDest dest) {
  switch (dest) {
    case FetchDest::kDocument:
      return "document";
    case FetchDest::kEmbed:
      return "embed";
    case FetchDest::kFont:
      return "font";
    case FetchDest::kImage:
      return "image";
    case FetchDest::kManifest:
      return "manifest";
    case FetchDest::kMedia:
      return "media";
    case FetchDest::kObject:
      return "object";
    case FetchDest::kScript:
      return "script";
    case FetchDest::kStyle:
      return "style";
    case FetchDest::kWorker:
      return "worker";
    case FetchDest::kXslt:
      return "xslt";
    case FetchDest::kEmpty:
      return "empty";
  }
  return "document";
}

std::vector<HeaderEntry> BuildChromeHeaders(
    const ChromeHeaderProfile& profile,
    RequestType request_type,
    FetchSite fetch_site,
    FetchMode fetch_mode,
    FetchDest fetch_dest,
    bool user_activated,
    const std::vector<HeaderEntry>& custom_headers) {
  std::vector<HeaderEntry> headers;
  headers.reserve(16);

  // Get major version from enum
  int major_version = static_cast<int>(profile.version);

  // Generate GREASE-randomized sec-ch-ua
  std::string sec_ch_ua = GenerateSecChUa(major_version);

  // Chrome 143 Navigation Request Header Order:
  // 1. sec-ch-ua
  // 2. sec-ch-ua-mobile
  // 3. sec-ch-ua-platform
  // 4. upgrade-insecure-requests (navigation only)
  // 5. user-agent
  // 6. accept
  // 7. sec-fetch-site
  // 8. sec-fetch-mode
  // 9. sec-fetch-user (navigation with user activation only)
  // 10. sec-fetch-dest
  // 11. accept-encoding
  // 12. accept-language
  // + any custom headers at the end

  // 1. sec-ch-ua
  headers.push_back({"sec-ch-ua", sec_ch_ua});

  // 2. sec-ch-ua-mobile
  headers.push_back({"sec-ch-ua-mobile",
                     std::string(SecChUaGenerator::GetMobile(profile.sec_ch_ua_mobile))});

  // 3. sec-ch-ua-platform
  headers.push_back({"sec-ch-ua-platform", profile.sec_ch_ua_platform});

  // 4. upgrade-insecure-requests (for navigation only)
  if (request_type == RequestType::kNavigation) {
    headers.push_back({"upgrade-insecure-requests", "1"});
  }

  // 5. user-agent
  headers.push_back({"user-agent", profile.user_agent});

  // 6. accept
  if (request_type == RequestType::kNavigation) {
    headers.push_back({"accept", profile.accept_navigation});
  } else {
    headers.push_back({"accept", profile.accept_xhr});
  }

  // 7. sec-fetch-site
  headers.push_back({"sec-fetch-site", std::string(FetchSiteToString(fetch_site))});

  // 8. sec-fetch-mode
  headers.push_back({"sec-fetch-mode", std::string(FetchModeToString(fetch_mode))});

  // 9. sec-fetch-user (only for navigation with user activation)
  if (request_type == RequestType::kNavigation && user_activated) {
    headers.push_back({"sec-fetch-user", "?1"});
  }

  // 10. sec-fetch-dest
  headers.push_back({"sec-fetch-dest", std::string(FetchDestToString(fetch_dest))});

  // 11. accept-encoding
  headers.push_back({"accept-encoding", profile.accept_encoding});

  // 12. accept-language
  headers.push_back({"accept-language", profile.accept_language});

  // Append custom headers at the end
  for (const auto& header : custom_headers) {
    headers.push_back(header);
  }

  return headers;
}

}  // namespace http2
}  // namespace chad

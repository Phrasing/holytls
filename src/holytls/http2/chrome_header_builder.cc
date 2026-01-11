// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/chrome_header_builder.h"

#include <cstring>

#include "holytls/base/sv_util.h"

namespace holytls {
namespace http2 {

AcceptChHints ParseAcceptCh(std::string_view accept_ch) {
  AcceptChHints hints;

  // Parse comma-separated list of hint names
  size_t pos = 0;
  while (pos < accept_ch.size()) {
    size_t comma = accept_ch.find(',', pos);
    if (comma == std::string_view::npos) {
      comma = accept_ch.size();
    }

    std::string_view hint = sv::Trim(accept_ch.substr(pos, comma - pos));

    if (sv::EqualsIgnoreCase(hint, "Sec-CH-UA-Full-Version-List")) {
      hints.full_version_list = true;
    } else if (sv::EqualsIgnoreCase(hint, "Sec-CH-UA-Arch")) {
      hints.arch = true;
    } else if (sv::EqualsIgnoreCase(hint, "Sec-CH-UA-Bitness")) {
      hints.bitness = true;
    } else if (sv::EqualsIgnoreCase(hint, "Sec-CH-UA-Model")) {
      hints.model = true;
    } else if (sv::EqualsIgnoreCase(hint, "Sec-CH-UA-WoW64")) {
      hints.wow64 = true;
    } else if (sv::EqualsIgnoreCase(hint, "Sec-CH-UA-Form-Factors")) {
      hints.form_factors = true;
    }

    pos = comma + 1;
  }

  return hints;
}

// Static header names definition
constexpr const char* ChromeHeaderBuilder::kHeaderNames[];

ChromeHeaderBuilder::ChromeHeaderBuilder(const ChromeHeaderProfile& profile,
                                         const SecChUaGenerator& sec_ch_ua)
    : profile_(profile), sec_ch_ua_(sec_ch_ua) {
  // Initialize with default values from profile

  // Pseudo-headers (will be set by caller)
  values_[kScheme] = "https";

  // Client hints (always sent)
  values_[kSecChUa] = sec_ch_ua_.Get();
  values_[kSecChUaMobile] =
      std::string(SecChUaGenerator::GetMobile(profile_.sec_ch_ua_mobile));
  values_[kSecChUaPlatform] = profile_.sec_ch_ua_platform;

  // Standard headers
  values_[kUserAgent] = profile_.user_agent;
  values_[kAccept] = profile_.accept_navigation;
  values_[kAcceptEncoding] = profile_.accept_encoding;
  values_[kAcceptLanguage] = profile_.accept_language;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetMethod(std::string_view method) {
  values_[kMethod] = std::string(method);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetAuthority(
    std::string_view authority) {
  values_[kAuthority] = std::string(authority);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetPath(std::string_view path) {
  values_[kPath] = std::string(path);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetScheme(std::string_view scheme) {
  values_[kScheme] = std::string(scheme);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetRequestType(RequestType type) {
  request_type_ = type;

  // Update accept header based on request type
  if (type == RequestType::kNavigation) {
    values_[kAccept] = profile_.accept_navigation;
    include_upgrade_insecure_requests_ = true;
  } else {
    values_[kAccept] = profile_.accept_xhr;
    include_upgrade_insecure_requests_ = false;
  }

  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetFetchMetadata(FetchSite site,
                                                           FetchMode mode,
                                                           FetchDest dest) {
  values_[kSecFetchSite] = std::string(FetchSiteToString(site));
  values_[kSecFetchMode] = std::string(FetchModeToString(mode));
  values_[kSecFetchDest] = std::string(FetchDestToString(dest));
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetUserActivated(bool activated) {
  include_sec_fetch_user_ =
      activated && (request_type_ == RequestType::kNavigation);
  if (include_sec_fetch_user_) {
    values_[kSecFetchUser] = "?1";
  }
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::AddHighEntropyHeaders(
    const AcceptChHints& hints) {
  // Add high-entropy headers in Chrome's order
  // These appear after the base headers but before custom headers

  if (hints.full_version_list) {
    high_entropy_headers_.emplace_back(
        "sec-ch-ua-full-version-list",
        sec_ch_ua_.GetFullVersionList(profile_.full_version));
  }

  if (hints.arch) {
    // x86 for 32-bit, x86_64 for 64-bit, arm for ARM
    high_entropy_headers_.emplace_back("sec-ch-ua-arch", "\"x86\"");
  }

  if (hints.bitness) {
    // "64" for 64-bit, "32" for 32-bit
    high_entropy_headers_.emplace_back("sec-ch-ua-bitness", "\"64\"");
  }

  if (hints.model) {
    // Empty for desktop, device model for mobile
    high_entropy_headers_.emplace_back("sec-ch-ua-model", "\"\"");
  }

  if (hints.wow64) {
    // Windows-on-Windows 64-bit
    high_entropy_headers_.emplace_back("sec-ch-ua-wow64", "?0");
  }

  if (hints.form_factors) {
    // "Desktop", "Tablet", "Mobile", etc.
    high_entropy_headers_.emplace_back("sec-ch-ua-form-factors", "\"Desktop\"");
  }

  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetUserAgent(std::string_view ua) {
  values_[kUserAgent] = std::string(ua);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetAccept(std::string_view accept) {
  values_[kAccept] = std::string(accept);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::SetAcceptLanguage(
    std::string_view lang) {
  values_[kAcceptLanguage] = std::string(lang);
  return *this;
}

ChromeHeaderBuilder& ChromeHeaderBuilder::AddCustomHeader(
    std::string_view name, std::string_view value) {
  // HTTP/2 requires lowercase header names
  // Branchless ASCII lowercase - avoids std::tolower locale overhead
  // and enables compiler auto-vectorization (SIMD)
  std::string lower_name;
  lower_name.resize_and_overwrite(name.size(), [&](char* buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
      char c = name[i];
      buf[i] = static_cast<char>(c + ((c >= 'A' && c <= 'Z') * 32));
    }
    return n;
  });
  custom_headers_.emplace_back(std::move(lower_name), std::string(value));
  return *this;
}

nghttp2_nv ChromeHeaderBuilder::MakeNv(const char* name, size_t name_len,
                                       const std::string& value) {
  nghttp2_nv nv;
  nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name));
  nv.namelen = name_len;
  nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
  nv.valuelen = value.size();
  // NO_COPY flags preserve order and prevent nghttp2 from reallocating
  nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
  return nv;
}

size_t ChromeHeaderBuilder::HeaderCount() const {
  size_t count = 0;

  // Always include pseudo-headers
  count += 4;  // :method, :authority, :scheme, :path

  // Client hints (always sent)
  count += 3;  // sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform

  // Conditional headers
  if (include_upgrade_insecure_requests_) ++count;

  // Always include these
  count += 1;  // user-agent
  count += 1;  // accept
  count += 3;  // sec-fetch-site, sec-fetch-mode, sec-fetch-dest

  if (include_sec_fetch_user_) ++count;

  count += 2;  // accept-encoding, accept-language

  // High-entropy headers
  count += high_entropy_headers_.size();

  // Custom headers
  count += custom_headers_.size();

  return count;
}

std::vector<nghttp2_nv> ChromeHeaderBuilder::Build() {
  std::vector<nghttp2_nv> nva;
  nva.reserve(HeaderCount());

  // Helper to add header by index
  auto add_header = [&](HeaderIndex idx) {
    nva.push_back(MakeNv(kHeaderNames[idx], std::strlen(kHeaderNames[idx]),
                         values_[idx]));
  };

  // Pseudo-headers (indices 0-3) - MUST be first, in this exact order
  add_header(kMethod);
  add_header(kAuthority);
  add_header(kScheme);
  add_header(kPath);

  // Client hints (indices 4-6)
  add_header(kSecChUa);
  add_header(kSecChUaMobile);
  add_header(kSecChUaPlatform);

  // High-entropy headers (from Accept-CH) - MUST come after sec-ch-ua-platform
  // and BEFORE upgrade-insecure-requests/user-agent
  for (const auto& [name, value] : high_entropy_headers_) {
    nghttp2_nv nv;
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
    nv.namelen = name.size();
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
    nv.valuelen = value.size();
    nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    nva.push_back(nv);
  }

  // upgrade-insecure-requests (index 7) - navigation only
  if (include_upgrade_insecure_requests_) {
    values_[kUpgradeInsecureRequests] = "1";
    add_header(kUpgradeInsecureRequests);
  }

  // user-agent (index 8)
  add_header(kUserAgent);

  // accept (index 9)
  add_header(kAccept);

  // sec-fetch-* (indices 10-13)
  add_header(kSecFetchSite);
  add_header(kSecFetchMode);
  if (include_sec_fetch_user_) {
    add_header(kSecFetchUser);
  }
  add_header(kSecFetchDest);

  // accept-encoding, accept-language (indices 14-15)
  add_header(kAcceptEncoding);
  add_header(kAcceptLanguage);

  // Custom headers at the end
  for (const auto& [name, value] : custom_headers_) {
    nghttp2_nv nv;
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
    nv.namelen = name.size();
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
    nv.valuelen = value.size();
    nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    nva.push_back(nv);
  }

  return nva;
}

}  // namespace http2
}  // namespace holytls

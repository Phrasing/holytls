// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/header_ids.h"

#include <algorithm>
#include <cctype>

namespace holytls {
namespace http2 {

namespace {

// Header name table (lowercase, matching enum order)
constexpr std::string_view kHeaderNames[] = {
    "cache-control",
    "connection",
    "date",
    "keep-alive",
    "via",
    "warning",
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "authorization",
    "cookie",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "origin",
    "range",
    "referer",
    "user-agent",
    "accept-ranges",
    "age",
    "etag",
    "expires",
    "last-modified",
    "location",
    "retry-after",
    "server",
    "set-cookie",
    "vary",
    "www-authenticate",
    "allow",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-range",
    "content-type",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-request-headers",
    "access-control-request-method",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "content-security-policy",
    "transfer-encoding",
    "upgrade",
    "alt-svc",
    "link",
    "pragma",
};

static_assert(sizeof(kHeaderNames) / sizeof(kHeaderNames[0]) ==
                  static_cast<size_t>(HeaderId::kKnownCount),
              "Header name table size mismatch");

// Case-insensitive comparison
bool EqualsIgnoreCase(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

}  // namespace

HeaderId LookupHeaderId(std::string_view name) {
  if (name.empty()) return HeaderId::kCustom;

  // Fast path: dispatch on first character (lowercase)
  int first = std::tolower(static_cast<unsigned char>(name[0]));

  switch (first) {
    case 'a':
      if (EqualsIgnoreCase(name, "accept")) return HeaderId::kAccept;
      if (EqualsIgnoreCase(name, "accept-charset"))
        return HeaderId::kAcceptCharset;
      if (EqualsIgnoreCase(name, "accept-encoding"))
        return HeaderId::kAcceptEncoding;
      if (EqualsIgnoreCase(name, "accept-language"))
        return HeaderId::kAcceptLanguage;
      if (EqualsIgnoreCase(name, "accept-ranges"))
        return HeaderId::kAcceptRanges;
      if (EqualsIgnoreCase(name, "access-control-allow-credentials"))
        return HeaderId::kAccessControlAllowCredentials;
      if (EqualsIgnoreCase(name, "access-control-allow-headers"))
        return HeaderId::kAccessControlAllowHeaders;
      if (EqualsIgnoreCase(name, "access-control-allow-methods"))
        return HeaderId::kAccessControlAllowMethods;
      if (EqualsIgnoreCase(name, "access-control-allow-origin"))
        return HeaderId::kAccessControlAllowOrigin;
      if (EqualsIgnoreCase(name, "access-control-expose-headers"))
        return HeaderId::kAccessControlExposeHeaders;
      if (EqualsIgnoreCase(name, "access-control-max-age"))
        return HeaderId::kAccessControlMaxAge;
      if (EqualsIgnoreCase(name, "access-control-request-headers"))
        return HeaderId::kAccessControlRequestHeaders;
      if (EqualsIgnoreCase(name, "access-control-request-method"))
        return HeaderId::kAccessControlRequestMethod;
      if (EqualsIgnoreCase(name, "age")) return HeaderId::kAge;
      if (EqualsIgnoreCase(name, "allow")) return HeaderId::kAllow;
      if (EqualsIgnoreCase(name, "alt-svc")) return HeaderId::kAltSvc;
      if (EqualsIgnoreCase(name, "authorization"))
        return HeaderId::kAuthorization;
      break;

    case 'c':
      if (EqualsIgnoreCase(name, "cache-control"))
        return HeaderId::kCacheControl;
      if (EqualsIgnoreCase(name, "connection")) return HeaderId::kConnection;
      if (EqualsIgnoreCase(name, "content-disposition"))
        return HeaderId::kContentDisposition;
      if (EqualsIgnoreCase(name, "content-encoding"))
        return HeaderId::kContentEncoding;
      if (EqualsIgnoreCase(name, "content-language"))
        return HeaderId::kContentLanguage;
      if (EqualsIgnoreCase(name, "content-length"))
        return HeaderId::kContentLength;
      if (EqualsIgnoreCase(name, "content-location"))
        return HeaderId::kContentLocation;
      if (EqualsIgnoreCase(name, "content-range"))
        return HeaderId::kContentRange;
      if (EqualsIgnoreCase(name, "content-security-policy"))
        return HeaderId::kContentSecurityPolicy;
      if (EqualsIgnoreCase(name, "content-type")) return HeaderId::kContentType;
      if (EqualsIgnoreCase(name, "cookie")) return HeaderId::kCookie;
      break;

    case 'd':
      if (EqualsIgnoreCase(name, "date")) return HeaderId::kDate;
      break;

    case 'e':
      if (EqualsIgnoreCase(name, "etag")) return HeaderId::kEtag;
      if (EqualsIgnoreCase(name, "expires")) return HeaderId::kExpires;
      break;

    case 'h':
      if (EqualsIgnoreCase(name, "host")) return HeaderId::kHost;
      break;

    case 'i':
      if (EqualsIgnoreCase(name, "if-match")) return HeaderId::kIfMatch;
      if (EqualsIgnoreCase(name, "if-modified-since"))
        return HeaderId::kIfModifiedSince;
      if (EqualsIgnoreCase(name, "if-none-match"))
        return HeaderId::kIfNoneMatch;
      if (EqualsIgnoreCase(name, "if-range")) return HeaderId::kIfRange;
      if (EqualsIgnoreCase(name, "if-unmodified-since"))
        return HeaderId::kIfUnmodifiedSince;
      break;

    case 'k':
      if (EqualsIgnoreCase(name, "keep-alive")) return HeaderId::kKeepAlive;
      break;

    case 'l':
      if (EqualsIgnoreCase(name, "last-modified"))
        return HeaderId::kLastModified;
      if (EqualsIgnoreCase(name, "link")) return HeaderId::kLink;
      if (EqualsIgnoreCase(name, "location")) return HeaderId::kLocation;
      break;

    case 'o':
      if (EqualsIgnoreCase(name, "origin")) return HeaderId::kOrigin;
      break;

    case 'p':
      if (EqualsIgnoreCase(name, "pragma")) return HeaderId::kPragma;
      break;

    case 'r':
      if (EqualsIgnoreCase(name, "range")) return HeaderId::kRange;
      if (EqualsIgnoreCase(name, "referer")) return HeaderId::kReferer;
      if (EqualsIgnoreCase(name, "retry-after")) return HeaderId::kRetryAfter;
      break;

    case 's':
      if (EqualsIgnoreCase(name, "server")) return HeaderId::kServer;
      if (EqualsIgnoreCase(name, "set-cookie")) return HeaderId::kSetCookie;
      if (EqualsIgnoreCase(name, "strict-transport-security"))
        return HeaderId::kStrictTransportSecurity;
      break;

    case 't':
      if (EqualsIgnoreCase(name, "transfer-encoding"))
        return HeaderId::kTransferEncoding;
      break;

    case 'u':
      if (EqualsIgnoreCase(name, "upgrade")) return HeaderId::kUpgrade;
      if (EqualsIgnoreCase(name, "user-agent")) return HeaderId::kUserAgent;
      break;

    case 'v':
      if (EqualsIgnoreCase(name, "vary")) return HeaderId::kVary;
      if (EqualsIgnoreCase(name, "via")) return HeaderId::kVia;
      break;

    case 'w':
      if (EqualsIgnoreCase(name, "warning")) return HeaderId::kWarning;
      if (EqualsIgnoreCase(name, "www-authenticate"))
        return HeaderId::kWwwAuthenticate;
      break;

    case 'x':
      if (EqualsIgnoreCase(name, "x-content-type-options"))
        return HeaderId::kXContentTypeOptions;
      if (EqualsIgnoreCase(name, "x-frame-options"))
        return HeaderId::kXFrameOptions;
      if (EqualsIgnoreCase(name, "x-xss-protection"))
        return HeaderId::kXXssProtection;
      break;
  }

  return HeaderId::kCustom;
}

std::string_view HeaderIdToName(HeaderId id) {
  auto index = static_cast<size_t>(id);
  if (index < static_cast<size_t>(HeaderId::kKnownCount)) {
    return kHeaderNames[index];
  }
  return {};
}

}  // namespace http2
}  // namespace holytls

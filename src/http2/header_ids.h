// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_HTTP2_HEADER_IDS_H_
#define CHAD_HTTP2_HEADER_IDS_H_

#include <cstdint>
#include <string_view>

namespace chad {
namespace http2 {

// Common HTTP header names interned as enum for zero-allocation lookup.
// Values 0-254 are known headers, 255 (kCustom) indicates name stored in
// buffer.
enum class HeaderId : uint8_t {
  // General headers
  kCacheControl = 0,  // cache-control
  kConnection,        // connection
  kDate,              // date
  kKeepAlive,         // keep-alive
  kVia,               // via
  kWarning,           // warning

  // Request headers
  kAccept,             // accept
  kAcceptCharset,      // accept-charset
  kAcceptEncoding,     // accept-encoding
  kAcceptLanguage,     // accept-language
  kAuthorization,      // authorization
  kCookie,             // cookie
  kHost,               // host
  kIfMatch,            // if-match
  kIfModifiedSince,    // if-modified-since
  kIfNoneMatch,        // if-none-match
  kIfRange,            // if-range
  kIfUnmodifiedSince,  // if-unmodified-since
  kOrigin,             // origin
  kRange,              // range
  kReferer,            // referer
  kUserAgent,          // user-agent

  // Response headers
  kAcceptRanges,     // accept-ranges
  kAge,              // age
  kEtag,             // etag
  kExpires,          // expires
  kLastModified,     // last-modified
  kLocation,         // location
  kRetryAfter,       // retry-after
  kServer,           // server
  kSetCookie,        // set-cookie
  kVary,             // vary
  kWwwAuthenticate,  // www-authenticate

  // Entity headers
  kAllow,               // allow
  kContentDisposition,  // content-disposition
  kContentEncoding,     // content-encoding
  kContentLanguage,     // content-language
  kContentLength,       // content-length
  kContentLocation,     // content-location
  kContentRange,        // content-range
  kContentType,         // content-type

  // CORS headers
  kAccessControlAllowCredentials,  // access-control-allow-credentials
  kAccessControlAllowHeaders,      // access-control-allow-headers
  kAccessControlAllowMethods,      // access-control-allow-methods
  kAccessControlAllowOrigin,       // access-control-allow-origin
  kAccessControlExposeHeaders,     // access-control-expose-headers
  kAccessControlMaxAge,            // access-control-max-age
  kAccessControlRequestHeaders,    // access-control-request-headers
  kAccessControlRequestMethod,     // access-control-request-method

  // Security headers
  kStrictTransportSecurity,  // strict-transport-security
  kXContentTypeOptions,      // x-content-type-options
  kXFrameOptions,            // x-frame-options
  kXXssProtection,           // x-xss-protection
  kContentSecurityPolicy,    // content-security-policy

  // Other common headers
  kTransferEncoding,  // transfer-encoding
  kUpgrade,           // upgrade
  kAltSvc,            // alt-svc
  kLink,              // link
  kPragma,            // pragma

  // Total count of known headers
  kKnownCount,

  // Unknown header - name stored in buffer
  kCustom = 0xFF
};

// Lookup header ID from name (case-insensitive).
// Returns kCustom if not a known header.
HeaderId LookupHeaderId(std::string_view name);

// Get canonical header name from ID.
// Returns empty string for kCustom.
std::string_view HeaderIdToName(HeaderId id);

}  // namespace http2
}  // namespace chad

#endif  // CHAD_HTTP2_HEADER_IDS_H_

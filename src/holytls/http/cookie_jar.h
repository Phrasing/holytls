// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// CookieJar - In-memory cookie storage and management.
// Handles Set-Cookie parsing, domain/path matching, and Cookie header building.

#ifndef HOLYTLS_HTTP_COOKIE_JAR_H_
#define HOLYTLS_HTTP_COOKIE_JAR_H_

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace holytls {
namespace http {

// SameSite attribute values
enum class SameSite {
  kNone,    // Cookie sent with all requests
  kLax,     // Cookie sent with top-level navigations and GET from third-party
  kStrict,  // Cookie only sent with same-site requests
};

// Represents a single HTTP cookie
struct Cookie {
  std::string name;
  std::string value;
  std::string domain;   // Domain the cookie applies to (with or without leading dot)
  std::string path;     // Path the cookie applies to
  uint64_t expires_ms = 0;  // Expiration time in milliseconds since epoch (0 = session)
  bool secure = false;      // Only send over HTTPS
  bool http_only = false;   // Not accessible via JavaScript
  SameSite same_site = SameSite::kLax;

  // Check if cookie has expired
  bool IsExpired(uint64_t now_ms) const {
    return expires_ms > 0 && now_ms >= expires_ms;
  }

  // Check if this is a session cookie (no expiration)
  bool IsSession() const { return expires_ms == 0; }
};

// In-memory cookie storage with thread-safe access.
// Implements RFC 6265 cookie matching semantics.
class CookieJar {
 public:
  CookieJar() = default;
  ~CookieJar() = default;

  // Non-copyable, movable
  CookieJar(const CookieJar&) = delete;
  CookieJar& operator=(const CookieJar&) = delete;
  CookieJar(CookieJar&&) = default;
  CookieJar& operator=(CookieJar&&) = default;

  // Parse a Set-Cookie header and store the cookie.
  // url: The URL the response came from (for domain/path defaults)
  // header: The Set-Cookie header value (without "Set-Cookie: " prefix)
  void ProcessSetCookie(std::string_view url, std::string_view header);

  // Build the Cookie header value for a request.
  // Returns empty string if no cookies match.
  // url: The URL being requested
  std::string GetCookieHeader(std::string_view url) const;

  // Get all cookies matching a URL (for inspection)
  std::vector<Cookie> GetCookies(std::string_view url) const;

  // Manual cookie management
  void SetCookie(const Cookie& cookie);
  void SetCookie(Cookie&& cookie);

  // Remove a specific cookie by name and domain
  bool RemoveCookie(std::string_view name, std::string_view domain);

  // Clear all cookies
  void ClearAll();

  // Clear expired cookies
  // Returns number of cookies removed
  size_t ClearExpired();

  // Clear cookies for a specific domain
  size_t ClearDomain(std::string_view domain);

  // Get total cookie count
  size_t Size() const;

  // Check if jar is empty
  bool Empty() const;

  // Debug: Get all cookies (for debugging only)
  std::vector<Cookie> GetAllCookies() const;

 private:
  // Parse URL into components for cookie matching
  struct UrlParts {
    std::string scheme;
    std::string host;
    uint16_t port;
    std::string path;
  };
  static bool ParseUrl(std::string_view url, UrlParts* parts);

  // Check if a cookie matches a URL
  static bool Matches(const Cookie& cookie, const UrlParts& url, bool is_secure);

  // Check if host matches cookie domain (handles leading dot)
  static bool DomainMatches(std::string_view host, std::string_view cookie_domain);

  // Check if request path matches cookie path
  static bool PathMatches(std::string_view request_path, std::string_view cookie_path);

  // Get current time in milliseconds
  static uint64_t NowMs();

  // Parse Set-Cookie header into Cookie struct
  static bool ParseSetCookie(std::string_view header, std::string_view request_host,
                             std::string_view request_path, Cookie* cookie);

  // Parse individual cookie attributes
  static void ParseAttribute(std::string_view attr, Cookie* cookie,
                             uint64_t now_ms);

  mutable std::mutex mutex_;
  std::vector<Cookie> cookies_;
};

}  // namespace http
}  // namespace holytls

#endif  // HOLYTLS_HTTP_COOKIE_JAR_H_

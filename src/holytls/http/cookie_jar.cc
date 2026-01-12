// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http/cookie_jar.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>

#include "holytls/util/sv_helpers.h"

namespace holytls {
namespace http {

// Import helpers for cleaner code
using util::EqualsIgnoreCase;
using util::ToLower;
using util::Trim;

namespace {

// Parse HTTP date formats (simplified - handles common formats)
// Returns milliseconds since epoch, or 0 on failure
uint64_t ParseHttpDate(std::string_view date) {
  // This is a simplified parser - a full implementation would handle
  // RFC 1123, RFC 850, and asctime formats
  // For now, we'll just try to parse the most common format:
  // "Wed, 09 Jun 2021 10:18:14 GMT"

  static const char* kMonths[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
  };

  // Skip day name if present
  size_t pos = date.find(',');
  if (pos != std::string_view::npos) {
    date = Trim(date.substr(pos + 1));
  }

  // Parse: DD Mon YYYY HH:MM:SS
  int day = 0, year = 0, hour = 0, min = 0, sec = 0;
  int month = -1;

  // Extract day
  while (!date.empty() && std::isdigit(static_cast<unsigned char>(date[0]))) {
    day = day * 10 + (date[0] - '0');
    date.remove_prefix(1);
  }
  date = Trim(date);

  // Extract month name
  if (date.size() >= 3) {
    std::string mon_str = ToLower(date.substr(0, 3));
    for (int i = 0; i < 12; ++i) {
      if (mon_str == kMonths[i]) {
        month = i;
        break;
      }
    }
    date.remove_prefix(3);
  }
  date = Trim(date);

  if (month < 0) return 0;

  // Extract year
  while (!date.empty() && std::isdigit(static_cast<unsigned char>(date[0]))) {
    year = year * 10 + (date[0] - '0');
    date.remove_prefix(1);
  }
  date = Trim(date);

  // Handle 2-digit years
  if (year < 100) {
    year += (year < 70) ? 2000 : 1900;
  }

  // Extract time HH:MM:SS
  if (date.size() >= 8) {
    hour = (date[0] - '0') * 10 + (date[1] - '0');
    min = (date[3] - '0') * 10 + (date[4] - '0');
    sec = (date[6] - '0') * 10 + (date[7] - '0');
  }

  // Convert to timestamp (simplified - doesn't handle all edge cases)
  // Days since epoch for each month start (non-leap year base)
  static const int kDaysBeforeMonth[] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
  };

  // Calculate days since 1970
  int64_t days = (year - 1970) * 365;
  // Add leap years
  days += (year - 1969) / 4;
  days -= (year - 1901) / 100;
  days += (year - 1601) / 400;
  // Add days for months
  days += kDaysBeforeMonth[month];
  // Add leap day if applicable
  if (month > 1 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
    days += 1;
  }
  days += day - 1;

  int64_t timestamp = days * 86400 + hour * 3600 + min * 60 + sec;
  return static_cast<uint64_t>(timestamp) * 1000;
}

}  // namespace

void CookieJar::ProcessSetCookie(std::string_view url, std::string_view header) {
  UrlParts parts;
  if (!ParseUrl(url, &parts)) {
    return;
  }

  Cookie cookie;
  if (!ParseSetCookie(header, parts.host, parts.path, &cookie)) {
    return;
  }

  // Validate domain - must be same or parent of request host
  if (!cookie.domain.empty()) {
    std::string lower_host = ToLower(parts.host);
    std::string lower_domain = ToLower(cookie.domain);

    // Remove leading dot for comparison
    std::string_view domain_check = lower_domain;
    if (!domain_check.empty() && domain_check[0] == '.') {
      domain_check.remove_prefix(1);
    }

    // Domain must match or be a parent domain
    if (lower_host != domain_check) {
      // Check if it's a valid parent domain
      if (lower_host.size() <= domain_check.size() ||
          lower_host.substr(lower_host.size() - domain_check.size()) != domain_check ||
          lower_host[lower_host.size() - domain_check.size() - 1] != '.') {
        return;  // Invalid domain - reject cookie
      }
    }
  } else {
    // No domain specified - use request host (host-only cookie)
    cookie.domain = ToLower(parts.host);
  }

  // Default path if not specified
  if (cookie.path.empty()) {
    // Use directory of request path
    size_t last_slash = parts.path.rfind('/');
    if (last_slash != std::string::npos && last_slash > 0) {
      cookie.path = parts.path.substr(0, last_slash);
    } else {
      cookie.path = "/";
    }
  }

  SetCookie(std::move(cookie));
}

std::string CookieJar::GetCookieHeader(std::string_view url) const {
  UrlParts parts;
  if (!ParseUrl(url, &parts)) {
    return "";
  }

  bool is_secure = (parts.scheme == "https");
  uint64_t now = NowMs();

  std::string result;
  std::lock_guard<std::mutex> lock(mutex_);

  for (const auto& cookie : cookies_) {
    // Skip expired cookies
    if (cookie.IsExpired(now)) {
      continue;
    }

    // Skip secure cookies for non-HTTPS
    if (cookie.secure && !is_secure) {
      continue;
    }

    // Check domain and path match
    if (!Matches(cookie, parts, is_secure)) {
      continue;
    }

    // Append to result
    if (!result.empty()) {
      result += "; ";
    }
    result += cookie.name;
    result += "=";
    result += cookie.value;
  }

  return result;
}

std::vector<Cookie> CookieJar::GetCookies(std::string_view url) const {
  UrlParts parts;
  if (!ParseUrl(url, &parts)) {
    return {};
  }

  bool is_secure = (parts.scheme == "https");
  uint64_t now = NowMs();

  std::vector<Cookie> result;
  std::lock_guard<std::mutex> lock(mutex_);

  for (const auto& cookie : cookies_) {
    if (!cookie.IsExpired(now) && Matches(cookie, parts, is_secure)) {
      result.push_back(cookie);
    }
  }

  return result;
}

void CookieJar::SetCookie(const Cookie& cookie) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Check if cookie already exists (same name, domain, path)
  for (auto& existing : cookies_) {
    if (existing.name == cookie.name &&
        EqualsIgnoreCase(existing.domain, cookie.domain) &&
        existing.path == cookie.path) {
      // Update existing cookie
      existing = cookie;
      return;
    }
  }

  // Add new cookie
  cookies_.push_back(cookie);
}

void CookieJar::SetCookie(Cookie&& cookie) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Check if cookie already exists
  for (auto& existing : cookies_) {
    if (existing.name == cookie.name &&
        EqualsIgnoreCase(existing.domain, cookie.domain) &&
        existing.path == cookie.path) {
      existing = std::move(cookie);
      return;
    }
  }

  cookies_.push_back(std::move(cookie));
}

bool CookieJar::RemoveCookie(std::string_view name, std::string_view domain) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = std::remove_if(cookies_.begin(), cookies_.end(),
                           [&](const Cookie& c) {
                             return c.name == name &&
                                    EqualsIgnoreCase(c.domain, domain);
                           });

  if (it != cookies_.end()) {
    cookies_.erase(it, cookies_.end());
    return true;
  }
  return false;
}

void CookieJar::ClearAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  cookies_.clear();
}

size_t CookieJar::ClearExpired() {
  uint64_t now = NowMs();
  std::lock_guard<std::mutex> lock(mutex_);

  size_t before = cookies_.size();
  auto it = std::remove_if(cookies_.begin(), cookies_.end(),
                           [now](const Cookie& c) { return c.IsExpired(now); });
  cookies_.erase(it, cookies_.end());

  return before - cookies_.size();
}

size_t CookieJar::ClearDomain(std::string_view domain) {
  std::lock_guard<std::mutex> lock(mutex_);

  size_t before = cookies_.size();
  auto it = std::remove_if(cookies_.begin(), cookies_.end(),
                           [&](const Cookie& c) {
                             return EqualsIgnoreCase(c.domain, domain);
                           });
  cookies_.erase(it, cookies_.end());

  return before - cookies_.size();
}

size_t CookieJar::Size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cookies_.size();
}

bool CookieJar::Empty() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cookies_.empty();
}

std::vector<Cookie> CookieJar::GetAllCookies() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cookies_;
}

bool CookieJar::ParseUrl(std::string_view url, UrlParts* parts) {
  // Parse scheme
  size_t scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos) {
    return false;
  }
  parts->scheme = ToLower(url.substr(0, scheme_end));
  url.remove_prefix(scheme_end + 3);

  // Parse host and port
  size_t path_start = url.find('/');
  std::string_view authority = (path_start != std::string_view::npos)
                                   ? url.substr(0, path_start)
                                   : url;

  size_t port_start = authority.rfind(':');
  if (port_start != std::string_view::npos) {
    parts->host = ToLower(authority.substr(0, port_start));
    std::string_view port_str = authority.substr(port_start + 1);
    parts->port = 0;
    for (char c : port_str) {
      if (c < '0' || c > '9') break;
      parts->port = parts->port * 10 + (c - '0');
    }
  } else {
    parts->host = ToLower(authority);
    parts->port = (parts->scheme == "https") ? 443 : 80;
  }

  // Parse path
  if (path_start != std::string_view::npos) {
    size_t query_start = url.find('?', path_start);
    if (query_start != std::string_view::npos) {
      parts->path = std::string(url.substr(path_start, query_start - path_start));
    } else {
      parts->path = std::string(url.substr(path_start));
    }
  } else {
    parts->path = "/";
  }

  return !parts->host.empty();
}

bool CookieJar::Matches(const Cookie& cookie, const UrlParts& url, bool is_secure) {
  // Check secure flag
  if (cookie.secure && !is_secure) {
    return false;
  }

  // Check domain match
  if (!DomainMatches(url.host, cookie.domain)) {
    return false;
  }

  // Check path match
  if (!PathMatches(url.path, cookie.path)) {
    return false;
  }

  return true;
}

bool CookieJar::DomainMatches(std::string_view host, std::string_view cookie_domain) {
  // Normalize: remove leading dot from cookie domain for comparison
  std::string_view domain = cookie_domain;
  bool is_domain_cookie = false;
  if (!domain.empty() && domain[0] == '.') {
    domain.remove_prefix(1);
    is_domain_cookie = true;
  }

  // Exact match
  if (EqualsIgnoreCase(host, domain)) {
    return true;
  }

  // Domain cookies can match subdomains
  if (is_domain_cookie && host.size() > domain.size()) {
    // Host must end with domain and have a dot before it
    size_t offset = host.size() - domain.size();
    if (host[offset - 1] == '.' &&
        EqualsIgnoreCase(host.substr(offset), domain)) {
      return true;
    }
  }

  return false;
}

bool CookieJar::PathMatches(std::string_view request_path, std::string_view cookie_path) {
  // Empty cookie path matches everything
  if (cookie_path.empty() || cookie_path == "/") {
    return true;
  }

  // Request path must start with cookie path
  if (!request_path.starts_with(cookie_path)) {
    return false;
  }

  // If request path is longer, next char must be '/' or cookie path must end with '/'
  if (request_path.size() > cookie_path.size()) {
    if (cookie_path.back() != '/' && request_path[cookie_path.size()] != '/') {
      return false;
    }
  }

  return true;
}

uint64_t CookieJar::NowMs() {
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
}

bool CookieJar::ParseSetCookie(std::string_view header, std::string_view request_host,
                               std::string_view request_path, Cookie* cookie) {
  // Parse name=value pair (required)
  size_t eq_pos = header.find('=');
  if (eq_pos == std::string_view::npos || eq_pos == 0) {
    return false;
  }

  size_t semicolon = header.find(';');
  std::string_view name_value = (semicolon != std::string_view::npos)
                                    ? header.substr(0, semicolon)
                                    : header;

  cookie->name = std::string(Trim(name_value.substr(0, eq_pos)));
  cookie->value = std::string(Trim(name_value.substr(eq_pos + 1)));

  if (cookie->name.empty()) {
    return false;
  }

  // Parse attributes
  uint64_t now = NowMs();
  std::string_view attrs = (semicolon != std::string_view::npos)
                               ? header.substr(semicolon + 1)
                               : std::string_view{};

  while (!attrs.empty()) {
    size_t next_semi = attrs.find(';');
    std::string_view attr = (next_semi != std::string_view::npos)
                                ? attrs.substr(0, next_semi)
                                : attrs;

    ParseAttribute(Trim(attr), cookie, now);

    if (next_semi == std::string_view::npos) {
      break;
    }
    attrs.remove_prefix(next_semi + 1);
  }

  return true;
}

void CookieJar::ParseAttribute(std::string_view attr, Cookie* cookie,
                               uint64_t now_ms) {
  if (attr.empty()) return;

  // Split into name and optional value
  size_t eq_pos = attr.find('=');
  std::string_view name = (eq_pos != std::string_view::npos)
                              ? Trim(attr.substr(0, eq_pos))
                              : Trim(attr);
  std::string_view value = (eq_pos != std::string_view::npos)
                               ? Trim(attr.substr(eq_pos + 1))
                               : std::string_view{};

  // Handle each attribute
  if (EqualsIgnoreCase(name, "Domain")) {
    cookie->domain = ToLower(value);
    // Ensure leading dot for domain cookies
    if (!cookie->domain.empty() && cookie->domain[0] != '.') {
      cookie->domain = "." + cookie->domain;
    }
  } else if (EqualsIgnoreCase(name, "Path")) {
    cookie->path = std::string(value);
  } else if (EqualsIgnoreCase(name, "Expires")) {
    uint64_t expires = ParseHttpDate(value);
    if (expires > 0) {
      cookie->expires_ms = expires;
    }
  } else if (EqualsIgnoreCase(name, "Max-Age")) {
    // Max-Age takes precedence over Expires
    int64_t max_age = 0;
    bool negative = false;
    for (char c : value) {
      if (c == '-') {
        negative = true;
      } else if (c >= '0' && c <= '9') {
        max_age = max_age * 10 + (c - '0');
      }
    }
    if (negative) {
      cookie->expires_ms = 1;  // Expired
    } else {
      cookie->expires_ms = now_ms + static_cast<uint64_t>(max_age) * 1000;
    }
  } else if (EqualsIgnoreCase(name, "Secure")) {
    cookie->secure = true;
  } else if (EqualsIgnoreCase(name, "HttpOnly")) {
    cookie->http_only = true;
  } else if (EqualsIgnoreCase(name, "SameSite")) {
    if (EqualsIgnoreCase(value, "Strict")) {
      cookie->same_site = SameSite::kStrict;
    } else if (EqualsIgnoreCase(value, "Lax")) {
      cookie->same_site = SameSite::kLax;
    } else if (EqualsIgnoreCase(value, "None")) {
      cookie->same_site = SameSite::kNone;
    }
  }
}

}  // namespace http
}  // namespace holytls

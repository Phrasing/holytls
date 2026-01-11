// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_UTIL_URL_PARSER_H_
#define HOLYTLS_UTIL_URL_PARSER_H_

#include <cstdint>
#include <string>
#include <string_view>

namespace holytls {
namespace util {

// Parsed URL components
struct ParsedUrl {
  std::string scheme;    // "https"
  std::string host;      // "example.com"
  uint16_t port;         // 443
  std::string path;      // "/api/v1/resource"
  std::string query;     // "foo=bar"
  std::string fragment;  // "section1"

  // Authority string (host:port or just host)
  std::string Authority() const;

  // Full path including query (for HTTP request)
  std::string PathWithQuery() const;

  bool IsHttps() const { return scheme == "https"; }
};

// Parse a URL string
// Returns false if URL is invalid
bool ParseUrl(std::string_view url, ParsedUrl* result);

}  // namespace util
}  // namespace holytls

#endif  // HOLYTLS_UTIL_URL_PARSER_H_

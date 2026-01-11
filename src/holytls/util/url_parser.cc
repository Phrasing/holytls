// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/util/url_parser.h"

#include <algorithm>
#include <cstdlib>

namespace holytls {
namespace util {

std::string ParsedUrl::Authority() const {
  if ((scheme == "https" && port == 443) || (scheme == "http" && port == 80)) {
    return host;
  }
  return host + ":" + std::to_string(port);
}

std::string ParsedUrl::PathWithQuery() const {
  if (query.empty()) {
    return path;
  }
  return path + "?" + query;
}

bool ParseUrl(std::string_view url, ParsedUrl* result) {
  if (result == nullptr) {
    return false;
  }

  std::string_view remaining = url;

  // Parse scheme
  auto scheme_end = remaining.find("://");
  if (scheme_end == std::string_view::npos) {
    return false;
  }
  result->scheme = std::string(remaining.substr(0, scheme_end));
  remaining = remaining.substr(scheme_end + 3);

  // Set default port based on scheme
  if (result->scheme == "https") {
    result->port = 443;
  } else if (result->scheme == "http") {
    result->port = 80;
  } else {
    result->port = 0;
  }

  // Parse authority (host:port)
  auto path_start = remaining.find('/');
  auto query_start = remaining.find('?');
  auto fragment_start = remaining.find('#');

  size_t authority_end = std::min({path_start, query_start, fragment_start});
  if (authority_end == std::string_view::npos) {
    authority_end = remaining.size();
  }

  std::string_view authority = remaining.substr(0, authority_end);

  // Check for port in authority
  auto port_sep = authority.rfind(':');
  if (port_sep != std::string_view::npos) {
    // Check if this is IPv6 (contains '[')
    auto ipv6_end = authority.find(']');
    if (ipv6_end == std::string_view::npos || port_sep > ipv6_end) {
      // This is a port separator
      result->host = std::string(authority.substr(0, port_sep));
      std::string port_str(authority.substr(port_sep + 1));
      result->port = static_cast<uint16_t>(std::atoi(port_str.c_str()));
    } else {
      result->host = std::string(authority);
    }
  } else {
    result->host = std::string(authority);
  }

  // Remove brackets from IPv6 host
  if (!result->host.empty() && result->host.front() == '[' &&
      result->host.back() == ']') {
    result->host = result->host.substr(1, result->host.size() - 2);
  }

  remaining = remaining.substr(authority_end);

  // Parse path
  if (!remaining.empty() && remaining.front() == '/') {
    auto path_end = std::min(remaining.find('?'), remaining.find('#'));
    if (path_end == std::string_view::npos) {
      result->path = std::string(remaining);
      remaining = {};
    } else {
      result->path = std::string(remaining.substr(0, path_end));
      remaining = remaining.substr(path_end);
    }
  } else {
    result->path = "/";
  }

  // Parse query
  if (!remaining.empty() && remaining.front() == '?') {
    remaining = remaining.substr(1);
    auto query_end = remaining.find('#');
    if (query_end == std::string_view::npos) {
      result->query = std::string(remaining);
      remaining = {};
    } else {
      result->query = std::string(remaining.substr(0, query_end));
      remaining = remaining.substr(query_end);
    }
  }

  // Parse fragment
  if (!remaining.empty() && remaining.front() == '#') {
    result->fragment = std::string(remaining.substr(1));
  }

  return !result->host.empty();
}

}  // namespace util
}  // namespace holytls

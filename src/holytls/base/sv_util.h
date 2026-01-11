// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// String view utilities - branchless, locale-free, SIMD-friendly operations.

#ifndef HOLYTLS_BASE_SV_UTIL_H_
#define HOLYTLS_BASE_SV_UTIL_H_

#include <cstddef>
#include <string>
#include <string_view>

namespace holytls {
namespace sv {

// Trim whitespace from both ends (no allocation)
inline std::string_view Trim(std::string_view s) {
  // ASCII whitespace: space, tab, newline, carriage return, form feed, vertical tab
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                        s.front() == '\n' || s.front() == '\r')) {
    s.remove_prefix(1);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                        s.back() == '\n' || s.back() == '\r')) {
    s.remove_suffix(1);
  }
  return s;
}

// Branchless ASCII lowercase character (avoids std::tolower locale overhead)
inline constexpr char ToLowerChar(char c) {
  return static_cast<char>(c + ((c >= 'A' && c <= 'Z') * 32));
}

// Branchless ASCII uppercase character
inline constexpr char ToUpperChar(char c) {
  return static_cast<char>(c - ((c >= 'a' && c <= 'z') * 32));
}

// Case-insensitive equality (branchless, no allocation)
inline bool EqualsIgnoreCase(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (ToLowerChar(a[i]) != ToLowerChar(b[i])) {
      return false;
    }
  }
  return true;
}

// Convert to lowercase string (uses resize_and_overwrite for efficiency)
inline std::string ToLower(std::string_view s) {
  std::string result;
  result.resize_and_overwrite(s.size(), [&](char* buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
      buf[i] = ToLowerChar(s[i]);
    }
    return n;
  });
  return result;
}

// Convert to uppercase string
inline std::string ToUpper(std::string_view s) {
  std::string result;
  result.resize_and_overwrite(s.size(), [&](char* buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
      buf[i] = ToUpperChar(s[i]);
    }
    return n;
  });
  return result;
}

// Check if string starts with prefix (case-sensitive)
inline constexpr bool StartsWith(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() &&
         s.substr(0, prefix.size()) == prefix;
}

// Check if string ends with suffix (case-sensitive)
inline constexpr bool EndsWith(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

// Check if string starts with prefix (case-insensitive)
inline bool StartsWithIgnoreCase(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() &&
         EqualsIgnoreCase(s.substr(0, prefix.size()), prefix);
}

// Check if string ends with suffix (case-insensitive)
inline bool EndsWithIgnoreCase(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         EqualsIgnoreCase(s.substr(s.size() - suffix.size()), suffix);
}

}  // namespace sv
}  // namespace holytls

#endif  // HOLYTLS_BASE_SV_UTIL_H_

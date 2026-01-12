// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// String view helper functions for common string operations.

#ifndef HOLYTLS_UTIL_SV_HELPERS_H_
#define HOLYTLS_UTIL_SV_HELPERS_H_

#include <cctype>
#include <string>
#include <string_view>

namespace holytls {
namespace util {

// Trim whitespace from both ends of a string_view
inline std::string_view Trim(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
    s.remove_prefix(1);
  }
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
    s.remove_suffix(1);
  }
  return s;
}

// Case-insensitive string comparison
inline bool EqualsIgnoreCase(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// Convert string to lowercase
inline std::string ToLower(std::string_view s) {
  std::string result(s);
  for (char& c : result) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return result;
}

}  // namespace util
}  // namespace holytls

#endif  // HOLYTLS_UTIL_SV_HELPERS_H_

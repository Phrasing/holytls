// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TYPES_H_
#define HOLYTLS_TYPES_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace holytls {

// HTTP header pair
struct Header {
  std::string name;
  std::string value;
};

// Collection of HTTP headers
using Headers = std::vector<Header>;

// Result type for operations that can fail
template <typename T>
struct Result {
  T value;
  bool ok;
  std::string error;

  explicit operator bool() const { return ok; }

  static Result Ok(T val) { return {std::move(val), true, {}}; }

  static Result Err(std::string msg) { return {{}, false, std::move(msg)}; }
};

// Specialization for void
template <>
struct Result<void> {
  bool ok;
  std::string error;

  explicit operator bool() const { return ok; }

  static Result Ok() { return {true, {}}; }

  static Result Err(std::string msg) { return {false, std::move(msg)}; }
};

// String8 - RAD-style non-owning string (ptr + size, no null terminator
// required) Inspired by raddebugger. Zero allocations, explicit size, safe
// operations.
struct String8 {
  const char* str;
  size_t size;

  constexpr String8() : str(nullptr), size(0) {}
  constexpr String8(const char* s, size_t n) : str(s), size(n) {}

  // Convert from string_view (zero-copy)
  constexpr String8(std::string_view sv) : str(sv.data()), size(sv.size()) {}

  // Convert from std::string (zero-copy view)
  String8(const std::string& s) : str(s.data()), size(s.size()) {}

  // Convert to string_view
  constexpr operator std::string_view() const { return {str, size}; }

  // Basic accessors
  constexpr bool empty() const { return size == 0; }
  constexpr const char* data() const { return str; }
  constexpr const char* begin() const { return str; }
  constexpr const char* end() const { return str + size; }
  constexpr char operator[](size_t i) const { return str[i]; }

  // Substring (no allocation)
  constexpr String8 substr(size_t pos, size_t len = ~size_t{0}) const {
    if (pos >= size) return {};
    if (len > size - pos) len = size - pos;
    return {str + pos, len};
  }

  constexpr String8 prefix(size_t n) const {
    return {str, n < size ? n : size};
  }

  constexpr String8 suffix(size_t n) const {
    return n < size ? String8{str + size - n, n} : *this;
  }

  // Comparison
  bool operator==(String8 other) const {
    return size == other.size &&
           (str == other.str || std::memcmp(str, other.str, size) == 0);
  }

  bool operator!=(String8 other) const { return !(*this == other); }

  // To std::string (allocates - use sparingly)
  std::string to_string() const { return {str, size}; }
};

// String8 literal helper
constexpr String8 operator""_s8(const char* str, size_t len) {
  return {str, len};
}

// Non-owning view of bytes
struct ByteSpan {
  const uint8_t* data;
  size_t size;

  ByteSpan() : data(nullptr), size(0) {}
  ByteSpan(const uint8_t* d, size_t s) : data(d), size(s) {}
  ByteSpan(const char* d, size_t s)
      : data(reinterpret_cast<const uint8_t*>(d)), size(s) {}

  explicit ByteSpan(std::string_view sv)
      : data(reinterpret_cast<const uint8_t*>(sv.data())), size(sv.size()) {}

  explicit ByteSpan(String8 s8)
      : data(reinterpret_cast<const uint8_t*>(s8.str)), size(s8.size) {}

  bool empty() const { return size == 0; }
};

// Mutable byte span
struct MutableByteSpan {
  uint8_t* data;
  size_t size;

  MutableByteSpan() : data(nullptr), size(0) {}
  MutableByteSpan(uint8_t* d, size_t s) : data(d), size(s) {}

  bool empty() const { return size == 0; }

  operator ByteSpan() const { return {data, size}; }
};

}  // namespace holytls

#endif  // HOLYTLS_TYPES_H_

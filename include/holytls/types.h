// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TYPES_H_
#define HOLYTLS_TYPES_H_

#include <cstddef>
#include <cstdint>
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

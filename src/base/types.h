// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Core type definitions and fixed-size containers for zero-allocation hot
// paths.

#ifndef CHAD_BASE_TYPES_H_
#define CHAD_BASE_TYPES_H_

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace chad {

// Fixed-capacity array with size tracking (no heap allocation)
template <typename T, size_t Capacity>
struct FixedArray {
  T data[Capacity];
  uint16_t len;

  constexpr FixedArray() : data{}, len(0) {}

  constexpr void push(T value) {
    if (len < Capacity) {
      data[len++] = value;
    }
  }

  constexpr T& operator[](size_t i) { return data[i]; }
  constexpr const T& operator[](size_t i) const { return data[i]; }

  constexpr size_t size() const { return len; }
  constexpr size_t capacity() const { return Capacity; }
  constexpr bool empty() const { return len == 0; }

  constexpr T* begin() { return data; }
  constexpr T* end() { return data + len; }
  constexpr const T* begin() const { return data; }
  constexpr const T* end() const { return data + len; }
};

// Fixed-capacity string (no heap allocation)
template <size_t Capacity>
struct FixedString {
  char data[Capacity];
  uint16_t len;

  constexpr FixedString() : data{}, len(0) {}

  constexpr FixedString(const char* s) : data{}, len(0) {
    while (s[len] && len < Capacity - 1) {
      data[len] = s[len];
      len++;
    }
    data[len] = '\0';
  }

  constexpr const char* c_str() const { return data; }
  constexpr size_t size() const { return len; }
  constexpr bool empty() const { return len == 0; }

  constexpr char& operator[](size_t i) { return data[i]; }
  constexpr const char& operator[](size_t i) const { return data[i]; }
};

// Span view (non-owning pointer + length)
template <typename T>
struct Span {
  T* ptr;
  size_t len;

  constexpr Span() : ptr(nullptr), len(0) {}
  constexpr Span(T* p, size_t n) : ptr(p), len(n) {}

  template <size_t N>
  constexpr Span(T (&arr)[N]) : ptr(arr), len(N) {}

  template <typename Container>
  Span(Container& c) : ptr(c.data()), len(c.size()) {}

  constexpr T& operator[](size_t i) { return ptr[i]; }
  constexpr const T& operator[](size_t i) const { return ptr[i]; }

  constexpr size_t size() const { return len; }
  constexpr bool empty() const { return len == 0; }

  constexpr T* begin() { return ptr; }
  constexpr T* end() { return ptr + len; }
  constexpr const T* begin() const { return ptr; }
  constexpr const T* end() const { return ptr + len; }

  constexpr T* data() { return ptr; }
  constexpr const T* data() const { return ptr; }
};

// FdTable - sparse array for fd -> pointer mapping
// Much faster than unordered_map for fd lookups
template <typename T, size_t MaxFds = 65536>
class FdTable {
 public:
  FdTable() { std::memset(entries_, 0, sizeof(entries_)); }

  void Set(int fd, T* ptr) {
    if (fd >= 0 && static_cast<size_t>(fd) < MaxFds) {
      if (entries_[fd] == nullptr && ptr != nullptr) {
        ++count_;
      } else if (entries_[fd] != nullptr && ptr == nullptr) {
        --count_;
      }
      entries_[fd] = ptr;
    }
  }

  T* Get(int fd) const {
    if (fd >= 0 && static_cast<size_t>(fd) < MaxFds) {
      return entries_[fd];
    }
    return nullptr;
  }

  void Remove(int fd) { Set(fd, nullptr); }

  bool Contains(int fd) const { return Get(fd) != nullptr; }

  size_t Count() const { return count_; }

  void Clear() {
    std::memset(entries_, 0, sizeof(entries_));
    count_ = 0;
  }

 private:
  T* entries_[MaxFds];
  size_t count_ = 0;
};

}  // namespace chad

#endif  // CHAD_BASE_TYPES_H_

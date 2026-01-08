// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Arena-backed zero-copy buffer for high-performance I/O.
// Designed for minimal allocations in hot paths.

#ifndef CHAD_BASE_BUFFER_H_
#define CHAD_BASE_BUFFER_H_

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "base/arena.h"

namespace chad {

// Lightweight buffer view (non-owning)
struct Buf {
  uint8_t* data;
  size_t len;
  size_t cap;

  constexpr Buf() : data(nullptr), len(0), cap(0) {}
  constexpr Buf(uint8_t* d, size_t l, size_t c) : data(d), len(l), cap(c) {}
  constexpr Buf(uint8_t* d, size_t l) : data(d), len(l), cap(l) {}

  // Read position helpers
  size_t Remaining() const { return cap - len; }
  uint8_t* End() { return data + len; }
  const uint8_t* End() const { return data + len; }

  // Append data (returns bytes written)
  size_t Append(const uint8_t* src, size_t n) {
    size_t to_copy = (n < Remaining()) ? n : Remaining();
    std::memcpy(End(), src, to_copy);
    len += to_copy;
    return to_copy;
  }

  size_t Append(const char* s) {
    return Append(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
  }

  // Clear buffer
  void Clear() { len = 0; }

  // As string view
  const char* c_str() const { return reinterpret_cast<const char*>(data); }
};

// Arena-backed buffer with automatic growth
struct ArenaBuf {
  Arena* arena;
  uint8_t* data;
  size_t len;
  size_t cap;

  static ArenaBuf Create(Arena* a, size_t initial_cap = 4096) {
    ArenaBuf buf;
    buf.arena = a;
    buf.data = PushArray(a, uint8_t, initial_cap);
    buf.len = 0;
    buf.cap = initial_cap;
    return buf;
  }

  size_t Remaining() const { return cap - len; }
  uint8_t* End() { return data + len; }

  void EnsureCapacity(size_t additional) {
    if (len + additional <= cap) return;

    // Grow by 2x or to fit
    size_t new_cap = cap * 2;
    if (new_cap < len + additional) {
      new_cap = len + additional;
    }

    uint8_t* new_data = PushArray(arena, uint8_t, new_cap);
    std::memcpy(new_data, data, len);
    data = new_data;
    cap = new_cap;
    // Old memory stays in arena, freed when arena is cleared
  }

  void Append(const uint8_t* src, size_t n) {
    EnsureCapacity(n);
    std::memcpy(End(), src, n);
    len += n;
  }

  void Append(const char* s) {
    Append(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
  }

  void AppendByte(uint8_t b) {
    EnsureCapacity(1);
    data[len++] = b;
  }

  void Clear() { len = 0; }

  Buf ToBuf() const { return Buf{data, len, cap}; }
};

// Ring buffer for zero-copy streaming I/O
struct RingBuf {
  uint8_t* data;
  size_t cap;
  size_t read_pos;
  size_t write_pos;

  static RingBuf Create(Arena* arena, size_t capacity) {
    RingBuf rb;
    rb.data = PushArray(arena, uint8_t, capacity);
    rb.cap = capacity;
    rb.read_pos = 0;
    rb.write_pos = 0;
    return rb;
  }

  size_t Size() const {
    return write_pos - read_pos;
  }

  size_t Space() const {
    return cap - Size();
  }

  bool Empty() const { return read_pos == write_pos; }
  bool Full() const { return Size() == cap; }

  // Get contiguous readable region
  Buf ReadableRegion() const {
    size_t start = read_pos % cap;
    size_t readable = Size();
    size_t contiguous = cap - start;
    if (contiguous > readable) contiguous = readable;
    return Buf{data + start, contiguous, contiguous};
  }

  // Get contiguous writable region
  Buf WritableRegion() const {
    size_t start = write_pos % cap;
    size_t space = Space();
    size_t contiguous = cap - start;
    if (contiguous > space) contiguous = space;
    return Buf{data + start, 0, contiguous};
  }

  // Consume bytes after reading
  void Consume(size_t n) {
    read_pos += n;
  }

  // Commit bytes after writing
  void Commit(size_t n) {
    write_pos += n;
  }

  // Write data to ring buffer
  size_t Write(const uint8_t* src, size_t n) {
    size_t total = 0;
    while (n > 0 && !Full()) {
      Buf region = WritableRegion();
      size_t to_copy = (n < region.cap) ? n : region.cap;
      std::memcpy(region.data, src, to_copy);
      Commit(to_copy);
      src += to_copy;
      n -= to_copy;
      total += to_copy;
    }
    return total;
  }

  // Read data from ring buffer
  size_t Read(uint8_t* dst, size_t n) {
    size_t total = 0;
    while (n > 0 && !Empty()) {
      Buf region = ReadableRegion();
      size_t to_copy = (n < region.len) ? n : region.len;
      std::memcpy(dst, region.data, to_copy);
      Consume(to_copy);
      dst += to_copy;
      n -= to_copy;
      total += to_copy;
    }
    return total;
  }

  void Clear() {
    read_pos = 0;
    write_pos = 0;
  }
};

}  // namespace chad

#endif  // CHAD_BASE_BUFFER_H_

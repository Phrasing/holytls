// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_CORE_IO_BUFFER_H_
#define HOLYTLS_CORE_IO_BUFFER_H_

// Include platform.h first for Windows compatibility
#include "holytls/util/platform.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// Platform-specific iovec definition
#ifdef _WIN32
namespace holytls {
namespace core {
// Windows uses WSABUF for scatter-gather I/O
// Note: We define our own iovec_t for portability instead of using WSABUF
struct iovec_t {
  void* iov_base;
  size_t iov_len;
};
}  // namespace core
}  // namespace holytls
#else
#include <sys/uio.h>
namespace holytls {
namespace core {
using iovec_t = struct iovec;
}  // namespace core
}  // namespace holytls
#endif

namespace holytls {
namespace core {

// Default chunk size optimized for TLS records (max 16KB)
inline constexpr size_t kDefaultChunkSize = 16384;

// Zero-copy I/O buffer with chunk-based storage
class IoBuffer {
 public:
  IoBuffer();
  explicit IoBuffer(size_t initial_capacity);
  ~IoBuffer();

  // Move-only
  IoBuffer(IoBuffer&& other) noexcept;
  IoBuffer& operator=(IoBuffer&& other) noexcept;
  IoBuffer(const IoBuffer&) = delete;
  IoBuffer& operator=(const IoBuffer&) = delete;

  // Write operations (append to end)
  void Append(const uint8_t* data, size_t len);
  void Append(std::string_view sv);
  void Append(const IoBuffer& other);

  // Reserve space for writing and get pointer
  // Use Commit() after writing to mark space as used
  uint8_t* Reserve(size_t len);
  void Commit(size_t len);

  // Read operations (consume from front)
  size_t Read(uint8_t* dest, size_t max_len);
  size_t ReadToString(std::string* dest, size_t max_len);

  // Peek without consuming
  const uint8_t* Peek(size_t* available) const;

  // Skip bytes (consume without copying)
  void Skip(size_t len);

  // Get scatter-gather iovec for writev/readv
  // Note: Returns internal pointers, valid until next modification
  std::vector<iovec_t> GetReadableIovec() const;
  std::vector<iovec_t> GetWritableIovec(size_t len);

  // Zero-allocation iovec: write to caller-provided array
  // Returns number of iovecs written (may be less than max_count)
  size_t GetReadableIovecInto(iovec_t* out, size_t max_count) const;

  // Size information
  size_t Size() const { return size_; }
  size_t Capacity() const { return capacity_; }
  bool Empty() const { return size_ == 0; }

  // Clear all data
  void Clear();

  // Shrink to fit (release unused chunks)
  void ShrinkToFit();

  // Direct access for simple cases
  // Only valid when buffer is contiguous (single chunk)
  bool IsContiguous() const;
  const uint8_t* Data() const;  // Only call if IsContiguous()

  // Zero-copy extraction: move all data out as contiguous vector
  // Consolidates chunks if needed, then takes ownership
  // Buffer is left empty after this call
  std::vector<uint8_t> TakeContiguous();

 private:
  struct Chunk {
    std::unique_ptr<uint8_t[]> data;
    size_t capacity;
    size_t start;  // Read position within chunk
    size_t end;    // Write position within chunk

    size_t ReadableSize() const { return end - start; }
    size_t WritableSize() const { return capacity - end; }
    bool Empty() const { return start >= end; }
  };

  void EnsureCapacity(size_t additional);
  Chunk& GetWriteChunk();
  void RemoveEmptyChunks();

  std::deque<Chunk> chunks_;
  size_t size_ = 0;      // Total readable bytes
  size_t capacity_ = 0;  // Total allocated capacity
};

}  // namespace core
}  // namespace holytls

#endif  // HOLYTLS_CORE_IO_BUFFER_H_

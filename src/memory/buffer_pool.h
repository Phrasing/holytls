// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_MEMORY_BUFFER_POOL_H_
#define CHAD_MEMORY_BUFFER_POOL_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace chad {
namespace memory {

// Buffer size classes optimized for network I/O
inline constexpr size_t kSmallBufferSize = 4096;     // 4KB - headers, small responses
inline constexpr size_t kMediumBufferSize = 16384;   // 16KB - TLS records
inline constexpr size_t kLargeBufferSize = 65536;    // 64KB - large responses

// Forward declaration
class BufferPool;

// Custom deleter that returns buffer to pool
struct BufferDeleter {
  BufferPool* pool = nullptr;
  size_t size = 0;

  void operator()(uint8_t* ptr);
};

// Unique pointer type for pooled buffers
using PooledBuffer = std::unique_ptr<uint8_t[], BufferDeleter>;

// Thread-safe buffer pool for network I/O operations.
// Pre-allocates buffers of common sizes to reduce allocation overhead.
class BufferPool {
 public:
  // Configuration for pool sizes
  struct Config {
    size_t small_count = 256;   // Number of small buffers
    size_t medium_count = 64;   // Number of medium buffers
    size_t large_count = 16;    // Number of large buffers
  };

  BufferPool();
  explicit BufferPool(const Config& config);
  ~BufferPool();

  // Non-copyable, non-movable
  BufferPool(const BufferPool&) = delete;
  BufferPool& operator=(const BufferPool&) = delete;
  BufferPool(BufferPool&&) = delete;
  BufferPool& operator=(BufferPool&&) = delete;

  // Acquire a buffer of at least the specified size.
  // May return a larger buffer if that's what's available.
  // Falls back to heap allocation if pool is exhausted.
  PooledBuffer Acquire(size_t min_size);

  // Return a buffer to the pool (called by BufferDeleter)
  void Release(uint8_t* buffer, size_t size);

  // Get actual size of buffer (useful when you got a larger one)
  static size_t ActualSize(size_t requested_size);

  // Statistics
  struct Stats {
    size_t small_available;
    size_t medium_available;
    size_t large_available;
    uint64_t acquisitions;
    uint64_t pool_hits;
    uint64_t pool_misses;
    uint64_t fallback_allocations;  // Requests larger than kLargeBufferSize
  };
  Stats GetStats() const;

 private:
  // Per-size-class pool
  struct SizeClass {
    std::mutex mutex;
    std::vector<std::unique_ptr<uint8_t[]>> free_list;
    size_t buffer_size;
    size_t initial_count;
  };

  void InitializeSizeClass(SizeClass& sc, size_t buffer_size, size_t count);
  PooledBuffer AcquireFromClass(SizeClass& sc);

  SizeClass small_;
  SizeClass medium_;
  SizeClass large_;

  // Statistics (atomic for thread-safe reads)
  std::atomic<uint64_t> acquisitions_{0};
  std::atomic<uint64_t> pool_hits_{0};
  std::atomic<uint64_t> pool_misses_{0};
  std::atomic<uint64_t> fallback_allocations_{0};
};

}  // namespace memory
}  // namespace chad

#endif  // CHAD_MEMORY_BUFFER_POOL_H_

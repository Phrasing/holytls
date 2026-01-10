// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "memory/buffer_pool.h"

#include <algorithm>

namespace chad {
namespace memory {

void BufferDeleter::operator()(uint8_t* ptr) {
  if (ptr == nullptr) {
    return;
  }

  if (pool != nullptr) {
    pool->Release(ptr, size);
  } else {
    // Fallback allocation, just delete
    delete[] ptr;
  }
}

BufferPool::BufferPool() : BufferPool(Config{}) {}

BufferPool::BufferPool(const Config& config) {
  InitializeSizeClass(small_, kSmallBufferSize, config.small_count);
  InitializeSizeClass(medium_, kMediumBufferSize, config.medium_count);
  InitializeSizeClass(large_, kLargeBufferSize, config.large_count);
}

BufferPool::~BufferPool() = default;

void BufferPool::InitializeSizeClass(SizeClass& sc, size_t buffer_size,
                                     size_t count) {
  sc.buffer_size = buffer_size;
  sc.initial_count = count;
  sc.free_list.reserve(count);

  for (size_t i = 0; i < count; ++i) {
    sc.free_list.push_back(std::make_unique<uint8_t[]>(buffer_size));
  }
}

PooledBuffer BufferPool::Acquire(size_t min_size) {
  acquisitions_.fetch_add(1, std::memory_order_relaxed);

  // Select appropriate size class
  if (min_size <= kSmallBufferSize) {
    auto buf = AcquireFromClass(small_);
    if (buf) {
      return buf;
    }
    // Fall through to medium
  }

  if (min_size <= kMediumBufferSize) {
    auto buf = AcquireFromClass(medium_);
    if (buf) {
      return buf;
    }
    // Fall through to large
  }

  if (min_size <= kLargeBufferSize) {
    auto buf = AcquireFromClass(large_);
    if (buf) {
      return buf;
    }
  }

  // Fallback: allocate from heap
  fallback_allocations_.fetch_add(1, std::memory_order_relaxed);
  pool_misses_.fetch_add(1, std::memory_order_relaxed);

  size_t actual_size = std::max(min_size, kLargeBufferSize);
  uint8_t* raw = new uint8_t[actual_size];

  BufferDeleter deleter;
  deleter.pool = nullptr;  // Will be deleted, not returned to pool
  deleter.size = actual_size;

  return PooledBuffer(raw, deleter);
}

PooledBuffer BufferPool::AcquireFromClass(SizeClass& sc) {
  std::lock_guard<std::mutex> lock(sc.mutex);

  if (sc.free_list.empty()) {
    pool_misses_.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }

  pool_hits_.fetch_add(1, std::memory_order_relaxed);

  // Take from back (LIFO for cache friendliness)
  std::unique_ptr<uint8_t[]> buf = std::move(sc.free_list.back());
  sc.free_list.pop_back();

  BufferDeleter deleter;
  deleter.pool = this;
  deleter.size = sc.buffer_size;

  return PooledBuffer(buf.release(), deleter);
}

void BufferPool::Release(uint8_t* buffer, size_t size) {
  if (buffer == nullptr) {
    return;
  }

  // Find the right size class
  SizeClass* sc = nullptr;
  if (size == kSmallBufferSize) {
    sc = &small_;
  } else if (size == kMediumBufferSize) {
    sc = &medium_;
  } else if (size == kLargeBufferSize) {
    sc = &large_;
  } else {
    // Unknown size, just delete
    delete[] buffer;
    return;
  }

  std::lock_guard<std::mutex> lock(sc->mutex);

  // Don't grow pool beyond 2x initial size
  if (sc->free_list.size() < sc->initial_count * 2) {
    sc->free_list.push_back(std::unique_ptr<uint8_t[]>(buffer));
  } else {
    // Pool is oversized, just delete
    delete[] buffer;
  }
}

size_t BufferPool::ActualSize(size_t requested_size) {
  if (requested_size <= kSmallBufferSize) {
    return kSmallBufferSize;
  }
  if (requested_size <= kMediumBufferSize) {
    return kMediumBufferSize;
  }
  if (requested_size <= kLargeBufferSize) {
    return kLargeBufferSize;
  }
  return requested_size;
}

BufferPool::Stats BufferPool::GetStats() const {
  Stats stats;

  {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(small_.mutex));
    stats.small_available = small_.free_list.size();
  }
  {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(medium_.mutex));
    stats.medium_available = medium_.free_list.size();
  }
  {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(large_.mutex));
    stats.large_available = large_.free_list.size();
  }

  stats.acquisitions = acquisitions_.load(std::memory_order_relaxed);
  stats.pool_hits = pool_hits_.load(std::memory_order_relaxed);
  stats.pool_misses = pool_misses_.load(std::memory_order_relaxed);
  stats.fallback_allocations =
      fallback_allocations_.load(std::memory_order_relaxed);

  return stats;
}

}  // namespace memory
}  // namespace chad

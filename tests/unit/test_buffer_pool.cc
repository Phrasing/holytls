// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "memory/buffer_pool.h"

#include <cassert>
#include <iostream>

void TestBufferPoolCreation() {
  std::cout << "Testing buffer pool creation... ";

  chad::memory::BufferPool::Config config;
  config.small_count = 32;
  config.medium_count = 16;
  config.large_count = 8;

  chad::memory::BufferPool pool(config);

  auto stats = pool.GetStats();
  assert(stats.small_available == 32);
  assert(stats.medium_available == 16);
  assert(stats.large_available == 8);

  std::cout << "PASSED\n";
}

void TestBufferAcquisition() {
  std::cout << "Testing buffer acquisition... ";

  chad::memory::BufferPool pool;

  // Acquire small buffer
  auto small = pool.Acquire(1024);
  assert(small != nullptr);

  // Acquire medium buffer
  auto medium = pool.Acquire(8192);
  assert(medium != nullptr);

  // Acquire large buffer
  auto large = pool.Acquire(32768);
  assert(large != nullptr);

  auto stats = pool.GetStats();
  assert(stats.acquisitions == 3);
  assert(stats.pool_hits == 3);

  std::cout << "PASSED\n";
}

void TestBufferRelease() {
  std::cout << "Testing buffer release... ";

  chad::memory::BufferPool pool;

  auto stats_before = pool.GetStats();
  size_t small_before = stats_before.small_available;

  {
    // Acquire and release via RAII
    auto buf = pool.Acquire(1024);
    assert(buf != nullptr);
  }

  auto stats_after = pool.GetStats();
  assert(stats_after.small_available == small_before);

  std::cout << "PASSED\n";
}

void TestActualSize() {
  std::cout << "Testing actual size calculation... ";

  assert(chad::memory::BufferPool::ActualSize(100) == 4096);
  assert(chad::memory::BufferPool::ActualSize(4096) == 4096);
  assert(chad::memory::BufferPool::ActualSize(5000) == 16384);
  assert(chad::memory::BufferPool::ActualSize(16384) == 16384);
  assert(chad::memory::BufferPool::ActualSize(20000) == 65536);
  assert(chad::memory::BufferPool::ActualSize(100000) == 100000);

  std::cout << "PASSED\n";
}

int main() {
  std::cout << "=== Buffer Pool Unit Tests ===\n";

  TestBufferPoolCreation();
  TestBufferAcquisition();
  TestBufferRelease();
  TestActualSize();

  std::cout << "\nAll buffer pool tests passed!\n";
  return 0;
}

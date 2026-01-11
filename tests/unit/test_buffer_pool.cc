// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/memory/buffer_pool.h"

#include <cassert>
#include <print>

void TestBufferPoolCreation() {
  std::print("Testing buffer pool creation... ");

  holytls::memory::BufferPool::Config config;
  config.small_count = 32;
  config.medium_count = 16;
  config.large_count = 8;

  holytls::memory::BufferPool pool(config);

  auto stats = pool.GetStats();
  assert(stats.small_available == 32);
  assert(stats.medium_available == 16);
  assert(stats.large_available == 8);

  std::println("PASSED");
}

void TestBufferAcquisition() {
  std::print("Testing buffer acquisition... ");

  holytls::memory::BufferPool pool;

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

  std::println("PASSED");
}

void TestBufferRelease() {
  std::print("Testing buffer release... ");

  holytls::memory::BufferPool pool;

  auto stats_before = pool.GetStats();
  size_t small_before = stats_before.small_available;

  {
    // Acquire and release via RAII
    auto buf = pool.Acquire(1024);
    assert(buf != nullptr);
  }

  auto stats_after = pool.GetStats();
  assert(stats_after.small_available == small_before);

  std::println("PASSED");
}

void TestActualSize() {
  std::print("Testing actual size calculation... ");

  assert(holytls::memory::BufferPool::ActualSize(100) == 4096);
  assert(holytls::memory::BufferPool::ActualSize(4096) == 4096);
  assert(holytls::memory::BufferPool::ActualSize(5000) == 16384);
  assert(holytls::memory::BufferPool::ActualSize(16384) == 16384);
  assert(holytls::memory::BufferPool::ActualSize(20000) == 65536);
  assert(holytls::memory::BufferPool::ActualSize(100000) == 100000);

  std::println("PASSED");
}

int main() {
  std::println("=== Buffer Pool Unit Tests ===");

  TestBufferPoolCreation();
  TestBufferAcquisition();
  TestBufferRelease();
  TestActualSize();

  std::println("\nAll buffer pool tests passed!");
  return 0;
}

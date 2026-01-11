// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Core component benchmarks: arena, buffer, reactor, FdTable

#include <cstdlib>
#include <cstring>
#include <list>
#include <print>
#include <unordered_map>
#include <vector>

#include "holytls/base/arena.h"
#include "holytls/base/buffer.h"
#include "holytls/base/list.h"
#include "holytls/base/types.h"
#include "bench_common.h"
#include "holytls/memory/slab_allocator.h"

using namespace holytls;
using namespace holytls::bench;

namespace {

// Benchmark arena allocation vs malloc
void BenchArenaAlloc() {
  Arena* arena = Arena::Create(64 * 1024);
  size_t alloc_count = 0;

  auto result = AutoBenchmark("Arena: 64-byte alloc", [&]() {
    void* p = ArenaPush(arena, 64);
    DoNotOptimize(p);
    // Clear periodically to benchmark fast path (bump allocation)
    if (++alloc_count >= 900) {
      ArenaClear(arena);
      alloc_count = 0;
    }
  });
  result.Print();

  ArenaClear(arena);
  alloc_count = 0;

  result = AutoBenchmark("Arena: 1KB alloc", [&]() {
    void* p = ArenaPush(arena, 1024);
    DoNotOptimize(p);
    // Clear periodically to benchmark fast path
    if (++alloc_count >= 60) {
      ArenaClear(arena);
      alloc_count = 0;
    }
  });
  result.Print();

  Arena::Destroy(arena);
}

void BenchMallocAlloc() {
  std::vector<void*> ptrs;
  ptrs.reserve(10000);

  auto result = AutoBenchmark("malloc: 64-byte alloc+free", [&]() {
    void* p = std::malloc(64);
    DoNotOptimize(p);
    std::free(p);
  });
  result.Print();

  result = AutoBenchmark("malloc: 1KB alloc+free", [&]() {
    void* p = std::malloc(1024);
    DoNotOptimize(p);
    std::free(p);
  });
  result.Print();
}

// Benchmark slab allocator
struct TestObject {
  uint64_t data[8];
};

void BenchSlabAlloc() {
  memory::SlabAllocator<TestObject, 256> alloc;

  auto result = AutoBenchmark("Slab: alloc+dealloc", [&]() {
    TestObject* obj = alloc.Allocate();
    DoNotOptimize(obj);
    alloc.Deallocate(obj);
  });
  result.Print();

  // Batch allocation
  std::vector<TestObject*> objs;
  objs.reserve(256);

  result = AutoBenchmark("Slab: batch alloc 256", [&]() {
    for (int i = 0; i < 256; ++i) {
      objs.push_back(alloc.Allocate());
    }
    for (auto* obj : objs) {
      alloc.Deallocate(obj);
    }
    objs.clear();
    DoNotOptimize(objs.data());
  });
  result.Print();
}

// Benchmark FdTable vs unordered_map
void BenchFdTable() {
  FdTable<int, 65536> table;
  int value = 42;

  // Pre-populate with some entries
  for (int i = 0; i < 1000; ++i) {
    table.Set(i * 10, &value);
  }

  auto result = AutoBenchmark("FdTable: lookup (hit)", [&]() {
    int* v = table.Get(5000);
    DoNotOptimize(v);
  });
  result.Print();

  result = AutoBenchmark("FdTable: lookup (miss)", [&]() {
    int* v = table.Get(5001);
    DoNotOptimize(v);
  });
  result.Print();

  result = AutoBenchmark("FdTable: set+remove", [&]() {
    table.Set(50000, &value);
    table.Remove(50000);
  });
  result.Print();
}

void BenchUnorderedMap() {
  std::unordered_map<int, int*> map;
  int value = 42;

  // Pre-populate with some entries
  for (int i = 0; i < 1000; ++i) {
    map[i * 10] = &value;
  }

  auto result = AutoBenchmark("unordered_map: lookup (hit)", [&]() {
    auto it = map.find(5000);
    DoNotOptimize(it);
  });
  result.Print();

  result = AutoBenchmark("unordered_map: lookup (miss)", [&]() {
    auto it = map.find(5001);
    DoNotOptimize(it);
  });
  result.Print();

  result = AutoBenchmark("unordered_map: insert+erase", [&]() {
    map[50000] = &value;
    map.erase(50000);
  });
  result.Print();
}

// Benchmark buffer operations
void BenchBuffer() {
  Arena* arena = Arena::Create(256 * 1024);
  uint8_t src[4096];
  std::memset(src, 'X', sizeof(src));

  // ArenaBuf
  {
    ArenaBuf buf = ArenaBuf::Create(arena, 4096);
    auto result = AutoBenchmark("ArenaBuf: append 64 bytes", [&]() {
      buf.Append(src, 64);
      if (buf.len > 100000) buf.Clear();
    });
    result.Print();

    buf.Clear();
    result = AutoBenchmark("ArenaBuf: append 4KB", [&]() {
      buf.Append(src, 4096);
      if (buf.len > 100000) buf.Clear();
    });
    result.Print();
  }

  // RingBuf
  {
    RingBuf ring = RingBuf::Create(arena, 64 * 1024);
    uint8_t dst[4096];

    auto result = AutoBenchmark("RingBuf: write+read 4KB", [&]() {
      ring.Write(src, 4096);
      ring.Read(dst, 4096);
      DoNotOptimize(dst[0]);
    });
    result.Print();
  }

  Arena::Destroy(arena);
}

// Benchmark std::vector vs fixed buffer
void BenchVectorVsFixed() {
  // std::vector
  {
    std::vector<uint8_t> vec;
    uint8_t src[64];
    std::memset(src, 'X', sizeof(src));

    auto result = AutoBenchmark("vector: push 64 bytes", [&]() {
      vec.insert(vec.end(), src, src + 64);
      if (vec.size() > 100000) vec.clear();
    });
    result.Print();
  }

  // Fixed array
  {
    FixedArray<uint8_t, 65536> arr;

    auto result = AutoBenchmark("FixedArray: push 64 items", [&]() {
      for (int i = 0; i < 64; ++i) {
        arr.push(static_cast<uint8_t>(i));
      }
      if (arr.len > 60000) arr.len = 0;
    });
    result.Print();
  }
}

// Benchmark intrusive list vs std::list
void BenchIntrusiveList() {
  struct Item {
    int value;
    DLLNode node;
  };

  Item items[1000];
  for (int i = 0; i < 1000; ++i) {
    items[i].value = i;
  }

  DLLList list;
  DLLInit(&list);

  // Add all items
  for (int i = 0; i < 1000; ++i) {
    DLLPushBack(&list, &items[i].node);
  }

  auto result = AutoBenchmark("DLLList: iterate 1000", [&]() {
    int sum = 0;
    DLLForEach(&list, n) {
      Item* item = ContainerOf(n, Item, node);
      sum += item->value;
    }
    DoNotOptimize(sum);
  });
  result.Print();

  result = AutoBenchmark("DLLList: iterate 1000 (prefetch)", [&]() {
    int sum = 0;
    DLLForEachPrefetch(&list, n) {
      Item* item = ContainerOf(n, Item, node);
      sum += item->value;
    }
    DoNotOptimize(sum);
  });
  result.Print();

  result = AutoBenchmark("DLLList: remove+push_back", [&]() {
    DLLNode* n = DLLPopFront(&list);
    DLLPushBack(&list, n);
  });
  result.Print();
}

void BenchStdList() {
  std::list<int> list;
  for (int i = 0; i < 1000; ++i) {
    list.push_back(i);
  }

  auto result = AutoBenchmark("std::list: iterate 1000", [&]() {
    int sum = 0;
    for (int v : list) {
      sum += v;
    }
    DoNotOptimize(sum);
  });
  result.Print();

  result = AutoBenchmark("std::list: splice front->back", [&]() {
    list.splice(list.end(), list, list.begin());
  });
  result.Print();
}

}  // namespace

int main() {
  std::println("=== HolyTLS Core Benchmarks ===");
  std::println("Comparing optimized vs standard library implementations\n");

  std::println("--- Memory Allocation ---");
  BenchArenaAlloc();
  BenchMallocAlloc();
  BenchSlabAlloc();

  std::println("\n--- Lookup Tables ---");
  BenchFdTable();
  BenchUnorderedMap();

  std::println("\n--- Buffers ---");
  BenchBuffer();
  BenchVectorVsFixed();

  std::println("\n--- Linked Lists ---");
  BenchIntrusiveList();
  BenchStdList();

  std::println("\n=== Benchmark Complete ===");
  return 0;
}

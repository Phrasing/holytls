// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Lightweight benchmark framework - no external dependencies.

#ifndef CHAD_BENCH_COMMON_H_
#define CHAD_BENCH_COMMON_H_

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace chad {
namespace bench {

// Prevent compiler from optimizing away a value
#ifdef _MSC_VER
template <typename T>
inline void DoNotOptimize(T&& value) {
  // Use volatile to prevent optimization
  volatile auto* p = &value;
  (void)p;
  _ReadWriteBarrier();
}
#else
template <typename T>
inline void DoNotOptimize(T&& value) {
  asm volatile("" : : "r,m"(value) : "memory");
}
#endif

// Memory barrier to prevent reordering
#ifdef _MSC_VER
inline void ClobberMemory() { _ReadWriteBarrier(); }
#else
inline void ClobberMemory() { asm volatile("" : : : "memory"); }
#endif

// High-resolution timer
struct Timer {
  using Clock = std::chrono::high_resolution_clock;
  using TimePoint = Clock::time_point;

  TimePoint start;

  void Start() { start = Clock::now(); }

  double ElapsedNs() const {
    auto end = Clock::now();
    return std::chrono::duration<double, std::nano>(end - start).count();
  }

  double ElapsedUs() const { return ElapsedNs() / 1000.0; }
  double ElapsedMs() const { return ElapsedNs() / 1000000.0; }
  double ElapsedSec() const { return ElapsedNs() / 1000000000.0; }
};

// Benchmark result
struct Result {
  std::string name;
  uint64_t iterations;
  double total_ns;
  double ns_per_op;
  double ops_per_sec;

  void Print() const {
    printf("%-40s %12llu iters %12.2f ns/op %12.2f M ops/sec\n", name.c_str(),
           static_cast<unsigned long long>(iterations), ns_per_op,
           ops_per_sec / 1e6);
    fflush(stdout);
  }
};

// Run a benchmark function
template <typename Func>
Result RunBenchmark(const char* name, uint64_t iterations, Func&& func) {
  // Warmup
  for (uint64_t i = 0; i < iterations / 10 + 1; ++i) {
    func();
    ClobberMemory();
  }

  Timer timer;
  timer.Start();

  for (uint64_t i = 0; i < iterations; ++i) {
    func();
    ClobberMemory();
  }

  double total_ns = timer.ElapsedNs();

  Result result;
  result.name = name;
  result.iterations = iterations;
  result.total_ns = total_ns;
  result.ns_per_op = total_ns / static_cast<double>(iterations);
  result.ops_per_sec = static_cast<double>(iterations) / (total_ns / 1e9);

  return result;
}

// Auto-tune iterations for ~1 second runtime
template <typename Func>
Result AutoBenchmark(const char* name, Func&& func) {
  // Warmup and estimate iterations needed
  Timer timer;

  // Start with small iteration count
  uint64_t iters = 1;
  double elapsed = 0;

  while (elapsed < 100000000.0) {  // 100ms warmup/calibration
    iters *= 2;
    timer.Start();
    for (uint64_t i = 0; i < iters; ++i) {
      func();
      ClobberMemory();
    }
    elapsed = timer.ElapsedNs();
  }

  // Scale to ~1 second
  double target_ns = 1e9;
  uint64_t target_iters =
      static_cast<uint64_t>(static_cast<double>(iters) * target_ns / elapsed);
  if (target_iters < 1) target_iters = 1;

  // Run actual benchmark
  timer.Start();
  for (uint64_t i = 0; i < target_iters; ++i) {
    func();
    ClobberMemory();
  }
  double total_ns = timer.ElapsedNs();

  Result result;
  result.name = name;
  result.iterations = target_iters;
  result.total_ns = total_ns;
  result.ns_per_op = total_ns / static_cast<double>(target_iters);
  result.ops_per_sec = static_cast<double>(target_iters) / (total_ns / 1e9);

  return result;
}

// Benchmark suite
class Suite {
 public:
  void Add(const char* name, std::function<void()> func) {
    benchmarks_.push_back({name, std::move(func)});
  }

  void Run() {
    printf("\n=== Benchmark Results ===\n\n");
    printf("%-40s %12s %12s %12s\n", "Benchmark", "Iterations", "ns/op",
           "M ops/sec");
    printf("%-40s %12s %12s %12s\n", "---------", "----------", "-----",
           "---------");

    for (const auto& bench : benchmarks_) {
      auto result = AutoBenchmark(bench.name.c_str(), bench.func);
      result.Print();
      results_.push_back(result);
    }

    printf("\n");
  }

  const std::vector<Result>& Results() const { return results_; }

 private:
  struct Benchmark {
    std::string name;
    std::function<void()> func;
  };

  std::vector<Benchmark> benchmarks_;
  std::vector<Result> results_;
};

// Memory stats
struct MemStats {
  size_t allocations;
  size_t deallocations;
  size_t bytes_allocated;
  size_t peak_bytes;

  void Print() const {
    printf("Memory: %zu allocs, %zu deallocs, %zu KB peak\n", allocations,
           deallocations, peak_bytes / 1024);
  }
};

}  // namespace bench
}  // namespace chad

#endif  // CHAD_BENCH_COMMON_H_

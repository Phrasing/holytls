// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/core/reactor.h"

#include <cassert>
#include <print>

void TestReactorCreation() {
  std::print("Testing reactor creation... ");

  holytls::core::ReactorConfig config;
  config.max_events = 512;
  config.epoll_timeout_ms = 50;

  holytls::core::Reactor reactor(config);

  assert(!reactor.running());
  assert(reactor.handler_count() == 0);

  std::println("PASSED");
}

void TestReactorTime() {
  std::print("Testing reactor time... ");

  holytls::core::Reactor reactor;

  uint64_t t1 = reactor.now_ms();
  assert(t1 > 0);

  // Time should be monotonic
  reactor.RunFor(10);
  uint64_t t2 = reactor.now_ms();
  assert(t2 >= t1);

  std::println("PASSED");
}

int main() {
  std::println("=== Reactor Unit Tests ===");

  TestReactorCreation();
  TestReactorTime();

  std::println("\nAll reactor tests passed!");
  return 0;
}

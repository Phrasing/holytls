// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "core/reactor.h"

#include <cassert>
#include <iostream>

void TestReactorCreation() {
  std::cout << "Testing reactor creation... ";

  chad::core::ReactorConfig config;
  config.max_events = 512;
  config.epoll_timeout_ms = 50;

  chad::core::Reactor reactor(config);

  assert(!reactor.running());
  assert(reactor.handler_count() == 0);

  std::cout << "PASSED\n";
}

void TestReactorTime() {
  std::cout << "Testing reactor time... ";

  chad::core::Reactor reactor;

  uint64_t t1 = reactor.now_ms();
  assert(t1 > 0);

  // Time should be monotonic
  reactor.RunFor(10);
  uint64_t t2 = reactor.now_ms();
  assert(t2 >= t1);

  std::cout << "PASSED\n";
}

int main() {
  std::cout << "=== Reactor Unit Tests ===\n";

  TestReactorCreation();
  TestReactorTime();

  std::cout << "\nAll reactor tests passed!\n";
  return 0;
}

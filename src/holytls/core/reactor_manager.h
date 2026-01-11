// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_CORE_REACTOR_MANAGER_H_
#define HOLYTLS_CORE_REACTOR_MANAGER_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "holytls/core/reactor.h"
#include "holytls/memory/buffer_pool.h"
#include "holytls/pool/connection_pool.h"
#include "holytls/tls/tls_context.h"
#include "holytls/util/dns_resolver.h"

namespace holytls {
namespace core {

// Configuration for ReactorManager
struct ReactorManagerConfig {
  // Number of reactor threads (0 = auto-detect CPU cores)
  size_t num_reactors = 0;

  // Pin threads to CPU cores (improves cache locality)
  bool pin_to_cores = false;

  // Per-reactor buffer pool configuration
  size_t buffer_pool_small_count = 64;
  size_t buffer_pool_medium_count = 16;
  size_t buffer_pool_large_count = 4;
};

// Per-reactor thread context with all resources
struct ReactorContext {
  // The reactor (event loop)
  std::unique_ptr<Reactor> reactor;

  // Thread running this reactor
  std::unique_ptr<std::thread> thread;

  // Per-reactor resources (no mutex contention)
  std::unique_ptr<memory::BufferPool> buffer_pool;
  std::unique_ptr<util::DnsResolver> dns_resolver;
  std::unique_ptr<pool::ConnectionPool> connection_pool;

  // Reactor index
  size_t index = 0;

  // Running flag
  std::atomic<bool> running{false};
};

// Manages multiple reactor threads for parallel I/O processing.
// Each reactor runs in its own thread with dedicated resources.
// Connections are distributed across reactors using consistent hashing.
class ReactorManager {
 public:
  explicit ReactorManager(const ReactorManagerConfig& config = {});
  ~ReactorManager();

  // Non-copyable, non-movable
  ReactorManager(const ReactorManager&) = delete;
  ReactorManager& operator=(const ReactorManager&) = delete;
  ReactorManager(ReactorManager&&) = delete;
  ReactorManager& operator=(ReactorManager&&) = delete;

  // Initialize with TLS factory and pool config
  // Must be called before Start()
  void Initialize(tls::TlsContextFactory* tls_factory,
                  const pool::ConnectionPoolConfig& pool_config);

  // Start all reactor threads
  void Start();

  // Stop all reactor threads (blocks until stopped)
  void Stop();

  bool IsRunning() const { return running_.load(std::memory_order_acquire); }
  size_t NumReactors() const { return contexts_.size(); }

  // Get reactor for a host (consistent hashing for connection affinity)
  // Same host:port always maps to same reactor for connection reuse
  ReactorContext* GetReactorForHost(const std::string& host, uint16_t port);

  // Get reactor by index
  ReactorContext* GetReactor(size_t index);

  // Round-robin reactor selection (for load balancing new hosts)
  ReactorContext* GetNextReactor();

  // Post callback to specific reactor (thread-safe)
  void Post(size_t reactor_index, std::function<void()> callback);

  // Post callback to all reactors (thread-safe)
  void PostAll(std::function<void()> callback);

  // Get total connections across all reactors
  size_t TotalConnections() const;

 private:
  void RunReactor(ReactorContext* ctx);
  size_t GetReactorIndex(const std::string& host, uint16_t port) const;

  ReactorManagerConfig config_;
  tls::TlsContextFactory* tls_factory_ = nullptr;
  pool::ConnectionPoolConfig pool_config_;

  std::vector<std::unique_ptr<ReactorContext>> contexts_;
  std::atomic<size_t> next_reactor_{0};  // For round-robin
  std::atomic<bool> running_{false};
  bool initialized_ = false;
};

}  // namespace core
}  // namespace holytls

#endif  // HOLYTLS_CORE_REACTOR_MANAGER_H_

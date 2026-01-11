// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_POOL_CONNECTION_POOL_H_
#define HOLYTLS_POOL_CONNECTION_POOL_H_

#include <memory>
#include <string>
#include <unordered_map>

#include "holytls/config.h"
#include "holytls/core/reactor.h"
#include "holytls/tls/tls_context.h"

namespace holytls {
namespace pool {

// Forward declarations
class HostPool;
class PooledConnection;

// Connection pool configuration
struct ConnectionPoolConfig {
  size_t max_connections_per_host = 6;  // Chrome default
  size_t max_total_connections = 256;
  uint64_t idle_timeout_ms = 300000;    // 5 minutes
  uint64_t connect_timeout_ms = 30000;  // 30 seconds
  bool enable_multiplexing = true;
  size_t max_streams_per_connection = 100;
};

// Global connection pool manager.
// NOT thread-safe - designed for single-reactor use.
// For multi-reactor, use one ConnectionPool per reactor.
class ConnectionPool {
 public:
  ConnectionPool(const ConnectionPoolConfig& config, core::Reactor* reactor,
                 tls::TlsContextFactory* tls_factory);
  ~ConnectionPool();

  // Non-copyable, non-movable
  ConnectionPool(const ConnectionPool&) = delete;
  ConnectionPool& operator=(const ConnectionPool&) = delete;
  ConnectionPool(ConnectionPool&&) = delete;
  ConnectionPool& operator=(ConnectionPool&&) = delete;

  // Acquire a connection to host:port
  // Returns nullptr if pool is exhausted
  PooledConnection* AcquireConnection(const std::string& host, uint16_t port);

  // Release a connection back to the pool
  void ReleaseConnection(PooledConnection* conn);

  // Remove a closed/failed connection
  void RemoveConnection(PooledConnection* conn);

  // Cleanup idle connections across all hosts
  void CleanupIdle(uint64_t now_ms);

  // Get or create a host pool (for direct connection creation)
  HostPool* GetOrCreateHostPool(const std::string& host, uint16_t port);

  // Statistics
  size_t TotalConnections() const;
  size_t TotalHosts() const;

 private:
  static std::string MakeHostKey(const std::string& host, uint16_t port);

  ConnectionPoolConfig config_;
  core::Reactor* reactor_;
  tls::TlsContextFactory* tls_factory_;
  std::unordered_map<std::string, std::unique_ptr<HostPool>> host_pools_;
  size_t total_connections_ = 0;
};

}  // namespace pool
}  // namespace holytls

#endif  // HOLYTLS_POOL_CONNECTION_POOL_H_

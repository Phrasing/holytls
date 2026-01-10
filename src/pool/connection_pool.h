// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_POOL_CONNECTION_POOL_H_
#define CHAD_POOL_CONNECTION_POOL_H_

#include <memory>
#include <string>
#include <unordered_map>

#include "chad/config.h"
#include "core/reactor.h"
#include "tls/tls_context.h"

namespace chad {
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
  ConnectionPool(const ConnectionPoolConfig& config,
                 core::Reactor* reactor,
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

  // Statistics
  size_t TotalConnections() const;
  size_t TotalHosts() const;

 private:
  HostPool* GetOrCreateHostPool(const std::string& host, uint16_t port);
  static std::string MakeHostKey(const std::string& host, uint16_t port);

  ConnectionPoolConfig config_;
  core::Reactor* reactor_;
  tls::TlsContextFactory* tls_factory_;
  std::unordered_map<std::string, std::unique_ptr<HostPool>> host_pools_;
  size_t total_connections_ = 0;
};

}  // namespace pool
}  // namespace chad

#endif  // CHAD_POOL_CONNECTION_POOL_H_

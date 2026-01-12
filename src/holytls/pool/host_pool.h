// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_POOL_HOST_POOL_H_
#define HOLYTLS_POOL_HOST_POOL_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "holytls/config.h"
#include "holytls/core/connection.h"
#include "holytls/core/reactor.h"
#include "holytls/tls/tls_context.h"

namespace holytls {
namespace pool {

// Forward declarations
class HostPool;

// Pooled connection wrapper with pool metadata
struct PooledConnection {
  // The underlying connection
  std::unique_ptr<core::Connection> connection;

  // Pool membership
  HostPool* host_pool = nullptr;

  // Timing
  uint64_t created_ms = 0;
  uint64_t last_used_ms = 0;

  // Stream tracking for HTTP/2 multiplexing
  size_t active_stream_count = 0;
  size_t max_streams = 100;

  // Health tracking
  size_t consecutive_errors = 0;
  bool marked_for_removal = false;

  bool HasCapacity() const {
    // Query connection for actual max streams (handles HTTP/1.1 vs HTTP/2)
    size_t actual_max = max_streams;
    if (connection && connection->IsConnected()) {
      actual_max = connection->MaxConcurrentStreams();
    }
    return active_stream_count < actual_max && !marked_for_removal;
  }

  bool IsIdle() const { return active_stream_count == 0; }
};

// Callback for when a pooled connection needs to be created
using ConnectionFactory = std::function<std::unique_ptr<core::Connection>(
    core::Reactor* reactor, tls::TlsContextFactory* tls_factory,
    const std::string& host, uint16_t port)>;

// Per-host connection pool configuration
struct HostPoolConfig {
  size_t max_connections = 6;  // Max connections to this host
  size_t max_streams_per_connection = 100;
  uint64_t idle_timeout_ms = 300000;    // 5 minutes
  uint64_t connect_timeout_ms = 30000;  // 30 seconds

  // Proxy configuration
  ProxyConfig proxy;
};

// Per-host connection pool.
// Manages connections to a single host:port pair.
// NOT thread-safe - designed for single-reactor use.
class HostPool {
 public:
  // Read-only pool identity (set at construction)
  const std::string host;
  const uint16_t port;

  HostPool(const std::string& h, uint16_t p, const HostPoolConfig& config,
           core::Reactor* reactor, tls::TlsContextFactory* tls_factory);
  ~HostPool();

  // Non-copyable, non-movable
  HostPool(const HostPool&) = delete;
  HostPool& operator=(const HostPool&) = delete;
  HostPool(HostPool&&) = delete;
  HostPool& operator=(HostPool&&) = delete;

  // Acquire a connection with available stream capacity.
  // Returns nullptr if no connection available and at limit.
  // The connection is marked as having one more active stream.
  PooledConnection* AcquireConnection();

  // Release a connection (decrements stream count).
  // If connection becomes idle, it's moved to idle list.
  void ReleaseConnection(PooledConnection* conn);

  // Mark a connection as failed (removes from pool).
  void FailConnection(PooledConnection* conn);

  // Create a new connection (async - returns immediately).
  // The connection will be added to active list when ready.
  // Returns false if at connection limit.
  bool CreateConnection(const std::string& resolved_ip, bool ipv6 = false);

  // Cleanup expired idle connections.
  // Returns number of connections closed.
  size_t CleanupIdle(uint64_t now_ms);

  // Pool statistics
  size_t TotalConnections() const { return connections_.size(); }
  size_t ActiveConnections() const;
  size_t IdleConnections() const;

 private:
  void OnConnectionIdle(core::Connection* conn);
  void RemoveConnection(PooledConnection* conn);
  void CleanupMarkedConnections();
  PooledConnection* FindConnectionWithCapacity();
  PooledConnection* FindIdleConnection();

  HostPoolConfig config_;
  core::Reactor* reactor_;
  tls::TlsContextFactory* tls_factory_;

  // All connections (owns the PooledConnection objects)
  std::vector<std::unique_ptr<PooledConnection>> connections_;
};

}  // namespace pool
}  // namespace holytls

#endif  // HOLYTLS_POOL_HOST_POOL_H_

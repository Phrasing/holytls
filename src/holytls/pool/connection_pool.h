// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_POOL_CONNECTION_POOL_H_
#define HOLYTLS_POOL_CONNECTION_POOL_H_

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include "holytls/config.h"
#include "holytls/core/reactor.h"
#include "holytls/tls/tls_context.h"

// Forward declare QUIC types to avoid including heavy headers
namespace holytls {
namespace quic {
class QuicTlsContext;
}
}  // namespace holytls

namespace holytls {
namespace pool {

// Forward declarations
class HostPool;
class PooledConnection;
class QuicHostPool;
struct QuicPooledConnection;

// Connection pool configuration
struct ConnectionPoolConfig {
  size_t max_connections_per_host = 6;  // Chrome default
  size_t max_total_connections = 256;
  uint64_t idle_timeout_ms = 300000;    // 5 minutes
  uint64_t connect_timeout_ms = 30000;  // 30 seconds
  bool enable_multiplexing = true;
  size_t max_streams_per_connection = 100;

  // Protocol preference
  ProtocolPreference protocol = ProtocolPreference::kHttp2Preferred;

  // HTTP/3 configuration (used when protocol allows QUIC)
  Http3Config http3;

  // Proxy configuration
  ProxyConfig proxy;
};

// Result type for protocol-agnostic connection acquisition
using AnyPooledConnection = std::variant<PooledConnection*, QuicPooledConnection*>;

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

  // Protocol-agnostic connection acquisition
  // Returns either a TCP connection (HTTP/1 or HTTP/2) or QUIC connection (HTTP/3)
  // based on the pool's protocol preference
  AnyPooledConnection AcquireAnyConnection(const std::string& host,
                                           uint16_t port);

  // Release any connection type back to the pool
  void ReleaseAnyConnection(AnyPooledConnection conn);

  // Remove any connection type (closed/failed)
  void RemoveAnyConnection(AnyPooledConnection conn);

  // TCP-specific: Acquire a connection to host:port
  // Returns nullptr if pool is exhausted
  PooledConnection* AcquireTcpConnection(const std::string& host, uint16_t port);

  // TCP-specific: Release a connection back to the pool
  void ReleaseTcpConnection(PooledConnection* conn);

  // TCP-specific: Remove a closed/failed connection
  void RemoveTcpConnection(PooledConnection* conn);

  // QUIC-specific: Acquire a QUIC connection to host:port
  // Returns nullptr if pool is exhausted or QUIC not enabled
  QuicPooledConnection* AcquireQuicConnection(const std::string& host,
                                              uint16_t port);

  // QUIC-specific: Release a QUIC connection back to the pool
  void ReleaseQuicConnection(QuicPooledConnection* conn);

  // QUIC-specific: Remove a closed/failed QUIC connection
  void RemoveQuicConnection(QuicPooledConnection* conn);

  // Cleanup idle connections across all hosts (both TCP and QUIC)
  void CleanupIdle(uint64_t now_ms);

  // Get or create a TCP host pool (for direct connection creation)
  HostPool* GetOrCreateHostPool(const std::string& host, uint16_t port);

  // Get or create a QUIC host pool
  QuicHostPool* GetOrCreateQuicHostPool(const std::string& host, uint16_t port);

  // Check if QUIC is enabled for this pool
  bool IsQuicEnabled() const;

  // Statistics
  size_t TotalConnections() const;
  size_t TotalQuicConnections() const;
  size_t TotalHosts() const;

  // Legacy compatibility: maps to AcquireTcpConnection
  PooledConnection* AcquireConnection(const std::string& host, uint16_t port) {
    return AcquireTcpConnection(host, port);
  }
  void ReleaseConnection(PooledConnection* conn) { ReleaseTcpConnection(conn); }
  void RemoveConnection(PooledConnection* conn) { RemoveTcpConnection(conn); }

 private:
  static std::string MakeHostKey(std::string_view host, uint16_t port);
  bool InitQuicContext();

  ConnectionPoolConfig config_;
  core::Reactor* reactor_;
  tls::TlsContextFactory* tls_factory_;

  // TCP host pools (HTTP/1.1 and HTTP/2)
  std::unordered_map<std::string, std::unique_ptr<HostPool>> host_pools_;

  // QUIC host pools (HTTP/3)
  std::unordered_map<std::string, std::unique_ptr<QuicHostPool>> quic_host_pools_;
  std::unique_ptr<quic::QuicTlsContext> quic_tls_ctx_;

  size_t total_connections_ = 0;
};

}  // namespace pool
}  // namespace holytls

#endif  // HOLYTLS_POOL_CONNECTION_POOL_H_

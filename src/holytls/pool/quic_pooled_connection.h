// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_POOL_QUIC_POOLED_CONNECTION_H_
#define HOLYTLS_POOL_QUIC_POOLED_CONNECTION_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "holytls/config.h"
#include "holytls/core/reactor.h"
#include "holytls/http2/h2_stream.h"
#include "holytls/quic/h3_session.h"
#include "holytls/quic/quic_connection.h"

namespace holytls {
namespace pool {

// Forward declarations
class QuicHostPool;

// Pooled QUIC connection wrapper with pool metadata
struct QuicPooledConnection {
  // The underlying QUIC connection
  std::unique_ptr<quic::QuicConnection> quic;

  // The HTTP/3 session
  std::unique_ptr<quic::H3Session> h3;

  // Pool membership
  QuicHostPool* host_pool = nullptr;

  // Host info
  std::string host;
  uint16_t port = 0;

  // Timing
  uint64_t created_ms = 0;
  uint64_t last_used_ms = 0;

  // Stream tracking
  size_t active_stream_count = 0;
  size_t max_streams = 100;

  // Health tracking
  size_t consecutive_errors = 0;
  bool marked_for_removal = false;

  // Check if connection can accept more streams
  bool HasCapacity() const {
    return quic && quic->IsConnected() && h3 && h3->CanSubmitRequest() &&
           active_stream_count < max_streams && !marked_for_removal;
  }

  bool IsIdle() const { return active_stream_count == 0; }
  bool IsConnected() const { return quic && quic->IsConnected(); }

  // Submit a request (compatible with H2Session interface)
  // Returns stream ID or -1 on error
  int64_t SubmitRequest(const http2::H2Headers& headers,
                        http2::H2StreamCallbacks callbacks,
                        const uint8_t* body = nullptr, size_t body_len = 0);

  // Flush pending H3 data to QUIC
  void FlushPendingData();
};

// Per-host QUIC connection pool configuration
struct QuicHostPoolConfig {
  size_t max_connections = 6;
  size_t max_streams_per_connection = 100;
  uint64_t idle_timeout_ms = 300000;    // 5 minutes
  uint64_t connect_timeout_ms = 30000;  // 30 seconds

  // QUIC transport parameters
  Http3Config h3_config;
};

// Per-host QUIC connection pool.
// Manages QUIC connections to a single host:port pair.
class QuicHostPool {
 public:
  const std::string host;
  const uint16_t port;

  QuicHostPool(const std::string& h, uint16_t p, const QuicHostPoolConfig& config,
               core::Reactor* reactor, quic::QuicTlsContext* tls_ctx);
  ~QuicHostPool();

  // Non-copyable, non-movable
  QuicHostPool(const QuicHostPool&) = delete;
  QuicHostPool& operator=(const QuicHostPool&) = delete;
  QuicHostPool(QuicHostPool&&) = delete;
  QuicHostPool& operator=(QuicHostPool&&) = delete;

  // Acquire a connection with available stream capacity
  QuicPooledConnection* AcquireConnection();

  // Release a connection (decrements stream count)
  void ReleaseConnection(QuicPooledConnection* conn);

  // Mark a connection as failed
  void FailConnection(QuicPooledConnection* conn);

  // Create a new QUIC connection (async)
  bool CreateConnection(const std::string& resolved_ip, bool ipv6 = false);

  // Cleanup expired idle connections
  size_t CleanupIdle(uint64_t now_ms);

  // Close all connections with optional completion callback
  // Used for cleanup when falling back from QUIC to TCP
  void CloseAllConnections(std::function<void()> on_complete = nullptr);

  // Pool statistics
  size_t TotalConnections() const { return connections_.size(); }
  size_t ActiveConnections() const;
  size_t IdleConnections() const;

 private:
  void RemoveConnection(QuicPooledConnection* conn);
  QuicPooledConnection* FindConnectionWithCapacity();

  QuicHostPoolConfig config_;
  core::Reactor* reactor_;
  quic::QuicTlsContext* tls_ctx_;

  std::vector<std::unique_ptr<QuicPooledConnection>> connections_;
};

}  // namespace pool
}  // namespace holytls

#endif  // HOLYTLS_POOL_QUIC_POOLED_CONNECTION_H_

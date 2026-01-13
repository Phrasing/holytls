// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/pool/quic_pooled_connection.h"

#include <algorithm>
#include <atomic>

namespace holytls {
namespace pool {

// QuicPooledConnection methods

int64_t QuicPooledConnection::SubmitRequest(const http2::H2Headers& headers,
                                             http2::H2StreamCallbacks callbacks,
                                             const uint8_t* body,
                                             size_t body_len) {
  if (!h3 || !h3->CanSubmitRequest()) {
    return -1;
  }

  int64_t stream_id = h3->SubmitRequest(headers, callbacks, body, body_len);
  if (stream_id >= 0) {
    active_stream_count++;
  }
  return stream_id;
}

void QuicPooledConnection::FlushPendingData() {
  if (!h3 || !quic) {
    return;
  }

  // Keep flushing until no more pending data
  // H3/QPACK may generate data on multiple streams that need to be sent in order
  constexpr int kMaxFlushIterations = 100;
  for (int iter = 0; iter < kMaxFlushIterations; ++iter) {
    std::vector<int64_t> pending_streams;
    h3->GetPendingStreams(pending_streams);

    if (pending_streams.empty()) {
      break;  // No more data to flush
    }

    bool wrote_any = false;
    for (int64_t stream_id : pending_streams) {
      uint8_t buf[4096];
      bool fin = false;
      ssize_t n = h3->ReadStreamData(stream_id, buf, sizeof(buf), fin);
      if (n > 0) {
        quic->WriteStream(stream_id, buf, static_cast<size_t>(n), fin);
        wrote_any = true;
      }
    }

    if (!wrote_any) {
      break;  // No data written, avoid infinite loop
    }
  }
}

// QuicHostPool methods

QuicHostPool::QuicHostPool(const std::string& h, uint16_t p,
                           const QuicHostPoolConfig& config,
                           core::Reactor* reactor,
                           quic::QuicTlsContext* tls_ctx)
    : host(h),
      port(p),
      config_(config),
      reactor_(reactor),
      tls_ctx_(tls_ctx) {}

QuicHostPool::~QuicHostPool() {
  // Close all connections
  for (auto& conn : connections_) {
    if (conn->quic) {
      conn->quic->Close();
    }
  }
}

QuicPooledConnection* QuicHostPool::AcquireConnection() {
  return FindConnectionWithCapacity();
}

void QuicHostPool::ReleaseConnection(QuicPooledConnection* conn) {
  if (!conn) return;

  if (conn->active_stream_count > 0) {
    conn->active_stream_count--;
  }
  conn->last_used_ms = reactor_->now_ms();
}

void QuicHostPool::FailConnection(QuicPooledConnection* conn) {
  if (!conn) return;

  conn->marked_for_removal = true;
  conn->consecutive_errors++;

  // Remove immediately
  RemoveConnection(conn);
}

bool QuicHostPool::CreateConnection(const std::string& resolved_ip, bool ipv6) {
  if (connections_.size() >= config_.max_connections) {
    return false;
  }

  // Create QUIC profile from config
  quic::ChromeQuicProfile profile;
  profile.max_idle_timeout = config_.h3_config.max_idle_timeout;
  profile.max_udp_payload_size = config_.h3_config.max_udp_payload_size;
  profile.initial_max_data = config_.h3_config.initial_max_data;
  profile.initial_max_stream_data_bidi_local =
      config_.h3_config.initial_max_stream_data_bidi_local;
  profile.initial_max_stream_data_bidi_remote =
      config_.h3_config.initial_max_stream_data_bidi_remote;
  profile.initial_max_stream_data_uni = config_.h3_config.initial_max_stream_data_uni;
  profile.initial_max_streams_bidi = config_.h3_config.initial_max_streams_bidi;
  profile.initial_max_streams_uni = config_.h3_config.initial_max_streams_uni;
  profile.ack_delay_exponent = config_.h3_config.ack_delay_exponent;
  profile.max_ack_delay = config_.h3_config.max_ack_delay;
  profile.disable_active_migration = config_.h3_config.disable_active_migration;

  // Create pooled connection
  auto pooled = std::make_unique<QuicPooledConnection>();
  pooled->host = host;
  pooled->port = port;
  pooled->host_pool = this;
  pooled->created_ms = reactor_->now_ms();
  pooled->last_used_ms = pooled->created_ms;
  pooled->max_streams = config_.max_streams_per_connection;

  // Create QUIC connection
  pooled->quic = std::make_unique<quic::QuicConnection>(
      reactor_, tls_ctx_, host, port, profile);

  // Set up connection callbacks
  QuicPooledConnection* conn_ptr = pooled.get();

  pooled->quic->SetConnectCallback([conn_ptr](bool success) {
    if (success && conn_ptr->quic) {
      // Initialize H3 session after QUIC handshake completes
      conn_ptr->h3 = std::make_unique<quic::H3Session>(conn_ptr->quic.get());
      conn_ptr->h3->Initialize();
    }
  });

  pooled->quic->SetStreamDataCallback(
      [conn_ptr](int64_t stream_id, const uint8_t* data, size_t len, bool fin) {
        if (conn_ptr->h3) {
          conn_ptr->h3->ProcessStreamData(stream_id, data, len, fin);
        }
      });

  pooled->quic->SetErrorCallback(
      [conn_ptr](uint64_t /*error_code*/, const std::string& /*reason*/) {
        conn_ptr->consecutive_errors++;
        conn_ptr->marked_for_removal = true;
      });

  // Start connection
  if (!pooled->quic->Connect(resolved_ip, ipv6)) {
    return false;
  }

  connections_.push_back(std::move(pooled));
  return true;
}

size_t QuicHostPool::CleanupIdle(uint64_t now_ms) {
  size_t closed = 0;
  auto it = connections_.begin();
  while (it != connections_.end()) {
    auto& conn = *it;
    bool should_remove = false;

    if (conn->marked_for_removal) {
      should_remove = true;
    } else if (conn->IsIdle() &&
               (now_ms - conn->last_used_ms) > config_.idle_timeout_ms) {
      // Idle timeout expired
      if (conn->quic) {
        conn->quic->Close();
      }
      should_remove = true;
    }

    if (should_remove) {
      it = connections_.erase(it);
      closed++;
    } else {
      ++it;
    }
  }
  return closed;
}

void QuicHostPool::CloseAllConnections(std::function<void()> on_complete) {
  if (connections_.empty()) {
    if (on_complete) {
      on_complete();
    }
    return;
  }

  // Track pending connection closes with a shared counter
  auto pending = std::make_shared<std::atomic<size_t>>(connections_.size());
  auto completion = std::make_shared<std::function<void()>>(std::move(on_complete));

  // Move connections to a shared vector to keep them alive until close completes
  auto alive_connections = std::make_shared<std::vector<std::unique_ptr<QuicPooledConnection>>>(
      std::move(connections_));

  for (auto& conn : *alive_connections) {
    if (conn->quic) {
      // Capture alive_connections to extend lifetime until all closes complete
      conn->quic->SetCloseCompleteCallback([pending, completion, alive_connections]() {
        if (pending->fetch_sub(1, std::memory_order_acq_rel) == 1) {
          // All connections closed, release the shared vector and call completion
          if (*completion) {
            (*completion)();
          }
        }
      });
      conn->quic->Close();
    } else {
      // No QUIC connection, just decrement counter
      if (pending->fetch_sub(1, std::memory_order_acq_rel) == 1) {
        if (*completion) {
          (*completion)();
        }
      }
    }
  }
  // connections_ is now empty (moved to alive_connections)
}

size_t QuicHostPool::ActiveConnections() const {
  size_t count = 0;
  for (const auto& conn : connections_) {
    if (!conn->IsIdle()) {
      count++;
    }
  }
  return count;
}

size_t QuicHostPool::IdleConnections() const {
  size_t count = 0;
  for (const auto& conn : connections_) {
    if (conn->IsIdle()) {
      count++;
    }
  }
  return count;
}

void QuicHostPool::RemoveConnection(QuicPooledConnection* conn) {
  auto it = std::find_if(connections_.begin(), connections_.end(),
                         [conn](const std::unique_ptr<QuicPooledConnection>& p) {
                           return p.get() == conn;
                         });
  if (it != connections_.end()) {
    if ((*it)->quic) {
      (*it)->quic->Close();
    }
    connections_.erase(it);
  }
}

QuicPooledConnection* QuicHostPool::FindConnectionWithCapacity() {
  for (auto& conn : connections_) {
    if (conn->HasCapacity()) {
      return conn.get();
    }
  }
  return nullptr;
}

}  // namespace pool
}  // namespace holytls

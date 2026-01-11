// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/pool/host_pool.h"

#include <algorithm>

namespace holytls {
namespace pool {

HostPool::HostPool(const std::string& host, uint16_t port,
                   const HostPoolConfig& config, core::Reactor* reactor,
                   tls::TlsContextFactory* tls_factory)
    : host_(host),
      port_(port),
      config_(config),
      reactor_(reactor),
      tls_factory_(tls_factory) {}

HostPool::~HostPool() {
  // Close all connections
  for (auto& pc : connections_) {
    if (pc && pc->connection) {
      pc->connection->Close();
    }
  }
  connections_.clear();
}

PooledConnection* HostPool::AcquireConnection() {
  // First, try to find an existing connection with capacity
  PooledConnection* conn = FindConnectionWithCapacity();
  if (conn) {
    conn->active_stream_count++;
    conn->last_used_ms = reactor_->now_ms();
    return conn;
  }

  // No connection with capacity available
  return nullptr;
}

void HostPool::ReleaseConnection(PooledConnection* conn) {
  if (!conn || conn->host_pool != this) {
    return;
  }

  if (conn->active_stream_count > 0) {
    conn->active_stream_count--;
  }

  conn->last_used_ms = reactor_->now_ms();

  // If connection has errors or is marked for removal, close it
  if (conn->marked_for_removal || conn->consecutive_errors > 3) {
    RemoveConnection(conn);
  }
}

void HostPool::FailConnection(PooledConnection* conn) {
  if (!conn || conn->host_pool != this) {
    return;
  }

  conn->consecutive_errors++;
  conn->marked_for_removal = true;

  // If connection is idle, remove it immediately
  if (conn->IsIdle()) {
    RemoveConnection(conn);
  }
}

bool HostPool::CreateConnection(const std::string& resolved_ip, bool ipv6) {
  // Check connection limit
  if (connections_.size() >= config_.max_connections) {
    return false;
  }

  // Create the connection
  auto connection =
      std::make_unique<core::Connection>(reactor_, tls_factory_, host_, port_);

  // Create pooled connection wrapper
  auto pooled = std::make_unique<PooledConnection>();
  pooled->connection = std::move(connection);
  pooled->host_pool = this;
  pooled->created_ms = reactor_->now_ms();
  pooled->last_used_ms = pooled->created_ms;
  pooled->max_streams = config_.max_streams_per_connection;

  // Set up idle callback to track when streams complete
  PooledConnection* raw_ptr = pooled.get();
  pooled->connection->SetIdleCallback([this, raw_ptr](core::Connection*) {
    // Connection is now idle - update last used time
    raw_ptr->last_used_ms = reactor_->now_ms();
  });

  // Start the connection
  if (!pooled->connection->Connect(resolved_ip, ipv6)) {
    return false;
  }

  connections_.push_back(std::move(pooled));
  return true;
}

size_t HostPool::CleanupIdle(uint64_t now_ms) {
  size_t closed = 0;

  // Remove idle connections that have exceeded timeout
  auto it = connections_.begin();
  while (it != connections_.end()) {
    auto& pc = *it;
    if (pc && pc->IsIdle() &&
        (now_ms - pc->last_used_ms) >= config_.idle_timeout_ms) {
      // Connection is idle and expired
      if (pc->connection) {
        pc->connection->Close();
      }
      it = connections_.erase(it);
      closed++;
    } else {
      ++it;
    }
  }

  return closed;
}

size_t HostPool::ActiveConnections() const {
  size_t count = 0;
  for (const auto& pc : connections_) {
    if (pc && !pc->IsIdle()) {
      count++;
    }
  }
  return count;
}

size_t HostPool::IdleConnections() const {
  size_t count = 0;
  for (const auto& pc : connections_) {
    if (pc && pc->IsIdle()) {
      count++;
    }
  }
  return count;
}

void HostPool::OnConnectionIdle(core::Connection* conn) {
  // Find the pooled connection for this raw connection
  for (auto& pc : connections_) {
    if (pc && pc->connection.get() == conn) {
      pc->last_used_ms = reactor_->now_ms();
      break;
    }
  }
}

void HostPool::RemoveConnection(PooledConnection* conn) {
  auto it = std::find_if(connections_.begin(), connections_.end(),
                         [conn](const std::unique_ptr<PooledConnection>& pc) {
                           return pc.get() == conn;
                         });

  if (it != connections_.end()) {
    if ((*it)->connection) {
      (*it)->connection->Close();
    }
    connections_.erase(it);
  }
}

PooledConnection* HostPool::FindConnectionWithCapacity() {
  PooledConnection* best = nullptr;
  size_t min_streams = SIZE_MAX;

  // Find connected connection with fewest active streams
  for (auto& pc : connections_) {
    if (pc && pc->connection && pc->connection->IsConnected() &&
        pc->HasCapacity()) {
      if (pc->active_stream_count < min_streams) {
        best = pc.get();
        min_streams = pc->active_stream_count;
      }
    }
  }

  return best;
}

PooledConnection* HostPool::FindIdleConnection() {
  // Find a fully idle connection (for reuse after becoming idle)
  for (auto& pc : connections_) {
    if (pc && pc->connection && pc->connection->IsConnected() && pc->IsIdle() &&
        !pc->marked_for_removal) {
      return pc.get();
    }
  }
  return nullptr;
}

}  // namespace pool
}  // namespace holytls

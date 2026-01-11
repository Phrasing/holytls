// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/pool/connection_pool.h"

#include "holytls/pool/host_pool.h"

namespace holytls {
namespace pool {

ConnectionPool::ConnectionPool(const ConnectionPoolConfig& config,
                               core::Reactor* reactor,
                               tls::TlsContextFactory* tls_factory)
    : config_(config), reactor_(reactor), tls_factory_(tls_factory) {}

ConnectionPool::~ConnectionPool() {
  // HostPools will clean up their connections in their destructors
  host_pools_.clear();
}

PooledConnection* ConnectionPool::AcquireConnection(const std::string& host,
                                                    uint16_t port) {
  HostPool* pool = GetOrCreateHostPool(host, port);
  if (!pool) {
    return nullptr;
  }

  return pool->AcquireConnection();
}

void ConnectionPool::ReleaseConnection(PooledConnection* conn) {
  if (!conn || !conn->host_pool) {
    return;
  }

  conn->host_pool->ReleaseConnection(conn);
}

void ConnectionPool::RemoveConnection(PooledConnection* conn) {
  if (!conn || !conn->host_pool) {
    return;
  }

  conn->host_pool->FailConnection(conn);
}

void ConnectionPool::CleanupIdle(uint64_t now_ms) {
  for (auto& [key, pool] : host_pools_) {
    if (pool) {
      pool->CleanupIdle(now_ms);
    }
  }

  // Remove empty host pools
  for (auto it = host_pools_.begin(); it != host_pools_.end();) {
    if (it->second && it->second->TotalConnections() == 0) {
      it = host_pools_.erase(it);
    } else {
      ++it;
    }
  }
}

size_t ConnectionPool::TotalConnections() const {
  size_t total = 0;
  for (const auto& [key, pool] : host_pools_) {
    if (pool) {
      total += pool->TotalConnections();
    }
  }
  return total;
}

size_t ConnectionPool::TotalHosts() const { return host_pools_.size(); }

HostPool* ConnectionPool::GetOrCreateHostPool(const std::string& host,
                                              uint16_t port) {
  std::string key = MakeHostKey(host, port);

  auto it = host_pools_.find(key);
  if (it != host_pools_.end()) {
    return it->second.get();
  }

  // Create new host pool
  HostPoolConfig host_config;
  host_config.max_connections = config_.max_connections_per_host;
  host_config.max_streams_per_connection = config_.max_streams_per_connection;
  host_config.idle_timeout_ms = config_.idle_timeout_ms;
  host_config.connect_timeout_ms = config_.connect_timeout_ms;

  auto pool = std::make_unique<HostPool>(host, port, host_config, reactor_,
                                         tls_factory_);

  HostPool* raw_ptr = pool.get();
  host_pools_[key] = std::move(pool);

  return raw_ptr;
}

std::string ConnectionPool::MakeHostKey(std::string_view host, uint16_t port) {
  std::string key;
  key.reserve(host.size() + 6);  // host + ":" + max 5 digits
  key.append(host);
  key += ':';
  key += std::to_string(port);
  return key;
}

}  // namespace pool
}  // namespace holytls

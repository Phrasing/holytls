// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "pool/connection_pool.h"

#include "pool/host_pool.h"

namespace chad {
namespace pool {

ConnectionPool::ConnectionPool(const ConnectionPoolConfig& config)
    : config_(config) {}

ConnectionPool::~ConnectionPool() = default;

PooledConnection* ConnectionPool::AcquireConnection(const std::string& /*host*/,
                                                    uint16_t /*port*/) {
  // TODO: Implement connection acquisition
  return nullptr;
}

void ConnectionPool::ReleaseConnection(PooledConnection* /*conn*/) {
  // TODO: Implement connection release
}

void ConnectionPool::RemoveConnection(PooledConnection* /*conn*/) {
  // TODO: Implement connection removal
}

void ConnectionPool::CleanupIdle(uint64_t /*now_ms*/) {
  // TODO: Implement idle cleanup
}

size_t ConnectionPool::TotalConnections() const {
  return 0;  // TODO
}

size_t ConnectionPool::TotalHosts() const {
  return host_pools_.size();
}

HostPool* ConnectionPool::GetOrCreateHostPool(const std::string& /*host*/,
                                              uint16_t /*port*/) {
  // TODO: Implement
  return nullptr;
}

}  // namespace pool
}  // namespace chad

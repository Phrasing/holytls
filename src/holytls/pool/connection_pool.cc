// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/pool/connection_pool.h"

#include "holytls/pool/host_pool.h"

#if defined(HOLYTLS_BUILD_QUIC)
#include "holytls/pool/quic_pooled_connection.h"
#include "holytls/quic/quic_connection.h"
#define HOLYTLS_QUIC_AVAILABLE 1
#else
#define HOLYTLS_QUIC_AVAILABLE 0
#endif

namespace holytls {
namespace pool {

ConnectionPool::ConnectionPool(const ConnectionPoolConfig& config,
                               core::Reactor* reactor,
                               tls::TlsContextFactory* tls_factory)
    : config_(config), reactor_(reactor), tls_factory_(tls_factory) {
#if HOLYTLS_QUIC_AVAILABLE
  // Initialize QUIC context if protocol preference allows it
  if (config_.protocol == ProtocolPreference::kAuto ||
      config_.protocol == ProtocolPreference::kHttp3Only) {
    InitQuicContext();
  }
#endif
}

ConnectionPool::~ConnectionPool() {
  // HostPools will clean up their connections in their destructors
  host_pools_.clear();
#if HOLYTLS_QUIC_AVAILABLE
  quic_host_pools_.clear();
#endif
}

bool ConnectionPool::InitQuicContext() {
#if HOLYTLS_QUIC_AVAILABLE
  if (quic_tls_ctx_) {
    return true;  // Already initialized
  }

  quic_tls_ctx_ = std::make_unique<quic::QuicTlsContext>();
  if (!quic_tls_ctx_->InitClient()) {
    quic_tls_ctx_.reset();
    return false;
  }
  return true;
#else
  return false;
#endif
}

bool ConnectionPool::IsQuicEnabled() const {
#if HOLYTLS_QUIC_AVAILABLE
  return quic_tls_ctx_ != nullptr &&
         (config_.protocol == ProtocolPreference::kAuto ||
          config_.protocol == ProtocolPreference::kHttp3Only);
#else
  return false;
#endif
}

// Protocol-agnostic connection acquisition
AnyPooledConnection ConnectionPool::AcquireAnyConnection(
    const std::string& host, uint16_t port) {
  switch (config_.protocol) {
    case ProtocolPreference::kHttp3Only:
#if HOLYTLS_QUIC_AVAILABLE
      return AcquireQuicConnection(host, port);
#else
      return static_cast<PooledConnection*>(nullptr);
#endif

    case ProtocolPreference::kAuto:
#if HOLYTLS_QUIC_AVAILABLE
      // Try QUIC first if enabled
      if (IsQuicEnabled()) {
        if (auto* quic = AcquireQuicConnection(host, port)) {
          return quic;
        }
      }
#endif
      // Fall through to TCP
      return AcquireTcpConnection(host, port);

    case ProtocolPreference::kHttp2Preferred:
    case ProtocolPreference::kHttp1Only:
    default:
      return AcquireTcpConnection(host, port);
  }
}

void ConnectionPool::ReleaseAnyConnection(AnyPooledConnection conn) {
  std::visit(
      [this](auto* c) {
        if constexpr (std::is_same_v<decltype(c), PooledConnection*>) {
          ReleaseTcpConnection(c);
        }
#if HOLYTLS_QUIC_AVAILABLE
        else if constexpr (std::is_same_v<decltype(c), QuicPooledConnection*>) {
          ReleaseQuicConnection(c);
        }
#endif
      },
      conn);
}

void ConnectionPool::RemoveAnyConnection(AnyPooledConnection conn) {
  std::visit(
      [this](auto* c) {
        if constexpr (std::is_same_v<decltype(c), PooledConnection*>) {
          RemoveTcpConnection(c);
        }
#if HOLYTLS_QUIC_AVAILABLE
        else if constexpr (std::is_same_v<decltype(c), QuicPooledConnection*>) {
          RemoveQuicConnection(c);
        }
#endif
      },
      conn);
}

// TCP connection methods
PooledConnection* ConnectionPool::AcquireTcpConnection(const std::string& host,
                                                       uint16_t port) {
  HostPool* pool = GetOrCreateHostPool(host, port);
  if (!pool) {
    return nullptr;
  }

  return pool->AcquireConnection();
}

void ConnectionPool::ReleaseTcpConnection(PooledConnection* conn) {
  if (!conn || !conn->host_pool) {
    return;
  }

  conn->host_pool->ReleaseConnection(conn);
}

void ConnectionPool::RemoveTcpConnection(PooledConnection* conn) {
  if (!conn || !conn->host_pool) {
    return;
  }

  conn->host_pool->FailConnection(conn);
}

// QUIC connection methods
QuicPooledConnection* ConnectionPool::AcquireQuicConnection(
    const std::string& host, uint16_t port) {
#if HOLYTLS_QUIC_AVAILABLE
  if (!IsQuicEnabled()) {
    return nullptr;
  }

  QuicHostPool* pool = GetOrCreateQuicHostPool(host, port);
  if (!pool) {
    return nullptr;
  }

  return pool->AcquireConnection();
#else
  (void)host;
  (void)port;
  return nullptr;
#endif
}

void ConnectionPool::ReleaseQuicConnection(QuicPooledConnection* conn) {
#if HOLYTLS_QUIC_AVAILABLE
  if (!conn || !conn->host_pool) {
    return;
  }

  conn->host_pool->ReleaseConnection(conn);
#else
  (void)conn;
#endif
}

void ConnectionPool::RemoveQuicConnection(QuicPooledConnection* conn) {
#if HOLYTLS_QUIC_AVAILABLE
  if (!conn || !conn->host_pool) {
    return;
  }

  conn->host_pool->FailConnection(conn);
#else
  (void)conn;
#endif
}

void ConnectionPool::CleanupIdle(uint64_t now_ms) {
  // Cleanup TCP host pools
  for (auto& [key, pool] : host_pools_) {
    if (pool) {
      pool->CleanupIdle(now_ms);
    }
  }

  // Remove empty TCP host pools
  for (auto it = host_pools_.begin(); it != host_pools_.end();) {
    if (it->second && it->second->TotalConnections() == 0) {
      it = host_pools_.erase(it);
    } else {
      ++it;
    }
  }

#if HOLYTLS_QUIC_AVAILABLE
  // Cleanup QUIC host pools
  for (auto& [key, pool] : quic_host_pools_) {
    if (pool) {
      pool->CleanupIdle(now_ms);
    }
  }

  // Remove empty QUIC host pools
  for (auto it = quic_host_pools_.begin(); it != quic_host_pools_.end();) {
    if (it->second && it->second->TotalConnections() == 0) {
      it = quic_host_pools_.erase(it);
    } else {
      ++it;
    }
  }
#endif
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

size_t ConnectionPool::TotalQuicConnections() const {
#if HOLYTLS_QUIC_AVAILABLE
  size_t total = 0;
  for (const auto& [key, pool] : quic_host_pools_) {
    if (pool) {
      total += pool->TotalConnections();
    }
  }
  return total;
#else
  return 0;
#endif
}

size_t ConnectionPool::TotalHosts() const {
  size_t total = host_pools_.size();
#if HOLYTLS_QUIC_AVAILABLE
  total += quic_host_pools_.size();
#endif
  return total;
}

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
  host_config.proxy = config_.proxy;

  auto pool = std::make_unique<HostPool>(host, port, host_config, reactor_,
                                         tls_factory_);

  HostPool* raw_ptr = pool.get();
  host_pools_[key] = std::move(pool);

  return raw_ptr;
}

QuicHostPool* ConnectionPool::GetOrCreateQuicHostPool(const std::string& host,
                                                      uint16_t port) {
#if HOLYTLS_QUIC_AVAILABLE
  if (!quic_tls_ctx_) {
    return nullptr;
  }

  std::string key = MakeHostKey(host, port);

  auto it = quic_host_pools_.find(key);
  if (it != quic_host_pools_.end()) {
    return it->second.get();
  }

  // Create QUIC host pool config from pool config
  QuicHostPoolConfig quic_config;
  quic_config.max_connections = config_.max_connections_per_host;
  quic_config.max_streams_per_connection = config_.max_streams_per_connection;
  quic_config.idle_timeout_ms = config_.idle_timeout_ms;
  quic_config.connect_timeout_ms = config_.connect_timeout_ms;
  quic_config.h3_config = config_.http3;

  auto pool = std::make_unique<QuicHostPool>(host, port, quic_config, reactor_,
                                             quic_tls_ctx_.get());

  QuicHostPool* raw_ptr = pool.get();
  quic_host_pools_[key] = std::move(pool);

  return raw_ptr;
#else
  (void)host;
  (void)port;
  return nullptr;
#endif
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

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/core/reactor_manager.h"

#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#endif

namespace holytls {
namespace core {

namespace {

// FNV-1a hash for consistent host:port distribution
uint64_t HashHostPort(std::string_view host, uint16_t port) {
  uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
  for (char c : host) {
    hash ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
    hash *= 1099511628211ULL;  // FNV prime
  }
  hash ^= static_cast<uint64_t>(port);
  hash *= 1099511628211ULL;
  hash ^= static_cast<uint64_t>(port >> 8);
  hash *= 1099511628211ULL;
  return hash;
}

// Get number of CPU cores
size_t GetCpuCount() {
  unsigned int count = std::thread::hardware_concurrency();
  return count > 0 ? count : 4;  // Default to 4 if detection fails
}

// Pin thread to specific CPU core
void PinThreadToCore([[maybe_unused]] size_t core_id) {
#ifdef _WIN32
  DWORD_PTR mask = 1ULL << core_id;
  SetThreadAffinityMask(GetCurrentThread(), mask);
#elif defined(__linux__)
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
  // macOS doesn't support thread pinning
}

}  // namespace

ReactorManager::ReactorManager(const ReactorManagerConfig& config)
    : config_(config) {
  // Determine number of reactors
  size_t num_reactors = config_.num_reactors;
  if (num_reactors == 0) {
    num_reactors = GetCpuCount();
  }

  // Create reactor contexts
  contexts_.reserve(num_reactors);
  for (size_t i = 0; i < num_reactors; ++i) {
    auto ctx = std::make_unique<ReactorContext>();
    ctx->index = i;
    ctx->reactor = std::make_unique<Reactor>();

    // Create per-reactor buffer pool
    memory::BufferPool::Config bp_config;
    bp_config.small_count = config_.buffer_pool_small_count;
    bp_config.medium_count = config_.buffer_pool_medium_count;
    bp_config.large_count = config_.buffer_pool_large_count;
    ctx->buffer_pool = std::make_unique<memory::BufferPool>(bp_config);

    // DNS resolver will be created after reactor starts (needs loop)
    contexts_.push_back(std::move(ctx));
  }
}

ReactorManager::~ReactorManager() { Stop(); }

void ReactorManager::Initialize(tls::TlsContextFactory* tls_factory,
                                const pool::ConnectionPoolConfig& pool_config) {
  if (initialized_) {
    return;
  }

  tls_factory_ = tls_factory;
  pool_config_ = pool_config;

  // Create per-reactor connection pools and DNS resolvers
  for (auto& ctx : contexts_) {
    ctx->dns_resolver =
        std::make_unique<util::DnsResolver>(ctx->reactor->loop());

    ctx->connection_pool = std::make_unique<pool::ConnectionPool>(
        pool_config_, ctx->reactor.get(), tls_factory_);
  }

  initialized_ = true;
}

void ReactorManager::Start() {
  if (running_.load(std::memory_order_acquire)) {
    return;  // Already running
  }

  if (!initialized_) {
    return;  // Not initialized
  }

  running_.store(true, std::memory_order_release);

  // Start reactor threads
  for (auto& ctx : contexts_) {
    ctx->running.store(true, std::memory_order_release);
    ctx->thread = std::make_unique<std::thread>(
        [this, raw_ctx = ctx.get()]() { RunReactor(raw_ctx); });
  }
}

void ReactorManager::Stop() {
  if (!running_.load(std::memory_order_acquire)) {
    return;  // Not running
  }

  running_.store(false, std::memory_order_release);

  // Signal all reactors to stop
  for (auto& ctx : contexts_) {
    ctx->running.store(false, std::memory_order_release);
    if (ctx->reactor) {
      ctx->reactor->Stop();
    }
  }

  // Wait for all threads to finish
  for (auto& ctx : contexts_) {
    if (ctx->thread && ctx->thread->joinable()) {
      ctx->thread->join();
    }
    ctx->thread.reset();
  }
}

ReactorContext* ReactorManager::GetReactorForHost(std::string_view host,
                                                  uint16_t port) {
  size_t index = GetReactorIndex(host, port);
  return contexts_[index].get();
}

ReactorContext* ReactorManager::GetReactor(size_t index) {
  if (index >= contexts_.size()) {
    return nullptr;
  }
  return contexts_[index].get();
}

ReactorContext* ReactorManager::GetNextReactor() {
  size_t index =
      next_reactor_.fetch_add(1, std::memory_order_relaxed) % contexts_.size();
  return contexts_[index].get();
}

void ReactorManager::Post(size_t reactor_index,
                          std::function<void()> callback) {
  if (reactor_index >= contexts_.size()) {
    return;
  }

  auto& ctx = contexts_[reactor_index];
  if (ctx && ctx->reactor) {
    ctx->reactor->Post(std::move(callback));
  }
}

void ReactorManager::PostAll(std::function<void()> callback) {
  for (auto& ctx : contexts_) {
    if (ctx && ctx->reactor) {
      // Make a copy of the callback for each reactor
      ctx->reactor->Post(callback);
    }
  }
}

size_t ReactorManager::TotalConnections() const {
  size_t total = 0;
  for (const auto& ctx : contexts_) {
    if (ctx && ctx->connection_pool) {
      total += ctx->connection_pool->TotalConnections();
    }
  }
  return total;
}

void ReactorManager::RunReactor(ReactorContext* ctx) {
  // Pin to CPU core if configured
  if (config_.pin_to_cores) {
    PinThreadToCore(ctx->index % GetCpuCount());
  }

  // Use Run() which properly blocks on UV_RUN_ONCE waiting for IO
  // This prevents CPU spinning when idle. The reactor's Stop() method
  // will signal it to exit when ReactorManager::Stop() is called.
  ctx->reactor->Run();
}

size_t ReactorManager::GetReactorIndex(std::string_view host,
                                       uint16_t port) const {
  uint64_t hash = HashHostPort(host, port);
  return hash % contexts_.size();
}

}  // namespace core
}  // namespace holytls

// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "tls/session_cache.h"

#include <openssl/err.h>

namespace chad {
namespace tls {

namespace {

// Static ex_data indices (initialized on first call)
int g_session_cache_index = -1;
int g_port_index = -1;

}  // namespace

int GetSessionCacheIndex() {
  if (g_session_cache_index < 0) {
    g_session_cache_index =
        SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }
  return g_session_cache_index;
}

int GetPortIndex() {
  if (g_port_index < 0) {
    g_port_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }
  return g_port_index;
}

TlsSessionCache::TlsSessionCache(SSL_CTX* ctx, size_t max_entries)
    : ctx_(ctx), max_entries_(max_entries) {
  DLLInit(&lru_list_);
}

TlsSessionCache::~TlsSessionCache() {
  // Entries are cleaned up automatically via unique_ptr
}

std::string TlsSessionCache::MakeKey(const std::string& host, uint16_t port) {
  return host + ":" + std::to_string(port);
}

void TlsSessionCache::Store(const std::string& host, uint16_t port,
                            SSL_SESSION* session) {
  if (!session) return;

  // Serialize session to ASN.1 DER bytes
  uint8_t* data = nullptr;
  size_t len = 0;
  if (!SSL_SESSION_to_bytes(session, &data, &len)) {
    ERR_clear_error();
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);

  std::string key = MakeKey(host, port);

  // Remove existing entry if present
  auto it = cache_.find(key);
  if (it != cache_.end()) {
    DLLRemove(&lru_list_, &it->second->lru_node);
    cache_.erase(it);
  }

  // Evict LRU entries if at capacity
  while (cache_.size() >= max_entries_ && !DLLIsEmpty(&lru_list_)) {
    EvictLruLocked();
  }

  // Create new entry
  auto entry = std::make_unique<SessionEntry>();
  entry->session_data.assign(data, data + len);
  entry->receipt_time = std::chrono::steady_clock::now();
  entry->lifetime_hint_seconds = SSL_SESSION_get_timeout(session);
  // BoringSSL uses SSL_SESSION_early_data_capable instead of get_max_early_data
  entry->max_early_data_size =
      SSL_SESSION_early_data_capable(session) ? 16384 : 0;
  entry->cache_key = key;

  OPENSSL_free(data);

  // Insert and add to LRU front (most recently used)
  SessionEntry* entry_ptr = entry.get();
  cache_[key] = std::move(entry);
  DLLPushFront(&lru_list_, &entry_ptr->lru_node);
}

SSL_SESSION* TlsSessionCache::Lookup(const std::string& host, uint16_t port) {
  std::lock_guard<std::mutex> lock(mutex_);

  std::string key = MakeKey(host, port);
  auto it = cache_.find(key);

  if (it == cache_.end()) {
    misses_.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }

  SessionEntry* entry = it->second.get();

  // Check expiry
  if (entry->IsExpired()) {
    DLLRemove(&lru_list_, &entry->lru_node);
    cache_.erase(it);
    misses_.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }

  // Deserialize session
  SSL_SESSION* session = SSL_SESSION_from_bytes(
      entry->session_data.data(), entry->session_data.size(), ctx_);

  if (!session) {
    // Corrupted entry, remove it
    ERR_clear_error();
    DLLRemove(&lru_list_, &entry->lru_node);
    cache_.erase(it);
    misses_.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
  }

  // Update LRU position (move to front)
  DLLRemove(&lru_list_, &entry->lru_node);
  DLLPushFront(&lru_list_, &entry->lru_node);

  hits_.fetch_add(1, std::memory_order_relaxed);
  return session;  // Caller must SSL_SESSION_free()
}

void TlsSessionCache::Remove(const std::string& host, uint16_t port) {
  std::lock_guard<std::mutex> lock(mutex_);

  std::string key = MakeKey(host, port);
  auto it = cache_.find(key);

  if (it != cache_.end()) {
    DLLRemove(&lru_list_, &it->second->lru_node);
    cache_.erase(it);
  }
}

size_t TlsSessionCache::PurgeExpired() {
  std::lock_guard<std::mutex> lock(mutex_);

  size_t removed = 0;

  // Iterate from back (oldest) to front
  DLLNode* node = lru_list_.last;
  while (node) {
    DLLNode* prev = node->prev;
    auto* entry = ContainerOf(node, SessionEntry, lru_node);

    if (entry->IsExpired()) {
      DLLRemove(&lru_list_, node);
      cache_.erase(entry->cache_key);
      removed++;
    }

    node = prev;
  }

  return removed;
}

size_t TlsSessionCache::Size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cache_.size();
}

void TlsSessionCache::EvictLruLocked() {
  // Remove from back of LRU list (least recently used)
  DLLNode* oldest = DLLPopBack(&lru_list_);
  if (oldest) {
    auto* entry = ContainerOf(oldest, SessionEntry, lru_node);
    cache_.erase(entry->cache_key);
  }
}

}  // namespace tls
}  // namespace chad

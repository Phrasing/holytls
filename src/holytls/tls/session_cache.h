// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TLS_SESSION_CACHE_H_
#define HOLYTLS_TLS_SESSION_CACHE_H_

// Include platform.h first for Windows compatibility
#include "holytls/util/platform.h"

#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "holytls/base/list.h"

namespace holytls {
namespace tls {

// Cached TLS session entry with metadata for Chrome-like resumption.
// Sessions are serialized to ASN.1 DER format for storage.
struct SessionEntry {
  // Serialized session data (ASN.1 DER via SSL_SESSION_to_bytes)
  std::vector<uint8_t> session_data;

  // Time when session ticket was received (for expiry calculation)
  std::chrono::steady_clock::time_point receipt_time;

  // Ticket lifetime hint from server (seconds)
  uint32_t lifetime_hint_seconds = 0;

  // Maximum early data size (0 = no 0-RTT support)
  uint32_t max_early_data_size = 0;

  // Cache key for reverse lookup during LRU eviction
  std::string cache_key;

  // Intrusive list node for LRU ordering
  DLLNode lru_node = {};

  // Check if session has expired based on lifetime hint
  bool IsExpired() const {
    auto now = std::chrono::steady_clock::now();
    auto age =
        std::chrono::duration_cast<std::chrono::seconds>(now - receipt_time)
            .count();
    return age >= static_cast<int64_t>(lifetime_hint_seconds);
  }

  // Check if this session supports 0-RTT early data
  bool SupportsEarlyData() const { return max_early_data_size > 0; }
};

// Thread-safe TLS session cache with LRU eviction.
// Follows Chrome's external cache model (SSL_SESS_CACHE_NO_INTERNAL_STORE).
//
// Usage:
//   1. Create cache with SSL_CTX pointer (needed for deserialization)
//   2. Install SSL_CTX_sess_set_new_cb() callback that calls Store()
//   3. Before handshake, call Lookup() and use SSL_set_session()
//   4. After handshake, check SSL_session_reused() to verify resumption
class TlsSessionCache {
 public:
  // Create cache with given SSL_CTX (for deserialization) and max capacity.
  // ctx must outlive the cache.
  explicit TlsSessionCache(SSL_CTX* ctx, size_t max_entries = 1024);
  ~TlsSessionCache();

  // Non-copyable, non-movable (contains mutex)
  TlsSessionCache(const TlsSessionCache&) = delete;
  TlsSessionCache& operator=(const TlsSessionCache&) = delete;
  TlsSessionCache(TlsSessionCache&&) = delete;
  TlsSessionCache& operator=(TlsSessionCache&&) = delete;

  // Store a new session ticket (called from SSL_CTX_sess_set_new_cb).
  // Thread-safe. Session is serialized and stored.
  void Store(const std::string& host, uint16_t port, SSL_SESSION* session);

  // Retrieve session for resumption.
  // Returns deserialized SSL_SESSION* or nullptr if not found/expired.
  // Caller MUST call SSL_SESSION_free() on returned pointer.
  // Thread-safe.
  SSL_SESSION* Lookup(const std::string& host, uint16_t port);

  // Remove session for a host:port (e.g., when resumption fails).
  // Thread-safe.
  void Remove(const std::string& host, uint16_t port);

  // Clean up expired sessions. Returns number of sessions removed.
  // Thread-safe.
  size_t PurgeExpired();

  // Get current number of cached sessions.
  size_t Size() const;

  // Statistics (lock-free reads)
  size_t Hits() const { return hits_.load(std::memory_order_relaxed); }
  size_t Misses() const { return misses_.load(std::memory_order_relaxed); }

 private:
  // Create cache key from host and port
  static std::string MakeKey(const std::string& host, uint16_t port);

  // Evict least recently used entry (caller must hold mutex)
  void EvictLruLocked();

  // SSL_CTX for SSL_SESSION_from_bytes() deserialization
  SSL_CTX* ctx_;

  // Mutex for thread-safe access
  mutable std::mutex mutex_;

  // Main storage: key -> session entry
  std::unordered_map<std::string, std::unique_ptr<SessionEntry>> cache_;

  // LRU list: front = most recently used, back = least recently used
  DLLList lru_list_ = {};

  // Maximum number of entries
  size_t max_entries_;

  // Statistics
  std::atomic<size_t> hits_{0};
  std::atomic<size_t> misses_{0};
};

// Global ex_data indices for SSL_CTX and SSL objects.
// These must be initialized once at startup.
int GetSessionCacheIndex();
int GetPortIndex();

}  // namespace tls
}  // namespace holytls

#endif  // HOLYTLS_TLS_SESSION_CACHE_H_

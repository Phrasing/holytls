// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_UTIL_DNS_RESOLVER_H_
#define HOLYTLS_UTIL_DNS_RESOLVER_H_

// Include platform.h first for Windows compatibility
#include "holytls/util/platform.h"

#include <uv.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace holytls {
namespace util {

// Resolved address
struct ResolvedAddress {
  std::string ip;
  bool is_ipv6;
};

// DNS resolution result callback
using DnsCallback = std::function<void(
    const std::vector<ResolvedAddress>& addresses, const std::string& error)>;

// Cache configuration
inline constexpr size_t kMaxCacheEntries = 256;
inline constexpr size_t kMaxAddressesPerEntry = 8;
inline constexpr uint64_t kDefaultCacheTtlMs = 60000;  // 60 seconds

// DNS cache entry (fixed-size, no heap allocation)
struct DnsCacheEntry {
  char hostname[256];
  uint64_t expires_at_ms;
  ResolvedAddress addresses[kMaxAddressesPerEntry];
  uint8_t address_count;
  bool valid;
};

// DNS resolver with caching using libuv's async getaddrinfo
// Cache uses fixed-size array for zero allocation in hot path
class DnsResolver {
 public:
  // Cache TTL in milliseconds (default 60 seconds)
  uint64_t cache_ttl_ms = kDefaultCacheTtlMs;

  // Create resolver attached to a libuv loop
  explicit DnsResolver(uv_loop_t* loop);
  ~DnsResolver();

  // Non-copyable
  DnsResolver(const DnsResolver&) = delete;
  DnsResolver& operator=(const DnsResolver&) = delete;

  // BLOCKING resolve - DO NOT use from reactor/event loop threads!
  // Can block for 1-5 seconds. Use ResolveAsync() instead.
  // Only use for initialization or non-reactor thread contexts.
  std::vector<ResolvedAddress> Resolve(const std::string& hostname,
                                       std::string* error);

  // Async resolve - checks cache first, then libuv thread pool
  // Callback is invoked on the event loop thread
  void ResolveAsync(const std::string& hostname, DnsCallback callback);

  // Clear all cached entries
  void ClearCache();

  // Get cache statistics
  size_t CacheHits() const { return cache_hits_; }
  size_t CacheMisses() const { return cache_misses_; }

  // Cancel all pending async requests
  void CancelAll();

 private:
  static void OnResolved(uv_getaddrinfo_t* req, int status,
                         struct addrinfo* res);
  static std::vector<ResolvedAddress> ParseAddrinfo(struct addrinfo* res);

  // Cache operations
  DnsCacheEntry* FindCached(const std::string& hostname, uint64_t now_ms);
  DnsCacheEntry* FindSlotForInsert(uint64_t now_ms);
  void StoreInCache(const std::string& hostname,
                    const std::vector<ResolvedAddress>& addrs, uint64_t now_ms);

  uv_loop_t* loop_;

  // DNS cache (fixed-size array, no dynamic allocation)
  DnsCacheEntry cache_[kMaxCacheEntries] = {};
  size_t cache_hits_ = 0;
  size_t cache_misses_ = 0;
};

}  // namespace util
}  // namespace holytls

#endif  // HOLYTLS_UTIL_DNS_RESOLVER_H_

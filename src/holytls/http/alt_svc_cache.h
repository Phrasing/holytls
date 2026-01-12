// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_HTTP_ALT_SVC_CACHE_H_
#define HOLYTLS_HTTP_ALT_SVC_CACHE_H_

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace holytls {
namespace http {

// Represents a single Alt-Svc entry for one protocol
struct AltSvcEntry {
  std::string protocol;  // "h3", "h3-29", etc.
  std::string host;      // Alternative host (empty = same as origin)
  uint16_t port = 0;
  uint64_t expires_ms = 0;

  bool IsExpired(uint64_t now_ms) const { return now_ms >= expires_ms; }

  bool SupportsHttp3() const {
    return protocol == "h3" || protocol.starts_with("h3-");
  }
};

// Cache entry for an origin (host:port combination)
struct OriginAltSvc {
  std::vector<AltSvcEntry> entries;
  uint64_t last_updated_ms = 0;
};

// Alt-Svc cache configuration
struct AltSvcCacheConfig {
  size_t max_entries = 1024;
  uint64_t default_max_age_ms = 86400000;   // 24 hours
  uint64_t max_max_age_ms = 604800000;      // 7 days cap
  uint64_t failure_penalty_ms = 300000;     // 5 minutes
};

// Thread-safe Alt-Svc cache for HTTP/3 discovery
//
// Chrome-like behavior:
// 1. Parse Alt-Svc headers from HTTP responses
// 2. Cache H3 availability per-origin with TTL
// 3. Query cache before connecting to prefer QUIC
// 4. Track failures to avoid retry spam
class AltSvcCache {
 public:
  explicit AltSvcCache(const AltSvcCacheConfig& config = {});
  ~AltSvcCache() = default;

  // Non-copyable, non-movable
  AltSvcCache(const AltSvcCache&) = delete;
  AltSvcCache& operator=(const AltSvcCache&) = delete;

  // Parse Alt-Svc header and store entries for origin
  // header format: "h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400"
  void ProcessAltSvc(std::string_view origin_host, uint16_t origin_port,
                     std::string_view header);

  // Get best HTTP/3 endpoint for origin, if available and not expired
  // Returns nullopt if no valid H3 entry exists or H3 recently failed
  std::optional<AltSvcEntry> GetHttp3Endpoint(std::string_view host,
                                               uint16_t port) const;

  // Check if origin has valid H3 support cached (and not in failure penalty)
  bool HasHttp3Support(std::string_view host, uint16_t port) const;

  // Mark H3 as failed for origin (temporary negative cache)
  void MarkHttp3Failed(std::string_view host, uint16_t port);

  // Clear H3 failure for origin (call after successful H3 connection)
  void ClearHttp3Failure(std::string_view host, uint16_t port);

  // Clear all entries for a specific origin
  void ClearOrigin(std::string_view host, uint16_t port);

  // Clear all entries
  void ClearAll();

  // Clear expired entries, returns number removed
  size_t ClearExpired();

  // Statistics
  size_t Size() const;
  size_t FailureCount() const;

 private:
  static std::string MakeOriginKey(std::string_view host, uint16_t port);
  static uint64_t NowMs();

  // Parser helpers
  static bool ParseAltSvcHeader(std::string_view header,
                                std::vector<AltSvcEntry>* entries,
                                uint64_t now_ms, uint64_t default_max_age_ms,
                                uint64_t max_max_age_ms);
  static bool ParseSingleEntry(std::string_view entry_str, AltSvcEntry* entry,
                               uint64_t now_ms, uint64_t default_max_age_ms,
                               uint64_t max_max_age_ms);
  static std::string_view Trim(std::string_view s);

  AltSvcCacheConfig config_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, OriginAltSvc> cache_;

  // Negative cache for failed H3 attempts (origin -> expiry timestamp)
  std::unordered_map<std::string, uint64_t> h3_failures_;
};

}  // namespace http
}  // namespace holytls

#endif  // HOLYTLS_HTTP_ALT_SVC_CACHE_H_

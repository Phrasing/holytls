// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "util/dns_resolver.h"

#include "util/platform.h"

#ifndef _WIN32
#include <netdb.h>
#endif

#include <algorithm>
#include <cstring>

namespace chad {
namespace util {

// Request context for async resolution
struct DnsRequest {
  uv_getaddrinfo_t req;
  DnsCallback callback;
  DnsResolver* resolver;
  std::string hostname;  // For caching the result
};

DnsResolver::DnsResolver(uv_loop_t* loop) : loop_(loop) {
  // Initialize cache entries
  for (auto& entry : cache_) {
    entry.valid = false;
  }
}

DnsResolver::~DnsResolver() {
  // Note: Any pending requests will be cancelled when the loop closes
}

std::vector<ResolvedAddress> DnsResolver::ParseAddrinfo(struct addrinfo* res) {
  std::vector<ResolvedAddress> results;

  for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
    char ip[INET6_ADDRSTRLEN];
    ResolvedAddress addr;

    if (p->ai_family == AF_INET) {
      auto* ipv4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
      inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
      addr.ip = ip;
      addr.is_ipv6 = false;
    } else if (p->ai_family == AF_INET6) {
      auto* ipv6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
      inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
      addr.ip = ip;
      addr.is_ipv6 = true;
    } else {
      continue;
    }

    results.push_back(addr);
  }

  return results;
}

// Cache lookup - returns cached entry if valid and not expired
DnsCacheEntry* DnsResolver::FindCached(const std::string& hostname,
                                       uint64_t now_ms) {
  for (auto& entry : cache_) {
    if (entry.valid && entry.expires_at_ms > now_ms &&
        std::strcmp(entry.hostname, hostname.c_str()) == 0) {
      return &entry;
    }
  }
  return nullptr;
}

// Find slot for new cache entry - prefer expired, then oldest
DnsCacheEntry* DnsResolver::FindSlotForInsert(uint64_t now_ms) {
  DnsCacheEntry* oldest_expired = nullptr;
  DnsCacheEntry* oldest_valid = nullptr;
  uint64_t oldest_time = UINT64_MAX;

  for (auto& entry : cache_) {
    if (!entry.valid) {
      // Empty slot - use immediately
      return &entry;
    }

    if (entry.expires_at_ms <= now_ms) {
      // Expired entry - prefer these
      if (!oldest_expired ||
          entry.expires_at_ms < oldest_expired->expires_at_ms) {
        oldest_expired = &entry;
      }
    } else {
      // Valid entry - track oldest for eviction
      if (entry.expires_at_ms < oldest_time) {
        oldest_time = entry.expires_at_ms;
        oldest_valid = &entry;
      }
    }
  }

  // Prefer expired entry, fall back to oldest valid
  return oldest_expired ? oldest_expired : oldest_valid;
}

// Store resolution result in cache
void DnsResolver::StoreInCache(const std::string& hostname,
                               const std::vector<ResolvedAddress>& addrs,
                               uint64_t now_ms) {
  DnsCacheEntry* slot = FindSlotForInsert(now_ms);
  if (!slot) {
    return;  // Shouldn't happen with fixed-size cache
  }

  // Copy hostname
  std::strncpy(slot->hostname, hostname.c_str(), sizeof(slot->hostname) - 1);
  slot->hostname[sizeof(slot->hostname) - 1] = '\0';

  // Copy addresses (up to max)
  slot->address_count =
      static_cast<uint8_t>(std::min(addrs.size(), kMaxAddressesPerEntry));
  for (size_t i = 0; i < slot->address_count; ++i) {
    slot->addresses[i] = addrs[i];
  }

  slot->expires_at_ms = now_ms + cache_ttl_ms_;
  slot->valid = true;
}

void DnsResolver::ClearCache() {
  for (auto& entry : cache_) {
    entry.valid = false;
  }
  cache_hits_ = 0;
  cache_misses_ = 0;
}

std::vector<ResolvedAddress> DnsResolver::Resolve(const std::string& hostname,
                                                  std::string* error) {
  // WARNING: This is a BLOCKING call that uses synchronous getaddrinfo().
  // Do NOT call from reactor/event loop threads - it can block for 1-5 seconds.
  // Use ResolveAsync() instead for non-blocking DNS resolution.
  struct addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;      // IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;  // TCP
  hints.ai_flags = AI_ADDRCONFIG;   // Only return addresses we can use

  struct addrinfo* res = nullptr;
  int ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);

  if (ret != 0) {
    if (error != nullptr) {
      *error = gai_strerror(ret);
    }
    return {};
  }

  auto results = ParseAddrinfo(res);
  freeaddrinfo(res);
  return results;
}

void DnsResolver::OnResolved(uv_getaddrinfo_t* req, int status,
                             struct addrinfo* res) {
  auto* dns_req = static_cast<DnsRequest*>(req->data);

  if (status < 0) {
    // Error - don't cache failures
    dns_req->callback({}, uv_strerror(status));
  } else {
    // Success - parse and cache results
    auto results = ParseAddrinfo(res);
    uv_freeaddrinfo(res);

    // Store in cache
    uint64_t now_ms = uv_now(dns_req->resolver->loop_);
    dns_req->resolver->StoreInCache(dns_req->hostname, results, now_ms);

    dns_req->callback(results, "");
  }

  delete dns_req;
}

void DnsResolver::ResolveAsync(const std::string& hostname,
                               DnsCallback callback) {
  uint64_t now_ms = uv_now(loop_);

  // Check cache first
  if (auto* entry = FindCached(hostname, now_ms)) {
    ++cache_hits_;
    // Return cached results
    std::vector<ResolvedAddress> results(
        entry->addresses, entry->addresses + entry->address_count);
    callback(results, "");
    return;
  }

  ++cache_misses_;

  // Cache miss - do async lookup
  auto* dns_req = new DnsRequest();
  dns_req->callback = std::move(callback);
  dns_req->resolver = this;
  dns_req->hostname = hostname;
  dns_req->req.data = dns_req;

  struct addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

  int ret = uv_getaddrinfo(loop_, &dns_req->req, OnResolved, hostname.c_str(),
                           nullptr, &hints);

  if (ret < 0) {
    // Failed to start async request - callback was already moved to dns_req
    dns_req->callback({}, uv_strerror(ret));
    delete dns_req;
  }
}

void DnsResolver::CancelAll() {
  // libuv doesn't provide a way to cancel individual getaddrinfo requests
  // They will complete on their own via the thread pool
}

}  // namespace util
}  // namespace chad

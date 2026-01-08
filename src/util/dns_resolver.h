// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_UTIL_DNS_RESOLVER_H_
#define CHAD_UTIL_DNS_RESOLVER_H_

#include <uv.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace chad {
namespace util {

// Resolved address
struct ResolvedAddress {
  std::string ip;
  bool is_ipv6;
};

// DNS resolution result callback
using DnsCallback =
    std::function<void(const std::vector<ResolvedAddress>& addresses,
                       const std::string& error)>;

// DNS resolver using libuv's async getaddrinfo
// Uses the libuv thread pool for non-blocking resolution
class DnsResolver {
 public:
  // Create resolver attached to a libuv loop
  explicit DnsResolver(uv_loop_t* loop);
  ~DnsResolver();

  // Non-copyable
  DnsResolver(const DnsResolver&) = delete;
  DnsResolver& operator=(const DnsResolver&) = delete;

  // Blocking resolve (for simple use cases)
  std::vector<ResolvedAddress> Resolve(const std::string& hostname,
                                       std::string* error);

  // Async resolve using libuv thread pool
  // Callback is invoked on the event loop thread
  void ResolveAsync(const std::string& hostname, DnsCallback callback);

  // Cancel all pending async requests
  void CancelAll();

 private:
  static void OnResolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
  static std::vector<ResolvedAddress> ParseAddrinfo(struct addrinfo* res);

  uv_loop_t* loop_;
};

}  // namespace util
}  // namespace chad

#endif  // CHAD_UTIL_DNS_RESOLVER_H_

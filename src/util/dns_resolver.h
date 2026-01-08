// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_UTIL_DNS_RESOLVER_H_
#define CHAD_UTIL_DNS_RESOLVER_H_

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

// Simple blocking DNS resolver
// TODO: Implement async resolver using c-ares
class DnsResolver {
 public:
  DnsResolver();
  ~DnsResolver();

  // Blocking resolve
  std::vector<ResolvedAddress> Resolve(const std::string& hostname,
                                       std::string* error);

  // Async resolve (currently just wraps blocking)
  void ResolveAsync(const std::string& hostname, DnsCallback callback);
};

}  // namespace util
}  // namespace chad

#endif  // CHAD_UTIL_DNS_RESOLVER_H_

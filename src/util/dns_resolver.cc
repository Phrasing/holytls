// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "util/dns_resolver.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>

namespace chad {
namespace util {

DnsResolver::DnsResolver() = default;
DnsResolver::~DnsResolver() = default;

std::vector<ResolvedAddress> DnsResolver::Resolve(const std::string& hostname,
                                                  std::string* error) {
  std::vector<ResolvedAddress> results;

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
    return results;
  }

  for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
    char ip[INET6_ADDRSTRLEN];
    ResolvedAddress addr;

    if (p->ai_family == AF_INET) {
      struct sockaddr_in* ipv4 =
          reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
      inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
      addr.ip = ip;
      addr.is_ipv6 = false;
    } else if (p->ai_family == AF_INET6) {
      struct sockaddr_in6* ipv6 =
          reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
      inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
      addr.ip = ip;
      addr.is_ipv6 = true;
    } else {
      continue;
    }

    results.push_back(addr);
  }

  freeaddrinfo(res);
  return results;
}

void DnsResolver::ResolveAsync(const std::string& hostname,
                               DnsCallback callback) {
  // Simple blocking implementation for now
  // TODO: Use c-ares for true async DNS
  std::string error;
  auto results = Resolve(hostname, &error);
  callback(results, error);
}

}  // namespace util
}  // namespace chad

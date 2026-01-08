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

// Request context for async resolution
struct DnsRequest {
  uv_getaddrinfo_t req;
  DnsCallback callback;
  DnsResolver* resolver;
};

DnsResolver::DnsResolver(uv_loop_t* loop) : loop_(loop) {}

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

std::vector<ResolvedAddress> DnsResolver::Resolve(const std::string& hostname,
                                                  std::string* error) {
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
    // Error
    dns_req->callback({}, uv_strerror(status));
  } else {
    // Success - parse results
    auto results = ParseAddrinfo(res);
    uv_freeaddrinfo(res);
    dns_req->callback(results, "");
  }

  delete dns_req;
}

void DnsResolver::ResolveAsync(const std::string& hostname,
                               DnsCallback callback) {
  auto* dns_req = new DnsRequest();
  dns_req->callback = std::move(callback);
  dns_req->resolver = this;
  dns_req->req.data = dns_req;

  struct addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;

  int ret = uv_getaddrinfo(loop_, &dns_req->req, OnResolved,
                           hostname.c_str(), nullptr, &hints);

  if (ret < 0) {
    // Failed to start async request
    callback({}, uv_strerror(ret));
    delete dns_req;
  }
}

void DnsResolver::CancelAll() {
  // libuv doesn't provide a way to cancel individual getaddrinfo requests
  // They will complete on their own via the thread pool
}

}  // namespace util
}  // namespace chad

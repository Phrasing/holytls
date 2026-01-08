// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_POOL_HOST_POOL_H_
#define CHAD_POOL_HOST_POOL_H_

#include <cstdint>
#include <string>

namespace chad {
namespace pool {

// Per-host connection pool
class HostPool {
 public:
  HostPool(const std::string& host, uint16_t port);
  ~HostPool();

  const std::string& host() const { return host_; }
  uint16_t port() const { return port_; }

 private:
  std::string host_;
  uint16_t port_;
};

}  // namespace pool
}  // namespace chad

#endif  // CHAD_POOL_HOST_POOL_H_

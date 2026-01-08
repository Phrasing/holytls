// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "pool/host_pool.h"

namespace chad {
namespace pool {

HostPool::HostPool(const std::string& host, uint16_t port)
    : host_(host), port_(port) {}

HostPool::~HostPool() = default;

}  // namespace pool
}  // namespace chad

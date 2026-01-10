// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_UTIL_SOCKET_UTILS_H_
#define CHAD_UTIL_SOCKET_UTILS_H_

#include <cstdint>
#include <string>

#include "util/platform.h"

namespace chad {
namespace util {

// Create a non-blocking TCP socket
// Returns socket on success, kInvalidSocket on error
socket_t CreateTcpSocket(bool ipv6);

// Configure socket options (TCP_NODELAY, SO_KEEPALIVE, etc.)
void ConfigureSocket(socket_t sock);

// Start non-blocking connect to the given IP and port
// Returns 0 if connect completed immediately, -1 on error, 1 if in progress
int ConnectNonBlocking(socket_t sock, const std::string& ip, uint16_t port,
                       bool ipv6);

// Check if a non-blocking connect has completed
// Call after socket becomes writable
// Returns true if connected, false if error
bool IsConnected(socket_t sock);

}  // namespace util
}  // namespace chad

#endif  // CHAD_UTIL_SOCKET_UTILS_H_

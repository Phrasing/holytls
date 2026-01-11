// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_UTIL_SOCKET_UTILS_H_
#define HOLYTLS_UTIL_SOCKET_UTILS_H_

#include <cstdint>
#include <string>

#include "holytls/util/platform.h"

namespace holytls {
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
}  // namespace holytls

#endif  // HOLYTLS_UTIL_SOCKET_UTILS_H_

// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_UTIL_SOCKET_UTILS_H_
#define CHAD_UTIL_SOCKET_UTILS_H_

#include <cstdint>
#include <string>

namespace chad {
namespace util {

// Create a non-blocking TCP socket
// Returns fd on success, -1 on error
int CreateTcpSocket(bool ipv6);

// Configure socket options (TCP_NODELAY, SO_KEEPALIVE, etc.)
void ConfigureSocket(int fd);

// Start non-blocking connect to the given IP and port
// Returns 0 if connect completed immediately, -1 on error, 1 if in progress
int ConnectNonBlocking(int fd, const std::string& ip, uint16_t port, bool ipv6);

// Check if a non-blocking connect has completed
// Call after socket becomes writable
// Returns true if connected, false if error (check errno)
bool IsConnected(int fd);

// Close a socket
void CloseSocket(int fd);

}  // namespace util
}  // namespace chad

#endif  // CHAD_UTIL_SOCKET_UTILS_H_

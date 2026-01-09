// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Platform abstraction layer for cross-platform socket operations.
// Provides unified types and macros for Windows and Unix platforms.

#ifndef CHAD_UTIL_PLATFORM_H_
#define CHAD_UTIL_PLATFORM_H_

#include <string>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>

  // Error code macros
  #define CHAD_SOCKET_ERROR_CODE WSAGetLastError()
  #define CHAD_WOULD_BLOCK_ERROR WSAEWOULDBLOCK
  #define CHAD_IN_PROGRESS_ERROR WSAEWOULDBLOCK
  #define CHAD_INTERRUPTED_ERROR WSAEINTR

#else  // Unix/Linux/macOS
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>

  // Error code macros
  #define CHAD_SOCKET_ERROR_CODE errno
  #define CHAD_WOULD_BLOCK_ERROR EWOULDBLOCK
  #define CHAD_IN_PROGRESS_ERROR EINPROGRESS
  #define CHAD_INTERRUPTED_ERROR EINTR

#endif

namespace chad {
namespace util {

// Socket type abstraction - in namespace so it can be referenced as util::socket_t
#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

// Initialize platform-specific networking (required on Windows)
// Call once at program startup. Safe to call multiple times.
// Returns true on success.
bool InitializeNetworking();

// Cleanup platform-specific networking (required on Windows)
// Call once at program shutdown.
void CleanupNetworking();

// Get human-readable error string for a socket error code
std::string GetSocketErrorString(int error_code);

// Get error string for the last socket error
std::string GetLastSocketErrorString();

// Set socket to non-blocking mode
// Returns true on success
bool SetNonBlocking(socket_t sock);

// Set close-on-exec flag (Unix only, no-op on Windows)
// Returns true on success
bool SetCloseOnExec(socket_t sock);

// Close a socket
void CloseSocket(socket_t sock);

}  // namespace util
}  // namespace chad

#endif  // CHAD_UTIL_PLATFORM_H_

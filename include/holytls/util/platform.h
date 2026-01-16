// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Platform abstraction layer for cross-platform socket operations.
// Provides unified types and macros for Windows and Unix platforms.
//
// IMPORTANT: This header must be included BEFORE any OpenSSL/BoringSSL headers
// to prevent Windows macro conflicts (X509_NAME, X509_EXTENSIONS, etc).

#ifndef HOLYTLS_UTIL_PLATFORM_H_
#define HOLYTLS_UTIL_PLATFORM_H_

// Standard types - include both C and C++ headers for compatibility
// nghttp2 is a C library and needs types in global namespace
#include <stddef.h>
#include <stdint.h>
#include <cstddef>
#include <cstdint>
#include <string>

#ifdef _WIN32
// These MUST be defined before including any Windows headers
// They are also set via target_compile_definitions in CMakeLists.txt
// but we define them here as a fallback for any edge cases
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef NOGDI
#define NOGDI
#endif

// Must include winsock2.h BEFORE windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Windows doesn't define ssize_t
#include <BaseTsd.h>
using ssize_t = SSIZE_T;

// CRITICAL: Undefine ALL conflicting Windows macros AFTER all Windows headers
// These macros from wincrypt.h conflict with BoringSSL types
#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef X509_EXTENSIONS
#undef X509_EXTENSIONS
#endif
#ifdef X509_CERT_PAIR
#undef X509_CERT_PAIR
#endif
#ifdef PKCS7_SIGNER_INFO
#undef PKCS7_SIGNER_INFO
#endif
#ifdef OCSP_REQUEST
#undef OCSP_REQUEST
#endif
#ifdef OCSP_RESPONSE
#undef OCSP_RESPONSE
#endif

// Undefine min/max macros that conflict with std::min/std::max
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

// Error code macros
#define HOLYTLS_SOCKET_ERROR_CODE WSAGetLastError()
#define HOLYTLS_WOULD_BLOCK_ERROR WSAEWOULDBLOCK
#define HOLYTLS_IN_PROGRESS_ERROR WSAEWOULDBLOCK
#define HOLYTLS_INTERRUPTED_ERROR WSAEINTR

#else  // Unix/Linux/macOS
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

// Error code macros
#define HOLYTLS_SOCKET_ERROR_CODE errno
#define HOLYTLS_WOULD_BLOCK_ERROR EWOULDBLOCK
#define HOLYTLS_IN_PROGRESS_ERROR EINPROGRESS
#define HOLYTLS_INTERRUPTED_ERROR EINTR

#endif

namespace holytls {
namespace util {

// Socket type abstraction - in namespace so it can be referenced as
// util::socket_t
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
}  // namespace holytls

#endif  // HOLYTLS_UTIL_PLATFORM_H_

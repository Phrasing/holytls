// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/util/socket_utils.h"

#include <cstring>

namespace holytls {
namespace util {

socket_t CreateTcpSocket(bool ipv6) {
  int domain = ipv6 ? AF_INET6 : AF_INET;
  socket_t sock = kInvalidSocket;

#ifdef _WIN32
  // Windows: create socket then set options
  sock = socket(domain, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    return kInvalidSocket;
  }
#else
// Unix: try SOCK_NONBLOCK and SOCK_CLOEXEC flags if available
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
  sock = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (sock >= 0) {
    return sock;  // Already configured
  }
#endif
  // Fallback: create socket then set options
  sock = socket(domain, SOCK_STREAM, 0);
  if (sock < 0) {
    return kInvalidSocket;
  }
#endif

  // Set non-blocking mode (required for async connect)
  // Note: libuv's uv_poll_init_socket() also sets FIONBIO, but we set it
  // explicitly
  if (!SetNonBlocking(sock)) {
    CloseSocket(sock);
    return kInvalidSocket;
  }
#ifndef _WIN32
  // Close-on-exec only needed on Unix
  if (!SetCloseOnExec(sock)) {
    CloseSocket(sock);
    return kInvalidSocket;
  }
#endif

  return sock;
}

void ConfigureSocket(socket_t sock) {
  // Disable Nagle's algorithm for lower latency
  int flag = 1;
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
             reinterpret_cast<const char*>(&flag), sizeof(flag));

  // Enable keep-alive
  setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
             reinterpret_cast<const char*>(&flag), sizeof(flag));

  // Set receive buffer size (256KB)
  int bufsize = 256 * 1024;
  setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
             reinterpret_cast<const char*>(&bufsize), sizeof(bufsize));

  // Set send buffer size (256KB)
  setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
             reinterpret_cast<const char*>(&bufsize), sizeof(bufsize));
}

int ConnectNonBlocking(socket_t sock, std::string_view ip, uint16_t port,
                       bool ipv6) {
  // inet_pton requires null-terminated string, copy to stack buffer
  // Max IPv6 length is 45 chars (e.g., "::ffff:255.255.255.255")
  char ip_buf[46];
  if (ip.size() >= sizeof(ip_buf)) return -1;
  std::memcpy(ip_buf, ip.data(), ip.size());
  ip_buf[ip.size()] = '\0';

  int ret;

  if (ipv6) {
    struct sockaddr_in6 addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip_buf, &addr.sin6_addr) != 1) {
      return -1;
    }
    ret =
        connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  } else {
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_buf, &addr.sin_addr) != 1) {
      return -1;
    }
    ret =
        connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  }

  if (ret == 0) {
    return 0;  // Connected immediately
  }

  int error = HOLYTLS_SOCKET_ERROR_CODE;
  if (error == HOLYTLS_IN_PROGRESS_ERROR ||
      error == HOLYTLS_WOULD_BLOCK_ERROR) {
    return 1;  // Connection in progress
  }

  return -1;  // Error
}

bool IsConnected(socket_t sock) {
  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error),
                 &len) < 0) {
    return false;
  }
  if (error != 0) {
#ifndef _WIN32
    errno = error;
#endif
    return false;
  }
  return true;
}

ssize_t SendNonBlocking(socket_t sock, const void* data, size_t len) {
#ifdef _WIN32
  int ret =
      send(sock, static_cast<const char*>(data), static_cast<int>(len), 0);
  if (ret == SOCKET_ERROR) {
    int error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
      return -1;  // Would block
    }
    return -2;  // Real error
  }
  return ret;
#else
  ssize_t ret = send(sock, data, len, MSG_NOSIGNAL);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return -1;  // Would block
    }
    return -2;  // Real error
  }
  return ret;
#endif
}

ssize_t RecvNonBlocking(socket_t sock, void* buf, size_t len) {
#ifdef _WIN32
  int ret = recv(sock, static_cast<char*>(buf), static_cast<int>(len), 0);
  if (ret == SOCKET_ERROR) {
    int error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
      return -1;  // Would block
    }
    return -2;  // Real error
  }
  return ret;  // 0 = EOF, >0 = bytes received
#else
  ssize_t ret = recv(sock, buf, len, 0);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return -1;  // Would block
    }
    return -2;  // Real error
  }
  return ret;  // 0 = EOF, >0 = bytes received
#endif
}

}  // namespace util
}  // namespace holytls

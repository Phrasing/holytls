// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "util/socket_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace chad {
namespace util {

int CreateTcpSocket(bool ipv6) {
  int domain = ipv6 ? AF_INET6 : AF_INET;
  int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  return fd;
}

void ConfigureSocket(int fd) {
  // Disable Nagle's algorithm for lower latency
  int flag = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

  // Enable keep-alive
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));

  // Set receive buffer size (256KB)
  int bufsize = 256 * 1024;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

  // Set send buffer size (256KB)
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
}

int ConnectNonBlocking(int fd, const std::string& ip, uint16_t port, bool ipv6) {
  if (ipv6) {
    struct sockaddr_in6 addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr) != 1) {
      return -1;
    }
    int ret = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret == 0) {
      return 0;  // Connected immediately
    }
    if (errno == EINPROGRESS) {
      return 1;  // Connection in progress
    }
    return -1;  // Error
  } else {
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
      return -1;
    }
    int ret = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret == 0) {
      return 0;  // Connected immediately
    }
    if (errno == EINPROGRESS) {
      return 1;  // Connection in progress
    }
    return -1;  // Error
  }
}

bool IsConnected(int fd) {
  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
    return false;
  }
  if (error != 0) {
    errno = error;
    return false;
  }
  return true;
}

void CloseSocket(int fd) {
  if (fd >= 0) {
    close(fd);
  }
}

}  // namespace util
}  // namespace chad

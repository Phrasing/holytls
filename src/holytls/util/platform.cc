// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/util/platform.h"

#include <cstring>

#ifdef _WIN32
#include <atomic>
#endif

namespace holytls {
namespace util {

#ifdef _WIN32

// Windows implementation

namespace {
std::atomic<bool> g_winsock_initialized{false};
}  // namespace

bool InitializeNetworking() {
  if (g_winsock_initialized.exchange(true)) {
    return true;  // Already initialized
  }

  WSADATA wsa_data;
  int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (result != 0) {
    g_winsock_initialized = false;
    return false;
  }
  return true;
}

void CleanupNetworking() {
  if (g_winsock_initialized.exchange(false)) {
    WSACleanup();
  }
}

std::string GetSocketErrorString(int error_code) {
  char* msg = nullptr;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 reinterpret_cast<LPSTR>(&msg), 0, nullptr);

  std::string result;
  if (msg) {
    result = msg;
    LocalFree(msg);
    // Remove trailing newline
    while (!result.empty() &&
           (result.back() == '\n' || result.back() == '\r')) {
      result.pop_back();
    }
  } else {
    result = "Unknown error " + std::to_string(error_code);
  }
  return result;
}

std::string GetLastSocketErrorString() {
  return GetSocketErrorString(WSAGetLastError());
}

bool SetNonBlocking(socket_t sock) {
  u_long mode = 1;  // 1 = non-blocking
  return ioctlsocket(sock, FIONBIO, &mode) == 0;
}

bool SetCloseOnExec(socket_t /*sock*/) {
  // Windows handles don't have the close-on-exec concept in the same way.
  // Sockets are not inherited by default unless explicitly specified.
  return true;
}

void CloseSocket(socket_t sock) {
  if (sock != INVALID_SOCKET) {
    closesocket(sock);
  }
}

#else  // Unix implementation

bool InitializeNetworking() {
  // No initialization needed on Unix
  return true;
}

void CleanupNetworking() {
  // No cleanup needed on Unix
}

std::string GetSocketErrorString(int error_code) {
  return std::strerror(error_code);
}

std::string GetLastSocketErrorString() { return std::strerror(errno); }

bool SetNonBlocking(socket_t sock) {
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    return false;
  }
  return fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1;
}

bool SetCloseOnExec(socket_t sock) {
  int flags = fcntl(sock, F_GETFD, 0);
  if (flags == -1) {
    return false;
  }
  return fcntl(sock, F_SETFD, flags | FD_CLOEXEC) != -1;
}

void CloseSocket(socket_t sock) {
  if (sock >= 0) {
    close(sock);
  }
}

#endif

}  // namespace util
}  // namespace holytls

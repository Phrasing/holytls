// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/core/udp_socket.h"

#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace holytls {
namespace core {

UdpSocket::UdpSocket(Reactor* reactor) : reactor_(reactor) {
  std::memset(&udp_handle_, 0, sizeof(udp_handle_));
  udp_handle_.data = this;
}

UdpSocket::~UdpSocket() {
  if (is_open_) {
    Close();
  }
}

bool UdpSocket::Bind(uint16_t port, bool ipv6) {
  if (is_open_) {
    return false;
  }

  int rv = uv_udp_init(reactor_->loop(), &udp_handle_);
  if (rv != 0) {
    return false;
  }

  sockaddr_storage addr{};

  if (ipv6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_addr = in6addr_any;
    addr6->sin6_port = htons(port);
  } else {
    auto* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = INADDR_ANY;
    addr4->sin_port = htons(port);
  }

  rv = uv_udp_bind(&udp_handle_, reinterpret_cast<sockaddr*>(&addr), 0);
  if (rv != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&udp_handle_), nullptr);
    return false;
  }

  is_open_ = true;
  return true;
}

bool UdpSocket::Connect(const std::string& host, uint16_t port, bool ipv6) {
  if (!MakeSockaddr(host, port, ipv6, &remote_addr_, &remote_addr_len_)) {
    return false;
  }

  // If not yet bound, bind to ephemeral port
  if (!is_open_) {
    if (!Bind(0, ipv6)) {
      return false;
    }
  }

  // libuv doesn't have uv_udp_connect, but we store the remote address
  // and use it as default destination for Send()
  return true;
}

bool UdpSocket::StartReceive() {
  if (!is_open_ || is_receiving_) {
    return false;
  }

  int rv = uv_udp_recv_start(&udp_handle_, OnAlloc, OnReceive);
  if (rv != 0) {
    return false;
  }

  is_receiving_ = true;
  return true;
}

bool UdpSocket::StopReceive() {
  if (!is_receiving_) {
    return false;
  }

  int rv = uv_udp_recv_stop(&udp_handle_);
  if (rv != 0) {
    return false;
  }

  is_receiving_ = false;
  return true;
}

bool UdpSocket::Send(const uint8_t* data, size_t len, const sockaddr* addr) {
  if (!is_open_) {
    return false;
  }

  // Use connected address if no address specified
  const sockaddr* dest = addr;
  if (!dest && remote_addr_len_ > 0) {
    dest = reinterpret_cast<const sockaddr*>(&remote_addr_);
  }
  if (!dest) {
    return false;  // No destination
  }

  // Create send request
  auto req = std::make_unique<SendRequest>();
  req->data.assign(data, data + len);
  req->socket = this;

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char*>(req->data.data()),
                             static_cast<unsigned int>(req->data.size()));

  int rv = uv_udp_send(&req->req, &udp_handle_, &buf, 1, dest, OnSend);
  if (rv != 0) {
    return false;
  }

  // Transfer ownership to pending list
  pending_sends_.push_back(std::move(req));
  return true;
}

bool UdpSocket::SendBatch(std::span<const UdpPacket> packets) {
  bool all_ok = true;
  for (const auto& packet : packets) {
    if (!Send(packet.data.data(), packet.data.size(),
              reinterpret_cast<const sockaddr*>(&packet.addr))) {
      all_ok = false;
    }
  }
  return all_ok;
}

void UdpSocket::Close() {
  if (!is_open_) {
    return;
  }

  if (is_receiving_) {
    uv_udp_recv_stop(&udp_handle_);
    is_receiving_ = false;
  }

  is_open_ = false;
  uv_close(reinterpret_cast<uv_handle_t*>(&udp_handle_), OnClose);
}

bool UdpSocket::GetLocalAddress(sockaddr_storage* addr, socklen_t* len) const {
  if (!is_open_) {
    return false;
  }

  int namelen = sizeof(sockaddr_storage);
  int rv = uv_udp_getsockname(&udp_handle_, reinterpret_cast<sockaddr*>(addr),
                              &namelen);
  if (rv != 0) {
    return false;
  }

  *len = static_cast<socklen_t>(namelen);
  return true;
}

uint16_t UdpSocket::LocalPort() const {
  sockaddr_storage addr{};
  socklen_t len;
  if (!GetLocalAddress(&addr, &len)) {
    return 0;
  }

  if (addr.ss_family == AF_INET) {
    return ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    return ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
  }
  return 0;
}

// Static callbacks

void UdpSocket::OnAlloc(uv_handle_t* handle, size_t /*suggested_size*/,
                        uv_buf_t* buf) {
  auto* socket = static_cast<UdpSocket*>(handle->data);
  buf->base = reinterpret_cast<char*>(socket->recv_buffer_.data());
  buf->len = static_cast<unsigned int>(socket->recv_buffer_.size());
}

void UdpSocket::OnReceive(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                          const sockaddr* addr, unsigned /*flags*/) {
  auto* socket = static_cast<UdpSocket*>(handle->data);

  if (nread < 0) {
    // Error
    if (socket->error_callback_) {
      socket->error_callback_(static_cast<int>(nread));
    }
    return;
  }

  if (nread == 0 && addr == nullptr) {
    // Nothing received, no address = EAGAIN
    return;
  }

  if (nread > 0 && socket->receive_callback_) {
    socklen_t addr_len = 0;
    if (addr) {
      addr_len = (addr->sa_family == AF_INET6) ? sizeof(sockaddr_in6)
                                               : sizeof(sockaddr_in);
    }
    socket->receive_callback_(reinterpret_cast<const uint8_t*>(buf->base),
                              static_cast<size_t>(nread), addr, addr_len);
  }
}

void UdpSocket::OnSend(uv_udp_send_t* req, int status) {
  auto* send_req = reinterpret_cast<SendRequest*>(req);
  auto* socket = send_req->socket;

  // Remove from pending list
  auto it = std::find_if(
      socket->pending_sends_.begin(), socket->pending_sends_.end(),
      [req](const std::unique_ptr<SendRequest>& r) { return &r->req == req; });
  if (it != socket->pending_sends_.end()) {
    socket->pending_sends_.erase(it);
  }

  // Report error if any
  if (status != 0 && socket->error_callback_) {
    socket->error_callback_(status);
  }
}

void UdpSocket::OnClose(uv_handle_t* handle) {
  auto* socket = static_cast<UdpSocket*>(handle->data);
  if (socket && socket->close_complete_callback_) {
    socket->close_complete_callback_();
  }
}

// Helper functions

bool MakeSockaddr(const std::string& ip, uint16_t port, bool ipv6,
                  sockaddr_storage* addr, socklen_t* len) {
  std::memset(addr, 0, sizeof(*addr));

  if (ipv6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(addr);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &addr6->sin6_addr) != 1) {
      return false;
    }
    *len = sizeof(sockaddr_in6);
  } else {
    auto* addr4 = reinterpret_cast<sockaddr_in*>(addr);
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr4->sin_addr) != 1) {
      return false;
    }
    *len = sizeof(sockaddr_in);
  }

  return true;
}

std::string FormatSockaddr(const sockaddr* addr) {
  if (!addr) {
    return "<null>";
  }

  char buf[INET6_ADDRSTRLEN];
  std::ostringstream oss;

  if (addr->sa_family == AF_INET) {
    auto* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
    inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf));
    oss << buf << ":" << ntohs(addr4->sin_port);
  } else if (addr->sa_family == AF_INET6) {
    auto* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
    inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf));
    oss << "[" << buf << "]:" << ntohs(addr6->sin6_port);
  } else {
    oss << "<unknown family>";
  }

  return oss.str();
}

}  // namespace core
}  // namespace holytls

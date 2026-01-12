// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_CORE_UDP_SOCKET_H_
#define HOLYTLS_CORE_UDP_SOCKET_H_

#include "holytls/util/platform.h"

#include <uv.h>

#include <array>
#include <cstdint>
#include <functional>
#include <queue>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/core/reactor.h"

namespace holytls {
namespace core {

// Maximum UDP payload size (MTU - IP/UDP headers)
// For QUIC, this is typically 1200-1350 bytes for initial packets
inline constexpr size_t kMaxUdpPayloadSize = 1500;

// Maximum number of datagrams to batch send
inline constexpr size_t kMaxSendBatchSize = 64;

// UDP packet with source/destination address
struct UdpPacket {
  sockaddr_storage addr;
  socklen_t addr_len = 0;
  std::vector<uint8_t> data;

  UdpPacket() = default;
  UdpPacket(const sockaddr* sa, socklen_t len, const uint8_t* buf, size_t size)
      : addr_len(len), data(buf, buf + size) {
    std::memcpy(&addr, sa, len);
  }
};

// Callback types
using UdpReceiveCallback =
    std::function<void(const uint8_t* data, size_t len, const sockaddr* addr,
                       socklen_t addr_len)>;
using UdpSendCallback = std::function<void(int status)>;
using UdpErrorCallback = std::function<void(int error_code)>;

// UDP socket wrapper for libuv
// Provides async send/receive for QUIC connections
class UdpSocket {
 public:
  explicit UdpSocket(Reactor* reactor);
  ~UdpSocket();

  // Non-copyable, non-movable
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;
  UdpSocket(UdpSocket&&) = delete;
  UdpSocket& operator=(UdpSocket&&) = delete;

  // Initialize and bind to local address
  // port=0 for ephemeral port
  bool Bind(uint16_t port = 0, bool ipv6 = false);

  // Connect to remote address (sets default destination)
  // For QUIC client connections
  bool Connect(const std::string& host, uint16_t port, bool ipv6 = false);

  // Start receiving datagrams
  bool StartReceive();

  // Stop receiving datagrams
  bool StopReceive();

  // Send datagram to address (or connected address if nullptr)
  // Returns true if queued successfully
  bool Send(const uint8_t* data, size_t len, const sockaddr* addr = nullptr);

  // Send datagram using std::span
  bool Send(std::span<const uint8_t> data, const sockaddr* addr = nullptr) {
    return Send(data.data(), data.size(), addr);
  }

  // Send multiple datagrams (batch send for performance)
  bool SendBatch(std::span<const UdpPacket> packets);

  // Set receive callback
  void SetReceiveCallback(UdpReceiveCallback callback) {
    receive_callback_ = std::move(callback);
  }

  // Set error callback
  void SetErrorCallback(UdpErrorCallback callback) {
    error_callback_ = std::move(callback);
  }

  // Close the socket
  void Close();

  // Check if socket is open
  bool IsOpen() const { return is_open_; }

  // Get local address after bind
  bool GetLocalAddress(sockaddr_storage* addr, socklen_t* len) const;

  // Get local port
  uint16_t LocalPort() const;

  // Get remote (connected) address
  const sockaddr_storage& remote_addr() const { return remote_addr_; }
  socklen_t remote_addr_len() const { return remote_addr_len_; }

  // Access underlying handle (for advanced use)
  uv_udp_t* handle() { return &udp_handle_; }

  // Get reactor
  Reactor* reactor() { return reactor_; }

 private:
  static void OnAlloc(uv_handle_t* handle, size_t suggested_size,
                      uv_buf_t* buf);
  static void OnReceive(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                        const sockaddr* addr, unsigned flags);
  static void OnSend(uv_udp_send_t* req, int status);
  static void OnClose(uv_handle_t* handle);

  Reactor* reactor_;
  uv_udp_t udp_handle_;
  bool is_open_ = false;
  bool is_receiving_ = false;

  // Remote address for connected mode
  sockaddr_storage remote_addr_{};
  socklen_t remote_addr_len_ = 0;

  // Receive buffer (reused across callbacks)
  std::array<uint8_t, kMaxUdpPayloadSize> recv_buffer_;

  // Callbacks
  UdpReceiveCallback receive_callback_;
  UdpErrorCallback error_callback_;

  // Pending send requests
  struct SendRequest {
    uv_udp_send_t req;
    std::vector<uint8_t> data;
    UdpSocket* socket;
  };
  std::vector<std::unique_ptr<SendRequest>> pending_sends_;
};

// Helper to create sockaddr from IP string and port
bool MakeSockaddr(const std::string& ip, uint16_t port, bool ipv6,
                  sockaddr_storage* addr, socklen_t* len);

// Helper to format sockaddr as string
std::string FormatSockaddr(const sockaddr* addr);

}  // namespace core
}  // namespace holytls

#endif  // HOLYTLS_CORE_UDP_SOCKET_H_

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// SOCKS tunnel for proxy support.
// Establishes a tunnel through a SOCKS4/4a/5/5h proxy to the target host.

#ifndef HOLYTLS_PROXY_SOCKS_PROXY_H_
#define HOLYTLS_PROXY_SOCKS_PROXY_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/config.h"
#include "holytls/proxy/http_proxy.h"  // For TunnelState, TunnelResult
#include "holytls/util/platform.h"

namespace holytls {
namespace proxy {

// SOCKS5 handshake state machine
enum class Socks5State {
  kIdle,                // Not started
  kSendingGreeting,     // Sending version + auth methods
  kReadingAuthMethod,   // Reading server's chosen auth method
  kSendingAuth,         // Sending username/password auth
  kReadingAuthResult,   // Reading auth result
  kSendingConnect,      // Sending CONNECT request
  kReadingConnectReply, // Reading CONNECT reply
  kConnected,           // Tunnel established
  kError,               // Error occurred
};

// SOCKS4/4a handshake state machine
enum class Socks4State {
  kIdle,                // Not started
  kSendingConnect,      // Sending CONNECT request
  kReadingReply,        // Reading reply
  kConnected,           // Tunnel established
  kError,               // Error occurred
};

// SOCKS proxy tunnel handler.
// Non-blocking state machine for establishing SOCKS4/4a/5/5h proxy tunnels.
class SocksProxyTunnel {
 public:
  // Create a SOCKS tunnel handler
  // proxy_type: kSocks4, kSocks4a, kSocks5, or kSocks5h
  // For SOCKS4/4a: target_ip is only needed for SOCKS4 (not 4a)
  // For SOCKS5: target_ip is only needed for SOCKS5 (not 5h)
  SocksProxyTunnel(ProxyType proxy_type,
                   std::string_view target_host, uint16_t target_port,
                   std::string_view target_ip = "",
                   std::string_view proxy_username = "",
                   std::string_view proxy_password = "");

  // Start the tunnel handshake (call after TCP connect to proxy)
  TunnelResult Start();

  // Continue handshake when socket is writable
  TunnelResult OnWritable(util::socket_t fd);

  // Continue handshake when socket is readable
  TunnelResult OnReadable(util::socket_t fd);

  // State accessors
  bool IsConnected() const;
  bool HasError() const;
  const std::string& last_error() const { return last_error_; }

  // For use by Connection to drive state machine
  bool WantsWrite() const;
  bool WantsRead() const;

 private:
  // SOCKS5 protocol methods
  TunnelResult StartSocks5();
  TunnelResult Socks5OnWritable(util::socket_t fd);
  TunnelResult Socks5OnReadable(util::socket_t fd);
  void BuildSocks5Greeting();
  void BuildSocks5Auth();
  void BuildSocks5Connect();
  TunnelResult ParseSocks5AuthMethod();
  TunnelResult ParseSocks5AuthResult();
  TunnelResult ParseSocks5ConnectReply();

  // SOCKS4/4a protocol methods
  TunnelResult StartSocks4();
  TunnelResult Socks4OnWritable(util::socket_t fd);
  TunnelResult Socks4OnReadable(util::socket_t fd);
  void BuildSocks4Connect();
  TunnelResult ParseSocks4Reply();

  // Parse IPv4 address string to bytes
  static bool ParseIpv4(std::string_view ip, uint8_t out[4]);
  // Parse IPv6 address string to bytes
  static bool ParseIpv6(std::string_view ip, uint8_t out[16]);

  ProxyType proxy_type_;
  std::string target_host_;
  uint16_t target_port_;
  std::string target_ip_;  // Resolved IP (for SOCKS4/SOCKS5 non-'h' variants)
  std::string proxy_username_;
  std::string proxy_password_;

  // SOCKS5 state
  Socks5State socks5_state_ = Socks5State::kIdle;
  uint8_t socks5_auth_method_ = 0;  // Server's chosen auth method

  // SOCKS4 state
  Socks4State socks4_state_ = Socks4State::kIdle;

  std::string last_error_;

  // Send buffer
  std::vector<uint8_t> send_buf_;
  size_t send_offset_ = 0;

  // Receive buffer
  std::vector<uint8_t> recv_buf_;
  static constexpr size_t kMaxRecvSize = 512;
};

}  // namespace proxy
}  // namespace holytls

#endif  // HOLYTLS_PROXY_SOCKS_PROXY_H_

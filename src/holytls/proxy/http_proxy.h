// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// HTTP CONNECT tunnel for proxy support.
// Establishes a tunnel through an HTTP/HTTPS proxy to the target host.

#ifndef HOLYTLS_PROXY_HTTP_PROXY_H_
#define HOLYTLS_PROXY_HTTP_PROXY_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/util/platform.h"

namespace holytls {
namespace proxy {

// State of CONNECT tunnel handshake
enum class TunnelState {
  kIdle,           // Not started
  kSendingRequest, // Sending CONNECT request
  kReadingResponse,// Reading proxy response
  kConnected,      // Tunnel established
  kError,          // Error occurred
};

// Result of tunnel operations
enum class TunnelResult {
  kOk,        // Operation completed successfully
  kWantWrite, // Need to write more data
  kWantRead,  // Need to read more data
  kError,     // Error occurred
};

// HTTP CONNECT tunnel handler.
// Non-blocking state machine for establishing proxy tunnels.
class HttpProxyTunnel {
 public:
  HttpProxyTunnel(std::string_view target_host, uint16_t target_port,
                  std::string_view proxy_username = "",
                  std::string_view proxy_password = "");

  // Start the tunnel handshake (call after TCP connect to proxy)
  TunnelResult Start();

  // Continue handshake when socket is writable
  TunnelResult OnWritable(util::socket_t fd);

  // Continue handshake when socket is readable
  TunnelResult OnReadable(util::socket_t fd);

  // State accessors
  TunnelState state() const { return state_; }
  bool IsConnected() const { return state_ == TunnelState::kConnected; }
  bool HasError() const { return state_ == TunnelState::kError; }
  const std::string& last_error() const { return last_error_; }

 private:
  // Build the CONNECT request
  void BuildRequest();

  // Parse the proxy response
  TunnelResult ParseResponse();

  // Base64 encode for proxy auth
  static std::string Base64Encode(std::string_view input);

  std::string target_host_;
  uint16_t target_port_;
  std::string proxy_username_;
  std::string proxy_password_;

  TunnelState state_ = TunnelState::kIdle;
  std::string last_error_;

  // Request buffer
  std::string request_;
  size_t request_sent_ = 0;

  // Response buffer
  std::vector<char> response_buf_;
  static constexpr size_t kMaxResponseSize = 4096;
};

}  // namespace proxy
}  // namespace holytls

#endif  // HOLYTLS_PROXY_HTTP_PROXY_H_

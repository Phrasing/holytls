// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/proxy/http_proxy.h"

#include <cstring>

#include "holytls/util/socket_utils.h"

namespace holytls {
namespace proxy {

HttpProxyTunnel::HttpProxyTunnel(std::string_view target_host,
                                 uint16_t target_port,
                                 std::string_view proxy_username,
                                 std::string_view proxy_password)
    : target_host_(target_host),
      target_port_(target_port),
      proxy_username_(proxy_username),
      proxy_password_(proxy_password) {
  response_buf_.reserve(kMaxResponseSize);
}

TunnelResult HttpProxyTunnel::Start() {
  if (state_ != TunnelState::kIdle) {
    last_error_ = "Tunnel already started";
    state_ = TunnelState::kError;
    return TunnelResult::kError;
  }

  BuildRequest();
  state_ = TunnelState::kSendingRequest;
  request_sent_ = 0;

  return TunnelResult::kWantWrite;
}

TunnelResult HttpProxyTunnel::OnWritable(util::socket_t fd) {
  if (state_ != TunnelState::kSendingRequest) {
    return TunnelResult::kError;
  }

  // Send remaining request data
  const char* data = request_.data() + request_sent_;
  size_t remaining = request_.size() - request_sent_;

  ssize_t sent = util::SendNonBlocking(fd, data, remaining);
  if (sent < 0) {
    // Would block
    return TunnelResult::kWantWrite;
  }

  request_sent_ += static_cast<size_t>(sent);

  if (request_sent_ < request_.size()) {
    // More to send
    return TunnelResult::kWantWrite;
  }

  // Request fully sent, wait for response
  state_ = TunnelState::kReadingResponse;
  return TunnelResult::kWantRead;
}

TunnelResult HttpProxyTunnel::OnReadable(util::socket_t fd) {
  if (state_ != TunnelState::kReadingResponse) {
    return TunnelResult::kError;
  }

  // Read response data
  char buf[1024];
  ssize_t n = util::RecvNonBlocking(fd, buf, sizeof(buf));

  if (n < 0) {
    // Would block
    return TunnelResult::kWantRead;
  }

  if (n == 0) {
    // Connection closed
    last_error_ = "Proxy closed connection";
    state_ = TunnelState::kError;
    return TunnelResult::kError;
  }

  // Append to response buffer
  if (response_buf_.size() + static_cast<size_t>(n) > kMaxResponseSize) {
    last_error_ = "Proxy response too large";
    state_ = TunnelState::kError;
    return TunnelResult::kError;
  }

  response_buf_.insert(response_buf_.end(), buf, buf + n);

  // Try to parse response
  return ParseResponse();
}

void HttpProxyTunnel::BuildRequest() {
  // Build CONNECT request
  request_ = "CONNECT ";
  request_ += target_host_;
  request_ += ":";
  request_ += std::to_string(target_port_);
  request_ += " HTTP/1.1\r\n";

  request_ += "Host: ";
  request_ += target_host_;
  request_ += ":";
  request_ += std::to_string(target_port_);
  request_ += "\r\n";

  // Add proxy authentication if provided
  if (!proxy_username_.empty()) {
    std::string credentials = proxy_username_ + ":" + proxy_password_;
    std::string encoded = Base64Encode(credentials);
    request_ += "Proxy-Authorization: Basic ";
    request_ += encoded;
    request_ += "\r\n";
  }

  // Chrome-like headers for the CONNECT request
  request_ += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/143.0.0.0 Safari/537.36\r\n";
  request_ += "Proxy-Connection: keep-alive\r\n";

  request_ += "\r\n";
}

TunnelResult HttpProxyTunnel::ParseResponse() {
  // Look for end of HTTP headers
  std::string_view response(response_buf_.data(), response_buf_.size());
  size_t header_end = response.find("\r\n\r\n");

  if (header_end == std::string_view::npos) {
    // Haven't received full headers yet
    return TunnelResult::kWantRead;
  }

  // Parse status line
  // Format: HTTP/1.x STATUS_CODE STATUS_TEXT
  size_t first_space = response.find(' ');
  if (first_space == std::string_view::npos || first_space > 12) {
    last_error_ = "Invalid proxy response";
    state_ = TunnelState::kError;
    return TunnelResult::kError;
  }

  size_t second_space = response.find(' ', first_space + 1);
  if (second_space == std::string_view::npos) {
    last_error_ = "Invalid proxy response";
    state_ = TunnelState::kError;
    return TunnelResult::kError;
  }

  std::string_view status_str =
      response.substr(first_space + 1, second_space - first_space - 1);

  // Parse status code
  int status_code = 0;
  for (char c : status_str) {
    if (c < '0' || c > '9') {
      last_error_ = "Invalid status code";
      state_ = TunnelState::kError;
      return TunnelResult::kError;
    }
    status_code = status_code * 10 + (c - '0');
  }

  // Check for successful tunnel establishment
  if (status_code == 200) {
    state_ = TunnelState::kConnected;
    return TunnelResult::kOk;
  }

  // Handle common proxy errors
  if (status_code == 407) {
    last_error_ = "Proxy authentication required";
  } else if (status_code == 403) {
    last_error_ = "Proxy denied access";
  } else if (status_code == 502) {
    last_error_ = "Proxy bad gateway";
  } else if (status_code == 503) {
    last_error_ = "Proxy service unavailable";
  } else {
    last_error_ = "Proxy returned status " + std::to_string(status_code);
  }

  state_ = TunnelState::kError;
  return TunnelResult::kError;
}

std::string HttpProxyTunnel::Base64Encode(std::string_view input) {
  static constexpr char kBase64Chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string output;
  output.reserve(((input.size() + 2) / 3) * 4);

  size_t i = 0;
  while (i < input.size()) {
    uint32_t octet_a = static_cast<uint8_t>(input[i++]);
    uint32_t octet_b = (i < input.size()) ? static_cast<uint8_t>(input[i++]) : 0;
    uint32_t octet_c = (i < input.size()) ? static_cast<uint8_t>(input[i++]) : 0;

    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    output += kBase64Chars[(triple >> 18) & 0x3F];
    output += kBase64Chars[(triple >> 12) & 0x3F];
    output += (i > input.size() + 1) ? '=' : kBase64Chars[(triple >> 6) & 0x3F];
    output += (i > input.size()) ? '=' : kBase64Chars[triple & 0x3F];
  }

  return output;
}

}  // namespace proxy
}  // namespace holytls

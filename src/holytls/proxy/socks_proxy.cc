// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/proxy/socks_proxy.h"

#include <cstring>

#include "holytls/proxy/socks_constants.h"
#include "holytls/util/socket_utils.h"

namespace holytls {
namespace proxy {

SocksProxyTunnel::SocksProxyTunnel(ProxyType proxy_type,
                                   std::string_view target_host,
                                   uint16_t target_port,
                                   std::string_view target_ip,
                                   std::string_view proxy_username,
                                   std::string_view proxy_password)
    : proxy_type_(proxy_type),
      target_host_(target_host),
      target_port_(target_port),
      target_ip_(target_ip),
      proxy_username_(proxy_username),
      proxy_password_(proxy_password) {
  recv_buf_.reserve(kMaxRecvSize);
}

TunnelResult SocksProxyTunnel::Start() {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return StartSocks5();
  } else if (proxy_type_ == ProxyType::kSocks4 ||
             proxy_type_ == ProxyType::kSocks4a) {
    return StartSocks4();
  }

  last_error_ = "Unsupported proxy type";
  return TunnelResult::kError;
}

TunnelResult SocksProxyTunnel::OnWritable(util::socket_t fd) {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return Socks5OnWritable(fd);
  } else {
    return Socks4OnWritable(fd);
  }
}

TunnelResult SocksProxyTunnel::OnReadable(util::socket_t fd) {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return Socks5OnReadable(fd);
  } else {
    return Socks4OnReadable(fd);
  }
}

bool SocksProxyTunnel::IsConnected() const {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return socks5_state_ == Socks5State::kConnected;
  } else {
    return socks4_state_ == Socks4State::kConnected;
  }
}

bool SocksProxyTunnel::HasError() const {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return socks5_state_ == Socks5State::kError;
  } else {
    return socks4_state_ == Socks4State::kError;
  }
}

bool SocksProxyTunnel::WantsWrite() const {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return socks5_state_ == Socks5State::kSendingGreeting ||
           socks5_state_ == Socks5State::kSendingAuth ||
           socks5_state_ == Socks5State::kSendingConnect;
  } else {
    return socks4_state_ == Socks4State::kSendingConnect;
  }
}

bool SocksProxyTunnel::WantsRead() const {
  if (proxy_type_ == ProxyType::kSocks5 ||
      proxy_type_ == ProxyType::kSocks5h) {
    return socks5_state_ == Socks5State::kReadingAuthMethod ||
           socks5_state_ == Socks5State::kReadingAuthResult ||
           socks5_state_ == Socks5State::kReadingConnectReply;
  } else {
    return socks4_state_ == Socks4State::kReadingReply;
  }
}

// =============================================================================
// SOCKS5 Implementation
// =============================================================================

TunnelResult SocksProxyTunnel::StartSocks5() {
  if (socks5_state_ != Socks5State::kIdle) {
    last_error_ = "SOCKS5 tunnel already started";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  BuildSocks5Greeting();
  socks5_state_ = Socks5State::kSendingGreeting;
  send_offset_ = 0;

  return TunnelResult::kWantWrite;
}

TunnelResult SocksProxyTunnel::Socks5OnWritable(util::socket_t fd) {
  if (send_offset_ >= send_buf_.size()) {
    // Nothing to send, shouldn't happen
    return TunnelResult::kError;
  }

  const uint8_t* data = send_buf_.data() + send_offset_;
  size_t remaining = send_buf_.size() - send_offset_;

  ssize_t sent = util::SendNonBlocking(fd, data, remaining);
  if (sent < 0) {
    // Would block
    return TunnelResult::kWantWrite;
  }

  send_offset_ += static_cast<size_t>(sent);

  if (send_offset_ < send_buf_.size()) {
    // More to send
    return TunnelResult::kWantWrite;
  }

  // All data sent, transition to reading state
  recv_buf_.clear();

  switch (socks5_state_) {
    case Socks5State::kSendingGreeting:
      socks5_state_ = Socks5State::kReadingAuthMethod;
      return TunnelResult::kWantRead;

    case Socks5State::kSendingAuth:
      socks5_state_ = Socks5State::kReadingAuthResult;
      return TunnelResult::kWantRead;

    case Socks5State::kSendingConnect:
      socks5_state_ = Socks5State::kReadingConnectReply;
      return TunnelResult::kWantRead;

    default:
      last_error_ = "Invalid SOCKS5 state in OnWritable";
      socks5_state_ = Socks5State::kError;
      return TunnelResult::kError;
  }
}

TunnelResult SocksProxyTunnel::Socks5OnReadable(util::socket_t fd) {
  uint8_t buf[256];
  ssize_t n = util::RecvNonBlocking(fd, buf, sizeof(buf));

  if (n < 0) {
    // Would block
    return TunnelResult::kWantRead;
  }

  if (n == 0) {
    last_error_ = "SOCKS5 proxy closed connection";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  if (recv_buf_.size() + static_cast<size_t>(n) > kMaxRecvSize) {
    last_error_ = "SOCKS5 response too large";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  recv_buf_.insert(recv_buf_.end(), buf, buf + n);

  switch (socks5_state_) {
    case Socks5State::kReadingAuthMethod:
      return ParseSocks5AuthMethod();

    case Socks5State::kReadingAuthResult:
      return ParseSocks5AuthResult();

    case Socks5State::kReadingConnectReply:
      return ParseSocks5ConnectReply();

    default:
      last_error_ = "Invalid SOCKS5 state in OnReadable";
      socks5_state_ = Socks5State::kError;
      return TunnelResult::kError;
  }
}

void SocksProxyTunnel::BuildSocks5Greeting() {
  // Greeting format: VER | NMETHODS | METHODS
  // We offer: no auth (0x00), and username/password (0x02) if credentials provided
  send_buf_.clear();
  send_buf_.push_back(kSocks5Version);

  if (!proxy_username_.empty()) {
    // Offer both no-auth and password auth
    send_buf_.push_back(2);  // NMETHODS = 2
    send_buf_.push_back(socks5::kAuthNone);
    send_buf_.push_back(socks5::kAuthPassword);
  } else {
    // Only offer no-auth
    send_buf_.push_back(1);  // NMETHODS = 1
    send_buf_.push_back(socks5::kAuthNone);
  }
}

void SocksProxyTunnel::BuildSocks5Auth() {
  // Password auth subnegotiation format (RFC 1929):
  // VER | ULEN | UNAME | PLEN | PASSWD
  send_buf_.clear();
  send_buf_.push_back(socks5::kAuthPasswordVersion);  // Subnegotiation version

  // Username
  uint8_t ulen = static_cast<uint8_t>(
      std::min(proxy_username_.size(), static_cast<size_t>(255)));
  send_buf_.push_back(ulen);
  send_buf_.insert(send_buf_.end(), proxy_username_.begin(),
                   proxy_username_.begin() + ulen);

  // Password
  uint8_t plen = static_cast<uint8_t>(
      std::min(proxy_password_.size(), static_cast<size_t>(255)));
  send_buf_.push_back(plen);
  send_buf_.insert(send_buf_.end(), proxy_password_.begin(),
                   proxy_password_.begin() + plen);
}

void SocksProxyTunnel::BuildSocks5Connect() {
  // Connect request format:
  // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
  send_buf_.clear();
  send_buf_.push_back(kSocks5Version);
  send_buf_.push_back(socks5::kCmdConnect);
  send_buf_.push_back(socks5::kReserved);

  // Determine address type
  bool use_domain = (proxy_type_ == ProxyType::kSocks5h) || target_ip_.empty();

  if (use_domain) {
    // Domain name (SOCKS5h or no resolved IP available)
    send_buf_.push_back(socks5::kAtypDomain);
    uint8_t len = static_cast<uint8_t>(
        std::min(target_host_.size(), static_cast<size_t>(255)));
    send_buf_.push_back(len);
    send_buf_.insert(send_buf_.end(), target_host_.begin(),
                     target_host_.begin() + len);
  } else {
    // Try to parse as IPv4 or IPv6
    uint8_t ipv4[4];
    uint8_t ipv6[16];

    if (ParseIpv4(target_ip_, ipv4)) {
      send_buf_.push_back(socks5::kAtypIpv4);
      send_buf_.insert(send_buf_.end(), ipv4, ipv4 + 4);
    } else if (ParseIpv6(target_ip_, ipv6)) {
      send_buf_.push_back(socks5::kAtypIpv6);
      send_buf_.insert(send_buf_.end(), ipv6, ipv6 + 16);
    } else {
      // Fallback to domain name
      send_buf_.push_back(socks5::kAtypDomain);
      uint8_t len = static_cast<uint8_t>(
          std::min(target_host_.size(), static_cast<size_t>(255)));
      send_buf_.push_back(len);
      send_buf_.insert(send_buf_.end(), target_host_.begin(),
                       target_host_.begin() + len);
    }
  }

  // Port (network byte order)
  send_buf_.push_back(static_cast<uint8_t>((target_port_ >> 8) & 0xFF));
  send_buf_.push_back(static_cast<uint8_t>(target_port_ & 0xFF));
}

TunnelResult SocksProxyTunnel::ParseSocks5AuthMethod() {
  // Response format: VER | METHOD
  if (recv_buf_.size() < 2) {
    return TunnelResult::kWantRead;
  }

  if (recv_buf_[0] != kSocks5Version) {
    last_error_ = "Invalid SOCKS5 version from proxy";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  socks5_auth_method_ = recv_buf_[1];

  if (socks5_auth_method_ == socks5::kAuthNoAcceptable) {
    last_error_ = "SOCKS5 proxy: no acceptable authentication method";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  if (socks5_auth_method_ == socks5::kAuthPassword) {
    // Need to send authentication
    if (proxy_username_.empty()) {
      last_error_ = "SOCKS5 proxy requires authentication but no credentials";
      socks5_state_ = Socks5State::kError;
      return TunnelResult::kError;
    }

    BuildSocks5Auth();
    socks5_state_ = Socks5State::kSendingAuth;
    send_offset_ = 0;
    return TunnelResult::kWantWrite;
  } else if (socks5_auth_method_ == socks5::kAuthNone) {
    // No auth needed, proceed to connect
    BuildSocks5Connect();
    socks5_state_ = Socks5State::kSendingConnect;
    send_offset_ = 0;
    return TunnelResult::kWantWrite;
  } else {
    last_error_ = "SOCKS5 proxy selected unsupported auth method";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }
}

TunnelResult SocksProxyTunnel::ParseSocks5AuthResult() {
  // Response format: VER | STATUS
  if (recv_buf_.size() < 2) {
    return TunnelResult::kWantRead;
  }

  if (recv_buf_[0] != socks5::kAuthPasswordVersion) {
    last_error_ = "Invalid SOCKS5 auth version";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  if (recv_buf_[1] != socks5::kAuthSuccess) {
    last_error_ = "SOCKS5 authentication failed";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  // Auth successful, proceed to connect
  BuildSocks5Connect();
  socks5_state_ = Socks5State::kSendingConnect;
  send_offset_ = 0;
  recv_buf_.clear();
  return TunnelResult::kWantWrite;
}

TunnelResult SocksProxyTunnel::ParseSocks5ConnectReply() {
  // Response format: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
  // Minimum: 4 bytes header + 1 (IPv4 addr length byte) + 2 (port) = 7
  // But we need to determine ATYP to know full length

  if (recv_buf_.size() < 4) {
    return TunnelResult::kWantRead;
  }

  if (recv_buf_[0] != kSocks5Version) {
    last_error_ = "Invalid SOCKS5 version in connect reply";
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  uint8_t rep = recv_buf_[1];
  if (rep != socks5::kRepSucceeded) {
    last_error_ = std::string("SOCKS5 connect failed: ") +
                  socks5::ReplyCodeToString(rep);
    socks5_state_ = Socks5State::kError;
    return TunnelResult::kError;
  }

  // Determine required response length based on address type
  uint8_t atyp = recv_buf_[3];
  size_t required_len = 4;  // VER + REP + RSV + ATYP

  switch (atyp) {
    case socks5::kAtypIpv4:
      required_len += 4 + 2;  // 4 bytes IPv4 + 2 bytes port
      break;
    case socks5::kAtypIpv6:
      required_len += 16 + 2;  // 16 bytes IPv6 + 2 bytes port
      break;
    case socks5::kAtypDomain:
      if (recv_buf_.size() < 5) {
        return TunnelResult::kWantRead;
      }
      required_len += 1 + recv_buf_[4] + 2;  // 1 byte len + domain + 2 bytes port
      break;
    default:
      last_error_ = "Unknown address type in SOCKS5 reply";
      socks5_state_ = Socks5State::kError;
      return TunnelResult::kError;
  }

  if (recv_buf_.size() < required_len) {
    return TunnelResult::kWantRead;
  }

  // Connection established
  socks5_state_ = Socks5State::kConnected;
  return TunnelResult::kOk;
}

// =============================================================================
// SOCKS4/4a Implementation
// =============================================================================

TunnelResult SocksProxyTunnel::StartSocks4() {
  if (socks4_state_ != Socks4State::kIdle) {
    last_error_ = "SOCKS4 tunnel already started";
    socks4_state_ = Socks4State::kError;
    return TunnelResult::kError;
  }

  // SOCKS4 (non-'a') requires a resolved IP
  if (proxy_type_ == ProxyType::kSocks4 && target_ip_.empty()) {
    last_error_ = "SOCKS4 requires resolved target IP";
    socks4_state_ = Socks4State::kError;
    return TunnelResult::kError;
  }

  BuildSocks4Connect();
  socks4_state_ = Socks4State::kSendingConnect;
  send_offset_ = 0;

  return TunnelResult::kWantWrite;
}

TunnelResult SocksProxyTunnel::Socks4OnWritable(util::socket_t fd) {
  if (send_offset_ >= send_buf_.size()) {
    return TunnelResult::kError;
  }

  const uint8_t* data = send_buf_.data() + send_offset_;
  size_t remaining = send_buf_.size() - send_offset_;

  ssize_t sent = util::SendNonBlocking(fd, data, remaining);
  if (sent < 0) {
    return TunnelResult::kWantWrite;
  }

  send_offset_ += static_cast<size_t>(sent);

  if (send_offset_ < send_buf_.size()) {
    return TunnelResult::kWantWrite;
  }

  // All data sent
  recv_buf_.clear();
  socks4_state_ = Socks4State::kReadingReply;
  return TunnelResult::kWantRead;
}

TunnelResult SocksProxyTunnel::Socks4OnReadable(util::socket_t fd) {
  uint8_t buf[64];
  ssize_t n = util::RecvNonBlocking(fd, buf, sizeof(buf));

  if (n < 0) {
    return TunnelResult::kWantRead;
  }

  if (n == 0) {
    last_error_ = "SOCKS4 proxy closed connection";
    socks4_state_ = Socks4State::kError;
    return TunnelResult::kError;
  }

  if (recv_buf_.size() + static_cast<size_t>(n) > kMaxRecvSize) {
    last_error_ = "SOCKS4 response too large";
    socks4_state_ = Socks4State::kError;
    return TunnelResult::kError;
  }

  recv_buf_.insert(recv_buf_.end(), buf, buf + n);

  return ParseSocks4Reply();
}

void SocksProxyTunnel::BuildSocks4Connect() {
  // SOCKS4 request format:
  // VN | CD | DSTPORT | DSTIP | USERID | NULL
  // SOCKS4a: If IP is 0.0.0.x (x != 0), append domain name after NULL

  send_buf_.clear();
  send_buf_.push_back(kSocks4Version);
  send_buf_.push_back(socks4::kCmdConnect);

  // Port (network byte order)
  send_buf_.push_back(static_cast<uint8_t>((target_port_ >> 8) & 0xFF));
  send_buf_.push_back(static_cast<uint8_t>(target_port_ & 0xFF));

  bool use_socks4a = (proxy_type_ == ProxyType::kSocks4a);

  if (use_socks4a) {
    // SOCKS4a: Use 0.0.0.x IP address as marker, domain follows USER ID
    send_buf_.push_back(0x00);
    send_buf_.push_back(0x00);
    send_buf_.push_back(0x00);
    send_buf_.push_back(0x01);  // Non-zero last octet
  } else {
    // SOCKS4: Use resolved IPv4 address
    uint8_t ipv4[4] = {0, 0, 0, 0};
    if (!ParseIpv4(target_ip_, ipv4)) {
      // IPv6 not supported in SOCKS4, this will fail
      // We already validated this in StartSocks4
    }
    send_buf_.insert(send_buf_.end(), ipv4, ipv4 + 4);
  }

  // User ID (username or empty)
  if (!proxy_username_.empty()) {
    send_buf_.insert(send_buf_.end(), proxy_username_.begin(),
                     proxy_username_.end());
  }
  send_buf_.push_back(0x00);  // NULL terminator for user ID

  // SOCKS4a: Append domain name
  if (use_socks4a) {
    send_buf_.insert(send_buf_.end(), target_host_.begin(), target_host_.end());
    send_buf_.push_back(0x00);  // NULL terminator for domain
  }
}

TunnelResult SocksProxyTunnel::ParseSocks4Reply() {
  // Reply format: VN | CD | DSTPORT | DSTIP
  // Total: 8 bytes
  if (recv_buf_.size() < 8) {
    return TunnelResult::kWantRead;
  }

  // VN should be 0 (some proxies return 0x04)
  // We accept both
  if (recv_buf_[0] != 0x00 && recv_buf_[0] != kSocks4Version) {
    last_error_ = "Invalid SOCKS4 version in reply";
    socks4_state_ = Socks4State::kError;
    return TunnelResult::kError;
  }

  uint8_t cd = recv_buf_[1];
  if (cd != socks4::kRepGranted) {
    last_error_ = std::string("SOCKS4 connect failed: ") +
                  socks4::ReplyCodeToString(cd);
    socks4_state_ = Socks4State::kError;
    return TunnelResult::kError;
  }

  // Connection established
  socks4_state_ = Socks4State::kConnected;
  return TunnelResult::kOk;
}

// =============================================================================
// Helper functions
// =============================================================================

bool SocksProxyTunnel::ParseIpv4(std::string_view ip, uint8_t out[4]) {
  // Parse dotted decimal IPv4 (e.g., "192.168.1.1")
  int octets[4];
  int count = 0;
  size_t pos = 0;

  for (int i = 0; i < 4; ++i) {
    if (pos >= ip.size()) return false;

    int val = 0;
    bool found_digit = false;
    while (pos < ip.size() && ip[pos] >= '0' && ip[pos] <= '9') {
      val = val * 10 + (ip[pos] - '0');
      if (val > 255) return false;
      ++pos;
      found_digit = true;
    }

    if (!found_digit) return false;
    octets[count++] = val;

    if (i < 3) {
      if (pos >= ip.size() || ip[pos] != '.') return false;
      ++pos;
    }
  }

  if (count != 4 || pos != ip.size()) return false;

  for (int i = 0; i < 4; ++i) {
    out[i] = static_cast<uint8_t>(octets[i]);
  }

  return true;
}

bool SocksProxyTunnel::ParseIpv6(std::string_view ip, uint8_t out[16]) {
  // Simplified IPv6 parser (handles most common formats)
  // Full format: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
  // Compressed: 2001:db8:85a3::8a2e:370:7334

  std::memset(out, 0, 16);

  // Handle empty or obviously invalid
  if (ip.empty() || ip.size() > 45) return false;

  // Check for IPv4-mapped IPv6 (::ffff:192.168.1.1)
  if (ip.size() > 7 && ip.substr(0, 7) == "::ffff:") {
    std::memset(out, 0, 10);
    out[10] = 0xFF;
    out[11] = 0xFF;
    return ParseIpv4(ip.substr(7), out + 12);
  }

  size_t double_colon_pos = ip.find("::");
  bool has_double_colon = (double_colon_pos != std::string_view::npos);

  // Count colons to validate
  int colon_count = 0;
  for (char c : ip) {
    if (c == ':') ++colon_count;
  }

  // Parse groups
  uint16_t groups[8] = {0};
  int group_count = 0;
  int groups_after_double_colon = 0;
  bool parsing_after = false;

  size_t pos = 0;
  while (pos < ip.size() && group_count < 8) {
    // Check for ::
    if (pos == double_colon_pos) {
      parsing_after = true;
      pos += 2;
      if (pos >= ip.size()) break;
      continue;
    }

    // Parse hex group
    uint16_t val = 0;
    bool found = false;
    while (pos < ip.size()) {
      char c = ip[pos];
      int digit = -1;
      if (c >= '0' && c <= '9') digit = c - '0';
      else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
      else break;

      val = (val << 4) | static_cast<uint16_t>(digit);
      ++pos;
      found = true;
    }

    if (found) {
      if (parsing_after) {
        ++groups_after_double_colon;
      }
      groups[group_count++] = val;
    }

    // Skip single colon
    if (pos < ip.size() && ip[pos] == ':') {
      ++pos;
    }
  }

  if (!has_double_colon && group_count != 8) return false;

  // Expand :: by shifting groups_after_double_colon to the end
  if (has_double_colon) {
    int groups_before = group_count - groups_after_double_colon;
    int zeros_to_insert = 8 - group_count;

    // Move after groups to their final positions
    for (int i = groups_after_double_colon - 1; i >= 0; --i) {
      groups[7 - (groups_after_double_colon - 1 - i)] =
          groups[groups_before + i];
    }

    // Zero out the middle
    for (int i = 0; i < zeros_to_insert; ++i) {
      groups[groups_before + i] = 0;
    }
  }

  // Convert to bytes
  for (int i = 0; i < 8; ++i) {
    out[i * 2] = static_cast<uint8_t>((groups[i] >> 8) & 0xFF);
    out[i * 2 + 1] = static_cast<uint8_t>(groups[i] & 0xFF);
  }

  return true;
}

}  // namespace proxy
}  // namespace holytls

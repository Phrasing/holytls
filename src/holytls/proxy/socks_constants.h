// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// SOCKS protocol constants (RFC 1928 for SOCKS5, SOCKS4/4a de facto standard)

#ifndef HOLYTLS_PROXY_SOCKS_CONSTANTS_H_
#define HOLYTLS_PROXY_SOCKS_CONSTANTS_H_

#include <cstdint>

namespace holytls {
namespace proxy {

// SOCKS protocol versions
constexpr uint8_t kSocks4Version = 0x04;
constexpr uint8_t kSocks5Version = 0x05;

// SOCKS5 authentication methods (RFC 1928)
namespace socks5 {

// Authentication methods
constexpr uint8_t kAuthNone = 0x00;         // No authentication required
constexpr uint8_t kAuthGssapi = 0x01;       // GSSAPI
constexpr uint8_t kAuthPassword = 0x02;     // Username/password (RFC 1929)
constexpr uint8_t kAuthNoAcceptable = 0xFF; // No acceptable methods

// Password authentication subnegotiation version (RFC 1929)
constexpr uint8_t kAuthPasswordVersion = 0x01;

// Password authentication status
constexpr uint8_t kAuthSuccess = 0x00;

// Commands
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdBind = 0x02;
constexpr uint8_t kCmdUdpAssociate = 0x03;

// Address types
constexpr uint8_t kAtypIpv4 = 0x01;    // IPv4 address (4 bytes)
constexpr uint8_t kAtypDomain = 0x03;  // Domain name (1 byte length + name)
constexpr uint8_t kAtypIpv6 = 0x04;    // IPv6 address (16 bytes)

// Reply field (status codes)
constexpr uint8_t kRepSucceeded = 0x00;
constexpr uint8_t kRepGeneralFailure = 0x01;
constexpr uint8_t kRepConnectionNotAllowed = 0x02;
constexpr uint8_t kRepNetworkUnreachable = 0x03;
constexpr uint8_t kRepHostUnreachable = 0x04;
constexpr uint8_t kRepConnectionRefused = 0x05;
constexpr uint8_t kRepTtlExpired = 0x06;
constexpr uint8_t kRepCommandNotSupported = 0x07;
constexpr uint8_t kRepAddressTypeNotSupported = 0x08;

// Reserved byte
constexpr uint8_t kReserved = 0x00;

// Get human-readable error message for reply code
inline const char* ReplyCodeToString(uint8_t code) {
  switch (code) {
    case kRepSucceeded: return "succeeded";
    case kRepGeneralFailure: return "general SOCKS server failure";
    case kRepConnectionNotAllowed: return "connection not allowed by ruleset";
    case kRepNetworkUnreachable: return "network unreachable";
    case kRepHostUnreachable: return "host unreachable";
    case kRepConnectionRefused: return "connection refused";
    case kRepTtlExpired: return "TTL expired";
    case kRepCommandNotSupported: return "command not supported";
    case kRepAddressTypeNotSupported: return "address type not supported";
    default: return "unknown error";
  }
}

}  // namespace socks5

// SOCKS4/4a constants
namespace socks4 {

// Commands
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdBind = 0x02;

// Reply codes (status)
constexpr uint8_t kRepGranted = 0x5A;          // Request granted
constexpr uint8_t kRepRejected = 0x5B;         // Request rejected or failed
constexpr uint8_t kRepNoIdentd = 0x5C;         // Cannot connect to identd
constexpr uint8_t kRepIdentdMismatch = 0x5D;   // Identd user mismatch

// SOCKS4a: first three octets of IP must be 0, fourth non-zero
// Indicates domain name follows the user ID
constexpr uint8_t kSocks4aMarker = 0x00;

// Get human-readable error message for reply code
inline const char* ReplyCodeToString(uint8_t code) {
  switch (code) {
    case kRepGranted: return "request granted";
    case kRepRejected: return "request rejected or failed";
    case kRepNoIdentd: return "cannot connect to client identd";
    case kRepIdentdMismatch: return "client identd user mismatch";
    default: return "unknown error";
  }
}

}  // namespace socks4

}  // namespace proxy
}  // namespace holytls

#endif  // HOLYTLS_PROXY_SOCKS_CONSTANTS_H_

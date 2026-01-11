// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_ERROR_H_
#define HOLYTLS_ERROR_H_

#include <string>
#include <string_view>

namespace holytls {

// Error codes for the client
enum class ErrorCode {
  kOk = 0,

  // DNS errors
  kDnsResolutionFailed,
  kDnsTimeout,

  // Connection errors
  kConnectionRefused,
  kConnectionReset,
  kConnectionTimeout,
  kNetworkUnreachable,
  kHostUnreachable,

  // TLS errors
  kTlsHandshakeFailed,
  kTlsCertificateError,
  kTlsProtocolError,

  // HTTP/2 errors
  kH2ProtocolError,
  kH2StreamError,
  kH2FlowControlError,
  kH2SettingsTimeout,

  // Request errors
  kRequestTimeout,
  kRequestCancelled,
  kTooManyRedirects,
  kInvalidUrl,
  kInvalidHeader,

  // Pool errors
  kPoolExhausted,
  kNoAvailableConnection,

  // Internal errors
  kInternalError,
  kOutOfMemory,
};

// Error information with code and message
class Error {
 public:
  Error() : code_(ErrorCode::kOk) {}
  Error(ErrorCode code, std::string message)
      : code_(code), message_(std::move(message)) {}

  // Factory methods
  static Error Ok() { return {}; }

  static Error Dns(std::string_view msg) {
    return {ErrorCode::kDnsResolutionFailed, std::string(msg)};
  }

  static Error Connection(ErrorCode code, std::string_view msg) {
    return {code, std::string(msg)};
  }

  static Error Tls(std::string_view msg) {
    return {ErrorCode::kTlsHandshakeFailed, std::string(msg)};
  }

  static Error Http2(std::string_view msg) {
    return {ErrorCode::kH2ProtocolError, std::string(msg)};
  }

  static Error Timeout() {
    return {ErrorCode::kRequestTimeout, "request timed out"};
  }

  static Error Cancelled() {
    return {ErrorCode::kRequestCancelled, "request cancelled"};
  }

  static Error InvalidUrl(std::string_view msg) {
    return {ErrorCode::kInvalidUrl, std::string(msg)};
  }

  static Error Internal(std::string_view msg) {
    return {ErrorCode::kInternalError, std::string(msg)};
  }

  static Error Connection(std::string_view msg) {
    return {ErrorCode::kConnectionRefused, std::string(msg)};
  }

  // Check if error occurred
  explicit operator bool() const { return code_ != ErrorCode::kOk; }
  bool ok() const { return code_ == ErrorCode::kOk; }

  // Accessors
  ErrorCode code() const { return code_; }
  const std::string& message() const { return message_; }

 private:
  ErrorCode code_;
  std::string message_;
};

}  // namespace holytls

#endif  // HOLYTLS_ERROR_H_

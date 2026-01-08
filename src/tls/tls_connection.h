// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_TLS_TLS_CONNECTION_H_
#define CHAD_TLS_TLS_CONNECTION_H_

#include <openssl/ssl.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "core/io_buffer.h"
#include "tls/tls_context.h"

namespace chad {
namespace tls {

// SSL object deleter
struct SslDeleter {
  void operator()(SSL* ssl) {
    if (ssl != nullptr) {
      SSL_free(ssl);
    }
  }
};

using SslPtr = std::unique_ptr<SSL, SslDeleter>;

// TLS connection state machine
enum class TlsState {
  kInit,         // Not started
  kConnecting,   // TCP connect in progress
  kHandshaking,  // TLS handshake in progress
  kConnected,    // Handshake complete, ready for data
  kShuttingDown, // TLS shutdown in progress
  kClosed,       // Connection closed
  kError,        // Error occurred
};

// Result of TLS I/O operations
enum class TlsResult {
  kOk,        // Operation completed successfully
  kWantRead,  // Need to wait for socket readable
  kWantWrite, // Need to wait for socket writable
  kEof,       // Connection closed cleanly
  kError,     // Error occurred
};

// Per-connection TLS wrapper with non-blocking I/O support.
class TlsConnection {
 public:
  // Create TLS connection wrapping the given socket fd
  TlsConnection(TlsContextFactory* factory, int fd, std::string_view hostname);
  ~TlsConnection();

  // Non-copyable, non-movable
  TlsConnection(const TlsConnection&) = delete;
  TlsConnection& operator=(const TlsConnection&) = delete;
  TlsConnection(TlsConnection&&) = delete;
  TlsConnection& operator=(TlsConnection&&) = delete;

  // Perform non-blocking TLS handshake.
  // Returns kOk when complete, kWantRead/kWantWrite when I/O needed.
  TlsResult DoHandshake();

  // Read decrypted data into buffer.
  // Returns kOk with data available, kWantRead if blocked, kEof on close.
  TlsResult Read(core::IoBuffer* buffer);

  // Read into raw buffer.
  // Returns bytes read, or 0 on EOF, -1 on error/would block.
  // Sets result out parameter to indicate actual result.
  ssize_t ReadRaw(uint8_t* dest, size_t max_len, TlsResult* result);

  // Write data (encrypts and sends).
  // Returns kOk when all data written, kWantWrite if blocked.
  TlsResult Write(const uint8_t* data, size_t len, size_t* written);

  // Write from IoBuffer.
  TlsResult Write(core::IoBuffer* buffer, size_t* written);

  // Initiate TLS shutdown.
  // Returns kOk when complete, kWantRead/kWantWrite when blocked.
  TlsResult Shutdown();

  // State accessors
  TlsState state() const { return state_; }
  bool IsConnected() const { return state_ == TlsState::kConnected; }
  bool IsHandshaking() const { return state_ == TlsState::kHandshaking; }
  bool HasError() const { return state_ == TlsState::kError; }

  // Get the last error message
  const std::string& last_error() const { return last_error_; }

  // Get negotiated ALPN protocol (e.g., "h2" or "http/1.1")
  std::string_view AlpnProtocol() const;

  // Check if HTTP/2 was negotiated
  bool IsHttp2() const;

  // Get the hostname being connected to
  const std::string& hostname() const { return hostname_; }

  // Get underlying socket fd
  int fd() const { return fd_; }

  // Get underlying SSL object (for advanced use)
  SSL* ssl() const { return ssl_.get(); }

 private:
  // Map SSL error to TlsResult
  TlsResult HandleSslError(int ssl_ret);

  // Set error state with message
  void SetError(const std::string& msg);

  SslPtr ssl_;
  TlsState state_ = TlsState::kInit;
  int fd_;
  std::string hostname_;
  std::string last_error_;

  // Cached ALPN result (empty until handshake complete)
  mutable std::string alpn_protocol_;
};

}  // namespace tls
}  // namespace chad

#endif  // CHAD_TLS_TLS_CONNECTION_H_

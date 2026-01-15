// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_TLS_TLS_CONNECTION_H_
#define HOLYTLS_TLS_TLS_CONNECTION_H_

// Include platform.h first for Windows compatibility (ssize_t, header guards)
#include "holytls/util/platform.h"

#include <openssl/ssl.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "holytls/core/io_buffer.h"
#include "holytls/tls/tls_context.h"

namespace holytls {
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

enum class TlsState {
  kInit,
  kConnecting,
  kHandshaking,
  kConnected,
  kShuttingDown,
  kClosed,
  kError,
};

enum class TlsResult {
  kOk,
  kWantRead,
  kWantWrite,
  kEof,
  kError,
};

// Per-connection TLS wrapper with non-blocking I/O support.
class TlsConnection {
 public:
  // Read-only connection properties (set at construction)
  const int fd;
  const uint16_t port;
  const std::string hostname;

  // Create TLS connection wrapping the given socket fd.
  // Port is used for session cache keying.
  TlsConnection(TlsContextFactory* factory, int socket_fd,
                std::string_view host, uint16_t p = 443);
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

  // State queries
  TlsState state() const { return state_; }
  bool IsConnected() const { return state_ == TlsState::kConnected; }
  bool IsHandshaking() const { return state_ == TlsState::kHandshaking; }
  bool HasError() const { return state_ == TlsState::kError; }

  const std::string& last_error() const { return last_error_; }

  // Returns negotiated ALPN protocol (e.g., "h2" or "http/1.1")
  std::string_view AlpnProtocol() const;
  bool IsHttp2() const;

  // Only meaningful after handshake completes
  bool SessionResumed() const;

  SSL* ssl() const { return ssl_.get(); }

 private:
  TlsResult HandleSslError(int ssl_ret);
  void SetError(const std::string& msg);

  SslPtr ssl_;
  TlsState state_ = TlsState::kInit;
  std::string last_error_;

  // Cached ALPN result (empty until handshake complete)
  mutable std::string alpn_protocol_;
};

}  // namespace tls
}  // namespace holytls

#endif  // HOLYTLS_TLS_TLS_CONNECTION_H_

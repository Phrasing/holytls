// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/tls/tls_connection.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cstring>

#include "holytls/tls/session_cache.h"
#include "holytls/util/platform.h"

namespace holytls {
namespace tls {

TlsConnection::TlsConnection(TlsContextFactory* factory, int fd,
                             std::string_view hostname, uint16_t port)
    : fd_(fd), port_(port), hostname_(hostname) {
  // Create SSL object
  ssl_.reset(factory->CreateSsl());
  if (!ssl_) {
    SetError("Failed to create SSL object");
    return;
  }

  // Attach to socket
  if (SSL_set_fd(ssl_.get(), fd) != 1) {
    SetError("Failed to set SSL fd");
    return;
  }

  // Set SNI (Server Name Indication)
  if (!hostname_.empty()) {
    SSL_set_tlsext_host_name(ssl_.get(), hostname_.c_str());
  }

  // Store port in SSL ex_data for new_session_cb
  SSL_set_ex_data(ssl_.get(), GetPortIndex(),
                  reinterpret_cast<void*>(static_cast<uintptr_t>(port)));

  // Attempt session resumption if cache enabled
  if (auto* cache = factory->session_cache()) {
    SSL_SESSION* cached = cache->Lookup(std::string(hostname), port);
    if (cached) {
      SSL_set_session(ssl_.get(), cached);
      SSL_SESSION_free(cached);  // SSL_set_session increments refcount
    }
  }

  // Put in client mode
  SSL_set_connect_state(ssl_.get());

  state_ = TlsState::kHandshaking;
}

TlsConnection::~TlsConnection() = default;

TlsResult TlsConnection::DoHandshake() {
  if (state_ == TlsState::kConnected) {
    return TlsResult::kOk;
  }

  if (state_ != TlsState::kHandshaking) {
    SetError("Invalid state for handshake");
    return TlsResult::kError;
  }

  ERR_clear_error();
  int ret = SSL_do_handshake(ssl_.get());

  if (ret == 1) {
    // Handshake complete
    state_ = TlsState::kConnected;
    return TlsResult::kOk;
  }

  return HandleSslError(ret);
}

TlsResult TlsConnection::Read(core::IoBuffer* buffer) {
  if (state_ != TlsState::kConnected) {
    return TlsResult::kError;
  }

  // Reserve space in buffer
  constexpr size_t kReadChunkSize = 16384;  // TLS record size
  uint8_t* dest = buffer->Reserve(kReadChunkSize);

  TlsResult result;
  ssize_t bytes = ReadRaw(dest, kReadChunkSize, &result);

  if (bytes > 0) {
    buffer->Commit(static_cast<size_t>(bytes));
    return TlsResult::kOk;
  }

  return result;
}

ssize_t TlsConnection::ReadRaw(uint8_t* dest, size_t max_len,
                               TlsResult* result) {
  if (state_ != TlsState::kConnected) {
    *result = TlsResult::kError;
    return -1;
  }

  ERR_clear_error();
  int ret = SSL_read(ssl_.get(), dest, static_cast<int>(max_len));

  if (ret > 0) {
    *result = TlsResult::kOk;
    return ret;
  }

  *result = HandleSslError(ret);

  if (*result == TlsResult::kEof) {
    return 0;
  }

  return -1;
}

TlsResult TlsConnection::Write(const uint8_t* data, size_t len,
                               size_t* written) {
  if (state_ != TlsState::kConnected) {
    return TlsResult::kError;
  }

  *written = 0;

  // Single SSL_write per call to avoid blocking event loop with large writes.
  // Caller should call again if more data needs to be written.
  ERR_clear_error();
  int to_write = static_cast<int>(std::min(len, size_t{16384}));  // Cap at 16KB
  int ret = SSL_write(ssl_.get(), data, to_write);

  if (ret > 0) {
    *written = static_cast<size_t>(ret);
    // Return kWantWrite if more data remains, letting reactor re-schedule
    return (*written < len) ? TlsResult::kWantWrite : TlsResult::kOk;
  }

  return HandleSslError(ret);
}

TlsResult TlsConnection::Write(core::IoBuffer* buffer, size_t* written) {
  if (state_ != TlsState::kConnected) {
    return TlsResult::kError;
  }

  *written = 0;

  while (!buffer->Empty()) {
    size_t available;
    const uint8_t* data = buffer->Peek(&available);

    size_t bytes_written = 0;
    TlsResult result = Write(data, available, &bytes_written);

    if (bytes_written > 0) {
      buffer->Skip(bytes_written);
      *written += bytes_written;
    }

    if (result != TlsResult::kOk) {
      return result;
    }
  }

  return TlsResult::kOk;
}

TlsResult TlsConnection::Shutdown() {
  if (state_ == TlsState::kClosed) {
    return TlsResult::kOk;
  }

  if (state_ == TlsState::kError) {
    return TlsResult::kError;
  }

  state_ = TlsState::kShuttingDown;

  ERR_clear_error();
  int ret = SSL_shutdown(ssl_.get());

  if (ret == 1) {
    // Shutdown complete
    state_ = TlsState::kClosed;
    return TlsResult::kOk;
  }

  if (ret == 0) {
    // Need to call SSL_shutdown again
    ret = SSL_shutdown(ssl_.get());
    if (ret == 1) {
      state_ = TlsState::kClosed;
      return TlsResult::kOk;
    }
  }

  TlsResult result = HandleSslError(ret);
  if (result == TlsResult::kEof) {
    state_ = TlsState::kClosed;
    return TlsResult::kOk;
  }

  return result;
}

std::string_view TlsConnection::AlpnProtocol() const {
  if (!alpn_protocol_.empty()) {
    return alpn_protocol_;
  }

  if (state_ != TlsState::kConnected) {
    return "";
  }

  const unsigned char* proto = nullptr;
  unsigned int proto_len = 0;

  SSL_get0_alpn_selected(ssl_.get(), &proto, &proto_len);

  if (proto != nullptr && proto_len > 0) {
    alpn_protocol_.assign(reinterpret_cast<const char*>(proto), proto_len);
  }

  return alpn_protocol_;
}

bool TlsConnection::IsHttp2() const { return AlpnProtocol() == "h2"; }

bool TlsConnection::SessionResumed() const {
  if (state_ != TlsState::kConnected) {
    return false;
  }
  return SSL_session_reused(ssl_.get()) != 0;
}

TlsResult TlsConnection::HandleSslError(int ssl_ret) {
  int err = SSL_get_error(ssl_.get(), ssl_ret);

  switch (err) {
    case SSL_ERROR_WANT_READ:
      return TlsResult::kWantRead;

    case SSL_ERROR_WANT_WRITE:
      return TlsResult::kWantWrite;

    case SSL_ERROR_ZERO_RETURN:
      // Clean shutdown
      state_ = TlsState::kClosed;
      return TlsResult::kEof;

    case SSL_ERROR_SYSCALL: {
      // Check for EOF (connection reset)
      if (ssl_ret == 0) {
        state_ = TlsState::kClosed;
        return TlsResult::kEof;
      }
      // System error
      SetError("SSL syscall error: " + util::GetLastSocketErrorString());
      return TlsResult::kError;
    }

    case SSL_ERROR_SSL: {
      // Protocol error
      uint32_t openssl_err = static_cast<uint32_t>(ERR_get_error());
      char err_buf[256];
      ERR_error_string_n(openssl_err, err_buf, sizeof(err_buf));
      SetError(std::string("SSL error: ") + err_buf);
      return TlsResult::kError;
    }

    default:
      SetError("Unknown SSL error");
      return TlsResult::kError;
  }
}

void TlsConnection::SetError(const std::string& msg) {
  state_ = TlsState::kError;
  last_error_ = msg;
}

}  // namespace tls
}  // namespace holytls

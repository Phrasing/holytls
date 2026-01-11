// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_CORE_CONNECTION_H_
#define HOLYTLS_CORE_CONNECTION_H_

// Include platform.h first for Windows compatibility
#include "holytls/util/platform.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "holytls/core/io_buffer.h"
#include "holytls/core/reactor.h"
#include "holytls/http2/h2_session.h"
#include "holytls/tls/tls_connection.h"

namespace holytls {
namespace core {

// Connection state machine
enum class ConnectionState {
  kConnecting,    // TCP connect in progress
  kTlsHandshake,  // TLS handshake in progress
  kConnected,     // Ready for HTTP/2 requests
  kClosing,       // Shutdown in progress
  kClosed,        // Connection closed
  kError,         // Error occurred
};

// Response data
struct Response {
  int status_code = 0;
  http2::PackedHeaders headers;
  std::vector<uint8_t> body;

  std::string body_string() const {
    return std::string(body.begin(), body.end());
  }
};

// Forward declaration for callback types
class Connection;

// Callback types
using ResponseCallback = std::function<void(const Response& response)>;
using ErrorCallback = std::function<void(const std::string& error)>;
using IdleCallback = std::function<void(Connection*)>;

// Connection configuration options
struct ConnectionOptions {
  // Automatically decompress response bodies (br, gzip, zstd, deflate)
  bool auto_decompress = true;
};

// HTTP/2 connection over TLS.
// Implements EventHandler to integrate with Reactor.
class Connection : public EventHandler {
 public:
  Connection(Reactor* reactor, tls::TlsContextFactory* tls_factory,
             const std::string& host, uint16_t port,
             const ConnectionOptions& options = {});
  ~Connection() override;

  // Non-copyable, non-movable
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;
  Connection(Connection&&) = delete;
  Connection& operator=(Connection&&) = delete;

  // Start connection (DNS resolution must be done already)
  // ip can be IPv4 or IPv6 address
  bool Connect(const std::string& ip, bool ipv6 = false);

  // Send a GET request
  void SendRequest(
      const std::string& method, const std::string& path,
      const std::vector<std::pair<std::string, std::string>>& headers,
      ResponseCallback on_response, ErrorCallback on_error = nullptr);

  // Close the connection
  void Close();

  // Set callback for when connection becomes idle (no active requests)
  void SetIdleCallback(IdleCallback callback) {
    idle_callback_ = std::move(callback);
  }

  // State accessors
  ConnectionState state() const { return state_; }
  bool IsConnected() const { return state_ == ConnectionState::kConnected; }
  bool IsClosed() const { return state_ == ConnectionState::kClosed; }
  bool IsIdle() const {
    return active_requests_.empty() && pending_requests_.empty();
  }

  // Stream capacity (for HTTP/2 multiplexing)
  size_t ActiveStreamCount() const { return active_requests_.size(); }

  // EventHandler interface
  void OnReadable() override;
  void OnWritable() override;
  void OnError(int error_code) override;
  void OnClose() override;
  int fd() const override { return static_cast<int>(fd_); }

 private:
  void HandleConnecting();
  void HandleTlsHandshake();
  void HandleConnected();
  void FlushSendBuffer();
  void SetError(const std::string& msg);

  Reactor* reactor_;
  tls::TlsContextFactory* tls_factory_;
  std::string host_;
  uint16_t port_;

  util::socket_t fd_ = util::kInvalidSocket;
  ConnectionState state_ = ConnectionState::kClosed;

  std::unique_ptr<tls::TlsConnection> tls_;
  std::unique_ptr<http2::H2Session> h2_;

  // Pending request data (for when connection is still being established)
  struct PendingRequest {
    std::string method;
    std::string path;
    std::vector<std::pair<std::string, std::string>> headers;
    ResponseCallback on_response;
    ErrorCallback on_error;
  };
  std::vector<PendingRequest> pending_requests_;

  // Active response tracking
  struct ActiveRequest {
    ResponseCallback on_response;
    ErrorCallback on_error;
    int status_code = 0;
    http2::PackedHeaders headers;
    IoBuffer body_buffer;  // O(1) append instead of O(n) vector insert
  };
  std::unordered_map<int32_t, ActiveRequest> active_requests_;

  std::string last_error_;

  // Configuration
  ConnectionOptions options_;

  // Idle callback (notifies pool when connection has no active requests)
  IdleCallback idle_callback_;
};

}  // namespace core
}  // namespace holytls

#endif  // HOLYTLS_CORE_CONNECTION_H_

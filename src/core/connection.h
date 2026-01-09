// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_CORE_CONNECTION_H_
#define CHAD_CORE_CONNECTION_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "core/reactor.h"
#include "http2/h2_session.h"
#include "tls/tls_connection.h"

namespace chad {
namespace core {

// Connection state machine
enum class ConnectionState {
  kConnecting,     // TCP connect in progress
  kTlsHandshake,   // TLS handshake in progress
  kConnected,      // Ready for HTTP/2 requests
  kClosing,        // Shutdown in progress
  kClosed,         // Connection closed
  kError,          // Error occurred
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

// Callback types
using ResponseCallback = std::function<void(const Response& response)>;
using ErrorCallback = std::function<void(const std::string& error)>;

// HTTP/2 connection over TLS.
// Implements EventHandler to integrate with Reactor.
class Connection : public EventHandler {
 public:
  Connection(Reactor* reactor, tls::TlsContextFactory* tls_factory,
             const std::string& host, uint16_t port);
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
  void SendRequest(const std::string& method, const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   ResponseCallback on_response, ErrorCallback on_error = nullptr);

  // Close the connection
  void Close();

  // State accessors
  ConnectionState state() const { return state_; }
  bool IsConnected() const { return state_ == ConnectionState::kConnected; }
  bool IsClosed() const { return state_ == ConnectionState::kClosed; }

  // EventHandler interface
  void OnReadable() override;
  void OnWritable() override;
  void OnError(int error_code) override;
  void OnClose() override;
  int fd() const override { return fd_; }

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

  int fd_ = -1;
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
    Response response;
  };
  std::unordered_map<int32_t, ActiveRequest> active_requests_;

  std::string last_error_;
};

}  // namespace core
}  // namespace chad

#endif  // CHAD_CORE_CONNECTION_H_

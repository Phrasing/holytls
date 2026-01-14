// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Mock HTTP servers for protocol testing
// These servers run in the same reactor as tests for deterministic behavior

#ifndef HOLYTLS_TESTS_PROTOCOL_MOCK_SERVER_H_
#define HOLYTLS_TESTS_PROTOCOL_MOCK_SERVER_H_

#include <uv.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "holytls/core/reactor.h"

namespace holytls {
namespace test {

// Received HTTP request (for verification)
struct ReceivedRequest {
  std::string method;
  std::string path;
  std::string http_version;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
};

// Configured HTTP response
struct MockResponse {
  int status_code = 200;
  std::string status_text = "OK";
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  bool chunked = false;
};

// Simple HTTP/1.1 mock server
// Accepts TCP connections and responds with configurable HTTP/1.1 responses
class MockHttp1Server {
 public:
  explicit MockHttp1Server(core::Reactor* reactor);
  ~MockHttp1Server();

  // Non-copyable
  MockHttp1Server(const MockHttp1Server&) = delete;
  MockHttp1Server& operator=(const MockHttp1Server&) = delete;

  // Start listening on ephemeral port, returns assigned port
  uint16_t Start();

  // Stop the server
  void Stop();

  // Configure response for next request
  void SetResponse(int status, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers = {});

  // Configure chunked response
  void SetChunkedResponse(int status, const std::vector<std::string>& chunks,
                          const std::vector<std::pair<std::string, std::string>>& headers = {});

  // Get last received request (for verification)
  const ReceivedRequest& GetLastRequest() const { return last_request_; }

  // Get number of requests received
  size_t RequestCount() const { return request_count_; }

  // Check if server is running
  bool IsRunning() const { return running_; }

 private:
  struct ClientConnection;

  static void OnNewConnection(uv_stream_t* server, int status);
  static void OnAlloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
  static void OnRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
  static void OnWrite(uv_write_t* req, int status);
  static void OnClose(uv_handle_t* handle);
  static void OnServerClose(uv_handle_t* handle);

  void HandleRequest(ClientConnection* client);
  bool ParseRequest(const std::string& data, ReceivedRequest* request);
  std::string BuildResponse();
  std::string BuildChunkedResponse();

  core::Reactor* reactor_;
  uv_tcp_t server_;
  bool running_ = false;
  uint16_t port_ = 0;

  MockResponse response_;
  std::vector<std::string> chunks_;
  ReceivedRequest last_request_;
  size_t request_count_ = 0;

  std::vector<std::unique_ptr<ClientConnection>> clients_;
};

// HTTP/2 mock server using nghttp2
// Speaks HTTP/2 frames over TLS
class MockHttp2Server {
 public:
  explicit MockHttp2Server(core::Reactor* reactor);
  ~MockHttp2Server();

  // Start listening with TLS, returns assigned port
  uint16_t Start();
  void Stop();

  // Configure response
  void SetResponse(int status, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers = {});

  // HTTP/2 specific
  size_t ActiveStreamCount() const { return active_streams_; }
  void SendGoaway(uint32_t error_code);

  const ReceivedRequest& GetLastRequest() const { return last_request_; }
  size_t RequestCount() const { return request_count_; }
  bool IsRunning() const { return running_; }

 private:
  core::Reactor* reactor_;
  bool running_ = false;
  uint16_t port_ = 0;
  size_t active_streams_ = 0;
  MockResponse response_;
  ReceivedRequest last_request_;
  size_t request_count_ = 0;

  // Implementation details for HTTP/2 (nghttp2 server session)
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

#if defined(HOLYTLS_BUILD_QUIC)
// HTTP/3 mock server using ngtcp2 + nghttp3
// Speaks QUIC/HTTP/3 over UDP
class MockHttp3Server {
 public:
  explicit MockHttp3Server(core::Reactor* reactor);
  ~MockHttp3Server();

  // Start listening on UDP, returns assigned port
  uint16_t Start();
  void Stop();

  // Configure response
  void SetResponse(int status, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers = {});

  const ReceivedRequest& GetLastRequest() const { return last_request_; }
  size_t RequestCount() const { return request_count_; }
  bool IsRunning() const { return running_; }

 private:
  core::Reactor* reactor_;
  bool running_ = false;
  uint16_t port_ = 0;
  MockResponse response_;
  ReceivedRequest last_request_;
  size_t request_count_ = 0;

  // Implementation details for HTTP/3 (ngtcp2 + nghttp3)
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
#endif  // HOLYTLS_BUILD_QUIC

}  // namespace test
}  // namespace holytls

#endif  // HOLYTLS_TESTS_PROTOCOL_MOCK_SERVER_H_

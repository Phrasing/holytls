// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "mock_server.h"

#include <picohttpparser.h>

#include <cstring>
#include <sstream>

namespace holytls {
namespace test {

namespace {

// Case-insensitive header name comparison
bool HeaderNameEquals(const char* a, size_t a_len, const char* b) {
  size_t b_len = std::strlen(b);
  if (a_len != b_len) return false;
  for (size_t i = 0; i < a_len; ++i) {
    char ca = a[i];
    char cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca += 32;
    if (cb >= 'A' && cb <= 'Z') cb += 32;
    if (ca != cb) return false;
  }
  return true;
}

}  // namespace

// Client connection state for HTTP/1 server
struct MockHttp1Server::ClientConnection {
  uv_tcp_t handle;
  MockHttp1Server* server;
  std::string recv_buffer;
  size_t last_parse_len = 0;  // For incremental parsing
  size_t headers_len = 0;     // Length of headers (from phr_parse_request)
  size_t content_length = 0;  // Content-Length value
  bool headers_complete = false;
};

// Write request data that persists until write completes
struct WriteData {
  uv_write_t req;
  std::string data;
};

MockHttp1Server::MockHttp1Server(core::Reactor* reactor) : reactor_(reactor) {
  std::memset(&server_, 0, sizeof(server_));
}

MockHttp1Server::~MockHttp1Server() {
  if (running_) {
    Stop();
  }
}

uint16_t MockHttp1Server::Start() {
  if (running_) {
    return port_;
  }

  int rv = uv_tcp_init(reactor_->loop(), &server_);
  if (rv != 0) {
    return 0;
  }

  server_.data = this;

  // Bind to ephemeral port on localhost
  sockaddr_in addr;
  uv_ip4_addr("127.0.0.1", 0, &addr);
  rv = uv_tcp_bind(&server_, reinterpret_cast<const sockaddr*>(&addr), 0);
  if (rv != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&server_), nullptr);
    return 0;
  }

  rv =
      uv_listen(reinterpret_cast<uv_stream_t*>(&server_), 128, OnNewConnection);
  if (rv != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&server_), nullptr);
    return 0;
  }

  // Get assigned port
  sockaddr_storage storage;
  int namelen = sizeof(storage);
  uv_tcp_getsockname(&server_, reinterpret_cast<sockaddr*>(&storage), &namelen);
  port_ = ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port);

  running_ = true;
  return port_;
}

void MockHttp1Server::Stop() {
  if (!running_) {
    return;
  }

  // Close all client connections
  for (auto& client : clients_) {
    if (client) {
      uv_close(reinterpret_cast<uv_handle_t*>(&client->handle), OnClose);
    }
  }
  clients_.clear();

  // Close server
  uv_close(reinterpret_cast<uv_handle_t*>(&server_), OnServerClose);
  running_ = false;
}

void MockHttp1Server::SetResponse(
    int status, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers) {
  response_.status_code = status;
  response_.body = body;
  response_.headers = headers;
  response_.chunked = false;

  // Set status text
  switch (status) {
    case 200:
      response_.status_text = "OK";
      break;
    case 201:
      response_.status_text = "Created";
      break;
    case 204:
      response_.status_text = "No Content";
      break;
    case 301:
      response_.status_text = "Moved Permanently";
      break;
    case 302:
      response_.status_text = "Found";
      break;
    case 304:
      response_.status_text = "Not Modified";
      break;
    case 400:
      response_.status_text = "Bad Request";
      break;
    case 401:
      response_.status_text = "Unauthorized";
      break;
    case 403:
      response_.status_text = "Forbidden";
      break;
    case 404:
      response_.status_text = "Not Found";
      break;
    case 500:
      response_.status_text = "Internal Server Error";
      break;
    case 502:
      response_.status_text = "Bad Gateway";
      break;
    case 503:
      response_.status_text = "Service Unavailable";
      break;
    default:
      response_.status_text = "Unknown";
      break;
  }

  chunks_.clear();
}

void MockHttp1Server::SetChunkedResponse(
    int status, const std::vector<std::string>& chunks,
    const std::vector<std::pair<std::string, std::string>>& headers) {
  response_.status_code = status;
  response_.headers = headers;
  response_.chunked = true;
  chunks_ = chunks;

  // Compute body from chunks for reference
  response_.body.clear();
  for (const auto& chunk : chunks) {
    response_.body += chunk;
  }
}

void MockHttp1Server::OnNewConnection(uv_stream_t* server, int status) {
  if (status < 0) {
    return;
  }

  auto* self = static_cast<MockHttp1Server*>(server->data);

  auto client = std::make_unique<ClientConnection>();
  client->server = self;

  int rv = uv_tcp_init(self->reactor_->loop(), &client->handle);
  if (rv != 0) {
    return;
  }

  client->handle.data = client.get();

  rv = uv_accept(server, reinterpret_cast<uv_stream_t*>(&client->handle));
  if (rv != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&client->handle), nullptr);
    return;
  }

  rv = uv_read_start(reinterpret_cast<uv_stream_t*>(&client->handle), OnAlloc,
                     OnRead);
  if (rv != 0) {
    uv_close(reinterpret_cast<uv_handle_t*>(&client->handle), nullptr);
    return;
  }

  self->clients_.push_back(std::move(client));
}

void MockHttp1Server::OnAlloc(uv_handle_t* /*handle*/, size_t suggested_size,
                              uv_buf_t* buf) {
  buf->base = new char[suggested_size];
  buf->len = static_cast<unsigned int>(suggested_size);
}

void MockHttp1Server::OnRead(uv_stream_t* stream, ssize_t nread,
                             const uv_buf_t* buf) {
  auto* client = static_cast<ClientConnection*>(stream->data);

  if (nread < 0) {
    delete[] buf->base;
    uv_close(reinterpret_cast<uv_handle_t*>(stream), OnClose);
    return;
  }

  if (nread > 0) {
    client->recv_buffer.append(buf->base, static_cast<size_t>(nread));
  }
  delete[] buf->base;

  // Parse headers using picohttpparser (incremental)
  if (!client->headers_complete) {
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor_version;
    struct phr_header headers[100];
    size_t num_headers = 100;

    int pret = phr_parse_request(client->recv_buffer.c_str(),
                                 client->recv_buffer.size(), &method,
                                 &method_len, &path, &path_len, &minor_version,
                                 headers, &num_headers, client->last_parse_len);

    if (pret == -1) {
      // Parse error - close connection
      uv_close(reinterpret_cast<uv_handle_t*>(stream), OnClose);
      return;
    }

    if (pret == -2) {
      // Incomplete - need more data
      client->last_parse_len = client->recv_buffer.size();
      return;
    }

    // Headers complete
    client->headers_complete = true;
    client->headers_len = static_cast<size_t>(pret);

    // Extract Content-Length from parsed headers (case-insensitive)
    for (size_t i = 0; i < num_headers; ++i) {
      if (HeaderNameEquals(headers[i].name, headers[i].name_len,
                           "content-length")) {
        client->content_length =
            std::stoull(std::string(headers[i].value, headers[i].value_len));
        break;
      }
    }
  }

  // Check if body is complete
  size_t body_received = client->recv_buffer.size() - client->headers_len;
  if (client->headers_complete && body_received >= client->content_length) {
    client->server->HandleRequest(client);
  }
}

void MockHttp1Server::HandleRequest(ClientConnection* client) {
  // Parse the request
  ReceivedRequest request;
  if (ParseRequest(client->recv_buffer, &request)) {
    last_request_ = std::move(request);
    request_count_++;
  }

  // Build and send response
  std::string response_data;
  if (response_.chunked) {
    response_data = BuildChunkedResponse();
  } else {
    response_data = BuildResponse();
  }

  // Allocate write request and buffer that persists until write completes
  auto* write_data = new WriteData;
  write_data->data = std::move(response_data);

  uv_buf_t buf =
      uv_buf_init(const_cast<char*>(write_data->data.data()),
                  static_cast<unsigned int>(write_data->data.size()));
  write_data->req.data = write_data;

  uv_write(&write_data->req, reinterpret_cast<uv_stream_t*>(&client->handle),
           &buf, 1, OnWrite);

  // Reset client state for potential keep-alive
  client->recv_buffer.clear();
  client->last_parse_len = 0;
  client->headers_len = 0;
  client->content_length = 0;
  client->headers_complete = false;
}

bool MockHttp1Server::ParseRequest(const std::string& data,
                                   ReceivedRequest* request) {
  const char* method;
  size_t method_len;
  const char* path;
  size_t path_len;
  int minor_version;
  struct phr_header headers[100];
  size_t num_headers = 100;

  int pret =
      phr_parse_request(data.c_str(), data.size(), &method, &method_len, &path,
                        &path_len, &minor_version, headers, &num_headers, 0);

  if (pret <= 0) {
    // Parse error or incomplete request
    return false;
  }

  // Extract parsed values
  request->method = std::string(method, method_len);
  request->path = std::string(path, path_len);
  request->http_version = "HTTP/1." + std::to_string(minor_version);

  // Copy headers
  request->headers.clear();
  for (size_t i = 0; i < num_headers; ++i) {
    request->headers.emplace_back(
        std::string(headers[i].name, headers[i].name_len),
        std::string(headers[i].value, headers[i].value_len));
  }

  // Extract body (data after headers)
  request->body = data.substr(static_cast<size_t>(pret));

  return true;
}

std::string MockHttp1Server::BuildResponse() {
  std::ostringstream oss;
  oss << "HTTP/1.1 " << response_.status_code << " " << response_.status_text
      << "\r\n";

  // Add Content-Length if not present
  bool has_content_length = false;
  for (const auto& h : response_.headers) {
    oss << h.first << ": " << h.second << "\r\n";
    if (h.first == "Content-Length") {
      has_content_length = true;
    }
  }

  if (!has_content_length) {
    oss << "Content-Length: " << response_.body.size() << "\r\n";
  }

  oss << "\r\n";
  oss << response_.body;

  return oss.str();
}

std::string MockHttp1Server::BuildChunkedResponse() {
  std::ostringstream oss;
  oss << "HTTP/1.1 " << response_.status_code << " " << response_.status_text
      << "\r\n";

  for (const auto& h : response_.headers) {
    oss << h.first << ": " << h.second << "\r\n";
  }
  oss << "Transfer-Encoding: chunked\r\n";
  oss << "\r\n";

  for (const auto& chunk : chunks_) {
    oss << std::hex << chunk.size() << "\r\n";
    oss << chunk << "\r\n";
  }
  oss << "0\r\n\r\n";

  return oss.str();
}

void MockHttp1Server::OnWrite(uv_write_t* req, int /*status*/) {
  auto* write_data = static_cast<WriteData*>(req->data);
  delete write_data;
}

void MockHttp1Server::OnClose(uv_handle_t* handle) {
  auto* client = static_cast<ClientConnection*>(handle->data);
  auto* server = client->server;

  // Remove from clients list
  auto it = std::find_if(server->clients_.begin(), server->clients_.end(),
                         [client](const std::unique_ptr<ClientConnection>& c) {
                           return c.get() == client;
                         });
  if (it != server->clients_.end()) {
    server->clients_.erase(it);
  }
}

void MockHttp1Server::OnServerClose(uv_handle_t* /*handle*/) {
  // Server closed
}

// ============================================================================
// MockHttp2Server - Placeholder implementation
// ============================================================================

struct MockHttp2Server::Impl {
  // TODO: nghttp2 server session
};

MockHttp2Server::MockHttp2Server(core::Reactor* reactor) : reactor_(reactor) {}

MockHttp2Server::~MockHttp2Server() {
  if (running_) {
    Stop();
  }
}

uint16_t MockHttp2Server::Start() {
  // TODO: Implement HTTP/2 server with TLS and nghttp2
  running_ = true;
  port_ = 0;
  return port_;
}

void MockHttp2Server::Stop() { running_ = false; }

void MockHttp2Server::SetResponse(
    int status, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers) {
  response_.status_code = status;
  response_.body = body;
  response_.headers = headers;
}

void MockHttp2Server::SendGoaway(uint32_t /*error_code*/) {
  // TODO: Send GOAWAY frame
}

// ============================================================================
// MockHttp3Server - Placeholder implementation
// ============================================================================

#if defined(HOLYTLS_BUILD_QUIC)
struct MockHttp3Server::Impl {
  // TODO: ngtcp2 + nghttp3 server
};

MockHttp3Server::MockHttp3Server(core::Reactor* reactor) : reactor_(reactor) {}

MockHttp3Server::~MockHttp3Server() {
  if (running_) {
    Stop();
  }
}

uint16_t MockHttp3Server::Start() {
  // TODO: Implement HTTP/3 server with QUIC
  running_ = true;
  port_ = 0;
  return port_;
}

void MockHttp3Server::Stop() { running_ = false; }

void MockHttp3Server::SetResponse(
    int status, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers) {
  response_.status_code = status;
  response_.body = body;
  response_.headers = headers;
}
#endif  // HOLYTLS_BUILD_QUIC

}  // namespace test
}  // namespace holytls

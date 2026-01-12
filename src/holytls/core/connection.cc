// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/core/connection.h"

#include <cstring>
#include <unordered_map>

#include "holytls/http2/chrome_h2_profile.h"
#include "holytls/http2/chrome_header_profile.h"
#include "holytls/http2/header_ids.h"
#include "holytls/util/async_decompressor.h"
#include "holytls/util/decompressor.h"

#include "holytls/util/platform.h"
#include "holytls/util/socket_utils.h"

namespace holytls {
namespace core {

Connection::Connection(Reactor* reactor, tls::TlsContextFactory* tls_factory,
                       const std::string& host, uint16_t port,
                       const ConnectionOptions& options)
    : reactor_(reactor),
      tls_factory_(tls_factory),
      host_(host),
      port_(port),
      options_(options) {}

Connection::~Connection() { Close(); }

bool Connection::Connect(std::string_view ip, bool ipv6) {
  // Create socket
  fd_ = util::CreateTcpSocket(ipv6);
  if (fd_ == util::kInvalidSocket) {
    SetError("Failed to create socket");
    return false;
  }

  util::ConfigureSocket(fd_);

  // Start non-blocking connect
  int ret = util::ConnectNonBlocking(fd_, ip, port_, ipv6);
  if (ret < 0) {
    SetError("Connect failed: " + util::GetLastSocketErrorString());
    util::CloseSocket(fd_);
    fd_ = util::kInvalidSocket;
    return false;
  }

  state_ = ConnectionState::kConnecting;

  // Register with reactor - watch for writable to know when connect completes
  // On Windows, AFD_POLL may need both read+write to properly detect connect
  // completion
#ifdef _WIN32
  if (!reactor_->Add(this, EventType::kReadWrite)) {
#else
  if (!reactor_->Add(this, EventType::kWrite)) {
#endif
    SetError("Failed to register with reactor");
    util::CloseSocket(fd_);
    fd_ = util::kInvalidSocket;
    state_ = ConnectionState::kError;
    return false;
  }

  // If connect completed immediately (localhost), handle it
  if (ret == 0) {
    HandleConnecting();
  }

  return true;
}

void Connection::SendRequest(
    const std::string& method, const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::span<const std::string_view> header_order,
    ResponseCallback on_response, ErrorCallback on_error) {
  if (state_ == ConnectionState::kConnected && CanSubmitRequest()) {
    // Connection ready, submit request immediately
    http2::H2Headers h2_headers;
    h2_headers.method = method;
    h2_headers.scheme = "https";
    h2_headers.authority = host_;
    h2_headers.path = path;

    if (!header_order.empty()) {
      // Full control mode: user specifies exact header order
      // Build a map for O(1) lookup
      std::unordered_map<std::string_view, std::string_view> header_map;
      for (const auto& [name, value] : headers) {
        header_map[name] = value;
      }

      // Add headers in specified order
      for (const auto& name : header_order) {
        auto it = header_map.find(name);
        if (it != header_map.end()) {
          h2_headers.Add(std::string(it->first), std::string(it->second));
          header_map.erase(it);
        }
      }

      // Append any remaining headers not in order list
      for (const auto& [name, value] : header_map) {
        h2_headers.Add(std::string(name), std::string(value));
      }
    } else {
      // Auto mode: use Chrome header profile
      auto chrome_version = tls_factory_->chrome_version();
      const auto& header_profile = http2::GetChromeHeaderProfile(chrome_version);

      // Determine request type and fetch metadata
      http2::RequestType request_type = http2::RequestType::kNavigation;
      http2::FetchSite fetch_site = http2::FetchSite::kNone;
      http2::FetchMode fetch_mode = http2::FetchMode::kNavigate;
      http2::FetchDest fetch_dest = http2::FetchDest::kDocument;
      bool user_activated = true;

      // Convert user headers to HeaderEntry format for custom overrides
      std::vector<http2::HeaderEntry> custom_headers;
      for (const auto& [name, value] : headers) {
        custom_headers.push_back({name, value});
      }

      // Build ordered Chrome headers with GREASE sec-ch-ua
      auto chrome_headers = http2::BuildChromeHeaders(
          header_profile, request_type, fetch_site, fetch_mode, fetch_dest,
          user_activated, custom_headers);

      // Add all headers in Chrome's exact order
      for (const auto& header : chrome_headers) {
        h2_headers.Add(header.name, header.value);
      }
    }

    http2::H2StreamCallbacks stream_callbacks;
    int32_t stream_id = -1;

    stream_callbacks.on_headers =
        [this](int32_t sid, const http2::PackedHeaders& resp_headers) {
          auto it = active_requests_.find(sid);
          if (it != active_requests_.end()) {
            it->second.headers = resp_headers;
            it->second.status_code = resp_headers.status_code();
          }
        };

    stream_callbacks.on_data = [this](int32_t sid, const uint8_t* data,
                                      size_t len) {
      auto it = active_requests_.find(sid);
      if (it != active_requests_.end()) {
        // O(1) amortized append instead of O(n) vector insert
        it->second.body_buffer.Append(data, len);
      }
    };

    stream_callbacks.on_close = [this](int32_t sid, uint32_t error_code) {
      auto it = active_requests_.find(sid);
      if (it != active_requests_.end()) {
        if (error_code == 0 && it->second.on_response) {
          // Build Response from ActiveRequest
          Response response;
          response.status_code = it->second.status_code;
          response.headers = std::move(it->second.headers);

          // Copy body from IoBuffer to vector (single allocation + copy)
          size_t body_size = it->second.body_buffer.Size();
          if (body_size > 0) {
            response.body.resize(body_size);
            it->second.body_buffer.Read(response.body.data(), body_size);
          }

          // Decompress response body if enabled and Content-Encoding header is
          // present
          if (options_.auto_decompress) {
            auto encoding_str =
                response.headers.Get(http2::HeaderId::kContentEncoding);
            auto encoding = util::ParseContentEncoding(encoding_str);

            if (encoding != util::ContentEncoding::kIdentity &&
                encoding != util::ContentEncoding::kUnknown &&
                !response.body.empty()) {
              // Capture callback and response for async completion
              auto response_cb = std::move(it->second.on_response);
              auto resp = std::move(response);

              // Erase request before async work to avoid iterator invalidation
              active_requests_.erase(it);

              // Check idle state now (before async work)
              bool should_notify_idle =
                  active_requests_.empty() && pending_requests_.empty();
              auto idle_cb = idle_callback;
              Connection* self = this;

              // Queue async decompression - runs on thread pool
              // Extract body before creating lambda to avoid move-order issues
              auto compressed_body = std::move(resp.body);
              util::DecompressAsync(
                  reactor_->loop(), encoding, std::move(compressed_body),
                  [response_cb = std::move(response_cb), resp = std::move(resp),
                   should_notify_idle, idle_cb,
                   self](std::vector<uint8_t> result_body, bool /* success */,
                         const std::string& /* error */) mutable {
                    // On success: result_body is decompressed data
                    // On failure: result_body is original compressed data
                    resp.body = std::move(result_body);
                    response_cb(resp);

                    // Notify idle after response delivered
                    if (should_notify_idle && idle_cb) {
                      idle_cb(self);
                    }
                  });
              return;  // Response delivered async
            }
          }

          it->second.on_response(response);
        } else if (error_code != 0 && it->second.on_error) {
          it->second.on_error("Stream error: " + std::to_string(error_code));
        }
        active_requests_.erase(it);

        // Notify pool/owner that connection is now idle
        if (active_requests_.empty() && pending_requests_.empty()) {
          if (idle_callback) {
            idle_callback(this);
          }
        }
      }
    };

    // Submit to appropriate session
    if (h2_) {
      stream_id = h2_->SubmitRequest(h2_headers, stream_callbacks);
    } else if (h1_) {
      stream_id = h1_->SubmitRequest(h2_headers, stream_callbacks, header_order);
    }
    if (stream_id < 0) {
      if (on_error) {
        on_error("Failed to submit request");
      }
      return;
    }

    // Store active request
    ActiveRequest active;
    active.on_response = on_response;
    active.on_error = on_error;
    active_requests_[stream_id] = std::move(active);

    // Flush send buffer
    FlushSendBuffer();
  } else {
    // Queue request for when connection is ready
    // Copy header_order span to vector for storage
    std::vector<std::string_view> order_copy(header_order.begin(),
                                              header_order.end());
    pending_requests_.push_back(
        {method, path, headers, std::move(order_copy), on_response, on_error});
  }
}

void Connection::Close() {
  if (fd_ != util::kInvalidSocket) {
    reactor_->Remove(this);
    if (tls_) {
      tls_->Shutdown();
    }
    util::CloseSocket(fd_);
    fd_ = util::kInvalidSocket;
  }
  state_ = ConnectionState::kClosed;
  h2_.reset();
  h1_.reset();
  tls_.reset();
}

void Connection::OnReadable() {
  switch (state_) {
    case ConnectionState::kConnecting:
      // On Windows, readable during connect means we should check connection
      // status
      HandleConnecting();
      break;
    case ConnectionState::kTlsHandshake:
      HandleTlsHandshake();
      break;
    case ConnectionState::kConnected:
      HandleConnected();
      break;
    default:
      break;
  }
}

void Connection::OnWritable() {
  switch (state_) {
    case ConnectionState::kConnecting:
      HandleConnecting();
      break;
    case ConnectionState::kTlsHandshake:
      HandleTlsHandshake();
      break;
    case ConnectionState::kConnected:
      FlushSendBuffer();
      break;
    default:
      break;
  }
}

void Connection::OnError(int error_code) {
  SetError("Socket error: " + std::to_string(error_code));
  state_ = ConnectionState::kError;
  Close();

  // Notify pending requests
  for (auto& req : pending_requests_) {
    if (req.on_error) {
      req.on_error(last_error_);
    }
  }
  pending_requests_.clear();

  // Notify active requests
  for (auto& [sid, req] : active_requests_) {
    if (req.on_error) {
      req.on_error(last_error_);
    }
  }
  active_requests_.clear();

  reactor_->Stop();
}

void Connection::OnClose() {
  Close();
  reactor_->Stop();
}

void Connection::HandleConnecting() {
  // Check if connect completed
  if (!util::IsConnected(fd_)) {
    SetError("Connection failed: " + util::GetLastSocketErrorString());
    state_ = ConnectionState::kError;
    Close();
    reactor_->Stop();
    return;
  }

  // TCP connected, start TLS handshake
  tls_ = std::make_unique<tls::TlsConnection>(tls_factory_, fd_, host_, port_);
  state_ = ConnectionState::kTlsHandshake;

  // Update reactor to watch for read and write
  reactor_->Modify(this, EventType::kReadWrite);

  // Start handshake
  HandleTlsHandshake();
}

void Connection::HandleTlsHandshake() {
  tls::TlsResult result = tls_->DoHandshake();

  switch (result) {
    case tls::TlsResult::kOk: {
      // Handshake complete
      state_ = ConnectionState::kConnected;

      // Check ALPN protocol to determine HTTP version
      std::string_view protocol = tls_->AlpnProtocol();

      // Use HTTP/2 if negotiated, or if ALPN empty and not forcing HTTP/1.1
      bool use_http2 = (protocol == "h2") ||
                       (protocol.empty() && !tls_factory_->force_http1());
      if (use_http2) {
        // HTTP/2 (default if no ALPN or h2 negotiated)
        auto chrome_version = tls_factory_->chrome_version();
        const auto& h2_profile = http2::GetChromeH2Profile(chrome_version);

        http2::H2SessionCallbacks session_callbacks;
        session_callbacks.on_error = [this](int code, const std::string& msg) {
          SetError("H2 error " + std::to_string(code) + ": " + msg);
        };
        session_callbacks.on_goaway = [this](int32_t last_sid, uint32_t code) {
          if (code != 0) {
            SetError("GOAWAY received with error: " + std::to_string(code));
          }
        };

        h2_ = std::make_unique<http2::H2Session>(h2_profile, session_callbacks);
        if (!h2_->Initialize()) {
          SetError("Failed to initialize H2 session");
          state_ = ConnectionState::kError;
          Close();
          reactor_->Stop();
          return;
        }
      } else {
        // HTTP/1.1
        http1::H1Session::SessionCallbacks session_callbacks;
        session_callbacks.on_error = [this](int code, const std::string& msg) {
          SetError("H1 error " + std::to_string(code) + ": " + msg);
        };

        h1_ = std::make_unique<http1::H1Session>(session_callbacks);
        if (!h1_->Initialize()) {
          SetError("Failed to initialize H1 session");
          state_ = ConnectionState::kError;
          Close();
          reactor_->Stop();
          return;
        }
      }

      // Flush connection preface (for HTTP/2) or nothing (for HTTP/1.1)
      FlushSendBuffer();

      // Submit pending requests
      for (auto& req : pending_requests_) {
        SendRequest(req.method, req.path, req.headers, req.header_order,
                    req.on_response, req.on_error);
      }
      pending_requests_.clear();
      break;
    }

    case tls::TlsResult::kWantRead:
      reactor_->Modify(this, EventType::kRead);
      break;

    case tls::TlsResult::kWantWrite:
      reactor_->Modify(this, EventType::kWrite);
      break;

    case tls::TlsResult::kError:
      SetError("TLS handshake failed: " + tls_->last_error());
      state_ = ConnectionState::kError;
      Close();
      reactor_->Stop();
      break;

    default:
      break;
  }
}

void Connection::HandleConnected() {
  // Read decrypted data from TLS
  // Limit iterations to prevent starving other connections with large responses
  constexpr int kMaxReadsPerCallback = 4;  // ~64KB max per callback
  uint8_t buf[16384];
  tls::TlsResult result;
  int reads = 0;

  while (reads < kMaxReadsPerCallback) {
    ssize_t n = tls_->ReadRaw(buf, sizeof(buf), &result);

    if (n > 0) {
      ++reads;
      // Feed data to HTTP session (h2 or h1)
      ssize_t consumed = -1;
      if (h2_) {
        consumed = h2_->Receive(buf, static_cast<size_t>(n));
      } else if (h1_) {
        consumed = h1_->Receive(buf, static_cast<size_t>(n));
      }
      if (consumed < 0) {
        SetError(h2_ ? "H2 receive error" : "H1 receive error");
        state_ = ConnectionState::kError;
        Close();
        reactor_->Stop();
        return;
      }

      // Send any pending data
      FlushSendBuffer();
    } else if (result == tls::TlsResult::kWantRead) {
      // Need more data from socket
      break;
    } else if (result == tls::TlsResult::kEof) {
      // Connection closed
      Close();
      reactor_->Stop();
      return;
    } else if (result == tls::TlsResult::kError) {
      SetError("TLS read error: " + tls_->last_error());
      state_ = ConnectionState::kError;
      Close();
      reactor_->Stop();
      return;
    } else {
      break;
    }
  }
  // If we hit the limit, the socket will still be readable and we'll be called
  // again on the next event loop iteration, allowing other connections to run.
}

void Connection::FlushSendBuffer() {
  if (!tls_ || (!h2_ && !h1_)) {
    return;
  }

  // Helper to check if session wants to write
  auto wants_write = [this]() {
    return (h2_ && h2_->WantsWrite()) || (h1_ && h1_->WantsWrite());
  };

  // Helper to get pending data
  auto get_pending = [this]() -> std::pair<const uint8_t*, size_t> {
    if (h2_) return h2_->GetPendingData();
    if (h1_) return h1_->GetPendingData();
    return {nullptr, 0};
  };

  // Helper to mark data as sent
  auto data_sent = [this](size_t len) {
    if (h2_) h2_->DataSent(len);
    else if (h1_) h1_->DataSent(len);
  };

  // Limit write iterations to prevent blocking on large sends
  constexpr int kMaxWritesPerFlush = 4;
  int writes = 0;

  while (wants_write() && writes < kMaxWritesPerFlush) {
    auto [data, len] = get_pending();
    if (len == 0) {
      break;
    }

    size_t written = 0;
    tls::TlsResult result = tls_->Write(data, len, &written);

    if (written > 0) {
      data_sent(written);
      ++writes;
    }

    if (result == tls::TlsResult::kWantWrite) {
      reactor_->Modify(this, EventType::kReadWrite);
      break;
    } else if (result == tls::TlsResult::kError) {
      SetError("TLS write error");
      break;
    }
  }

  // If we have more data but hit the limit, ensure we stay armed for write
  if (wants_write() && writes >= kMaxWritesPerFlush) {
    reactor_->Modify(this, EventType::kReadWrite);
  }
}

void Connection::SetError(const std::string& msg) {
  last_error_ = msg;
  state_ = ConnectionState::kError;
}

}  // namespace core
}  // namespace holytls

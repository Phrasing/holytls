// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "core/connection.h"

#include <cerrno>
#include <cstring>

#include "http2/chrome_h2_profile.h"
#include "util/socket_utils.h"

namespace chad {
namespace core {

Connection::Connection(Reactor* reactor, tls::TlsContextFactory* tls_factory,
                       const std::string& host, uint16_t port)
    : reactor_(reactor),
      tls_factory_(tls_factory),
      host_(host),
      port_(port) {}

Connection::~Connection() {
  Close();
}

bool Connection::Connect(const std::string& ip, bool ipv6) {
  // Create socket
  fd_ = util::CreateTcpSocket(ipv6);
  if (fd_ < 0) {
    SetError("Failed to create socket");
    return false;
  }

  util::ConfigureSocket(fd_);

  // Start non-blocking connect
  int ret = util::ConnectNonBlocking(fd_, ip, port_, ipv6);
  if (ret < 0) {
    SetError("Connect failed: " + std::string(std::strerror(errno)));
    util::CloseSocket(fd_);
    fd_ = -1;
    return false;
  }

  state_ = ConnectionState::kConnecting;

  // Register with reactor - watch for writable to know when connect completes
  if (!reactor_->Add(this, EventType::kWrite)) {
    SetError("Failed to register with reactor");
    util::CloseSocket(fd_);
    fd_ = -1;
    state_ = ConnectionState::kError;
    return false;
  }

  // If connect completed immediately (localhost), handle it
  if (ret == 0) {
    HandleConnecting();
  }

  return true;
}

void Connection::SendRequest(const std::string& method, const std::string& path,
                             const std::vector<std::pair<std::string, std::string>>& headers,
                             ResponseCallback on_response, ErrorCallback on_error) {
  if (state_ == ConnectionState::kConnected && h2_) {
    // Connection ready, submit request immediately
    http2::H2Headers h2_headers;
    h2_headers.method = method;
    h2_headers.scheme = "https";
    h2_headers.authority = host_;
    h2_headers.path = path;

    for (const auto& [name, value] : headers) {
      h2_headers.Add(name, value);
    }

    http2::H2StreamCallbacks stream_callbacks;
    int32_t stream_id = -1;

    stream_callbacks.on_headers = [this, stream_id](int32_t sid, const http2::PackedHeaders& resp_headers) {
      auto it = active_requests_.find(sid);
      if (it != active_requests_.end()) {
        it->second.response.headers = resp_headers;
        it->second.response.status_code = resp_headers.status_code();
      }
    };

    stream_callbacks.on_data = [this](int32_t sid, const uint8_t* data, size_t len) {
      auto it = active_requests_.find(sid);
      if (it != active_requests_.end()) {
        it->second.response.body.insert(it->second.response.body.end(), data, data + len);
      }
    };

    stream_callbacks.on_close = [this](int32_t sid, uint32_t error_code) {
      auto it = active_requests_.find(sid);
      if (it != active_requests_.end()) {
        if (error_code == 0 && it->second.on_response) {
          it->second.on_response(it->second.response);
        } else if (error_code != 0 && it->second.on_error) {
          it->second.on_error("Stream error: " + std::to_string(error_code));
        }
        active_requests_.erase(it);

        // If no more active requests, stop the reactor
        if (active_requests_.empty() && pending_requests_.empty()) {
          reactor_->Stop();
        }
      }
    };

    stream_id = h2_->SubmitRequest(h2_headers, stream_callbacks);
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
    pending_requests_.push_back({method, path, headers, on_response, on_error});
  }
}

void Connection::Close() {
  if (fd_ >= 0) {
    reactor_->Remove(this);
    if (tls_) {
      tls_->Shutdown();
    }
    util::CloseSocket(fd_);
    fd_ = -1;
  }
  state_ = ConnectionState::kClosed;
  h2_.reset();
  tls_.reset();
}

void Connection::OnReadable() {
  switch (state_) {
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
    SetError("Connection failed: " + std::string(std::strerror(errno)));
    state_ = ConnectionState::kError;
    Close();
    reactor_->Stop();
    return;
  }

  // TCP connected, start TLS handshake
  tls_ = std::make_unique<tls::TlsConnection>(tls_factory_, fd_, host_);
  state_ = ConnectionState::kTlsHandshake;

  // Update reactor to watch for read and write
  reactor_->Modify(this, EventType::kReadWrite);

  // Start handshake
  HandleTlsHandshake();
}

void Connection::HandleTlsHandshake() {
  tls::TlsResult result = tls_->DoHandshake();

  switch (result) {
    case tls::TlsResult::kOk:
      // Handshake complete
      state_ = ConnectionState::kConnected;

      // Initialize HTTP/2 session
      {
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
      }

      // Flush connection preface
      FlushSendBuffer();

      // Submit pending requests
      for (auto& req : pending_requests_) {
        SendRequest(req.method, req.path, req.headers, req.on_response, req.on_error);
      }
      pending_requests_.clear();
      break;

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
  uint8_t buf[16384];
  tls::TlsResult result;

  while (true) {
    ssize_t n = tls_->ReadRaw(buf, sizeof(buf), &result);

    if (n > 0) {
      // Feed data to HTTP/2 session
      ssize_t consumed = h2_->Receive(buf, static_cast<size_t>(n));
      if (consumed < 0) {
        SetError("H2 receive error");
        state_ = ConnectionState::kError;
        Close();
        reactor_->Stop();
        return;
      }

      // Send any pending data
      FlushSendBuffer();
    } else if (result == tls::TlsResult::kWantRead) {
      // Need more data
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
}

void Connection::FlushSendBuffer() {
  if (!h2_ || !tls_) {
    return;
  }

  while (h2_->WantsWrite()) {
    auto [data, len] = h2_->GetPendingData();
    if (len == 0) {
      break;
    }

    size_t written = 0;
    tls::TlsResult result = tls_->Write(data, len, &written);

    if (written > 0) {
      h2_->DataSent(written);
    }

    if (result == tls::TlsResult::kWantWrite) {
      reactor_->Modify(this, EventType::kReadWrite);
      break;
    } else if (result == tls::TlsResult::kError) {
      SetError("TLS write error");
      break;
    }
  }
}

void Connection::SetError(const std::string& msg) {
  last_error_ = msg;
  state_ = ConnectionState::kError;
}

}  // namespace core
}  // namespace chad

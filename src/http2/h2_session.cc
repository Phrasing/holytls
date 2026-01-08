// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "http2/h2_session.h"

#include <cstring>

namespace chad {
namespace http2 {

namespace {

// Helper to create nghttp2_nv from strings
nghttp2_nv MakeNv(const std::string& name, const std::string& value,
                  uint8_t flags = NGHTTP2_NV_FLAG_NONE) {
  nghttp2_nv nv;
  nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
  nv.namelen = name.size();
  nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
  nv.valuelen = value.size();
  nv.flags = flags;
  return nv;
}

}  // namespace

H2Session::H2Session(const ChromeH2Profile& profile,
                     H2SessionCallbacks callbacks)
    : profile_(profile), callbacks_(std::move(callbacks)) {}

H2Session::~H2Session() = default;

bool H2Session::Initialize() {
  // Create nghttp2 callbacks
  nghttp2_session_callbacks* callbacks;
  if (nghttp2_session_callbacks_new(&callbacks) != 0) {
    SetError("Failed to create nghttp2 callbacks");
    return false;
  }

  // Set callbacks
  nghttp2_session_callbacks_set_send_callback(callbacks, OnSendCallback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       OnFrameRecvCallback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, OnDataChunkRecvCallback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                         OnStreamCloseCallback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, OnHeaderCallback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, OnBeginHeadersCallback);

  // Create client session
  nghttp2_session* session_raw;
  int rv = nghttp2_session_client_new(&session_raw, callbacks, this);
  nghttp2_session_callbacks_del(callbacks);

  if (rv != 0) {
    SetError("Failed to create nghttp2 session");
    return false;
  }

  session_.reset(session_raw);

  // Send connection preface with Chrome-matching SETTINGS
  SendChromeSettings();

  // Send WINDOW_UPDATE to match Chrome's flow control
  SendChromeWindowUpdate();

  return true;
}

int32_t H2Session::SubmitRequest(const H2Headers& headers,
                                 H2StreamCallbacks stream_callbacks,
                                 const uint8_t* body, size_t body_len) {
  if (!session_ || fatal_error_) {
    return -1;
  }

  // Build header array with Chrome's pseudo-header ordering
  std::vector<nghttp2_nv> nva = BuildHeaderNvArray(headers);

  // Data provider for request body (if any)
  nghttp2_data_provider* data_prd = nullptr;
  nghttp2_data_provider data_prd_storage;

  if (body != nullptr && body_len > 0) {
    // For simplicity, we don't support streaming body yet
    // In production, implement a proper data provider
    data_prd = &data_prd_storage;
    // TODO: Implement body streaming
  }

  // Submit request
  int32_t stream_id = nghttp2_submit_request(session_.get(), nullptr, nva.data(),
                                             nva.size(), data_prd, nullptr);

  if (stream_id < 0) {
    SetError(std::string("Failed to submit request: ") +
             nghttp2_strerror(stream_id));
    return -1;
  }

  // Create stream object
  auto stream =
      std::make_unique<H2Stream>(stream_id, std::move(stream_callbacks));
  streams_[stream_id] = std::move(stream);

  // Mark local side closed (we're not sending body in this simple impl)
  streams_[stream_id]->MarkLocalClosed();

  return stream_id;
}

ssize_t H2Session::Receive(const uint8_t* data, size_t len) {
  if (!session_ || fatal_error_) {
    return -1;
  }

  ssize_t rv = nghttp2_session_mem_recv(session_.get(), data, len);

  if (rv < 0) {
    SetError(std::string("nghttp2_session_mem_recv failed: ") +
             nghttp2_strerror(static_cast<int>(rv)));
    return -1;
  }

  return rv;
}

std::pair<const uint8_t*, size_t> H2Session::GetPendingData() {
  // First, pump nghttp2 to generate output
  while (nghttp2_session_want_write(session_.get()) != 0) {
    const uint8_t* data;
    ssize_t len = nghttp2_session_mem_send(session_.get(), &data);

    if (len < 0) {
      SetError(std::string("nghttp2_session_mem_send failed: ") +
               nghttp2_strerror(static_cast<int>(len)));
      break;
    }

    if (len == 0) {
      break;
    }

    // Append to send buffer
    send_buffer_.Append(data, static_cast<size_t>(len));
  }

  // Return buffered data
  size_t available;
  const uint8_t* ptr = send_buffer_.Peek(&available);
  return {ptr, available};
}

void H2Session::DataSent(size_t len) {
  send_buffer_.Skip(len);
}

bool H2Session::WantsWrite() const {
  if (!session_ || fatal_error_) {
    return false;
  }

  return send_buffer_.Size() > 0 ||
         nghttp2_session_want_write(session_.get()) != 0;
}

bool H2Session::CanSubmitRequest() const {
  if (!session_ || fatal_error_) {
    return false;
  }

  return nghttp2_session_check_request_allowed(session_.get()) != 0;
}

H2Stream* H2Session::GetStream(int32_t stream_id) {
  auto it = streams_.find(stream_id);
  if (it == streams_.end()) {
    return nullptr;
  }
  return it->second.get();
}

// Static callbacks

ssize_t H2Session::OnSendCallback(nghttp2_session* /*session*/,
                                  const uint8_t* data, size_t length,
                                  int /*flags*/, void* user_data) {
  auto* self = static_cast<H2Session*>(user_data);
  return self->HandleSend(data, length);
}

int H2Session::OnFrameRecvCallback(nghttp2_session* /*session*/,
                                   const nghttp2_frame* frame,
                                   void* user_data) {
  auto* self = static_cast<H2Session*>(user_data);
  return self->HandleFrameRecv(frame);
}

int H2Session::OnDataChunkRecvCallback(nghttp2_session* /*session*/,
                                       uint8_t /*flags*/, int32_t stream_id,
                                       const uint8_t* data, size_t len,
                                       void* user_data) {
  auto* self = static_cast<H2Session*>(user_data);
  return self->HandleDataChunkRecv(stream_id, data, len);
}

int H2Session::OnStreamCloseCallback(nghttp2_session* /*session*/,
                                     int32_t stream_id, uint32_t error_code,
                                     void* user_data) {
  auto* self = static_cast<H2Session*>(user_data);
  return self->HandleStreamClose(stream_id, error_code);
}

int H2Session::OnHeaderCallback(nghttp2_session* /*session*/,
                                const nghttp2_frame* frame, const uint8_t* name,
                                size_t namelen, const uint8_t* value,
                                size_t valuelen, uint8_t /*flags*/,
                                void* user_data) {
  auto* self = static_cast<H2Session*>(user_data);
  return self->HandleHeader(frame, name, namelen, value, valuelen);
}

int H2Session::OnBeginHeadersCallback(nghttp2_session* /*session*/,
                                      const nghttp2_frame* frame,
                                      void* user_data) {
  auto* self = static_cast<H2Session*>(user_data);
  return self->HandleBeginHeaders(frame);
}

// Instance handlers

ssize_t H2Session::HandleSend(const uint8_t* data, size_t length) {
  // Buffer the data
  send_buffer_.Append(data, length);
  return static_cast<ssize_t>(length);
}

int H2Session::HandleFrameRecv(const nghttp2_frame* frame) {
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
        // Headers complete, deliver to stream
        int32_t stream_id = frame->hd.stream_id;
        auto pending_it = pending_headers_.find(stream_id);
        if (pending_it != pending_headers_.end()) {
          auto stream = GetStream(stream_id);
          if (stream != nullptr) {
            stream->OnHeadersReceived(pending_it->second);
          }
          pending_headers_.erase(pending_it);
        }
      }
      break;

    case NGHTTP2_GOAWAY:
      if (callbacks_.on_goaway) {
        callbacks_.on_goaway(frame->goaway.last_stream_id,
                             frame->goaway.error_code);
      }
      break;

    default:
      break;
  }

  return 0;
}

int H2Session::HandleDataChunkRecv(int32_t stream_id, const uint8_t* data,
                                   size_t len) {
  auto stream = GetStream(stream_id);
  if (stream != nullptr) {
    stream->OnDataReceived(data, len);
  }
  return 0;
}

int H2Session::HandleStreamClose(int32_t stream_id, uint32_t error_code) {
  auto it = streams_.find(stream_id);
  if (it != streams_.end()) {
    it->second->OnStreamClose(error_code);
    streams_.erase(it);
  }
  return 0;
}

int H2Session::HandleHeader(const nghttp2_frame* frame, const uint8_t* name,
                            size_t namelen, const uint8_t* value,
                            size_t valuelen) {
  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  int32_t stream_id = frame->hd.stream_id;
  std::string header_name(reinterpret_cast<const char*>(name), namelen);
  std::string header_value(reinterpret_cast<const char*>(value), valuelen);

  auto& headers = pending_headers_[stream_id];

  // Handle pseudo-headers
  if (header_name == ":status") {
    headers.status = header_value;
  } else if (header_name[0] != ':') {
    // Regular header
    headers.Add(header_name, header_value);
  }

  return 0;
}

int H2Session::HandleBeginHeaders(const nghttp2_frame* frame) {
  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  // Initialize pending headers for this stream
  pending_headers_[frame->hd.stream_id] = H2Headers{};
  return 0;
}

void H2Session::SendChromeSettings() {
  const auto& s = profile_.settings;

  // Build SETTINGS entries matching Chrome's order
  // Chrome 143+ sends only 4 settings (omits MAX_CONCURRENT_STREAMS and MAX_FRAME_SIZE)
  std::vector<nghttp2_settings_entry> iv;

  iv.push_back({NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, s.header_table_size});
  iv.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, s.enable_push});

  if (s.send_max_concurrent_streams) {
    iv.push_back(
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, s.max_concurrent_streams});
  }

  iv.push_back({NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, s.initial_window_size});

  if (s.send_max_frame_size) {
    iv.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE, s.max_frame_size});
  }

  iv.push_back({NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, s.max_header_list_size});

  int rv = nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE, iv.data(),
                                   iv.size());
  if (rv != 0) {
    SetError(std::string("Failed to submit SETTINGS: ") +
             nghttp2_strerror(rv));
  }
}

void H2Session::SendChromeWindowUpdate() {
  // Chrome sends a large WINDOW_UPDATE on connection level (stream 0)
  // to increase flow control window to ~15MB
  int rv = nghttp2_submit_window_update(
      session_.get(), NGHTTP2_FLAG_NONE, 0,
      static_cast<int32_t>(profile_.connection_window_update));
  if (rv != 0) {
    SetError(std::string("Failed to submit WINDOW_UPDATE: ") +
             nghttp2_strerror(rv));
  }
}

std::vector<nghttp2_nv> H2Session::BuildHeaderNvArray(const H2Headers& headers) {
  std::vector<nghttp2_nv> nva;
  nva.reserve(headers.headers.size() + 4);

  // Chrome's pseudo-header order: :method, :authority, :scheme, :path (MASP)
  // This is critical for HTTP/2 fingerprinting!

  switch (profile_.pseudo_header_order) {
    case ChromeH2Profile::PseudoHeaderOrder::kMASP:
      // Chrome: method, authority, scheme, path
      nva.push_back(MakeNv(":method", headers.method));
      nva.push_back(MakeNv(":authority", headers.authority));
      nva.push_back(MakeNv(":scheme", headers.scheme));
      nva.push_back(MakeNv(":path", headers.path));
      break;

    case ChromeH2Profile::PseudoHeaderOrder::kMPAS:
      // Firefox: method, path, authority, scheme
      nva.push_back(MakeNv(":method", headers.method));
      nva.push_back(MakeNv(":path", headers.path));
      nva.push_back(MakeNv(":authority", headers.authority));
      nva.push_back(MakeNv(":scheme", headers.scheme));
      break;

    case ChromeH2Profile::PseudoHeaderOrder::kMSPA:
      // Safari: method, scheme, path, authority
      nva.push_back(MakeNv(":method", headers.method));
      nva.push_back(MakeNv(":scheme", headers.scheme));
      nva.push_back(MakeNv(":path", headers.path));
      nva.push_back(MakeNv(":authority", headers.authority));
      break;
  }

  // Add regular headers
  for (const auto& header : headers.headers) {
    nva.push_back(MakeNv(header.name, header.value));
  }

  return nva;
}

void H2Session::SetError(const std::string& msg) {
  fatal_error_ = true;
  last_error_ = msg;

  if (callbacks_.on_error) {
    callbacks_.on_error(-1, msg);
  }
}

}  // namespace http2
}  // namespace chad

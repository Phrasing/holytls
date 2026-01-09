// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_HTTP2_H2_SESSION_H_
#define CHAD_HTTP2_H2_SESSION_H_

// Include platform.h first for Windows compatibility and standard types
#include "util/platform.h"

#include <nghttp2/nghttp2.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "core/io_buffer.h"
#include "http2/chrome_h2_profile.h"
#include "http2/h2_stream.h"
#include "http2/packed_headers.h"

namespace chad {
namespace http2 {

// nghttp2 session deleter
struct NgSessionDeleter {
  void operator()(nghttp2_session* session) {
    if (session != nullptr) {
      nghttp2_session_del(session);
    }
  }
};

using NgSessionPtr = std::unique_ptr<nghttp2_session, NgSessionDeleter>;

// Session-level callbacks
struct H2SessionCallbacks {
  // Called when session encounters a fatal error
  std::function<void(int error_code, const std::string& msg)> on_error;

  // Called when GOAWAY is received
  std::function<void(int32_t last_stream_id, uint32_t error_code)> on_goaway;
};

// HTTP/2 session wrapper with Chrome fingerprint impersonation.
// Manages nghttp2 session and multiple streams.
class H2Session {
 public:
  H2Session(const ChromeH2Profile& profile, H2SessionCallbacks callbacks);
  ~H2Session();

  // Non-copyable, non-movable
  H2Session(const H2Session&) = delete;
  H2Session& operator=(const H2Session&) = delete;
  H2Session(H2Session&&) = delete;
  H2Session& operator=(H2Session&&) = delete;

  // Initialize session and prepare connection preface.
  // Must be called before any other operations.
  // The preface data will be available via GetPendingData().
  bool Initialize();

  // Submit a request.
  // Returns stream ID on success, -1 on error.
  int32_t SubmitRequest(const H2Headers& headers,
                        H2StreamCallbacks stream_callbacks,
                        const uint8_t* body = nullptr, size_t body_len = 0);

  // Feed received data into the session (from TLS layer).
  // Returns bytes consumed, or -1 on error.
  ssize_t Receive(const uint8_t* data, size_t len);

  // Get data to send (to TLS layer).
  // Returns pointer and size of pending data.
  // Data is valid until next call to GetPendingData() or DataSent().
  std::pair<const uint8_t*, size_t> GetPendingData();

  // Mark data as sent.
  // Call after successfully sending data from GetPendingData().
  void DataSent(size_t len);

  // Check if session has data to send
  bool WantsWrite() const;

  // Check if session can accept more requests
  bool CanSubmitRequest() const;

  // Get a stream by ID
  H2Stream* GetStream(int32_t stream_id);

  // Number of active streams
  size_t ActiveStreamCount() const { return streams_.size(); }

  // Check if session is still usable
  bool IsAlive() const { return !fatal_error_; }

  // Get the last error message
  const std::string& last_error() const { return last_error_; }

 private:
  // nghttp2 callbacks (static, forward to instance via user_data)
  static ssize_t OnSendCallback(nghttp2_session* session, const uint8_t* data,
                                size_t length, int flags, void* user_data);

  static int OnFrameRecvCallback(nghttp2_session* session,
                                 const nghttp2_frame* frame, void* user_data);

  static int OnDataChunkRecvCallback(nghttp2_session* session, uint8_t flags,
                                     int32_t stream_id, const uint8_t* data,
                                     size_t len, void* user_data);

  static int OnStreamCloseCallback(nghttp2_session* session, int32_t stream_id,
                                   uint32_t error_code, void* user_data);

  static int OnHeaderCallback(nghttp2_session* session,
                              const nghttp2_frame* frame, const uint8_t* name,
                              size_t namelen, const uint8_t* value,
                              size_t valuelen, uint8_t flags, void* user_data);

  static int OnBeginHeadersCallback(nghttp2_session* session,
                                    const nghttp2_frame* frame, void* user_data);

  // Instance methods called from static callbacks
  ssize_t HandleSend(const uint8_t* data, size_t length);
  int HandleFrameRecv(const nghttp2_frame* frame);
  int HandleDataChunkRecv(int32_t stream_id, const uint8_t* data, size_t len);
  int HandleStreamClose(int32_t stream_id, uint32_t error_code);
  int HandleHeader(const nghttp2_frame* frame, const uint8_t* name,
                   size_t namelen, const uint8_t* value, size_t valuelen);
  int HandleBeginHeaders(const nghttp2_frame* frame);

  // Send Chrome-matching SETTINGS frame
  void SendChromeSettings();

  // Send WINDOW_UPDATE to match Chrome's flow control
  void SendChromeWindowUpdate();

  // Build nghttp2_nv array with Chrome's pseudo-header ordering
  std::vector<nghttp2_nv> BuildHeaderNvArray(const H2Headers& headers);

  // Set error state
  void SetError(const std::string& msg);

  NgSessionPtr session_;
  ChromeH2Profile profile_;
  H2SessionCallbacks callbacks_;

  // Active streams
  std::unordered_map<int32_t, std::unique_ptr<H2Stream>> streams_;

  // Pending header builders (for streams where headers are being received)
  std::unordered_map<int32_t, PackedHeadersBuilder> pending_builders_;

  // Output buffer (data to send)
  core::IoBuffer send_buffer_;
  size_t send_offset_ = 0;

  // Error state
  bool fatal_error_ = false;
  std::string last_error_;
};

}  // namespace http2
}  // namespace chad

#endif  // CHAD_HTTP2_H2_SESSION_H_

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_HTTP1_H1_SESSION_H_
#define HOLYTLS_HTTP1_H1_SESSION_H_

#include "holytls/util/platform.h"

#include <picohttpparser.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/core/io_buffer.h"
#include "holytls/http2/h2_stream.h"  // For H2Headers, H2StreamCallbacks
#include "holytls/http2/packed_headers.h"

namespace holytls {
namespace http1 {

// HTTP/1.1 session - handles request serialization and response parsing.
// No multiplexing - one request at a time.
class H1Session {
 public:
  // Session-level callbacks
  struct SessionCallbacks {
    std::function<void(int error_code, const std::string& msg)> on_error;
  };

  H1Session(SessionCallbacks callbacks);
  ~H1Session();

  // Non-copyable, non-movable
  H1Session(const H1Session&) = delete;
  H1Session& operator=(const H1Session&) = delete;
  H1Session(H1Session&&) = delete;
  H1Session& operator=(H1Session&&) = delete;

  bool Initialize();

  // Submit a request.
  // If header_order is non-empty, headers are sent in that order.
  // Otherwise, Chrome's default HTTP/1.1 header order is used.
  // Returns stream ID on success (always 1 for HTTP/1.1), -1 on error.
  int32_t SubmitRequest(const http2::H2Headers& headers,
                        http2::H2StreamCallbacks stream_callbacks,
                        std::span<const std::string_view> header_order = {},
                        const uint8_t* body = nullptr, size_t body_len = 0);

  // Feed received data into the session (from TLS layer).
  // Returns bytes consumed, or -1 on error.
  ssize_t Receive(const uint8_t* data, size_t len);

  // Get data to send (to TLS layer).
  std::pair<const uint8_t*, size_t> GetPendingData();

  // Mark data as sent.
  void DataSent(size_t len);

  bool WantsWrite() const;
  bool CanSubmitRequest() const;
  bool IsAlive() const { return !fatal_error_; }
  const std::string& last_error() const { return last_error_; }

 private:
  // Parse state machine
  enum class ParseState {
    kIdle,            // No request in flight
    kParsingHeaders,  // Waiting for headers to complete
    kParsingBody,     // Reading body with Content-Length
    kParsingChunked,  // Reading chunked body
  };

  // Build HTTP/1.1 request string
  void BuildRequest(const http2::H2Headers& headers,
                    std::span<const std::string_view> header_order,
                    const uint8_t* body, size_t body_len);

  // Parse response headers, returns bytes consumed or -1 on error, -2 if
  // incomplete
  int ParseHeaders();

  // Parse body data
  void ParseBody();

  // Complete the current request
  void CompleteRequest(uint32_t error_code = 0);

  // Set error state
  void SetError(const std::string& msg);

  SessionCallbacks callbacks_;

  // Current request state
  int32_t current_stream_id_ = 0;
  http2::H2StreamCallbacks stream_callbacks_;
  ParseState parse_state_ = ParseState::kIdle;

  // Response parsing
  int status_code_ = 0;
  http2::PackedHeadersBuilder headers_builder_;
  size_t content_length_ = 0;
  size_t body_received_ = 0;
  bool chunked_ = false;

  // Chunked decoder state (from picohttpparser)
  phr_chunked_decoder chunked_decoder_;

  // Receive buffer (accumulates incoming data)
  std::vector<uint8_t> recv_buffer_;

  // Send buffer (request to send)
  core::IoBuffer send_buffer_;
  size_t send_offset_ = 0;

  // Error state
  bool fatal_error_ = false;
  std::string last_error_;
};

}  // namespace http1
}  // namespace holytls

#endif  // HOLYTLS_HTTP1_H1_SESSION_H_

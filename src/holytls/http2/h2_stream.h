// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_HTTP2_H2_STREAM_H_
#define HOLYTLS_HTTP2_H2_STREAM_H_

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "holytls/types.h"
#include "holytls/core/io_buffer.h"
#include "holytls/http2/packed_headers.h"

namespace holytls {
namespace http2 {

// HTTP/2 stream state
enum class H2StreamState {
  kIdle,
  kOpen,
  kHalfClosedLocal,   // We sent END_STREAM
  kHalfClosedRemote,  // Peer sent END_STREAM
  kClosed,
};

// HTTP/2 header collection
struct H2Headers {
  // Pseudo-headers (required for requests)
  std::string method;     // :method
  std::string scheme;     // :scheme
  std::string authority;  // :authority (host:port)
  std::string path;       // :path

  // Response pseudo-header
  std::string status;  // :status (response only)

  // Regular headers
  Headers headers;

  // Build from URL and method
  static H2Headers ForRequest(std::string_view method, std::string_view url);

  // Add a header
  void Add(std::string_view name, std::string_view value);

  // Get header value (returns empty if not found)
  std::string_view Get(std::string_view name) const;

  // Check if header exists
  bool Has(std::string_view name) const;
};

// Callbacks for stream events
struct H2StreamCallbacks {
  // Called when response headers are complete
  std::function<void(int32_t stream_id, const PackedHeaders& headers)>
      on_headers;

  // Called when response data chunk received
  std::function<void(int32_t stream_id, const uint8_t* data, size_t len)>
      on_data;

  // Called when stream is complete (END_STREAM received or error)
  std::function<void(int32_t stream_id, uint32_t error_code)> on_close;
};

// HTTP/2 stream - represents a single request/response pair
class H2Stream {
 public:
  H2Stream(int32_t stream_id, H2StreamCallbacks callbacks);
  ~H2Stream();

  // Non-copyable, non-movable
  H2Stream(const H2Stream&) = delete;
  H2Stream& operator=(const H2Stream&) = delete;
  H2Stream(H2Stream&&) = delete;
  H2Stream& operator=(H2Stream&&) = delete;

  // Stream ID
  int32_t stream_id() const { return stream_id_; }

  // State
  H2StreamState state() const { return state_; }
  bool IsOpen() const { return state_ == H2StreamState::kOpen; }
  bool IsClosed() const { return state_ == H2StreamState::kClosed; }

  // Response data
  const PackedHeaders& response_headers() const { return response_headers_; }
  const core::IoBuffer& response_body() const { return response_body_; }

  // Response status code (0 if not yet received)
  int status_code() const;

  // Called by H2Session when headers are received
  void OnHeadersReceived(PackedHeaders&& headers);

  // Called by H2Session when data is received
  void OnDataReceived(const uint8_t* data, size_t len);

  // Called by H2Session when stream ends
  void OnStreamClose(uint32_t error_code);

  // Mark local side as closed (we sent END_STREAM)
  void MarkLocalClosed();

 private:
  int32_t stream_id_;
  H2StreamState state_ = H2StreamState::kIdle;
  H2StreamCallbacks callbacks_;

  PackedHeaders response_headers_;
  core::IoBuffer response_body_;
};

}  // namespace http2
}  // namespace holytls

#endif  // HOLYTLS_HTTP2_H2_STREAM_H_

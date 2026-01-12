// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_QUIC_H3_SESSION_H_
#define HOLYTLS_QUIC_H3_SESSION_H_

#include "holytls/util/platform.h"

#include <nghttp3/nghttp3.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "holytls/http2/h2_stream.h"
#include "holytls/http2/packed_headers.h"
#include "holytls/quic/quic_connection.h"

namespace holytls {
namespace quic {

// H3 session state
enum class H3State {
  kIdle,       // Not initialized
  kReady,      // Ready for requests
  kGoingAway,  // Received GOAWAY
  kClosed,     // Session closed
  kError,      // Error occurred
};

// Stream callbacks (mirrors H2Session)
struct H3StreamCallbacks {
  std::function<void(int status_code, const http2::PackedHeaders& headers)>
      on_headers;
  std::function<void(const uint8_t* data, size_t len)> on_data;
  std::function<void()> on_complete;
  std::function<void(uint64_t error_code, const std::string& reason)> on_error;
};

// HTTP/3 session wrapping nghttp3
// Provides HTTP/3 request/response handling on top of QUIC
class H3Session {
 public:
  explicit H3Session(QuicConnection* quic);
  ~H3Session();

  // Non-copyable, non-movable
  H3Session(const H3Session&) = delete;
  H3Session& operator=(const H3Session&) = delete;
  H3Session(H3Session&&) = delete;
  H3Session& operator=(H3Session&&) = delete;

  // Initialize the session (call after QUIC handshake completes)
  bool Initialize();

  // Submit a request
  // Returns stream ID or -1 on error
  int64_t SubmitRequest(
      const std::string& method, const std::string& authority,
      const std::string& path,
      const std::vector<std::pair<std::string, std::string>>& headers,
      const H3StreamCallbacks& callbacks);

  // Submit request with body
  int64_t SubmitRequest(
      const std::string& method, const std::string& authority,
      const std::string& path,
      const std::vector<std::pair<std::string, std::string>>& headers,
      std::span<const uint8_t> body, const H3StreamCallbacks& callbacks);

  // Submit request using H2Headers (compatible with H2Session interface)
  // Returns stream ID or -1 on error
  int64_t SubmitRequest(const http2::H2Headers& headers,
                        http2::H2StreamCallbacks stream_callbacks,
                        const uint8_t* body = nullptr, size_t body_len = 0);

  // Write additional data to stream
  ssize_t WriteStreamData(int64_t stream_id, const uint8_t* data, size_t len,
                          bool fin = false);

  // Process incoming QUIC stream data
  // Called by QuicConnection when data is received on a stream
  int ProcessStreamData(int64_t stream_id, const uint8_t* data, size_t len,
                        bool fin);

  // Get data to send on QUIC streams
  // Returns number of streams with pending data
  int GetPendingStreams(std::vector<int64_t>& stream_ids);

  // Read data for a stream to send over QUIC
  ssize_t ReadStreamData(int64_t stream_id, uint8_t* buf, size_t buflen,
                         bool& fin);

  // Acknowledge sent data
  void AckStreamData(int64_t stream_id, size_t datalen);

  // Block/unblock stream
  void BlockStream(int64_t stream_id);
  void UnblockStream(int64_t stream_id);

  // Close stream with error
  void ResetStream(int64_t stream_id, uint64_t app_error_code);

  // Shutdown the session
  void Shutdown();

  // State accessors
  H3State state() const { return state_; }
  bool IsReady() const { return state_ == H3State::kReady; }
  bool CanSubmitRequest() const {
    return state_ == H3State::kReady && !going_away_;
  }

  // Get QUIC connection
  QuicConnection* quic() { return quic_; }

  // Access underlying nghttp3 connection (for advanced use)
  nghttp3_conn* conn() { return conn_; }

 private:
  // nghttp3 callbacks
  static int OnAckedStreamData(nghttp3_conn* conn, int64_t stream_id,
                               uint64_t datalen, void* user_data,
                               void* stream_user_data);
  static int OnStreamClose(nghttp3_conn* conn, int64_t stream_id,
                           uint64_t app_error_code, void* user_data,
                           void* stream_user_data);
  static int OnRecvData(nghttp3_conn* conn, int64_t stream_id,
                        const uint8_t* data, size_t datalen, void* user_data,
                        void* stream_user_data);
  static int OnDeferredConsume(nghttp3_conn* conn, int64_t stream_id,
                               size_t consumed, void* user_data,
                               void* stream_user_data);
  static int OnBeginHeaders(nghttp3_conn* conn, int64_t stream_id,
                            void* user_data, void* stream_user_data);
  static int OnRecvHeader(nghttp3_conn* conn, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                          uint8_t flags, void* user_data,
                          void* stream_user_data);
  static int OnEndHeaders(nghttp3_conn* conn, int64_t stream_id, int fin,
                          void* user_data, void* stream_user_data);
  static int OnEndStream(nghttp3_conn* conn, int64_t stream_id, void* user_data,
                         void* stream_user_data);
  static int OnStopSending(nghttp3_conn* conn, int64_t stream_id,
                           uint64_t app_error_code, void* user_data,
                           void* stream_user_data);
  static int OnResetStream(nghttp3_conn* conn, int64_t stream_id,
                           uint64_t app_error_code, void* user_data,
                           void* stream_user_data);
  static int OnShutdown(nghttp3_conn* conn, int64_t id, void* user_data);
  static int OnRecvSettings(nghttp3_conn* conn, const nghttp3_settings* settings,
                            void* user_data);

  // Create control and QPACK streams
  bool CreateControlStreams();

  QuicConnection* quic_;
  nghttp3_conn* conn_ = nullptr;
  H3State state_ = H3State::kIdle;
  bool going_away_ = false;

  // Control stream IDs
  int64_t ctrl_stream_id_ = -1;
  int64_t qpack_enc_stream_id_ = -1;
  int64_t qpack_dec_stream_id_ = -1;

  // Active streams with their callbacks
  struct StreamContext {
    H3StreamCallbacks callbacks;
    int status_code = 0;
    http2::PackedHeadersBuilder headers_builder;
    bool headers_complete = false;
  };
  std::unordered_map<int64_t, StreamContext> streams_;
};

}  // namespace quic
}  // namespace holytls

#endif  // HOLYTLS_QUIC_H3_SESSION_H_

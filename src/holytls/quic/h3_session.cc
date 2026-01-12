// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/quic/h3_session.h"

#include <cstring>

namespace holytls {
namespace quic {

H3Session::H3Session(QuicConnection* quic) : quic_(quic) {}

H3Session::~H3Session() {
  if (conn_) {
    nghttp3_conn_del(conn_);
  }
}

bool H3Session::Initialize() {
  if (state_ != H3State::kIdle) {
    return false;
  }

  // Set up callbacks
  nghttp3_callbacks callbacks{};
  callbacks.acked_stream_data = OnAckedStreamData;
  callbacks.stream_close = OnStreamClose;
  callbacks.recv_data = OnRecvData;
  callbacks.deferred_consume = OnDeferredConsume;
  callbacks.begin_headers = OnBeginHeaders;
  callbacks.recv_header = OnRecvHeader;
  callbacks.end_headers = OnEndHeaders;
  callbacks.end_stream = OnEndStream;
  callbacks.stop_sending = OnStopSending;
  callbacks.reset_stream = OnResetStream;
  callbacks.shutdown = OnShutdown;
  callbacks.recv_settings = OnRecvSettings;

  // Set up settings with Chrome-like values
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_max_dtable_capacity = 65536;
  settings.qpack_blocked_streams = 100;
  settings.enable_connect_protocol = 0;  // Chrome disables by default

  // Create client connection
  int rv = nghttp3_conn_client_new(&conn_, &callbacks, &settings, nullptr, this);
  if (rv != 0) {
    return false;
  }

  // Create control and QPACK streams
  if (!CreateControlStreams()) {
    nghttp3_conn_del(conn_);
    conn_ = nullptr;
    return false;
  }

  state_ = H3State::kReady;
  return true;
}

bool H3Session::CreateControlStreams() {
  // Open control stream (unidirectional)
  ctrl_stream_id_ = quic_->OpenUniStream();
  if (ctrl_stream_id_ < 0) {
    return false;
  }

  int rv = nghttp3_conn_bind_control_stream(conn_, ctrl_stream_id_);
  if (rv != 0) {
    return false;
  }

  // Open QPACK encoder stream
  qpack_enc_stream_id_ = quic_->OpenUniStream();
  if (qpack_enc_stream_id_ < 0) {
    return false;
  }

  // Open QPACK decoder stream
  qpack_dec_stream_id_ = quic_->OpenUniStream();
  if (qpack_dec_stream_id_ < 0) {
    return false;
  }

  rv = nghttp3_conn_bind_qpack_streams(conn_, qpack_enc_stream_id_,
                                        qpack_dec_stream_id_);
  if (rv != 0) {
    return false;
  }

  return true;
}

int64_t H3Session::SubmitRequest(
    const std::string& method, const std::string& authority,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const H3StreamCallbacks& callbacks) {
  return SubmitRequest(method, authority, path, headers, {}, callbacks);
}

int64_t H3Session::SubmitRequest(
    const std::string& method, const std::string& authority,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::span<const uint8_t> body, const H3StreamCallbacks& callbacks) {
  if (!CanSubmitRequest()) {
    return -1;
  }

  // Open a new bidirectional stream
  int64_t stream_id = quic_->OpenBidiStream();
  if (stream_id < 0) {
    return -1;
  }

  // Build nghttp3 headers
  std::vector<nghttp3_nv> nva;
  nva.reserve(4 + headers.size());

  // Pseudo-headers first
  auto add_header = [&nva](std::string_view name, std::string_view value) {
    nghttp3_nv nv;
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
    nv.namelen = name.size();
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
    nv.valuelen = value.size();
    nv.flags = NGHTTP3_NV_FLAG_NONE;
    nva.push_back(nv);
  };

  add_header(":method", method);
  add_header(":scheme", "https");
  add_header(":authority", authority);
  add_header(":path", path);

  // Additional headers
  for (const auto& [name, value] : headers) {
    add_header(name, value);
  }

  // Submit request
  nghttp3_data_reader* data_reader = nullptr;
  int rv = nghttp3_conn_submit_request(conn_, stream_id, nva.data(), nva.size(),
                                        data_reader, nullptr);
  if (rv != 0) {
    quic_->ResetStream(stream_id, NGHTTP3_H3_INTERNAL_ERROR);
    return -1;
  }

  // Store stream context
  StreamContext ctx;
  ctx.callbacks = callbacks;
  streams_[stream_id] = std::move(ctx);

  // Note: Don't send data or FIN here.
  // The caller should use GetPendingStreams/ReadStreamData to get the
  // encoded headers (and body if provided), then send via QUIC.
  // nghttp3 will set fin=1 in the output when the request is complete.

  return stream_id;
}

int64_t H3Session::SubmitRequest(const http2::H2Headers& headers,
                                  http2::H2StreamCallbacks stream_callbacks,
                                  const uint8_t* body, size_t body_len) {
  // Convert H2Headers to vector<pair> format
  std::vector<std::pair<std::string, std::string>> header_pairs;
  header_pairs.reserve(headers.headers.size());
  for (const auto& [name, value] : headers.headers) {
    header_pairs.emplace_back(name, value);
  }

  // Convert H2StreamCallbacks to H3StreamCallbacks
  // Note: H2 callbacks include stream_id, H3 callbacks don't (stream tracked internally)
  H3StreamCallbacks h3_callbacks;

  // Capture stream_id for forwarding to H2-style callbacks
  // We'll get the actual stream_id after submitting
  auto stream_id_holder = std::make_shared<int64_t>(-1);

  h3_callbacks.on_headers = [stream_callbacks, stream_id_holder](
                                int status_code,
                                const http2::PackedHeaders& packed_headers) {
    if (stream_callbacks.on_headers) {
      stream_callbacks.on_headers(*stream_id_holder, packed_headers);
    }
  };

  h3_callbacks.on_data = [stream_callbacks, stream_id_holder](const uint8_t* data,
                                                               size_t len) {
    if (stream_callbacks.on_data) {
      stream_callbacks.on_data(*stream_id_holder, data, len);
    }
  };

  h3_callbacks.on_complete = [stream_callbacks, stream_id_holder]() {
    if (stream_callbacks.on_close) {
      stream_callbacks.on_close(*stream_id_holder, 0);  // 0 = no error
    }
  };

  h3_callbacks.on_error = [stream_callbacks, stream_id_holder](
                              uint64_t error_code, const std::string& /*reason*/) {
    if (stream_callbacks.on_close) {
      stream_callbacks.on_close(*stream_id_holder, static_cast<uint32_t>(error_code));
    }
  };

  // Submit using the existing method
  int64_t stream_id = SubmitRequest(headers.method, headers.authority, headers.path,
                                     header_pairs, {body, body_len}, h3_callbacks);

  // Store stream_id for callbacks
  *stream_id_holder = stream_id;

  return stream_id;
}

ssize_t H3Session::WriteStreamData(int64_t stream_id, const uint8_t* data,
                                    size_t len, bool fin) {
  // For HTTP/3, body data goes through QUIC directly
  return quic_->WriteStream(stream_id, data, len, fin);
}

int H3Session::ProcessStreamData(int64_t stream_id, const uint8_t* data,
                                  size_t len, bool fin) {
  if (!conn_) {
    return -1;
  }

  nghttp3_ssize nconsumed =
      nghttp3_conn_read_stream(conn_, stream_id, data, len, fin);
  if (nconsumed < 0) {
    return static_cast<int>(nconsumed);
  }

  return 0;
}

int H3Session::GetPendingStreams(std::vector<int64_t>& stream_ids) {
  if (!conn_) {
    return 0;
  }

  stream_ids.clear();
  nghttp3_vec vec[8];
  int64_t out_stream_id;
  int pfin;

  // Check if there's any stream with pending data
  nghttp3_ssize sveccnt = nghttp3_conn_writev_stream(conn_, &out_stream_id,
                                                      &pfin, vec, 8);
  if (sveccnt > 0 && out_stream_id >= 0) {
    stream_ids.push_back(out_stream_id);
  }

  return static_cast<int>(stream_ids.size());
}

ssize_t H3Session::ReadStreamData(int64_t stream_id, uint8_t* buf,
                                   size_t buflen, bool& fin) {
  if (!conn_) {
    return -1;
  }

  // We need to find data for this specific stream
  // nghttp3_conn_writev_stream will give us the next stream with data
  nghttp3_vec vec[8];
  int64_t out_stream_id;
  int pfin;

  nghttp3_ssize sveccnt = nghttp3_conn_writev_stream(conn_, &out_stream_id,
                                                      &pfin, vec, 8);
  if (sveccnt < 0) {
    return static_cast<ssize_t>(sveccnt);
  }

  if (sveccnt == 0 || out_stream_id != stream_id) {
    // No data for this stream
    return 0;
  }

  fin = (pfin != 0);

  // Copy data to buffer and calculate total length
  size_t total = 0;
  size_t vec_total = 0;
  for (int i = 0; i < static_cast<int>(sveccnt); ++i) {
    vec_total += vec[i].len;
    if (total < buflen) {
      size_t to_copy = std::min(vec[i].len, buflen - total);
      std::memcpy(buf + total, vec[i].base, to_copy);
      total += to_copy;
    }
  }

  // Tell nghttp3 we've consumed this data
  int rv = nghttp3_conn_add_write_offset(conn_, stream_id, vec_total);
  if (rv != 0) {
    return -1;
  }

  return static_cast<ssize_t>(total);
}

void H3Session::AckStreamData(int64_t stream_id, size_t datalen) {
  if (conn_) {
    nghttp3_conn_add_ack_offset(conn_, stream_id, datalen);
  }
}

void H3Session::BlockStream(int64_t stream_id) {
  if (conn_) {
    nghttp3_conn_block_stream(conn_, stream_id);
  }
}

void H3Session::UnblockStream(int64_t stream_id) {
  if (conn_) {
    nghttp3_conn_unblock_stream(conn_, stream_id);
  }
}

void H3Session::ResetStream(int64_t stream_id, uint64_t app_error_code) {
  if (conn_) {
    nghttp3_conn_shutdown_stream_read(conn_, stream_id);
  }
  quic_->ResetStream(stream_id, app_error_code);
}

void H3Session::Shutdown() {
  if (conn_) {
    nghttp3_conn_shutdown(conn_);
  }
  going_away_ = true;
}

// Static nghttp3 callbacks

int H3Session::OnAckedStreamData(nghttp3_conn* /*conn*/, int64_t /*stream_id*/,
                                  uint64_t /*datalen*/, void* /*user_data*/,
                                  void* /*stream_user_data*/) {
  // Data was acknowledged, could free send buffers
  return 0;
}

int H3Session::OnStreamClose(nghttp3_conn* /*conn*/, int64_t stream_id,
                              uint64_t app_error_code, void* user_data,
                              void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  auto it = session->streams_.find(stream_id);
  if (it != session->streams_.end()) {
    if (app_error_code != 0 && it->second.callbacks.on_error) {
      it->second.callbacks.on_error(app_error_code, "Stream closed with error");
    }
    session->streams_.erase(it);
  }

  return 0;
}

int H3Session::OnRecvData(nghttp3_conn* /*conn*/, int64_t stream_id,
                           const uint8_t* data, size_t datalen,
                           void* user_data, void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  auto it = session->streams_.find(stream_id);
  if (it != session->streams_.end() && it->second.callbacks.on_data) {
    it->second.callbacks.on_data(data, datalen);
  }

  return 0;
}

int H3Session::OnDeferredConsume(nghttp3_conn* /*conn*/, int64_t stream_id,
                                  size_t consumed, void* user_data,
                                  void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  // Extend stream flow control window
  ngtcp2_conn_extend_max_stream_offset(session->quic_->conn(), stream_id,
                                        consumed);
  ngtcp2_conn_extend_max_offset(session->quic_->conn(), consumed);

  return 0;
}

int H3Session::OnBeginHeaders(nghttp3_conn* /*conn*/, int64_t stream_id,
                               void* user_data, void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  auto it = session->streams_.find(stream_id);
  if (it != session->streams_.end()) {
    // Reset headers builder for new response
    it->second.headers_builder = http2::PackedHeadersBuilder();
    it->second.headers_complete = false;
  }

  return 0;
}

int H3Session::OnRecvHeader(nghttp3_conn* /*conn*/, int64_t stream_id,
                             int32_t /*token*/, nghttp3_rcbuf* name,
                             nghttp3_rcbuf* value, uint8_t /*flags*/,
                             void* user_data, void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  auto it = session->streams_.find(stream_id);
  if (it == session->streams_.end()) {
    return 0;
  }

  nghttp3_vec namev = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec valuev = nghttp3_rcbuf_get_buf(value);

  std::string_view name_sv(reinterpret_cast<char*>(namev.base), namev.len);
  std::string_view value_sv(reinterpret_cast<char*>(valuev.base), valuev.len);

  // Check for :status pseudo-header
  if (name_sv == ":status") {
    it->second.headers_builder.SetStatus(value_sv);
    it->second.status_code = 0;
    for (char c : value_sv) {
      if (c >= '0' && c <= '9') {
        it->second.status_code = it->second.status_code * 10 + (c - '0');
      }
    }
  } else {
    // Add to headers builder
    it->second.headers_builder.Add(name_sv, value_sv);
  }

  return 0;
}

int H3Session::OnEndHeaders(nghttp3_conn* /*conn*/, int64_t stream_id,
                             int /*fin*/, void* user_data,
                             void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  auto it = session->streams_.find(stream_id);
  if (it != session->streams_.end()) {
    it->second.headers_complete = true;
    // Build the packed headers
    http2::PackedHeaders headers = it->second.headers_builder.Build();
    if (it->second.callbacks.on_headers) {
      it->second.callbacks.on_headers(it->second.status_code, headers);
    }
  }

  return 0;
}

int H3Session::OnEndStream(nghttp3_conn* /*conn*/, int64_t stream_id,
                            void* user_data, void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);

  auto it = session->streams_.find(stream_id);
  if (it != session->streams_.end() && it->second.callbacks.on_complete) {
    it->second.callbacks.on_complete();
  }

  return 0;
}

int H3Session::OnStopSending(nghttp3_conn* /*conn*/, int64_t stream_id,
                              uint64_t app_error_code, void* user_data,
                              void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);
  session->quic_->ResetStream(stream_id, app_error_code);
  return 0;
}

int H3Session::OnResetStream(nghttp3_conn* /*conn*/, int64_t stream_id,
                              uint64_t app_error_code, void* user_data,
                              void* /*stream_user_data*/) {
  auto* session = static_cast<H3Session*>(user_data);
  session->quic_->ResetStream(stream_id, app_error_code);
  return 0;
}

int H3Session::OnShutdown(nghttp3_conn* /*conn*/, int64_t /*id*/,
                           void* user_data) {
  auto* session = static_cast<H3Session*>(user_data);
  session->going_away_ = true;
  session->state_ = H3State::kGoingAway;
  return 0;
}

int H3Session::OnRecvSettings(nghttp3_conn* /*conn*/,
                               const nghttp3_settings* /*settings*/,
                               void* /*user_data*/) {
  // Settings received from server
  return 0;
}

}  // namespace quic
}  // namespace holytls

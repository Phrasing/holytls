// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/quic/quic_connection.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <cstring>

namespace holytls {
namespace quic {

namespace {

// ALPN for HTTP/3
constexpr uint8_t kH3Alpn[] = "\x02h3";
constexpr size_t kH3AlpnLen = sizeof(kH3Alpn) - 1;

// Generate random bytes using BoringSSL
void GenerateRandom(uint8_t* dest, size_t len) {
  // RAND_bytes takes int, but we know len fits since it's for crypto ops
  RAND_bytes(dest, len);
}

// Get current timestamp in nanoseconds
ngtcp2_tstamp GetTimestamp() {
  return static_cast<ngtcp2_tstamp>(uv_hrtime());
}

}  // namespace

// QuicTlsContext implementation

QuicTlsContext::QuicTlsContext() = default;

QuicTlsContext::~QuicTlsContext() {
  if (ssl_ctx_) {
    SSL_CTX_free(ssl_ctx_);
  }
}

bool QuicTlsContext::InitClient() {
  ssl_ctx_ = SSL_CTX_new(TLS_client_method());
  if (!ssl_ctx_) {
    return false;
  }

  // Configure for QUIC
  if (ngtcp2_crypto_boringssl_configure_client_context(ssl_ctx_) != 0) {
    SSL_CTX_free(ssl_ctx_);
    ssl_ctx_ = nullptr;
    return false;
  }

  // Use system CA certificates
  SSL_CTX_set_default_verify_paths(ssl_ctx_);

  // Set supported groups (Chrome-like order)
  if (SSL_CTX_set1_groups_list(ssl_ctx_, "X25519:P-256:P-384") != 1) {
    SSL_CTX_free(ssl_ctx_);
    ssl_ctx_ = nullptr;
    return false;
  }

  return true;
}

// QuicConnection implementation

QuicConnection::QuicConnection(core::Reactor* reactor, QuicTlsContext* tls_ctx,
                               const std::string& host, uint16_t port,
                               const ChromeQuicProfile& profile)
    : reactor_(reactor),
      tls_ctx_(tls_ctx),
      host_(host),
      port_(port),
      profile_(profile) {
  // Initialize conn_ref for ngtcp2 crypto callbacks
  conn_ref_.get_conn = &QuicConnection::GetConn;
  conn_ref_.user_data = this;
}

QuicConnection::~QuicConnection() {
  // Note: Close() must be called before destruction to properly
  // clean up libuv handles. The timer handle cannot be safely closed
  // in the destructor because uv_close is asynchronous.

  if (state_ != QuicState::kClosed && state_ != QuicState::kIdle) {
    // Force close without sending close frame
    if (timer_active_ && timer_initialized_) {
      uv_timer_stop(&timer_);
      timer_active_ = false;
    }
    if (udp_socket_) {
      udp_socket_->StopReceive();
    }
    state_ = QuicState::kClosed;
  }

  if (ssl_) {
    SSL_free(ssl_);
  }
  if (conn_) {
    ngtcp2_conn_del(conn_);
  }
}

bool QuicConnection::Connect(std::string_view ip, bool ipv6) {
  if (state_ != QuicState::kIdle) {
    return false;
  }

  // Create UDP socket
  udp_socket_ = std::make_unique<core::UdpSocket>(reactor_);
  if (!udp_socket_->Connect(std::string(ip), port_, ipv6)) {
    last_error_ = "Failed to create UDP socket";
    state_ = QuicState::kError;
    return false;
  }

  // Store remote address
  remote_addr_ = udp_socket_->remote_addr();
  remote_addr_len_ = udp_socket_->remote_addr_len();

  // Get local address
  if (!udp_socket_->GetLocalAddress(&local_addr_, &local_addr_len_)) {
    last_error_ = "Failed to get local address";
    state_ = QuicState::kError;
    return false;
  }

  // Initialize QUIC connection
  if (!InitializeConnection(reinterpret_cast<sockaddr*>(&remote_addr_),
                             remote_addr_len_)) {
    state_ = QuicState::kError;
    return false;
  }

  // Initialize TLS
  if (!InitializeTls()) {
    state_ = QuicState::kError;
    return false;
  }

  // Set up receive callback
  udp_socket_->SetReceiveCallback(
      [this](const uint8_t* data, size_t len, const sockaddr* addr,
             socklen_t addr_len) { OnUdpReceive(data, len, addr, addr_len); });

  // Start receiving
  if (!udp_socket_->StartReceive()) {
    last_error_ = "Failed to start UDP receive";
    state_ = QuicState::kError;
    return false;
  }

  // Initialize timer for retransmission
  uv_timer_init(reactor_->loop(), &timer_);
  timer_.data = this;
  timer_initialized_ = true;

  state_ = QuicState::kConnecting;

  // Send initial handshake packet
  if (WritePackets() != 0) {
    state_ = QuicState::kError;
    return false;
  }

  UpdateTimer();
  return true;
}

bool QuicConnection::InitializeConnection(const sockaddr* addr,
                                           socklen_t addr_len) {
  // Generate connection IDs
  ngtcp2_cid dcid, scid;
  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  GenerateRandom(dcid.data, dcid.datalen);
  scid.datalen = 16;
  GenerateRandom(scid.data, scid.datalen);

  // Set up ngtcp2 callbacks
  ngtcp2_callbacks callbacks{};
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_stream_data = OnReceiveStreamData;
  callbacks.acked_stream_data_offset = OnAckedStreamDataOffset;
  callbacks.stream_open = OnStreamOpen;
  callbacks.stream_close = OnStreamClose;
  callbacks.stream_reset = OnStreamReset;
  callbacks.handshake_completed = OnHandshakeCompleted;
  callbacks.handshake_confirmed = OnHandshakeConfirmed;
  callbacks.rand = OnRand;
  callbacks.get_new_connection_id = OnGetNewConnectionId;
  callbacks.remove_connection_id = OnRemoveConnectionId;
  callbacks.extend_max_local_streams_bidi = OnExtendMaxStreams;
  callbacks.extend_max_local_streams_uni = OnExtendMaxStreams;
  callbacks.get_path_challenge_data = OnGetPathChallengeData;

  // Set up ngtcp2_crypto callbacks
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx =
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

  // Set up transport settings
  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = GetTimestamp();
  settings.cc_algo = profile_.congestion_control;
  settings.max_tx_udp_payload_size = profile_.max_udp_payload_size;

  // Set up transport parameters
  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_data = profile_.initial_max_data;
  params.initial_max_stream_data_bidi_local =
      profile_.initial_max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      profile_.initial_max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = profile_.initial_max_stream_data_uni;
  params.initial_max_streams_bidi = profile_.initial_max_streams_bidi;
  params.initial_max_streams_uni = profile_.initial_max_streams_uni;
  params.max_idle_timeout = profile_.max_idle_timeout * NGTCP2_MILLISECONDS;
  params.max_udp_payload_size = profile_.max_udp_payload_size;
  params.ack_delay_exponent = profile_.ack_delay_exponent;
  params.max_ack_delay = profile_.max_ack_delay * NGTCP2_MILLISECONDS;
  params.disable_active_migration = profile_.disable_active_migration ? 1 : 0;

  // Create path
  ngtcp2_path path;
  path.local.addrlen = local_addr_len_;
  path.local.addr = reinterpret_cast<sockaddr*>(&local_addr_);
  path.remote.addrlen = addr_len;
  path.remote.addr = const_cast<sockaddr*>(addr);

  // Create client connection
  int rv = ngtcp2_conn_client_new(&conn_, &dcid, &scid, &path,
                                  NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                  &params, nullptr, this);
  if (rv != 0) {
    last_error_ = "ngtcp2_conn_client_new failed: " +
                  std::string(ngtcp2_strerror(rv));
    return false;
  }

  return true;
}

bool QuicConnection::InitializeTls() {
  ssl_ = SSL_new(tls_ctx_->native_handle());
  if (!ssl_) {
    last_error_ = "SSL_new failed";
    return false;
  }

  // Set app data for crypto callbacks
  SSL_set_app_data(ssl_, &conn_ref_);
  SSL_set_connect_state(ssl_);

  // Set ALPN (HTTP/3)
  SSL_set_alpn_protos(ssl_, kH3Alpn, kH3AlpnLen);

  // Set SNI
  SSL_set_tlsext_host_name(ssl_, host_.c_str());

  // Set QUIC method
  ngtcp2_conn_set_tls_native_handle(conn_, ssl_);

  return true;
}

int64_t QuicConnection::OpenBidiStream() {
  if (state_ != QuicState::kConnected) {
    return -1;
  }

  int64_t stream_id;
  int rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
  if (rv != 0) {
    return -1;
  }

  return stream_id;
}

int64_t QuicConnection::OpenUniStream() {
  if (state_ != QuicState::kConnected) {
    return -1;
  }

  int64_t stream_id;
  int rv = ngtcp2_conn_open_uni_stream(conn_, &stream_id, nullptr);
  if (rv != 0) {
    return -1;
  }

  return stream_id;
}

ssize_t QuicConnection::WriteStream(int64_t stream_id, const uint8_t* data,
                                     size_t len, bool fin) {
  if (state_ != QuicState::kConnected) {
    return -1;
  }

  uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
  ngtcp2_vec datav{const_cast<uint8_t*>(data), len};

  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite =
      ngtcp2_conn_writev_stream(conn_, nullptr, &pi, send_buffer_.data(),
                                 send_buffer_.size(), nullptr, flags, stream_id,
                                 &datav, 1, GetTimestamp());

  if (nwrite < 0) {
    if (nwrite == NGTCP2_ERR_WRITE_MORE) {
      // More data can be written in subsequent calls
      return static_cast<ssize_t>(len);
    }
    return -1;
  }

  if (nwrite > 0) {
    udp_socket_->Send(send_buffer_.data(), static_cast<size_t>(nwrite));
    UpdateTimer();
  }

  return static_cast<ssize_t>(len);
}

bool QuicConnection::ShutdownStream(int64_t stream_id) {
  if (!conn_) {
    return false;
  }

  int rv = ngtcp2_conn_shutdown_stream_write(conn_, 0, stream_id,
                                              NGTCP2_NO_ERROR);
  if (rv != 0) {
    return false;
  }

  WritePackets();
  return true;
}

bool QuicConnection::ResetStream(int64_t stream_id, uint64_t app_error_code) {
  if (!conn_) {
    return false;
  }

  int rv = ngtcp2_conn_shutdown_stream(conn_, 0, stream_id, app_error_code);
  if (rv != 0) {
    return false;
  }

  WritePackets();
  return true;
}

void QuicConnection::Close(uint64_t error_code, const std::string& reason) {
  if (state_ == QuicState::kClosed || state_ == QuicState::kIdle) {
    return;
  }

  if (conn_) {
    ngtcp2_ccerr ccerr;
    ngtcp2_ccerr_set_application_error(
        &ccerr, error_code,
        reinterpret_cast<const uint8_t*>(reason.data()), reason.size());

    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite =
        ngtcp2_conn_write_connection_close(conn_, nullptr, &pi,
                                            send_buffer_.data(),
                                            send_buffer_.size(), &ccerr,
                                            GetTimestamp());
    if (nwrite > 0 && udp_socket_ && udp_socket_->IsOpen()) {
      udp_socket_->Send(send_buffer_.data(), static_cast<size_t>(nwrite));
    }
  }

  state_ = QuicState::kClosed;

  if (timer_active_ && timer_initialized_) {
    uv_timer_stop(&timer_);
    timer_active_ = false;
  }
  if (udp_socket_) {
    udp_socket_->Close();
  }
}

void QuicConnection::OnUdpReceive(const uint8_t* data, size_t len,
                                   const sockaddr* addr, socklen_t addr_len) {
  if (!conn_) {
    return;
  }

  ngtcp2_path path;
  path.local.addrlen = local_addr_len_;
  path.local.addr = reinterpret_cast<sockaddr*>(&local_addr_);
  path.remote.addrlen = addr_len;
  path.remote.addr = const_cast<sockaddr*>(addr);

  ngtcp2_pkt_info pi{};

  int rv = ngtcp2_conn_read_pkt(conn_, &path, &pi, data, len, GetTimestamp());
  if (rv != 0) {
    if (rv == NGTCP2_ERR_DRAINING) {
      state_ = QuicState::kDraining;
    } else {
      // Handle error
      last_error_ = "ngtcp2_conn_read_pkt: " + std::string(ngtcp2_strerror(rv));
      if (on_error_) {
        on_error_(static_cast<uint64_t>(-rv), last_error_);
      }
    }
    return;
  }

  // Send any pending data
  WritePackets();
  UpdateTimer();
}

void QuicConnection::OnTimer() {
  if (!conn_) {
    return;
  }

  int rv = ngtcp2_conn_handle_expiry(conn_, GetTimestamp());
  if (rv != 0) {
    last_error_ = "ngtcp2_conn_handle_expiry: " +
                  std::string(ngtcp2_strerror(rv));
    if (on_error_) {
      on_error_(static_cast<uint64_t>(-rv), last_error_);
    }
    return;
  }

  WritePackets();
  UpdateTimer();
}

int QuicConnection::WritePackets() {
  if (!conn_) {
    return -1;
  }

  ngtcp2_pkt_info pi;

  for (;;) {
    ngtcp2_ssize nwrite =
        ngtcp2_conn_write_pkt(conn_, nullptr, &pi, send_buffer_.data(),
                               send_buffer_.size(), GetTimestamp());
    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        continue;
      }
      return static_cast<int>(nwrite);
    }

    if (nwrite == 0) {
      break;
    }

    udp_socket_->Send(send_buffer_.data(), static_cast<size_t>(nwrite));
  }

  return 0;
}

void QuicConnection::UpdateTimer() {
  if (!conn_ || !timer_initialized_) {
    return;
  }

  ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn_);
  ngtcp2_tstamp now = GetTimestamp();

  if (expiry <= now) {
    // Expired, handle immediately
    reactor_->Post([this]() { OnTimer(); });
    return;
  }

  // Convert to milliseconds
  uint64_t timeout_ms = (expiry - now) / NGTCP2_MILLISECONDS;
  if (timeout_ms == 0) {
    timeout_ms = 1;
  }

  // Stop existing timer if active
  if (timer_active_) {
    uv_timer_stop(&timer_);
  }

  // Start timer with callback
  uv_timer_start(
      &timer_,
      [](uv_timer_t* handle) {
        auto* qc = static_cast<QuicConnection*>(handle->data);
        qc->OnTimer();
      },
      timeout_ms, 0);
  timer_active_ = true;
}

// Static ngtcp2 callbacks

int QuicConnection::OnReceiveStreamData(ngtcp2_conn* /*conn*/, uint32_t flags,
                                         int64_t stream_id, uint64_t /*offset*/,
                                         const uint8_t* data, size_t datalen,
                                         void* user_data,
                                         void* /*stream_user_data*/) {
  auto* qc = static_cast<QuicConnection*>(user_data);
  bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;

  if (qc->on_stream_data_) {
    qc->on_stream_data_(stream_id, data, datalen, fin);
  }

  return 0;
}

int QuicConnection::OnAckedStreamDataOffset(ngtcp2_conn* /*conn*/,
                                             int64_t /*stream_id*/,
                                             uint64_t /*offset*/,
                                             uint64_t /*datalen*/,
                                             void* /*user_data*/,
                                             void* /*stream_user_data*/) {
  // Data was acknowledged, could free send buffers if tracking them
  return 0;
}

int QuicConnection::OnStreamOpen(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                  void* user_data) {
  auto* qc = static_cast<QuicConnection*>(user_data);

  if (qc->on_stream_open_) {
    qc->on_stream_open_(stream_id);
  }

  return 0;
}

int QuicConnection::OnStreamClose(ngtcp2_conn* /*conn*/, uint32_t /*flags*/,
                                   int64_t stream_id, uint64_t app_error_code,
                                   void* user_data,
                                   void* /*stream_user_data*/) {
  auto* qc = static_cast<QuicConnection*>(user_data);

  if (qc->on_stream_close_) {
    qc->on_stream_close_(stream_id, app_error_code);
  }

  return 0;
}

int QuicConnection::OnStreamReset(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                   uint64_t /*final_size*/,
                                   uint64_t app_error_code, void* user_data,
                                   void* /*stream_user_data*/) {
  auto* qc = static_cast<QuicConnection*>(user_data);

  if (qc->on_stream_close_) {
    qc->on_stream_close_(stream_id, app_error_code);
  }

  return 0;
}

int QuicConnection::OnHandshakeCompleted(ngtcp2_conn* /*conn*/,
                                          void* user_data) {
  auto* qc = static_cast<QuicConnection*>(user_data);

  // Get negotiated ALPN
  const uint8_t* alpn = nullptr;
  unsigned int alpnlen = 0;
  SSL_get0_alpn_selected(qc->ssl_, &alpn, &alpnlen);
  if (alpn && alpnlen > 0) {
    qc->negotiated_alpn_ = std::string(reinterpret_cast<const char*>(alpn),
                                        alpnlen);
  }

  qc->state_ = QuicState::kConnected;

  if (qc->on_connect_) {
    qc->on_connect_(true);
  }

  return 0;
}

int QuicConnection::OnHandshakeConfirmed(ngtcp2_conn* /*conn*/,
                                          void* /*user_data*/) {
  // Handshake is confirmed (1-RTT keys are available)
  return 0;
}

void QuicConnection::OnRand(uint8_t* dest, size_t destlen,
                             const ngtcp2_rand_ctx* /*rand_ctx*/) {
  GenerateRandom(dest, destlen);
}

int QuicConnection::OnGetNewConnectionId(ngtcp2_conn* /*conn*/,
                                          ngtcp2_cid* cid, uint8_t* token,
                                          size_t cidlen, void* /*user_data*/) {
  GenerateRandom(cid->data, cidlen);
  cid->datalen = cidlen;
  GenerateRandom(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

int QuicConnection::OnRemoveConnectionId(ngtcp2_conn* /*conn*/,
                                          const ngtcp2_cid* /*cid*/,
                                          void* /*user_data*/) {
  return 0;
}

int QuicConnection::OnExtendMaxStreams(ngtcp2_conn* /*conn*/,
                                        uint64_t /*max_streams*/,
                                        void* /*user_data*/) {
  return 0;
}

int QuicConnection::OnGetPathChallengeData(ngtcp2_conn* /*conn*/,
                                            uint8_t* data, void* /*user_data*/) {
  GenerateRandom(data, NGTCP2_PATH_CHALLENGE_DATALEN);
  return 0;
}

ngtcp2_conn* QuicConnection::GetConn(ngtcp2_crypto_conn_ref* conn_ref) {
  auto* qc = static_cast<QuicConnection*>(conn_ref->user_data);
  return qc->conn_;
}

}  // namespace quic
}  // namespace holytls

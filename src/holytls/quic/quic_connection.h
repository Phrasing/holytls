// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_QUIC_QUIC_CONNECTION_H_
#define HOLYTLS_QUIC_QUIC_CONNECTION_H_

#include "holytls/util/platform.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/core/reactor.h"
#include "holytls/core/udp_socket.h"

namespace holytls {
namespace quic {

// QUIC connection state
enum class QuicState {
  kIdle,       // Not connected
  kConnecting, // Handshake in progress
  kConnected,  // Handshake complete, ready for streams
  kDraining,   // Connection draining (graceful shutdown)
  kClosed,     // Connection closed
  kError,      // Error occurred
};

// Chrome-like QUIC transport parameters
// These match Chrome 131+ fingerprint
struct ChromeQuicProfile {
  uint64_t max_idle_timeout = 30000;          // 30 seconds
  uint64_t max_udp_payload_size = 1350;       // Standard QUIC MTU
  uint64_t initial_max_data = 15728640;       // 15 MB
  uint64_t initial_max_stream_data_bidi_local = 6291456;   // 6 MB
  uint64_t initial_max_stream_data_bidi_remote = 6291456;  // 6 MB
  uint64_t initial_max_stream_data_uni = 6291456;          // 6 MB
  uint64_t initial_max_streams_bidi = 100;
  uint64_t initial_max_streams_uni = 100;
  uint64_t ack_delay_exponent = 3;
  uint64_t max_ack_delay = 25;                // 25ms
  bool disable_active_migration = false;
  ngtcp2_cc_algo congestion_control = NGTCP2_CC_ALGO_CUBIC;
};

// Callbacks for QUIC events
using QuicConnectCallback = std::function<void(bool success)>;
using QuicStreamDataCallback =
    std::function<void(int64_t stream_id, const uint8_t* data, size_t len,
                       bool fin)>;
using QuicStreamOpenCallback = std::function<void(int64_t stream_id)>;
using QuicStreamCloseCallback = std::function<void(int64_t stream_id,
                                                    uint64_t app_error_code)>;
using QuicErrorCallback = std::function<void(uint64_t error_code,
                                             const std::string& reason)>;

// Forward declaration
class QuicConnection;

// QUIC TLS context for client connections
class QuicTlsContext {
 public:
  QuicTlsContext();
  ~QuicTlsContext();

  // Initialize for client connections
  bool InitClient();

  // Get native SSL_CTX handle
  SSL_CTX* native_handle() { return ssl_ctx_; }

 private:
  SSL_CTX* ssl_ctx_ = nullptr;
};

// QUIC connection wrapper using ngtcp2
class QuicConnection {
 public:
  QuicConnection(core::Reactor* reactor, QuicTlsContext* tls_ctx,
                 const std::string& host, uint16_t port,
                 const ChromeQuicProfile& profile = {});
  ~QuicConnection();

  // Non-copyable, non-movable
  QuicConnection(const QuicConnection&) = delete;
  QuicConnection& operator=(const QuicConnection&) = delete;
  QuicConnection(QuicConnection&&) = delete;
  QuicConnection& operator=(QuicConnection&&) = delete;

  // Connect to server (ip must be resolved already)
  bool Connect(std::string_view ip, bool ipv6 = false);

  // Open a new bidirectional stream
  // Returns stream ID or -1 on error
  int64_t OpenBidiStream();

  // Open a new unidirectional stream
  int64_t OpenUniStream();

  // Write data to stream
  // Returns number of bytes written or -1 on error
  ssize_t WriteStream(int64_t stream_id, const uint8_t* data, size_t len,
                      bool fin = false);

  // Write data using span
  ssize_t WriteStream(int64_t stream_id, std::span<const uint8_t> data,
                      bool fin = false) {
    return WriteStream(stream_id, data.data(), data.size(), fin);
  }

  // Shutdown stream (send FIN)
  bool ShutdownStream(int64_t stream_id);

  // Close stream with error code
  bool ResetStream(int64_t stream_id, uint64_t app_error_code);

  // Close connection with error code
  void Close(uint64_t error_code = 0, const std::string& reason = "");

  // State accessors
  QuicState state() const { return state_; }
  bool IsConnected() const { return state_ == QuicState::kConnected; }
  bool IsClosed() const {
    return state_ == QuicState::kClosed || state_ == QuicState::kError;
  }

  // Set callbacks
  void SetConnectCallback(QuicConnectCallback cb) {
    on_connect_ = std::move(cb);
  }
  void SetStreamDataCallback(QuicStreamDataCallback cb) {
    on_stream_data_ = std::move(cb);
  }
  void SetStreamOpenCallback(QuicStreamOpenCallback cb) {
    on_stream_open_ = std::move(cb);
  }
  void SetStreamCloseCallback(QuicStreamCloseCallback cb) {
    on_stream_close_ = std::move(cb);
  }
  void SetErrorCallback(QuicErrorCallback cb) { on_error_ = std::move(cb); }

  // Get the ALPN protocol negotiated (e.g., "h3")
  std::string_view negotiated_alpn() const { return negotiated_alpn_; }

  // Access underlying ngtcp2 connection (for advanced use)
  ngtcp2_conn* conn() { return conn_; }

 private:
  // Internal initialization
  bool InitializeConnection(const sockaddr* addr, socklen_t addr_len);
  bool InitializeTls();

  // Event handlers
  void OnUdpReceive(const uint8_t* data, size_t len, const sockaddr* addr,
                    socklen_t addr_len);
  void OnTimer();

  // ngtcp2 callbacks
  static int OnReceiveStreamData(ngtcp2_conn* conn, uint32_t flags,
                                  int64_t stream_id, uint64_t offset,
                                  const uint8_t* data, size_t datalen,
                                  void* user_data, void* stream_user_data);
  static int OnAckedStreamDataOffset(ngtcp2_conn* conn, int64_t stream_id,
                                      uint64_t offset, uint64_t datalen,
                                      void* user_data, void* stream_user_data);
  static int OnStreamOpen(ngtcp2_conn* conn, int64_t stream_id,
                          void* user_data);
  static int OnStreamClose(ngtcp2_conn* conn, uint32_t flags,
                            int64_t stream_id, uint64_t app_error_code,
                            void* user_data, void* stream_user_data);
  static int OnStreamReset(ngtcp2_conn* conn, int64_t stream_id,
                            uint64_t final_size, uint64_t app_error_code,
                            void* user_data, void* stream_user_data);
  static int OnHandshakeCompleted(ngtcp2_conn* conn, void* user_data);
  static int OnHandshakeConfirmed(ngtcp2_conn* conn, void* user_data);
  static void OnRand(uint8_t* dest, size_t destlen,
                     const ngtcp2_rand_ctx* rand_ctx);
  static int OnGetNewConnectionId(ngtcp2_conn* conn, ngtcp2_cid* cid,
                                   uint8_t* token, size_t cidlen,
                                   void* user_data);
  static int OnRemoveConnectionId(ngtcp2_conn* conn, const ngtcp2_cid* cid,
                                   void* user_data);
  static int OnExtendMaxStreams(ngtcp2_conn* conn, uint64_t max_streams,
                                 void* user_data);
  static int OnGetPathChallengeData(ngtcp2_conn* conn, uint8_t* data,
                                     void* user_data);

  // Crypto callbacks for ngtcp2_crypto_conn_ref
  static ngtcp2_conn* GetConn(ngtcp2_crypto_conn_ref* conn_ref);

  // Send pending data
  int SendPackets();
  int WritePackets();

  // Timer handling
  void UpdateTimer();

  core::Reactor* reactor_;
  QuicTlsContext* tls_ctx_;
  std::string host_;
  uint16_t port_;
  ChromeQuicProfile profile_;

  // QUIC connection
  ngtcp2_conn* conn_ = nullptr;
  ngtcp2_crypto_conn_ref conn_ref_;

  // TLS
  SSL* ssl_ = nullptr;

  // UDP socket
  std::unique_ptr<core::UdpSocket> udp_socket_;

  // Timer for retransmission/keepalive
  uv_timer_t timer_;
  bool timer_initialized_ = false;
  bool timer_active_ = false;

  // Connection state
  QuicState state_ = QuicState::kIdle;
  std::string negotiated_alpn_;

  // Remote address
  sockaddr_storage remote_addr_{};
  socklen_t remote_addr_len_ = 0;

  // Local address
  sockaddr_storage local_addr_{};
  socklen_t local_addr_len_ = 0;

  // Send buffer
  std::array<uint8_t, 1500> send_buffer_;

  // Callbacks
  QuicConnectCallback on_connect_;
  QuicStreamDataCallback on_stream_data_;
  QuicStreamOpenCallback on_stream_open_;
  QuicStreamCloseCallback on_stream_close_;
  QuicErrorCallback on_error_;

  // Last error info
  std::string last_error_;
};

}  // namespace quic
}  // namespace holytls

#endif  // HOLYTLS_QUIC_QUIC_CONNECTION_H_

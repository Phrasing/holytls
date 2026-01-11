// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_CONFIG_H_
#define HOLYTLS_CONFIG_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace holytls {

// Chrome version to impersonate
enum class ChromeVersion {
  kChrome120 = 120,
  kChrome125 = 125,
  kChrome130 = 130,
  kChrome131 = 131,
  kChrome143 = 143,
  kLatest = kChrome143,
};

// TLS configuration for Chrome impersonation
struct TlsConfig {
  // Chrome version for TLS fingerprint (JA3/JA4)
  ChromeVersion chrome_version = ChromeVersion::kLatest;

  // Certificate verification
  bool verify_certificates = true;
  std::string ca_bundle_path;  // Empty = system default

  // Client certificate authentication (optional)
  std::string client_cert_path;
  std::string client_key_path;

  // Session resumption
  bool enable_session_cache = true;
  size_t session_cache_size = 1024;

  // 0-RTT Early Data (Chrome enables this by default)
  bool enable_early_data = true;

  // Chrome 110+ randomizes TLS extension order
  bool permute_extensions = true;

  // Override specific cipher suites (empty = use Chrome profile)
  std::vector<std::string> cipher_override;
};

// HTTP/2 configuration for fingerprint matching
struct Http2Config {
  // Chrome version for HTTP/2 fingerprint (SETTINGS, header order)
  ChromeVersion chrome_version = ChromeVersion::kLatest;

  // Override SETTINGS values (nullopt = use Chrome defaults)
  std::optional<uint32_t> header_table_size;
  std::optional<uint32_t> max_concurrent_streams;
  std::optional<uint32_t> initial_window_size;
  std::optional<uint32_t> max_frame_size;
  std::optional<uint32_t> max_header_list_size;

  // Connection-level flow control window
  std::optional<uint32_t> connection_window_size;
};

// Connection pool configuration
struct PoolConfig {
  // Per-host connection limits (Chrome uses 6)
  size_t max_connections_per_host = 6;

  // Global connection limit
  size_t max_total_connections = 256;

  // Timeouts
  std::chrono::milliseconds idle_timeout{300000};    // 5 minutes
  std::chrono::milliseconds connect_timeout{30000};  // 30 seconds

  // HTTP/2 multiplexing
  bool enable_multiplexing = true;
  size_t max_streams_per_connection = 100;

  // Connection keep-alive
  std::chrono::milliseconds keepalive_interval{45000};  // 45 seconds
};

// Threading configuration
struct ThreadConfig {
  // Number of worker threads (0 = auto-detect CPU cores)
  size_t num_workers = 0;

  // Pin worker threads to CPU cores
  bool pin_to_cores = false;
};

// DNS configuration
struct DnsConfig {
  // Custom DNS servers (empty = system default)
  std::vector<std::string> servers;

  // Resolution timeout
  std::chrono::milliseconds timeout{5000};

  // DNS cache TTL (0 = respect server TTL)
  std::chrono::seconds cache_ttl{60};
};

// Main client configuration
struct ClientConfig {
  TlsConfig tls;
  Http2Config http2;
  PoolConfig pool;
  ThreadConfig threads;
  DnsConfig dns;

  // Default request timeout
  std::chrono::milliseconds default_timeout{30000};

  // User-Agent string (empty = auto-generate from chrome_version)
  std::string user_agent;

  // Follow redirects
  bool follow_redirects = true;
  int max_redirects = 10;

  // Automatic response body decompression (br, gzip, zstd, deflate)
  bool auto_decompress = true;

  // Factory methods for common configurations
  static ClientConfig Chrome120();
  static ClientConfig Chrome125();
  static ClientConfig Chrome130();
  static ClientConfig Chrome131();
  static ClientConfig Chrome143();
  static ClientConfig ChromeLatest();
};

// Runtime statistics
struct ClientStats {
  // Connection statistics
  size_t total_connections = 0;
  size_t active_connections = 0;
  size_t idle_connections = 0;
  size_t connections_created = 0;
  size_t connections_reused = 0;
  size_t connections_failed = 0;

  // Request statistics
  size_t requests_sent = 0;
  size_t requests_completed = 0;
  size_t requests_failed = 0;
  size_t requests_timeout = 0;

  // Data transfer
  uint64_t bytes_sent = 0;
  uint64_t bytes_received = 0;

  // Latency percentiles (milliseconds)
  double avg_dns_time_ms = 0.0;
  double avg_connect_time_ms = 0.0;
  double avg_tls_time_ms = 0.0;
  double avg_ttfb_ms = 0.0;
  double avg_total_time_ms = 0.0;
};

}  // namespace holytls

#endif  // HOLYTLS_CONFIG_H_

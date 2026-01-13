// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/client.h"

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <variant>

#include "holytls/config.h"
#include "holytls/core/reactor_manager.h"
#include "holytls/http/alt_svc_cache.h"
#include "holytls/http/cookie_jar.h"
#include "holytls/pool/connection_pool.h"
#include "holytls/pool/host_pool.h"
#include "holytls/tls/tls_context.h"
#include "holytls/util/dns_resolver.h"
#include "holytls/util/url_parser.h"

#if defined(HOLYTLS_BUILD_QUIC)
#include "holytls/http2/h2_stream.h"
#include "holytls/pool/quic_pooled_connection.h"
#define HOLYTLS_QUIC_AVAILABLE 1
#else
#define HOLYTLS_QUIC_AVAILABLE 0
#endif

namespace holytls {

// ClientConfig factory methods
ClientConfig ClientConfig::Chrome120() {
  ClientConfig config;
  config.tls.chrome_version = ChromeVersion::kChrome120;
  config.http2.chrome_version = ChromeVersion::kChrome120;
  return config;
}

ClientConfig ClientConfig::Chrome125() {
  ClientConfig config;
  config.tls.chrome_version = ChromeVersion::kChrome125;
  config.http2.chrome_version = ChromeVersion::kChrome125;
  return config;
}

ClientConfig ClientConfig::Chrome130() {
  ClientConfig config;
  config.tls.chrome_version = ChromeVersion::kChrome130;
  config.http2.chrome_version = ChromeVersion::kChrome130;
  return config;
}

ClientConfig ClientConfig::Chrome131() {
  ClientConfig config;
  config.tls.chrome_version = ChromeVersion::kChrome131;
  config.http2.chrome_version = ChromeVersion::kChrome131;
  return config;
}

ClientConfig ClientConfig::Chrome143() {
  ClientConfig config;
  config.tls.chrome_version = ChromeVersion::kChrome143;
  config.http2.chrome_version = ChromeVersion::kChrome143;
  return config;
}

ClientConfig ClientConfig::ChromeLatest() { return Chrome143(); }

// Method to string conversion
std::string_view MethodToString(Method method) {
  switch (method) {
    case Method::kGet:
      return "GET";
    case Method::kPost:
      return "POST";
    case Method::kPut:
      return "PUT";
    case Method::kDelete:
      return "DELETE";
    case Method::kPatch:
      return "PATCH";
    case Method::kHead:
      return "HEAD";
    case Method::kOptions:
      return "OPTIONS";
  }
  return "GET";
}

// Request implementation
Request& Request::SetMethod(Method m) {
  method = m;
  return *this;
}

Request& Request::SetUrl(std::string_view u) {
  url = std::string(u);
  return *this;
}

Request& Request::SetHeader(std::string_view name, std::string_view value) {
  headers.push_back({std::string(name), std::string(value)});
  return *this;
}

Request& Request::SetBody(const uint8_t* data, size_t len) {
  body.assign(data, data + len);
  return *this;
}

Request& Request::SetBody(std::string_view b) {
  body.assign(b.begin(), b.end());
  return *this;
}

Request& Request::SetTimeout(std::chrono::milliseconds t) {
  timeout = t;
  return *this;
}

Request& Request::SetHeaderOrder(std::span<const std::string_view> order) {
  header_order = order;
  return *this;
}

// Response implementation
std::string_view Response::GetHeader(std::string_view name) const {
  for (const auto& header : headers) {
    if (header.name == name) {
      return header.value;
    }
  }
  return "";
}

bool Response::HasHeader(std::string_view name) const {
  for (const auto& header : headers) {
    if (header.name == name) {
      return true;
    }
  }
  return false;
}

std::string_view Response::body_string() const {
  return std::string_view(reinterpret_cast<const char*>(body.data()),
                          body.size());
}

size_t Response::content_length() const {
  auto cl = GetHeader("content-length");
  if (cl.empty()) {
    return body.size();
  }
  return static_cast<size_t>(std::stoul(std::string(cl)));
}

// Pending request in queue
struct PendingRequest {
  Request request;
  util::ParsedUrl parsed_url;
  ResponseCallback callback;
  ProgressCallback progress;
};

// HttpClient implementation
class HttpClient::Impl {
 public:
  explicit Impl(const ClientConfig& config)
      : config_(config), reactor_manager_(MakeReactorConfig(config)) {
    // Initialize TLS factory (two-phase init)
    if (!tls_factory_.Initialize(MakeTlsConfig(config))) {
      // TLS initialization failed - error available via tls_factory_.last_error()
      // In practice, this rarely fails
    }

    // Create pool config from client config
    pool::ConnectionPoolConfig pool_config;
    pool_config.max_connections_per_host = config.pool.max_connections_per_host;
    pool_config.max_total_connections = config.pool.max_total_connections;
    pool_config.idle_timeout_ms =
        static_cast<uint64_t>(config.pool.idle_timeout.count());
    pool_config.connect_timeout_ms =
        static_cast<uint64_t>(config.pool.connect_timeout.count());
    pool_config.enable_multiplexing = config.pool.enable_multiplexing;
    pool_config.max_streams_per_connection =
        config.pool.max_streams_per_connection;
    pool_config.proxy = config.proxy;
    pool_config.protocol = config.protocol;
    pool_config.http3 = config.http3;

    // Initialize reactor manager
    reactor_manager_.Initialize(&tls_factory_, pool_config);

    // Store cookie jar reference
    cookie_jar_ = config.cookie_jar;

    // Store Alt-Svc cache reference
    alt_svc_cache_ = config.alt_svc_cache;
    alt_svc_enabled_ = config.alt_svc.enabled;
  }

  ~Impl() { Stop(); }

  void SendAsync(Request request, ResponseCallback callback,
                 ProgressCallback progress = nullptr) {
    // Parse URL
    util::ParsedUrl parsed;
    if (!util::ParseUrl(request.url, &parsed)) {
      if (callback) {
        callback(Response{}, Error{ErrorCode::kInvalidUrl, "Failed to parse URL"});
      }
      return;
    }

    // Only HTTPS is supported
    if (!parsed.IsHttps()) {
      if (callback) {
        callback(Response{}, Error{ErrorCode::kInvalidUrl, "Only HTTPS is supported"});
      }
      return;
    }

    auto* ctx = reactor_manager_.GetReactorForHost(parsed.host, parsed.port);
    if (!ctx) {
      if (callback) {
        callback(Response{}, Error{ErrorCode::kInternal, "No reactor available"});
      }
      return;
    }

    // Post request processing to the reactor thread
    reactor_manager_.Post(
        ctx->index, [this, ctx, request = std::move(request),
                     parsed = std::move(parsed), callback = std::move(callback),
                     progress = std::move(progress)]() mutable {
          ProcessRequest(ctx, std::move(request), std::move(parsed),
                         std::move(callback), std::move(progress));
        });
  }

  void Run() {
    running_.store(true, std::memory_order_release);
    reactor_manager_.Start();

    // Background threads handle the reactors; main thread just waits
    while (running_.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  void RunOnce() {
    if (!reactor_manager_.IsRunning()) {
      reactor_manager_.Start();
      // Give background threads time to start
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Background threads handle the work; yield to let them run
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  void Stop() {
    running_.store(false, std::memory_order_release);
    reactor_manager_.Stop();
  }

  bool IsRunning() const { return running_.load(std::memory_order_acquire); }

  ClientStats GetStats() const {
    ClientStats stats;
    stats.total_connections = reactor_manager_.TotalConnections();
    stats.active_connections = reactor_manager_.TotalConnections();
    stats.requests_sent = requests_sent_.load(std::memory_order_relaxed);
    stats.requests_completed =
        requests_completed_.load(std::memory_order_relaxed);
    stats.requests_failed = requests_failed_.load(std::memory_order_relaxed);
    return stats;
  }

  ChromeVersion GetChromeVersion() const { return config_.tls.chrome_version; }

 private:
  static TlsConfig MakeTlsConfig(const ClientConfig& config) {
    return config.tls;
  }

  static core::ReactorManagerConfig MakeReactorConfig(
      const ClientConfig& config) {
    core::ReactorManagerConfig rc;
    rc.num_reactors = config.threads.num_workers;
    rc.pin_to_cores = config.threads.pin_to_cores;
    return rc;
  }

  void ProcessRequest(core::ReactorContext* ctx, Request request,
                      util::ParsedUrl parsed, ResponseCallback callback,
                      ProgressCallback /*progress*/) {
    // Copy host before moving parsed into lambda (avoids reference
    // invalidation)
    std::string host = parsed.host;
    ctx->dns_resolver->ResolveAsync(
        host, [this, ctx, request = std::move(request),
               parsed = std::move(parsed), callback = std::move(callback)](
                  const std::vector<util::ResolvedAddress>& addresses,
                  const std::string& error) mutable {
          if (!error.empty() || addresses.empty()) {
            if (callback) {
              callback(
                  Response{},
                  Error{ErrorCode::kDns, error.empty() ? "No addresses found" : error});
            }
            requests_failed_.fetch_add(1, std::memory_order_relaxed);
            return;
          }

          // Protocol-agnostic connection acquisition
          auto* pool = ctx->connection_pool.get();
          auto any_conn = pool->AcquireAnyConnection(parsed.host, parsed.port);

          // Check if we got a connection
          bool has_connection = std::visit(
              [](auto* c) -> bool { return c != nullptr; }, any_conn);

          if (!has_connection) {
            // Need to create a new connection based on protocol preference
            const auto& addr = addresses[0];

#if HOLYTLS_QUIC_AVAILABLE
            // Determine if we should try QUIC:
            // 1. If kHttp3Only - always try QUIC
            // 2. If kAuto and Alt-Svc cache indicates H3 support - try QUIC
            // 3. If kAuto and pool has QUIC enabled - try QUIC
            bool should_try_quic = pool->IsQuicEnabled();

            // Check Alt-Svc cache for H3 hint when in Auto mode
            if (config_.protocol == ProtocolPreference::kAuto &&
                alt_svc_cache_ && alt_svc_enabled_) {
              if (alt_svc_cache_->HasHttp3Support(parsed.host, parsed.port)) {
                should_try_quic = true;
              }
            }

            if (should_try_quic) {
              // Try QUIC first
              auto* quic_pool =
                  pool->GetOrCreateQuicHostPool(parsed.host, parsed.port);
              if (quic_pool &&
                  quic_pool->CreateConnection(addr.ip, addr.is_ipv6)) {
                // Queue request for when QUIC connection is ready
                QueueRequest(ctx, parsed, addresses, std::move(request),
                             std::move(callback), true);
                return;
              }
              // QUIC failed, mark in cache and fall through to TCP if allowed
              if (alt_svc_cache_) {
                alt_svc_cache_->MarkHttp3Failed(parsed.host, parsed.port);
              }
              if (config_.protocol == ProtocolPreference::kHttp3Only) {
                if (callback) {
                  callback(Response{},
                           Error{ErrorCode::kConnection,
                                 "Failed to create QUIC connection"});
                }
                requests_failed_.fetch_add(1, std::memory_order_relaxed);
                return;
              }
            }
#endif

            // Create TCP connection
            auto* host_pool =
                pool->GetOrCreateHostPool(parsed.host, parsed.port);
            if (!host_pool) {
              if (callback) {
                callback(Response{},
                         Error{ErrorCode::kConnection, "Failed to create host pool"});
              }
              requests_failed_.fetch_add(1, std::memory_order_relaxed);
              return;
            }

            if (!host_pool->CreateConnection(addr.ip, addr.is_ipv6)) {
              if (callback) {
                callback(Response{},
                         Error{ErrorCode::kConnection, "Failed to create connection"});
              }
              requests_failed_.fetch_add(1, std::memory_order_relaxed);
              return;
            }

            // Queue request for when TCP connection is ready
            QueueRequest(ctx, parsed, addresses, std::move(request),
                         std::move(callback), false);
            return;
          }

          // Send request on existing connection
          std::visit(
              [this, &ctx, &parsed, &request, &callback](auto* conn) {
                if constexpr (std::is_same_v<decltype(conn),
                                             pool::PooledConnection*>) {
                  SendOnTcpConnection(ctx, conn, parsed, std::move(request),
                                      std::move(callback));
                }
#if HOLYTLS_QUIC_AVAILABLE
                else if constexpr (std::is_same_v<
                                       decltype(conn),
                                       pool::QuicPooledConnection*>) {
                  SendOnQuicConnection(ctx, conn, parsed, std::move(request),
                                       std::move(callback));
                }
#endif
              },
              any_conn);
        });
  }

  void QueueRequest(core::ReactorContext* ctx, const util::ParsedUrl& parsed,
                    const std::vector<util::ResolvedAddress>& addresses,
                    Request request, ResponseCallback callback, bool use_quic,
                    int retry_count = 0) {
    constexpr int kMaxRetries = 50;          // Max retries (50 * 100ms = 5s total)
    constexpr int kRetryDelayMs = 100;       // Delay between retries

    // Schedule a delayed retry using a timer
    // Note: Capture kMaxRetries for use in lambda
    auto retry_fn = [this, ctx, parsed, addresses, request = std::move(request),
                     callback = std::move(callback), use_quic,
                     retry_count, kMaxRetries]() mutable {
      auto* pool = ctx->connection_pool.get();

#if HOLYTLS_QUIC_AVAILABLE
      if (use_quic) {
        auto* quic_conn = pool->AcquireQuicConnection(parsed.host, parsed.port);
        if (quic_conn && quic_conn->IsConnected()) {
          SendOnQuicConnection(ctx, quic_conn, parsed, std::move(request),
                               std::move(callback));
          return;
        }

        // Check if we should fall back to TCP:
        // 1. QUIC connection is in error/closed state, or
        // 2. We've exceeded the QUIC retry limit (10 retries = 1 second)
        bool quic_failed = (quic_conn && quic_conn->quic &&
                            quic_conn->quic->IsClosed()) ||
                           (retry_count >= 10);

        if (quic_failed && config_.protocol != ProtocolPreference::kHttp3Only) {
          // Fall back to TCP - mark H3 failure and cleanup QUIC resources
          if (alt_svc_cache_) {
            alt_svc_cache_->MarkHttp3Failed(parsed.host, parsed.port);
          }

          // Remove the failed QUIC host pool to properly close handles
          // (async cleanup - completion callback not needed for fallback)
          pool->RemoveQuicHostPool(parsed.host, parsed.port);

          // Create TCP connection before queuing (like ProcessRequest does)
          auto* host_pool = pool->GetOrCreateHostPool(parsed.host, parsed.port);
          if (host_pool && !addresses.empty()) {
            const auto& addr = addresses[0];
            host_pool->CreateConnection(addr.ip, addr.is_ipv6);
          }

          // Continue with TCP - keep retry count for overall timeout
          // (40 more retries = 4 more seconds for TCP to connect)
          QueueRequest(ctx, parsed, addresses, std::move(request),
                       std::move(callback), false, retry_count);
          return;
        }
      } else
#endif
      {
        (void)use_quic;  // Suppress unused warning when QUIC not available
        auto* pooled = pool->AcquireTcpConnection(parsed.host, parsed.port);
        if (pooled && pooled->connection && pooled->connection->IsConnected()) {
          SendOnTcpConnection(ctx, pooled, parsed, std::move(request),
                              std::move(callback));
          return;
        }
      }

      if (retry_count < kMaxRetries) {
        // Retry after delay
        QueueRequest(ctx, parsed, addresses, std::move(request),
                     std::move(callback), use_quic, retry_count + 1);
      } else {
        // Max retries exceeded
        if (callback) {
          callback(Response{},
                   Error{ErrorCode::kTimeout, "Connection timeout after retries"});
        }
        requests_failed_.fetch_add(1, std::memory_order_relaxed);
      }
    };

    // Use libuv timer for the delay
    if (retry_count > 0) {
      auto* timer = new uv_timer_t;
      timer->data = new std::function<void()>(std::move(retry_fn));
      uv_timer_init(ctx->reactor->loop(), timer);
      uv_timer_start(
          timer,
          [](uv_timer_t* handle) {
            auto* fn = static_cast<std::function<void()>*>(handle->data);
            (*fn)();
            delete fn;
            uv_close(reinterpret_cast<uv_handle_t*>(handle),
                     [](uv_handle_t* h) { delete reinterpret_cast<uv_timer_t*>(h); });
          },
          kRetryDelayMs, 0);
    } else {
      // First attempt - try immediately via Post
      ctx->reactor->Post(std::move(retry_fn));
    }
  }

  void SendOnTcpConnection(core::ReactorContext* ctx,
                           pool::PooledConnection* pooled,
                           const util::ParsedUrl& parsed, Request request,
                           ResponseCallback callback) {
    requests_sent_.fetch_add(1, std::memory_order_relaxed);

    // Convert headers to connection format
    std::vector<std::pair<std::string, std::string>> conn_headers;
    for (const auto& h : request.headers) {
      conn_headers.emplace_back(h.name, h.value);
    }

    // Add cookies from cookie jar if available
    if (cookie_jar_) {
      std::string cookie_header = cookie_jar_->GetCookieHeader(request.url);
      if (!cookie_header.empty()) {
        conn_headers.emplace_back("cookie", std::move(cookie_header));
      }
    }

    // Share callback between success and error handlers to avoid double-move
    auto shared_cb = std::make_shared<ResponseCallback>(std::move(callback));

    // Capture URL and host/port for cookie and Alt-Svc processing
    std::string request_url = request.url;
    std::string origin_host = parsed.host;
    uint16_t origin_port = parsed.port;

    pooled->connection->SendRequest(
        std::string(MethodToString(request.method)), parsed.PathWithQuery(),
        conn_headers, request.header_order,
        [this, ctx, pooled, shared_cb, request_url = std::move(request_url),
         origin_host = std::move(origin_host),
         origin_port](const core::Response& core_resp) mutable {
          // Convert headers
          Headers resp_headers;
          for (size_t i = 0; i < core_resp.headers.size(); ++i) {
            resp_headers.push_back({std::string(core_resp.headers.name(i)),
                                    std::string(core_resp.headers.value(i))});
          }

          // Process Set-Cookie headers if cookie jar is available
          if (cookie_jar_) {
            for (size_t i = 0; i < core_resp.headers.size(); ++i) {
              std::string_view name = core_resp.headers.name(i);
              if (name == "set-cookie") {
                cookie_jar_->ProcessSetCookie(request_url, core_resp.headers.value(i));
              }
            }
          }

          // Process Alt-Svc headers for HTTP/3 discovery
          if (alt_svc_cache_ && alt_svc_enabled_) {
            for (size_t i = 0; i < core_resp.headers.size(); ++i) {
              std::string_view name = core_resp.headers.name(i);
              if (name == "alt-svc") {
                alt_svc_cache_->ProcessAltSvc(origin_host, origin_port,
                                               core_resp.headers.value(i));
              }
            }
          }

          // Build response
          Response response(core_resp.status_code, std::move(resp_headers),
                            core_resp.body);

          // Release connection back to pool
          ctx->connection_pool->ReleaseTcpConnection(pooled);

          requests_completed_.fetch_add(1, std::memory_order_relaxed);

          if (*shared_cb) {
            (*shared_cb)(std::move(response), Error{});
          }
        },
        [this, ctx, pooled, shared_cb](const std::string& error) mutable {
          // Mark connection as failed
          ctx->connection_pool->RemoveTcpConnection(pooled);

          requests_failed_.fetch_add(1, std::memory_order_relaxed);

          if (*shared_cb) {
            (*shared_cb)(Response{}, Error{ErrorCode::kConnection, error});
          }
        });
  }

#if HOLYTLS_QUIC_AVAILABLE
  void SendOnQuicConnection(core::ReactorContext* ctx,
                            pool::QuicPooledConnection* quic_conn,
                            const util::ParsedUrl& parsed, Request request,
                            ResponseCallback callback) {
    requests_sent_.fetch_add(1, std::memory_order_relaxed);

    // Build H2Headers from request
    http2::H2Headers h2_headers;
    h2_headers.method = std::string(MethodToString(request.method));
    h2_headers.authority = parsed.host;
    if (parsed.port != 443) {
      h2_headers.authority += ":" + std::to_string(parsed.port);
    }
    h2_headers.path = parsed.PathWithQuery();
    h2_headers.scheme = "https";

    // Add custom headers
    for (const auto& h : request.headers) {
      h2_headers.headers.emplace_back(h.name, h.value);
    }

    // Add cookies from cookie jar if available
    if (cookie_jar_) {
      std::string cookie_header = cookie_jar_->GetCookieHeader(request.url);
      if (!cookie_header.empty()) {
        h2_headers.headers.emplace_back("cookie", std::move(cookie_header));
      }
    }

    // Share callback between success and error handlers
    auto shared_cb = std::make_shared<ResponseCallback>(std::move(callback));
    std::string request_url = request.url;
    std::string origin_host = parsed.host;
    uint16_t origin_port = parsed.port;

    // Create response builder
    auto response_builder = std::make_shared<Response>();
    auto body_buffer = std::make_shared<std::vector<uint8_t>>();

    // Set up stream callbacks
    http2::H2StreamCallbacks stream_callbacks;

    stream_callbacks.on_headers = [this, response_builder, request_url,
                                   origin_host,
                                   origin_port](int /*stream_id*/,
                                                const http2::PackedHeaders& packed) {
      // Get status code from PackedHeaders (set via SetStatus in H3Session)
      response_builder->status_code = packed.status_code();

      // Extract regular headers
      for (size_t i = 0; i < packed.size(); ++i) {
        std::string_view name = packed.name(i);
        std::string_view value = packed.value(i);
        if (!name.empty() && name[0] != ':') {
          // Regular header (skip pseudo-headers)
          response_builder->headers.push_back(
              {std::string(name), std::string(value)});

          // Process Set-Cookie headers if cookie jar is available
          if (cookie_jar_ && name == "set-cookie") {
            cookie_jar_->ProcessSetCookie(request_url, value);
          }

          // Process Alt-Svc headers (even over H3, server may advertise)
          if (alt_svc_cache_ && alt_svc_enabled_ && name == "alt-svc") {
            alt_svc_cache_->ProcessAltSvc(origin_host, origin_port, value);
          }
        }
      }
    };

    stream_callbacks.on_data = [body_buffer](int /*stream_id*/,
                                             const uint8_t* data, size_t len) {
      body_buffer->insert(body_buffer->end(), data, data + len);
    };

    stream_callbacks.on_close = [this, ctx, quic_conn, shared_cb,
                                 response_builder, body_buffer, origin_host,
                                 origin_port](int /*stream_id*/,
                                              uint32_t error_code) {
      if (error_code == 0) {
        // Success - clear any H3 failure flag
        if (alt_svc_cache_) {
          alt_svc_cache_->ClearHttp3Failure(origin_host, origin_port);
        }

        response_builder->body = std::move(*body_buffer);
        ctx->connection_pool->ReleaseQuicConnection(quic_conn);
        requests_completed_.fetch_add(1, std::memory_order_relaxed);

        if (*shared_cb) {
          (*shared_cb)(std::move(*response_builder), Error{});
        }
      } else {
        // Error - mark H3 as failed for this origin
        if (alt_svc_cache_) {
          alt_svc_cache_->MarkHttp3Failed(origin_host, origin_port);
        }

        ctx->connection_pool->RemoveQuicConnection(quic_conn);
        requests_failed_.fetch_add(1, std::memory_order_relaxed);

        if (*shared_cb) {
          (*shared_cb)(Response{},
                       Error{ErrorCode::kConnection,
                             "HTTP/3 stream error: " + std::to_string(error_code)});
        }
      }
    };

    // Submit request using H3Session
    const uint8_t* body_data =
        request.body.empty() ? nullptr : request.body.data();
    size_t body_len = request.body.size();

    int64_t stream_id =
        quic_conn->SubmitRequest(h2_headers, stream_callbacks, body_data, body_len);

    if (stream_id < 0) {
      ctx->connection_pool->RemoveQuicConnection(quic_conn);
      requests_failed_.fetch_add(1, std::memory_order_relaxed);

      if (*shared_cb) {
        (*shared_cb)(Response{},
                     Error{ErrorCode::kConnection, "Failed to submit HTTP/3 request"});
      }
      return;
    }

    // Flush pending data to QUIC
    quic_conn->FlushPendingData();
  }
#endif

  ClientConfig config_;
  tls::TlsContextFactory tls_factory_;
  core::ReactorManager reactor_manager_;
  std::atomic<bool> running_{false};

  // Cookie jar (borrowed pointer, not owned)
  http::CookieJar* cookie_jar_ = nullptr;

  // Alt-Svc cache for HTTP/3 discovery (borrowed pointer, not owned)
  http::AltSvcCache* alt_svc_cache_ = nullptr;
  bool alt_svc_enabled_ = true;

  // Statistics
  std::atomic<size_t> requests_sent_{0};
  std::atomic<size_t> requests_completed_{0};
  std::atomic<size_t> requests_failed_{0};
};

HttpClient::HttpClient(const ClientConfig& config)
    : impl_(std::make_unique<Impl>(config)) {}

HttpClient::~HttpClient() = default;

void HttpClient::SendAsync(Request request, ResponseCallback callback) {
  impl_->SendAsync(std::move(request), std::move(callback));
}

void HttpClient::SendAsync(Request request, ResponseCallback callback,
                           ProgressCallback progress) {
  impl_->SendAsync(std::move(request), std::move(callback),
                   std::move(progress));
}

void HttpClient::Run() { impl_->Run(); }

void HttpClient::RunOnce() { impl_->RunOnce(); }

void HttpClient::Stop() { impl_->Stop(); }

bool HttpClient::IsRunning() const { return impl_->IsRunning(); }

ClientStats HttpClient::GetStats() const { return impl_->GetStats(); }

ChromeVersion HttpClient::GetChromeVersion() const {
  return impl_->GetChromeVersion();
}

}  // namespace holytls

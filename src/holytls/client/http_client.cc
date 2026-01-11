// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/client.h"

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "holytls/config.h"
#include "holytls/core/reactor_manager.h"
#include "holytls/pool/connection_pool.h"
#include "holytls/pool/host_pool.h"
#include "holytls/tls/tls_context.h"
#include "holytls/util/dns_resolver.h"
#include "holytls/util/url_parser.h"

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
Request& Request::SetMethod(Method method) {
  method_ = method;
  return *this;
}

Request& Request::SetUrl(std::string_view url) {
  url_ = std::string(url);
  return *this;
}

Request& Request::SetHeader(std::string_view name, std::string_view value) {
  headers_.push_back({std::string(name), std::string(value)});
  return *this;
}

Request& Request::SetBody(const uint8_t* data, size_t len) {
  body_.assign(data, data + len);
  return *this;
}

Request& Request::SetBody(std::string_view body) {
  body_.assign(body.begin(), body.end());
  return *this;
}

Request& Request::SetTimeout(std::chrono::milliseconds timeout) {
  timeout_ = timeout;
  return *this;
}

// Response implementation
std::string_view Response::GetHeader(std::string_view name) const {
  for (const auto& header : headers_) {
    if (header.name == name) {
      return header.value;
    }
  }
  return "";
}

bool Response::HasHeader(std::string_view name) const {
  for (const auto& header : headers_) {
    if (header.name == name) {
      return true;
    }
  }
  return false;
}

std::string_view Response::body_string() const {
  return std::string_view(reinterpret_cast<const char*>(body_.data()),
                          body_.size());
}

size_t Response::content_length() const {
  auto cl = GetHeader("content-length");
  if (cl.empty()) {
    return body_.size();
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
      : config_(config),
        tls_factory_(MakeTlsConfig(config)),
        reactor_manager_(MakeReactorConfig(config)) {
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

    // Initialize reactor manager
    reactor_manager_.Initialize(&tls_factory_, pool_config);
  }

  ~Impl() { Stop(); }

  void SendAsync(Request request, ResponseCallback callback,
                 ProgressCallback progress = nullptr) {
    // Parse URL
    util::ParsedUrl parsed;
    if (!util::ParseUrl(request.url(), &parsed)) {
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

          // Get or create connection
          auto* pool = ctx->connection_pool.get();
          auto* pooled = pool->AcquireConnection(parsed.host, parsed.port);

          if (!pooled) {
            // Need to create a new connection
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

            // Create connection with first resolved address
            const auto& addr = addresses[0];
            if (!host_pool->CreateConnection(addr.ip, addr.is_ipv6)) {
              if (callback) {
                callback(Response{},
                         Error{ErrorCode::kConnection, "Failed to create connection"});
              }
              requests_failed_.fetch_add(1, std::memory_order_relaxed);
              return;
            }

            // Queue request for when connection is ready
            QueueRequest(ctx, parsed, std::move(request), std::move(callback));
            return;
          }

          // Send request on existing connection
          SendOnConnection(ctx, pooled, parsed, std::move(request),
                           std::move(callback));
        });
  }

  void QueueRequest(core::ReactorContext* ctx, const util::ParsedUrl& parsed,
                    Request request, ResponseCallback callback) {
    // For simplicity, try again shortly after connection might be ready
    // A more sophisticated implementation would use a proper request queue
    ctx->reactor->Post([this, ctx, parsed, request = std::move(request),
                        callback = std::move(callback)]() mutable {
      auto* pool = ctx->connection_pool.get();
      auto* pooled = pool->AcquireConnection(parsed.host, parsed.port);

      if (pooled && pooled->connection && pooled->connection->IsConnected()) {
        SendOnConnection(ctx, pooled, parsed, std::move(request),
                         std::move(callback));
      } else {
        // Still not ready - retry with a slight delay
        // This is a simplified approach; production would use TimerWheel
        if (callback) {
          callback(Response{}, Error{ErrorCode::kConnection, "Connection not ready"});
        }
        requests_failed_.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }

  void SendOnConnection(core::ReactorContext* ctx,
                        pool::PooledConnection* pooled,
                        const util::ParsedUrl& parsed, Request request,
                        ResponseCallback callback) {
    requests_sent_.fetch_add(1, std::memory_order_relaxed);

    // Convert headers to connection format
    std::vector<std::pair<std::string, std::string>> headers;
    for (const auto& h : request.headers()) {
      headers.emplace_back(h.name, h.value);
    }

    // Share callback between success and error handlers to avoid double-move
    auto shared_cb = std::make_shared<ResponseCallback>(std::move(callback));

    pooled->connection->SendRequest(
        std::string(MethodToString(request.method())), parsed.PathWithQuery(),
        headers,
        [this, ctx, pooled,
         shared_cb](const core::Response& core_resp) mutable {
          // Convert headers
          Headers resp_headers;
          for (size_t i = 0; i < core_resp.headers.size(); ++i) {
            resp_headers.push_back({std::string(core_resp.headers.name(i)),
                                    std::string(core_resp.headers.value(i))});
          }

          // Build response
          Response response(core_resp.status_code, std::move(resp_headers),
                            core_resp.body);

          // Release connection back to pool
          ctx->connection_pool->ReleaseConnection(pooled);

          requests_completed_.fetch_add(1, std::memory_order_relaxed);

          if (*shared_cb) {
            (*shared_cb)(std::move(response), Error{});
          }
        },
        [this, ctx, pooled, shared_cb](const std::string& error) mutable {
          // Mark connection as failed
          ctx->connection_pool->RemoveConnection(pooled);

          requests_failed_.fetch_add(1, std::memory_order_relaxed);

          if (*shared_cb) {
            (*shared_cb)(Response{}, Error{ErrorCode::kConnection, error});
          }
        });
  }

  ClientConfig config_;
  tls::TlsContextFactory tls_factory_;
  core::ReactorManager reactor_manager_;
  std::atomic<bool> running_{false};

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

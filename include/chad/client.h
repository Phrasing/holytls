// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_CLIENT_H_
#define CHAD_CLIENT_H_

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "chad/config.h"
#include "chad/error.h"
#include "chad/types.h"

namespace chad {

// HTTP request method
enum class Method {
  kGet,
  kPost,
  kPut,
  kDelete,
  kPatch,
  kHead,
  kOptions,
};

// Convert method to string
std::string_view MethodToString(Method method);

// HTTP request builder
class Request {
 public:
  Request() = default;

  // Builder methods (chainable)
  Request& SetMethod(Method method);
  Request& SetUrl(std::string_view url);
  Request& SetHeader(std::string_view name, std::string_view value);
  Request& SetBody(const uint8_t* data, size_t len);
  Request& SetBody(std::string_view body);
  Request& SetTimeout(std::chrono::milliseconds timeout);

  // Accessors
  Method method() const { return method_; }
  const std::string& url() const { return url_; }
  const Headers& headers() const { return headers_; }
  const std::vector<uint8_t>& body() const { return body_; }
  std::chrono::milliseconds timeout() const { return timeout_; }

 private:
  Method method_ = Method::kGet;
  std::string url_;
  Headers headers_;
  std::vector<uint8_t> body_;
  std::chrono::milliseconds timeout_{30000};
};

// HTTP response
class Response {
 public:
  Response() = default;

  // Internal constructor for building responses
  Response(int status_code, Headers headers, std::vector<uint8_t> body)
      : status_code_(status_code),
        headers_(std::move(headers)),
        body_(std::move(body)) {}

  // Status
  int status_code() const { return status_code_; }
  bool is_success() const { return status_code_ >= 200 && status_code_ < 300; }
  bool is_redirect() const { return status_code_ >= 300 && status_code_ < 400; }

  // Headers
  const Headers& headers() const { return headers_; }
  std::string_view GetHeader(std::string_view name) const;
  bool HasHeader(std::string_view name) const;

  // Body
  const std::vector<uint8_t>& body() const { return body_; }
  std::string_view body_string() const;
  size_t content_length() const;

  // Timing information
  struct Timing {
    std::chrono::milliseconds dns{0};
    std::chrono::milliseconds connect{0};
    std::chrono::milliseconds tls{0};
    std::chrono::milliseconds ttfb{0};  // Time to first byte
    std::chrono::milliseconds total{0};
  };
  const Timing& timing() const { return timing_; }

 private:
  friend class HttpClient;  // Allow HttpClient::Impl access
  friend class PooledConnection;

  int status_code_ = 0;
  Headers headers_;
  std::vector<uint8_t> body_;
  Timing timing_;
};

// Callback types
using ResponseCallback = std::function<void(Response response, Error error)>;
using ProgressCallback = std::function<void(size_t downloaded, size_t total)>;

// Main HTTP client
class HttpClient {
 public:
  explicit HttpClient(
      const ClientConfig& config = ClientConfig::ChromeLatest());
  ~HttpClient();

  // Non-copyable, non-movable
  HttpClient(const HttpClient&) = delete;
  HttpClient& operator=(const HttpClient&) = delete;
  HttpClient(HttpClient&&) = delete;
  HttpClient& operator=(HttpClient&&) = delete;

  // Asynchronous request - callback invoked on event loop thread
  void SendAsync(Request request, ResponseCallback callback);

  // Asynchronous request with progress callback
  void SendAsync(Request request, ResponseCallback callback,
                 ProgressCallback progress);

  // Event loop control
  void Run();      // Run until Stop() is called
  void RunOnce();  // Process pending events once
  void Stop();     // Signal event loop to stop

  // Check if event loop is running
  bool IsRunning() const;

  // Get current statistics
  ClientStats GetStats() const;

  // Get the Chrome version being impersonated
  ChromeVersion GetChromeVersion() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace chad

#endif  // CHAD_CLIENT_H_

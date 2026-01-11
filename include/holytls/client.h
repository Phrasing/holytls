// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_CLIENT_H_
#define HOLYTLS_CLIENT_H_

#include <chrono>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/config.h"
#include "holytls/error.h"
#include "holytls/types.h"

namespace holytls {

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

// HTTP request
struct Request {
  Method method = Method::kGet;
  std::string url;
  Headers headers;
  std::vector<uint8_t> body;
  std::chrono::milliseconds timeout{30000};

  // Custom header order (full control mode)
  // When set, bypasses Chrome auto-generation - user provides all headers
  std::span<const std::string_view> header_order;

  // Builder methods (chainable)
  Request& SetMethod(Method m);
  Request& SetUrl(std::string_view u);
  Request& SetHeader(std::string_view name, std::string_view value);
  Request& SetBody(const uint8_t* data, size_t len);
  Request& SetBody(std::string_view b);
  Request& SetTimeout(std::chrono::milliseconds t);
  Request& SetHeaderOrder(std::span<const std::string_view> order);
};

// Timing information for response
struct Timing {
  std::chrono::milliseconds dns{0};
  std::chrono::milliseconds connect{0};
  std::chrono::milliseconds tls{0};
  std::chrono::milliseconds ttfb{0};  // Time to first byte
  std::chrono::milliseconds total{0};
};

// HTTP response
struct Response {
  int status_code = 0;
  Headers headers;
  std::vector<uint8_t> body;
  Timing timing;

  Response() = default;
  Response(int code, Headers hdrs, std::vector<uint8_t> data)
      : status_code(code), headers(std::move(hdrs)), body(std::move(data)) {}

  // Computed queries
  bool is_success() const { return status_code >= 200 && status_code < 300; }
  bool is_redirect() const { return status_code >= 300 && status_code < 400; }

  // Header utilities
  std::string_view GetHeader(std::string_view name) const;
  bool HasHeader(std::string_view name) const;

  // Body utilities
  std::string_view body_string() const;
  size_t content_length() const;
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

  ChromeVersion GetChromeVersion() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace holytls

#endif  // HOLYTLS_CLIENT_H_

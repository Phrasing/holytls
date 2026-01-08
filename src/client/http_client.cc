// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "chad/client.h"

#include "chad/config.h"

namespace chad {

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

ClientConfig ClientConfig::ChromeLatest() {
  return Chrome143();
}

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

// HttpClient implementation (stub for now)
class HttpClient::Impl {
 public:
  explicit Impl(const ClientConfig& config) : config_(config) {}

  ClientConfig config_;
  bool running_ = false;
};

HttpClient::HttpClient(const ClientConfig& config)
    : impl_(std::make_unique<Impl>(config)) {}

HttpClient::~HttpClient() = default;

void HttpClient::SendAsync(Request /*request*/, ResponseCallback /*callback*/) {
  // TODO: Implement
}

void HttpClient::SendAsync(Request /*request*/, ResponseCallback /*callback*/,
                           ProgressCallback /*progress*/) {
  // TODO: Implement
}

void HttpClient::Run() {
  impl_->running_ = true;
  // TODO: Implement event loop
}

void HttpClient::RunOnce() {
  // TODO: Implement
}

void HttpClient::Stop() {
  impl_->running_ = false;
}

bool HttpClient::IsRunning() const {
  return impl_->running_;
}

ClientStats HttpClient::GetStats() const {
  return ClientStats{};
}

ChromeVersion HttpClient::GetChromeVersion() const {
  return impl_->config_.tls.chrome_version;
}

}  // namespace chad

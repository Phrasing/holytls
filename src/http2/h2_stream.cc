// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "http2/h2_stream.h"

#include <algorithm>
#include <cstdlib>

namespace chad {
namespace http2 {

// H2Headers implementation

H2Headers H2Headers::ForRequest(std::string_view method, std::string_view url) {
  H2Headers headers;
  headers.method = std::string(method);

  // Parse URL: scheme://authority/path
  std::string_view remaining = url;

  // Extract scheme
  auto scheme_end = remaining.find("://");
  if (scheme_end != std::string_view::npos) {
    headers.scheme = std::string(remaining.substr(0, scheme_end));
    remaining = remaining.substr(scheme_end + 3);
  } else {
    headers.scheme = "https";  // Default to HTTPS
  }

  // Extract authority (host:port)
  auto path_start = remaining.find('/');
  if (path_start != std::string_view::npos) {
    headers.authority = std::string(remaining.substr(0, path_start));
    headers.path = std::string(remaining.substr(path_start));
  } else {
    headers.authority = std::string(remaining);
    headers.path = "/";  // Default path
  }

  // Ensure path is not empty
  if (headers.path.empty()) {
    headers.path = "/";
  }

  return headers;
}

void H2Headers::Add(std::string_view name, std::string_view value) {
  headers.push_back({std::string(name), std::string(value)});
}

std::string_view H2Headers::Get(std::string_view name) const {
  for (const auto& header : headers) {
    if (header.name == name) {
      return header.value;
    }
  }
  return "";
}

bool H2Headers::Has(std::string_view name) const {
  for (const auto& header : headers) {
    if (header.name == name) {
      return true;
    }
  }
  return false;
}

// H2Stream implementation

H2Stream::H2Stream(int32_t stream_id, H2StreamCallbacks callbacks)
    : stream_id_(stream_id), callbacks_(std::move(callbacks)) {
  state_ = H2StreamState::kOpen;
}

H2Stream::~H2Stream() = default;

int H2Stream::status_code() const {
  if (response_headers_.status.empty()) {
    return 0;
  }
  return std::atoi(response_headers_.status.c_str());
}

void H2Stream::OnHeadersReceived(const H2Headers& headers) {
  response_headers_ = headers;

  if (callbacks_.on_headers) {
    callbacks_.on_headers(stream_id_, headers);
  }
}

void H2Stream::OnDataReceived(const uint8_t* data, size_t len) {
  response_body_.Append(data, len);

  if (callbacks_.on_data) {
    callbacks_.on_data(stream_id_, data, len);
  }
}

void H2Stream::OnStreamClose(uint32_t error_code) {
  state_ = H2StreamState::kClosed;

  if (callbacks_.on_close) {
    callbacks_.on_close(stream_id_, error_code);
  }
}

void H2Stream::MarkLocalClosed() {
  if (state_ == H2StreamState::kOpen) {
    state_ = H2StreamState::kHalfClosedLocal;
  } else if (state_ == H2StreamState::kHalfClosedRemote) {
    state_ = H2StreamState::kClosed;
  }
}

}  // namespace http2
}  // namespace chad

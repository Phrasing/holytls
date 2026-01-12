// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http1/h1_session.h"

#include <picohttpparser.h>

#include <algorithm>
#include <cstring>

namespace holytls {
namespace http1 {

namespace {

// Chrome's HTTP/1.1 header order (differs from HTTP/2)
// These are the headers that come before user-specified headers
constexpr std::string_view kChromeHeaderOrder[] = {
    "Host",
    "Connection",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Accept",
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Sec-Fetch-User",
    "Sec-Fetch-Dest",
    "Accept-Encoding",
    "Accept-Language",
};

// Case-insensitive header name comparison
bool HeaderNameEquals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    char ca = a[i];
    char cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca += 32;
    if (cb >= 'A' && cb <= 'Z') cb += 32;
    if (ca != cb) return false;
  }
  return true;
}

// Find header order index (-1 if not in Chrome order)
int HeaderOrderIndex(std::string_view name) {
  for (size_t i = 0; i < std::size(kChromeHeaderOrder); ++i) {
    if (HeaderNameEquals(name, kChromeHeaderOrder[i])) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

}  // namespace

H1Session::H1Session(SessionCallbacks callbacks)
    : callbacks_(std::move(callbacks)) {
  std::memset(&chunked_decoder_, 0, sizeof(chunked_decoder_));
}

H1Session::~H1Session() = default;

bool H1Session::Initialize() {
  // Nothing special needed for HTTP/1.1
  return true;
}

int32_t H1Session::SubmitRequest(const http2::H2Headers& headers,
                                 http2::H2StreamCallbacks stream_callbacks,
                                 std::span<const std::string_view> header_order,
                                 const uint8_t* body, size_t body_len) {
  if (parse_state_ != ParseState::kIdle) {
    SetError("Cannot submit request while another is in flight");
    return -1;
  }

  current_stream_id_++;
  stream_callbacks_ = std::move(stream_callbacks);
  parse_state_ = ParseState::kParsingHeaders;

  // Reset response state
  status_code_ = 0;
  headers_builder_ = http2::PackedHeadersBuilder();
  content_length_ = 0;
  body_received_ = 0;
  chunked_ = false;
  std::memset(&chunked_decoder_, 0, sizeof(chunked_decoder_));
  chunked_decoder_.consume_trailer = 1;
  recv_buffer_.clear();

  BuildRequest(headers, header_order, body, body_len);

  return current_stream_id_;
}

void H1Session::BuildRequest(const http2::H2Headers& headers,
                             std::span<const std::string_view> header_order,
                             const uint8_t* body, size_t body_len) {
  send_buffer_.Clear();
  send_offset_ = 0;

  // Helper to append string data
  auto append_str = [this](const char* s, size_t len) {
    send_buffer_.Append(reinterpret_cast<const uint8_t*>(s), len);
  };
  auto append_sv = [this](std::string_view sv) {
    send_buffer_.Append(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
  };

  // Request line: METHOD PATH HTTP/1.1\r\n
  append_sv(headers.method);
  append_str(" ", 1);
  append_sv(headers.path);
  append_str(" HTTP/1.1\r\n", 11);

  if (!header_order.empty()) {
    // Custom header order mode: use headers in order from h2_headers.headers
    // The caller has already ordered them according to header_order
    // We just need to add Host if not present and Connection
    bool has_host = false;
    bool has_connection = false;

    for (const auto& [name, value] : headers.headers) {
      if (HeaderNameEquals(name, "host")) has_host = true;
      if (HeaderNameEquals(name, "connection")) has_connection = true;
    }

    // Add Host first if not in headers (required for HTTP/1.1)
    if (!has_host) {
      append_str("Host: ", 6);
      append_sv(headers.authority);
      append_str("\r\n", 2);
    }

    // Write headers in the order they appear (caller's order)
    for (const auto& [name, value] : headers.headers) {
      append_sv(name);
      append_str(": ", 2);
      append_sv(value);
      append_str("\r\n", 2);
    }

    // Add Connection if not in headers
    if (!has_connection) {
      append_str("Connection: keep-alive\r\n", 24);
    }
  } else {
    // Chrome order mode: sort headers according to Chrome's HTTP/1.1 order
    struct HeaderEntry {
      std::string_view name;
      std::string_view value;
      int order;
    };
    std::vector<HeaderEntry> sorted_headers;

    // Add Host header (from authority)
    sorted_headers.push_back(
        {"Host", headers.authority, HeaderOrderIndex("Host")});

    // Add Connection header
    sorted_headers.push_back(
        {"Connection", "keep-alive", HeaderOrderIndex("Connection")});

    // Add all headers from the request
    for (const auto& [name, value] : headers.headers) {
      // Skip host and connection as we already added them
      if (HeaderNameEquals(name, "host") ||
          HeaderNameEquals(name, "connection")) {
        continue;
      }
      sorted_headers.push_back({name, value, HeaderOrderIndex(name)});
    }

    // Sort: Chrome-ordered headers first (by order index), then others
    // (order=-1) at end
    std::stable_sort(sorted_headers.begin(), sorted_headers.end(),
                     [](const HeaderEntry& a, const HeaderEntry& b) {
                       if (a.order == -1 && b.order == -1) return false;
                       if (a.order == -1) return false;
                       if (b.order == -1) return true;
                       return a.order < b.order;
                     });

    // Write headers
    for (const auto& entry : sorted_headers) {
      append_sv(entry.name);
      append_str(": ", 2);
      append_sv(entry.value);
      append_str("\r\n", 2);
    }
  }

  // Add Content-Length if body present
  if (body != nullptr && body_len > 0) {
    std::string cl = "Content-Length: " + std::to_string(body_len) + "\r\n";
    append_str(cl.c_str(), cl.size());
  }

  // End of headers
  append_str("\r\n", 2);

  // Add body if present
  if (body != nullptr && body_len > 0) {
    send_buffer_.Append(body, body_len);
  }
}

ssize_t H1Session::Receive(const uint8_t* data, size_t len) {
  if (fatal_error_) {
    return -1;
  }

  if (parse_state_ == ParseState::kIdle) {
    // No request in flight, ignore data
    return static_cast<ssize_t>(len);
  }

  // Append to receive buffer
  recv_buffer_.insert(recv_buffer_.end(), data, data + len);

  // Parse based on state
  if (parse_state_ == ParseState::kParsingHeaders) {
    int result = ParseHeaders();
    if (result == -1) {
      SetError("Failed to parse HTTP response headers");
      return -1;
    }
    // If headers parsed, continue to body
  }

  if (parse_state_ == ParseState::kParsingBody ||
      parse_state_ == ParseState::kParsingChunked) {
    ParseBody();
  }

  return static_cast<ssize_t>(len);
}

int H1Session::ParseHeaders() {
  int minor_version;
  int status;
  const char* msg;
  size_t msg_len;
  struct phr_header headers[100];
  size_t num_headers = 100;

  int pret = phr_parse_response(
      reinterpret_cast<const char*>(recv_buffer_.data()), recv_buffer_.size(),
      &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

  if (pret == -2) {
    // Incomplete, need more data
    return 0;
  }

  if (pret == -1) {
    // Parse error
    return -1;
  }

  // Headers complete
  status_code_ = status;

  // Build packed headers
  for (size_t i = 0; i < num_headers; ++i) {
    std::string_view name(headers[i].name, headers[i].name_len);
    std::string_view value(headers[i].value, headers[i].value_len);

    headers_builder_.Add(name, value);

    // Check for Content-Length or Transfer-Encoding
    if (HeaderNameEquals(name, "content-length")) {
      content_length_ = std::stoull(std::string(value));
    } else if (HeaderNameEquals(name, "transfer-encoding")) {
      if (value.find("chunked") != std::string_view::npos) {
        chunked_ = true;
      }
    }
  }

  // Set status and deliver headers callback
  headers_builder_.SetStatus(std::to_string(status_code_));
  auto packed = headers_builder_.Build();
  if (stream_callbacks_.on_headers) {
    stream_callbacks_.on_headers(current_stream_id_, packed);
  }

  // Remove parsed headers from buffer
  recv_buffer_.erase(recv_buffer_.begin(),
                     recv_buffer_.begin() + static_cast<size_t>(pret));

  // Determine body parsing mode
  if (chunked_) {
    parse_state_ = ParseState::kParsingChunked;
  } else if (content_length_ > 0) {
    parse_state_ = ParseState::kParsingBody;
  } else {
    // No body (or unknown length for some responses like 204/304)
    CompleteRequest();
  }

  return pret;
}

void H1Session::ParseBody() {
  if (recv_buffer_.empty()) {
    return;
  }

  if (parse_state_ == ParseState::kParsingBody) {
    // Content-Length based
    size_t remaining = content_length_ - body_received_;
    size_t to_consume = std::min(remaining, recv_buffer_.size());

    if (to_consume > 0 && stream_callbacks_.on_data) {
      stream_callbacks_.on_data(current_stream_id_, recv_buffer_.data(),
                                to_consume);
    }

    body_received_ += to_consume;
    recv_buffer_.erase(recv_buffer_.begin(),
                       recv_buffer_.begin() + static_cast<ptrdiff_t>(to_consume));

    if (body_received_ >= content_length_) {
      CompleteRequest();
    }
  } else if (parse_state_ == ParseState::kParsingChunked) {
    // Chunked transfer encoding
    size_t buf_len = recv_buffer_.size();
    ssize_t pret = phr_decode_chunked(
        &chunked_decoder_, reinterpret_cast<char*>(recv_buffer_.data()),
        &buf_len);

    if (pret == -1) {
      SetError("Failed to decode chunked response");
      CompleteRequest(1);
      return;
    }

    // buf_len now contains the decoded length
    if (buf_len > 0 && stream_callbacks_.on_data) {
      stream_callbacks_.on_data(current_stream_id_, recv_buffer_.data(),
                                buf_len);
    }

    if (pret >= 0) {
      // Chunked decoding complete
      recv_buffer_.clear();
      CompleteRequest();
    } else {
      // Need more data, but we consumed some
      // phr_decode_chunked modifies the buffer in-place
      recv_buffer_.resize(buf_len);
    }
  }
}

void H1Session::CompleteRequest(uint32_t error_code) {
  if (stream_callbacks_.on_close) {
    stream_callbacks_.on_close(current_stream_id_, error_code);
  }

  // Reset state
  stream_callbacks_ = {};
  parse_state_ = ParseState::kIdle;
}

std::pair<const uint8_t*, size_t> H1Session::GetPendingData() {
  if (send_offset_ >= send_buffer_.Size()) {
    return {nullptr, 0};
  }
  return {send_buffer_.Data() + send_offset_,
          send_buffer_.Size() - send_offset_};
}

void H1Session::DataSent(size_t len) { send_offset_ += len; }

bool H1Session::WantsWrite() const {
  return send_offset_ < send_buffer_.Size();
}

bool H1Session::CanSubmitRequest() const {
  return !fatal_error_ && parse_state_ == ParseState::kIdle;
}

void H1Session::SetError(const std::string& msg) {
  fatal_error_ = true;
  last_error_ = msg;
  if (callbacks_.on_error) {
    callbacks_.on_error(-1, msg);
  }
}

}  // namespace http1
}  // namespace holytls

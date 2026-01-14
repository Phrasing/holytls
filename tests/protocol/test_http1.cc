// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// HTTP/1.1 protocol tests
// Tests the H1Session class for correct HTTP/1.1 request/response handling

#include <cassert>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include "holytls/http1/h1_session.h"
#include "holytls/http2/h2_stream.h"
#include "holytls/http2/packed_headers.h"

using namespace holytls;

// ============================================================================
// Test: Basic GET request serialization
// ============================================================================

void TestHttp1RequestSerialization() {
  std::print("Testing HTTP/1.1 request serialization... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  // Set up stream callbacks to capture response
  int received_status = 0;
  std::string received_body;
  bool request_complete = false;

  http2::H2StreamCallbacks stream_callbacks;
  stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& headers) {
    received_status = headers.status_code();
  };
  stream_callbacks.on_data = [&](int32_t, const uint8_t* data, size_t len) {
    received_body.append(reinterpret_cast<const char*>(data), len);
  };
  stream_callbacks.on_close = [&](int32_t, uint32_t) {
    request_complete = true;
  };

  // Build request headers
  http2::H2Headers headers;
  headers.method = "GET";
  headers.path = "/test";
  headers.authority = "example.com";
  headers.scheme = "https";

  // Submit request
  int32_t stream_id = session.SubmitRequest(headers, stream_callbacks);
  assert(stream_id == 1);  // HTTP/1.1 always uses stream ID 1

  // Get serialized request
  auto [data, len] = session.GetPendingData();
  assert(len > 0);

  std::string request(reinterpret_cast<const char*>(data), len);

  // Verify request format
  assert(request.find("GET /test HTTP/1.1\r\n") == 0);
  assert(request.find("Host: example.com\r\n") != std::string::npos);
  assert(request.find("\r\n\r\n") != std::string::npos);

  session.DataSent(len);

  // Now feed a response
  constexpr std::string_view response =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 12\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n"
      "Hello World!";

  ssize_t consumed = session.Receive(
      reinterpret_cast<const uint8_t*>(response.data()), response.size());
  assert(consumed > 0);

  // Verify response was parsed
  assert(received_status == 200);
  assert(received_body == "Hello World!");
  assert(request_complete);

  std::println("PASSED");
}

// ============================================================================
// Test: POST request with body
// ============================================================================

void TestHttp1PostWithBody() {
  std::print("Testing HTTP/1.1 POST with body... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  int received_status = 0;
  bool request_complete = false;

  http2::H2StreamCallbacks stream_callbacks;
  stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& headers) {
    received_status = headers.status_code();
  };
  stream_callbacks.on_close = [&](int32_t, uint32_t) {
    request_complete = true;
  };

  http2::H2Headers headers;
  headers.method = "POST";
  headers.path = "/api/data";
  headers.authority = "example.com";
  headers.scheme = "https";
  headers.Add("Content-Type", "application/json");

  constexpr std::string_view body = R"({"key": "value"})";

  int32_t stream_id = session.SubmitRequest(
      headers, stream_callbacks, {},
      reinterpret_cast<const uint8_t*>(body.data()), body.size());
  assert(stream_id == 1);

  auto [data, len] = session.GetPendingData();
  std::string request(reinterpret_cast<const char*>(data), len);

  // Verify POST request format
  assert(request.find("POST /api/data HTTP/1.1\r\n") == 0);
  assert(request.find("Content-Length: 16\r\n") != std::string::npos);
  assert(request.find(R"({"key": "value"})") != std::string::npos);

  session.DataSent(len);

  // Feed response
  constexpr std::string_view response =
      "HTTP/1.1 201 Created\r\n"
      "Content-Length: 0\r\n"
      "\r\n";

  session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

  assert(received_status == 201);
  assert(request_complete);

  std::println("PASSED");
}

// ============================================================================
// Test: Various status codes
// ============================================================================

void TestHttp1StatusCodes() {
  std::print("Testing HTTP/1.1 status codes... ");

  struct TestCase {
    int status_code;
    std::string_view status_text;
  };

  constexpr TestCase test_cases[] = {
      {200, "OK"},
      {201, "Created"},
      {204, "No Content"},
      {301, "Moved Permanently"},
      {302, "Found"},
      {304, "Not Modified"},
      {400, "Bad Request"},
      {401, "Unauthorized"},
      {403, "Forbidden"},
      {404, "Not Found"},
      {500, "Internal Server Error"},
      {502, "Bad Gateway"},
      {503, "Service Unavailable"},
  };

  for (const auto& tc : test_cases) {
    http1::H1Session::SessionCallbacks callbacks;
    http1::H1Session session(callbacks);
    assert(session.Initialize());

    int received_status = 0;

    http2::H2StreamCallbacks stream_callbacks;
    stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& headers) {
      received_status = headers.status_code();
    };
    stream_callbacks.on_close = [](int32_t, uint32_t) {};

    http2::H2Headers headers;
    headers.method = "GET";
    headers.path = "/";
    headers.authority = "example.com";
    headers.scheme = "https";

    session.SubmitRequest(headers, stream_callbacks);
    auto [data, len] = session.GetPendingData();
    session.DataSent(len);

    // Build response with specific status code
    std::string response = "HTTP/1.1 " + std::to_string(tc.status_code) + " " +
                           std::string(tc.status_text) + "\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n";

    session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

    assert(received_status == tc.status_code);
  }

  std::println("PASSED");
}

// ============================================================================
// Test: Chunked transfer encoding
// ============================================================================

void TestHttp1ChunkedEncoding() {
  std::print("Testing HTTP/1.1 chunked encoding... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  int received_status = 0;
  std::string received_body;
  bool request_complete = false;

  http2::H2StreamCallbacks stream_callbacks;
  stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& headers) {
    received_status = headers.status_code();
  };
  stream_callbacks.on_data = [&](int32_t, const uint8_t* data, size_t len) {
    received_body.append(reinterpret_cast<const char*>(data), len);
  };
  stream_callbacks.on_close = [&](int32_t, uint32_t) {
    request_complete = true;
  };

  http2::H2Headers headers;
  headers.method = "GET";
  headers.path = "/chunked";
  headers.authority = "example.com";
  headers.scheme = "https";

  session.SubmitRequest(headers, stream_callbacks);
  auto [data, len] = session.GetPendingData();
  session.DataSent(len);

  // Chunked response
  constexpr std::string_view response =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "5\r\n"
      "Hello\r\n"
      "7\r\n"
      " World!\r\n"
      "0\r\n"
      "\r\n";

  session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

  assert(received_status == 200);
  assert(received_body == "Hello World!");
  assert(request_complete);

  std::println("PASSED");
}

// ============================================================================
// Test: Large body
// ============================================================================

void TestHttp1LargeBody() {
  std::print("Testing HTTP/1.1 large body... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  std::string received_body;
  bool request_complete = false;

  http2::H2StreamCallbacks stream_callbacks;
  stream_callbacks.on_headers = [](int32_t, const http2::PackedHeaders&) {};
  stream_callbacks.on_data = [&](int32_t, const uint8_t* data, size_t len) {
    received_body.append(reinterpret_cast<const char*>(data), len);
  };
  stream_callbacks.on_close = [&](int32_t, uint32_t) {
    request_complete = true;
  };

  http2::H2Headers headers;
  headers.method = "GET";
  headers.path = "/large";
  headers.authority = "example.com";
  headers.scheme = "https";

  session.SubmitRequest(headers, stream_callbacks);
  auto [data, len] = session.GetPendingData();
  session.DataSent(len);

  // Create a 1MB body
  constexpr size_t kBodySize = 1024 * 1024;
  constexpr size_t kChunkSize = 8192;
  std::string large_body(kBodySize, 'X');

  std::string response_headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: " + std::to_string(large_body.size()) + "\r\n"
      "\r\n";

  // Feed headers first
  session.Receive(reinterpret_cast<const uint8_t*>(response_headers.data()),
                  response_headers.size());

  // Feed body in chunks
  size_t offset = 0;
  while (offset < large_body.size()) {
    size_t chunk_size = std::min<size_t>(kChunkSize, large_body.size() - offset);
    session.Receive(reinterpret_cast<const uint8_t*>(large_body.data() + offset),
                    chunk_size);
    offset += chunk_size;
  }

  assert(request_complete);
  assert(received_body.size() == large_body.size());
  assert(received_body == large_body);

  std::println("PASSED");
}

// ============================================================================
// Test: Multiple requests (keep-alive)
// ============================================================================

void TestHttp1KeepAlive() {
  std::print("Testing HTTP/1.1 keep-alive... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  // First request
  {
    int received_status = 0;
    bool complete = false;

    http2::H2StreamCallbacks stream_callbacks;
    stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& h) {
      received_status = h.status_code();
    };
    stream_callbacks.on_close = [&](int32_t, uint32_t) { complete = true; };

    http2::H2Headers headers;
    headers.method = "GET";
    headers.path = "/first";
    headers.authority = "example.com";
    headers.scheme = "https";

    session.SubmitRequest(headers, stream_callbacks);
    auto [data, len] = session.GetPendingData();
    session.DataSent(len);

    constexpr std::string_view response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "first";

    session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

    assert(received_status == 200);
    assert(complete);
  }

  // Session should still be alive for second request
  assert(session.IsAlive());
  assert(session.CanSubmitRequest());

  // Second request
  {
    int received_status = 0;
    bool complete = false;

    http2::H2StreamCallbacks stream_callbacks;
    stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& h) {
      received_status = h.status_code();
    };
    stream_callbacks.on_close = [&](int32_t, uint32_t) { complete = true; };

    http2::H2Headers headers;
    headers.method = "GET";
    headers.path = "/second";
    headers.authority = "example.com";
    headers.scheme = "https";

    session.SubmitRequest(headers, stream_callbacks);
    auto [data, len] = session.GetPendingData();
    session.DataSent(len);

    constexpr std::string_view response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "second";

    session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

    assert(received_status == 200);
    assert(complete);
  }

  std::println("PASSED");
}

// ============================================================================
// Test: Custom headers
// ============================================================================

void TestHttp1CustomHeaders() {
  std::print("Testing HTTP/1.1 custom headers... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  std::vector<std::pair<std::string, std::string>> received_headers;

  http2::H2StreamCallbacks stream_callbacks;
  stream_callbacks.on_headers = [&](int32_t, const http2::PackedHeaders& headers) {
    for (size_t i = 0; i < headers.size(); ++i) {
      received_headers.emplace_back(
          std::string(headers.name(i)),
          std::string(headers.value(i)));
    }
  };
  stream_callbacks.on_close = [](int32_t, uint32_t) {};

  http2::H2Headers headers;
  headers.method = "GET";
  headers.path = "/";
  headers.authority = "example.com";
  headers.scheme = "https";
  headers.Add("X-Custom-Header", "custom-value");
  headers.Add("Authorization", "Bearer token123");

  session.SubmitRequest(headers, stream_callbacks);
  auto [data, len] = session.GetPendingData();
  std::string request(reinterpret_cast<const char*>(data), len);

  // Verify custom headers in request
  assert(request.find("X-Custom-Header: custom-value\r\n") != std::string::npos);
  assert(request.find("Authorization: Bearer token123\r\n") != std::string::npos);

  session.DataSent(len);

  // Response with custom headers
  constexpr std::string_view response =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 0\r\n"
      "X-Response-Header: response-value\r\n"
      "X-Another: another-value\r\n"
      "\r\n";

  session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

  // Verify we received the custom headers
  bool found_response_header = false;
  bool found_another = false;
  for (const auto& h : received_headers) {
    if (h.first == "x-response-header" && h.second == "response-value") {
      found_response_header = true;
    }
    if (h.first == "x-another" && h.second == "another-value") {
      found_another = true;
    }
  }
  assert(found_response_header);
  assert(found_another);

  std::println("PASSED");
}

// ============================================================================
// Test: Cannot submit while request in flight
// ============================================================================

void TestHttp1NoMultiplexing() {
  std::print("Testing HTTP/1.1 no multiplexing... ");

  http1::H1Session::SessionCallbacks callbacks;
  http1::H1Session session(callbacks);
  assert(session.Initialize());

  http2::H2StreamCallbacks stream_callbacks;
  stream_callbacks.on_headers = [](int32_t, const http2::PackedHeaders&) {};
  stream_callbacks.on_close = [](int32_t, uint32_t) {};

  http2::H2Headers headers;
  headers.method = "GET";
  headers.path = "/first";
  headers.authority = "example.com";
  headers.scheme = "https";

  // First request
  int32_t stream_id = session.SubmitRequest(headers, stream_callbacks);
  assert(stream_id == 1);
  assert(!session.CanSubmitRequest());  // Cannot submit while first is in flight

  // Second request should fail
  headers.path = "/second";
  int32_t stream_id2 = session.SubmitRequest(headers, stream_callbacks);
  assert(stream_id2 == -1);  // Should fail

  // Complete first request
  auto [data, len] = session.GetPendingData();
  session.DataSent(len);

  constexpr std::string_view response =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 0\r\n"
      "\r\n";

  session.Receive(reinterpret_cast<const uint8_t*>(response.data()), response.size());

  // Now we can submit again
  assert(session.CanSubmitRequest());

  std::println("PASSED");
}

// ============================================================================
// Main
// ============================================================================

int main() {
  std::println("=== HTTP/1.1 Protocol Tests ===\n");

  TestHttp1RequestSerialization();
  TestHttp1PostWithBody();
  TestHttp1StatusCodes();
  TestHttp1ChunkedEncoding();
  TestHttp1LargeBody();
  TestHttp1KeepAlive();
  TestHttp1CustomHeaders();
  TestHttp1NoMultiplexing();

  std::println("\n=== All HTTP/1.1 tests passed! ===");
  return 0;
}

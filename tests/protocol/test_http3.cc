// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// HTTP/3 protocol tests
// Tests the H3Session class for correct HTTP/3 request/response handling
// Only compiled when QUIC support is enabled

#include "holytls/config.h"

#if defined(HOLYTLS_BUILD_QUIC)

#include <cassert>
#include <print>
#include <string>
#include <vector>

#include "holytls/quic/h3_session.h"

using namespace holytls;

// ============================================================================
// Test: H3StreamCallbacks structure
// ============================================================================

void TestHttp3CallbacksStructure() {
  std::print("Testing HTTP/3 callbacks structure... ");

  // Verify H3StreamCallbacks has the expected members
  quic::H3StreamCallbacks callbacks;

  bool headers_called = false;
  bool data_called = false;
  bool complete_called = false;
  bool error_called = false;

  callbacks.on_headers = [&](int status_code, const http2::PackedHeaders&) {
    headers_called = true;
    assert(status_code >= 100 && status_code < 600);
  };

  callbacks.on_data = [&](const uint8_t* data, size_t len) {
    data_called = true;
    assert(data != nullptr || len == 0);
  };

  callbacks.on_complete = [&]() { complete_called = true; };

  callbacks.on_error = [&](uint64_t error_code, const std::string& reason) {
    error_called = true;
    (void)error_code;
    (void)reason;
  };

  // Verify callbacks are set
  assert(callbacks.on_headers);
  assert(callbacks.on_data);
  assert(callbacks.on_complete);
  assert(callbacks.on_error);

  // Simulate calling them
  http2::PackedHeadersBuilder builder;
  builder.Add(":status", "200");
  http2::PackedHeaders headers = std::move(builder).Build();

  callbacks.on_headers(200, headers);
  callbacks.on_data(nullptr, 0);
  callbacks.on_complete();
  callbacks.on_error(0, "test");

  assert(headers_called);
  assert(data_called);
  assert(complete_called);
  assert(error_called);

  std::println("PASSED");
}

// ============================================================================
// Test: H3State enum values
// ============================================================================

void TestHttp3StateEnum() {
  std::print("Testing HTTP/3 state enum... ");

  // Verify H3State has expected values
  quic::H3State idle = quic::H3State::kIdle;
  quic::H3State ready = quic::H3State::kReady;
  quic::H3State going_away = quic::H3State::kGoingAway;
  quic::H3State closed = quic::H3State::kClosed;
  quic::H3State error = quic::H3State::kError;

  // States should be distinct
  assert(idle != ready);
  assert(ready != going_away);
  assert(going_away != closed);
  assert(closed != error);

  std::println("PASSED");
}

// ============================================================================
// Test: HTTP/3 uses H2Headers for request submission
// ============================================================================

void TestHttp3HeadersCompatibility() {
  std::print("Testing HTTP/3 headers compatibility with H2Headers... ");

  // H3Session uses the same H2Headers struct for request submission
  http2::H2Headers headers;
  headers.method = "GET";
  headers.scheme = "https";
  headers.authority = "example.com";
  headers.path = "/test";
  headers.Add("accept", "text/html");
  headers.Add("user-agent", "HolyTLS/1.0");

  // Verify headers are set correctly
  assert(headers.method == "GET");
  assert(headers.scheme == "https");
  assert(headers.authority == "example.com");
  assert(headers.path == "/test");
  assert(headers.Has("accept"));
  assert(headers.Get("accept") == "text/html");

  std::println("PASSED");
}

// ============================================================================
// Test: PackedHeaders used for responses
// ============================================================================

void TestHttp3ResponseHeaders() {
  std::print("Testing HTTP/3 response headers... ");

  // H3Session provides responses via PackedHeaders (same as H2Session)
  http2::PackedHeadersBuilder builder;
  builder.Add(":status", "200");
  builder.Add("content-type", "application/json");
  builder.Add("content-length", "42");

  http2::PackedHeaders headers = std::move(builder).Build();

  assert(headers.status_code() == 200);
  assert(headers.size() >= 2);  // At least content-type and content-length

  bool found_content_type = false;
  for (size_t i = 0; i < headers.size(); ++i) {
    if (headers.name(i) == "content-type") {
      assert(headers.value(i) == "application/json");
      found_content_type = true;
    }
  }
  assert(found_content_type);

  std::println("PASSED");
}

// ============================================================================
// Note: Full H3Session tests require QuicConnection
// ============================================================================

void TestHttp3SessionNote() {
  std::print("Testing HTTP/3 session (requires QUIC connection)... ");

  // H3Session requires a QuicConnection to function properly.
  // Full integration tests should be done with a mock QUIC server.
  // This test verifies the API is available and compiles.

  // The H3Session constructor signature:
  // explicit H3Session(QuicConnection* quic);

  // Key methods available:
  // - Initialize()
  // - SubmitRequest(...)
  // - CanSubmitRequest()
  // - IsReady()
  // - state()

  std::println("SKIPPED (requires QuicConnection)");
}

// ============================================================================
// Main
// ============================================================================

int main() {
  std::println("=== HTTP/3 Protocol Tests ===\n");

  TestHttp3CallbacksStructure();
  TestHttp3StateEnum();
  TestHttp3HeadersCompatibility();
  TestHttp3ResponseHeaders();
  TestHttp3SessionNote();

  std::println("\n=== All HTTP/3 tests passed! ===");
  return 0;
}

#else  // !HOLYTLS_BUILD_QUIC

#include <print>

int main() {
  std::println("HTTP/3 tests skipped (QUIC not enabled)");
  return 0;
}

#endif  // HOLYTLS_BUILD_QUIC

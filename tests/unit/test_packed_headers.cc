// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/header_ids.h"
#include "holytls/http2/packed_headers.h"

#include <cassert>
#include <cstring>
#include <iostream>

using namespace holytls::http2;

void TestHeaderIdLookup() {
  std::cout << "Testing HeaderId lookup... ";

  // Test known headers
  assert(LookupHeaderId("content-type") == HeaderId::kContentType);
  assert(LookupHeaderId("content-length") == HeaderId::kContentLength);
  assert(LookupHeaderId("cache-control") == HeaderId::kCacheControl);
  assert(LookupHeaderId("date") == HeaderId::kDate);
  assert(LookupHeaderId("server") == HeaderId::kServer);
  assert(LookupHeaderId("set-cookie") == HeaderId::kSetCookie);
  assert(LookupHeaderId("location") == HeaderId::kLocation);
  assert(LookupHeaderId("etag") == HeaderId::kEtag);

  // Test case-insensitive lookup
  assert(LookupHeaderId("Content-Type") == HeaderId::kContentType);
  assert(LookupHeaderId("CONTENT-TYPE") == HeaderId::kContentType);
  assert(LookupHeaderId("Content-LENGTH") == HeaderId::kContentLength);

  // Test unknown headers
  assert(LookupHeaderId("x-custom-header") == HeaderId::kCustom);
  assert(LookupHeaderId("unknown") == HeaderId::kCustom);
  assert(LookupHeaderId("my-header") == HeaderId::kCustom);

  std::cout << "PASSED\n";
}

void TestHeaderIdToName() {
  std::cout << "Testing HeaderId to name conversion... ";

  assert(HeaderIdToName(HeaderId::kContentType) == "content-type");
  assert(HeaderIdToName(HeaderId::kContentLength) == "content-length");
  assert(HeaderIdToName(HeaderId::kCacheControl) == "cache-control");
  assert(HeaderIdToName(HeaderId::kDate) == "date");
  assert(HeaderIdToName(HeaderId::kServer) == "server");
  assert(HeaderIdToName(HeaderId::kSetCookie) == "set-cookie");
  assert(HeaderIdToName(HeaderId::kLocation) == "location");

  // Custom headers have no canonical name
  assert(HeaderIdToName(HeaderId::kCustom) == "");

  std::cout << "PASSED\n";
}

void TestPackedHeadersBuilderBasic() {
  std::cout << "Testing PackedHeadersBuilder basic usage... ";

  PackedHeadersBuilder builder;
  builder.Add("content-type", "application/json");
  builder.Add("content-length", "1234");
  builder.Add("server", "nginx");
  builder.SetStatus("200");

  PackedHeaders headers = builder.Build();

  assert(headers.size() == 3);
  assert(headers.status_code() == 200);

  // Test lookup by HeaderId
  assert(headers.Get(HeaderId::kContentType) == "application/json");
  assert(headers.Get(HeaderId::kContentLength) == "1234");
  assert(headers.Get(HeaderId::kServer) == "nginx");

  // Test lookup by name
  assert(headers.Get("content-type") == "application/json");
  assert(headers.Get("content-length") == "1234");
  assert(headers.Get("server") == "nginx");

  // Test Has()
  assert(headers.Has("content-type"));
  assert(headers.Has("content-length"));
  assert(!headers.Has("x-nonexistent"));

  std::cout << "PASSED\n";
}

void TestPackedHeadersCustomHeaders() {
  std::cout << "Testing PackedHeaders with custom headers... ";

  PackedHeadersBuilder builder;
  builder.Add("content-type", "text/html");
  builder.Add("x-custom-header", "custom-value");
  builder.Add("x-another", "another-value");
  builder.SetStatus("201");

  PackedHeaders headers = builder.Build();

  assert(headers.size() == 3);
  assert(headers.status_code() == 201);

  // Known header
  assert(headers.Get(HeaderId::kContentType) == "text/html");
  assert(headers.Get("content-type") == "text/html");

  // Custom headers
  assert(headers.Get("x-custom-header") == "custom-value");
  assert(headers.Get("x-another") == "another-value");

  assert(headers.Has("x-custom-header"));
  assert(headers.Has("x-another"));

  std::cout << "PASSED\n";
}

void TestPackedHeadersIteration() {
  std::cout << "Testing PackedHeaders iteration... ";

  PackedHeadersBuilder builder;
  builder.Add("content-type", "text/plain");
  builder.Add("cache-control", "no-cache");
  builder.Add("x-custom", "value");

  PackedHeaders headers = builder.Build();

  assert(headers.size() == 3);

  // Test iteration
  assert(headers.id(0) == HeaderId::kContentType);
  assert(headers.name(0) == "content-type");
  assert(headers.value(0) == "text/plain");

  assert(headers.id(1) == HeaderId::kCacheControl);
  assert(headers.name(1) == "cache-control");
  assert(headers.value(1) == "no-cache");

  assert(headers.id(2) == HeaderId::kCustom);
  assert(headers.name(2) == "x-custom");
  assert(headers.value(2) == "value");

  std::cout << "PASSED\n";
}

void TestPackedHeadersEmpty() {
  std::cout << "Testing empty PackedHeaders... ";

  PackedHeadersBuilder builder;
  builder.SetStatus("204");

  PackedHeaders headers = builder.Build();

  assert(headers.size() == 0);
  assert(headers.status_code() == 204);
  assert(headers.Get(HeaderId::kContentType) == "");
  assert(headers.Get("content-type") == "");
  assert(!headers.Has("content-type"));

  std::cout << "PASSED\n";
}

void TestPackedHeadersMove() {
  std::cout << "Testing PackedHeaders move semantics... ";

  PackedHeadersBuilder builder;
  builder.Add("content-type", "application/json");
  builder.Add("server", "test");
  builder.SetStatus("200");

  PackedHeaders original = builder.Build();
  assert(original.size() == 2);

  // Move construct
  PackedHeaders moved(std::move(original));
  assert(moved.size() == 2);
  assert(moved.Get("content-type") == "application/json");
  assert(moved.Get("server") == "test");
  assert(moved.status_code() == 200);

  // Original should be empty after move
  assert(original.size() == 0);

  // Move assign
  PackedHeadersBuilder builder2;
  builder2.Add("date", "Mon, 01 Jan 2024");
  builder2.SetStatus("404");
  PackedHeaders another = builder2.Build();

  another = std::move(moved);
  assert(another.size() == 2);
  assert(another.Get("content-type") == "application/json");
  assert(another.status_code() == 200);

  std::cout << "PASSED\n";
}

void TestPackedHeadersCopy() {
  std::cout << "Testing PackedHeaders copy semantics... ";

  PackedHeadersBuilder builder;
  builder.Add("content-type", "text/html");
  builder.Add("x-custom", "custom-value");
  builder.SetStatus("200");

  PackedHeaders original = builder.Build();

  // Copy construct
  PackedHeaders copied(original);
  assert(copied.size() == original.size());
  assert(copied.status_code() == original.status_code());
  assert(copied.Get("content-type") == original.Get("content-type"));
  assert(copied.Get("x-custom") == original.Get("x-custom"));

  // Original unchanged
  assert(original.size() == 2);
  assert(original.Get("content-type") == "text/html");

  // Copy assign
  PackedHeadersBuilder builder2;
  builder2.Add("server", "nginx");
  builder2.SetStatus("301");
  PackedHeaders another = builder2.Build();

  another = original;
  assert(another.size() == 2);
  assert(another.Get("content-type") == "text/html");
  assert(another.Get("x-custom") == "custom-value");
  assert(another.status_code() == 200);

  // Original still unchanged
  assert(original.size() == 2);

  std::cout << "PASSED\n";
}

void TestPackedHeadersBuilderClear() {
  std::cout << "Testing PackedHeadersBuilder clear... ";

  PackedHeadersBuilder builder;
  builder.Add("content-type", "text/plain");
  builder.Add("server", "test");
  builder.SetStatus("200");

  // Build clears the builder
  PackedHeaders headers1 = builder.Build();
  assert(headers1.size() == 2);

  // Builder should be empty now, can be reused
  builder.Add("cache-control", "no-cache");
  builder.SetStatus("304");

  PackedHeaders headers2 = builder.Build();
  assert(headers2.size() == 1);
  assert(headers2.Get("cache-control") == "no-cache");
  assert(headers2.status_code() == 304);

  // First headers unchanged
  assert(headers1.size() == 2);
  assert(headers1.Get("content-type") == "text/plain");

  std::cout << "PASSED\n";
}

void TestPackedHeadersLargeHeaders() {
  std::cout << "Testing PackedHeaders with many headers... ";

  PackedHeadersBuilder builder;

  // Add many headers
  builder.Add("content-type", "application/json");
  builder.Add("content-length", "12345");
  builder.Add("content-encoding", "gzip");
  builder.Add("cache-control", "max-age=3600");
  builder.Add("date", "Mon, 01 Jan 2024 00:00:00 GMT");
  builder.Add("server", "nginx/1.20");
  builder.Add("etag", "\"abc123\"");
  builder.Add("last-modified", "Sun, 31 Dec 2023 23:59:59 GMT");
  builder.Add("vary", "Accept-Encoding");
  builder.Add("x-custom-1", "value1");
  builder.Add("x-custom-2", "value2");
  builder.Add("x-custom-3", "value3");
  builder.SetStatus("200");

  PackedHeaders headers = builder.Build();

  assert(headers.size() == 12);
  assert(headers.status_code() == 200);

  // Verify all headers
  assert(headers.Get("content-type") == "application/json");
  assert(headers.Get("content-length") == "12345");
  assert(headers.Get("content-encoding") == "gzip");
  assert(headers.Get("cache-control") == "max-age=3600");
  assert(headers.Get("date") == "Mon, 01 Jan 2024 00:00:00 GMT");
  assert(headers.Get("server") == "nginx/1.20");
  assert(headers.Get("etag") == "\"abc123\"");
  assert(headers.Get("last-modified") == "Sun, 31 Dec 2023 23:59:59 GMT");
  assert(headers.Get("vary") == "Accept-Encoding");
  assert(headers.Get("x-custom-1") == "value1");
  assert(headers.Get("x-custom-2") == "value2");
  assert(headers.Get("x-custom-3") == "value3");

  std::cout << "PASSED\n";
}

int main() {
  std::cout << "=== PackedHeaders Unit Tests ===\n\n";

  TestHeaderIdLookup();
  TestHeaderIdToName();
  TestPackedHeadersBuilderBasic();
  TestPackedHeadersCustomHeaders();
  TestPackedHeadersIteration();
  TestPackedHeadersEmpty();
  TestPackedHeadersMove();
  TestPackedHeadersCopy();
  TestPackedHeadersBuilderClear();
  TestPackedHeadersLargeHeaders();

  std::cout << "\nAll PackedHeaders tests passed!\n";
  return 0;
}

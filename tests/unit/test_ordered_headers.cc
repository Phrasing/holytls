// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http/ordered_headers.h"

#include <cassert>
#include <print>

using namespace holytls;
namespace headers = holytls::http::headers;

void TestBasicSetGetHasDelete() {
  std::print("Testing basic Set/Get/Has/Delete... ");

  headers::OrderedHeaders headers;
  assert(headers.headers.empty());
  assert(headers.headers.size() == 0);

  headers::Set(headers, "Content-Type", "application/json");
  assert(headers.headers.size() == 1);
  assert(!headers.headers.empty());
  assert(headers::Has(headers, "Content-Type"));
  assert(headers::Get(headers, "Content-Type") == "application/json");

  headers::Set(headers, "Accept", "text/html");
  assert(headers.headers.size() == 2);
  assert(headers::Has(headers, "Accept"));
  assert(headers::Get(headers, "Accept") == "text/html");

  // Delete
  assert(headers::Delete(headers, "Content-Type"));
  assert(headers.headers.size() == 1);
  assert(!headers::Has(headers, "Content-Type"));
  assert(headers::Get(headers, "Content-Type") == "");

  // Delete non-existent
  assert(!headers::Delete(headers, "X-NonExistent"));
  assert(headers.headers.size() == 1);

  std::println("PASSED");
}

void TestUpsertPreservesPosition() {
  std::print("Testing upsert replaces value, preserves position... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "First", "value1");
  headers::Set(headers, "Second", "value2");
  headers::Set(headers, "Third", "value3");

  // Upsert Second - should stay in middle position
  headers::Set(headers, "Second", "updated");

  // Verify order by iteration
  const auto& vec = headers.headers;
  assert(vec.size() == 3);
  assert(vec[0].name == "First");
  assert(vec[1].name == "Second");
  assert(vec[1].value == "updated");  // Value changed
  assert(vec[2].name == "Third");

  std::println("PASSED");
}

void TestCaseInsensitiveLookup() {
  std::print("Testing case-insensitive lookup... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "Content-Type", "application/json");

  // Lookup with different cases
  assert(headers::Has(headers, "content-type"));
  assert(headers::Has(headers, "CONTENT-TYPE"));
  assert(headers::Has(headers, "Content-TYPE"));
  assert(headers::Get(headers, "content-type") == "application/json");
  assert(headers::Get(headers, "CONTENT-TYPE") == "application/json");

  // Set with different case updates same header
  headers::Set(headers, "CONTENT-TYPE", "text/plain");
  assert(headers.headers.size() == 1);  // Still just one header
  assert(headers::Get(headers, "content-type") == "text/plain");

  // Delete with different case
  assert(headers::Delete(headers, "content-TYPE"));
  assert(headers.headers.empty());

  std::println("PASSED");
}

void TestAddCreatesDuplicates() {
  std::print("Testing Add creates duplicates... ");

  headers::OrderedHeaders headers;
  headers::Add(headers, "Set-Cookie", "session=abc");
  headers::Add(headers, "Set-Cookie", "user=xyz");
  headers::Add(headers, "Set-Cookie", "theme=dark");

  // Size counts all headers
  assert(headers.headers.size() == 3);

  // Get returns first value
  assert(headers::Get(headers, "Set-Cookie") == "session=abc");

  // GetAll returns all values in order
  auto values = headers::GetAll(headers, "Set-Cookie");
  assert(values.size() == 3);
  assert(values[0] == "session=abc");
  assert(values[1] == "user=xyz");
  assert(values[2] == "theme=dark");

  // Direct access has all three
  const auto& vec = headers.headers;
  assert(vec.size() == 3);
  for (const auto& h : vec) {
    assert(h.name == "Set-Cookie");
  }

  std::println("PASSED");
}

void TestGetAllReturnsAllDuplicatesInOrder() {
  std::print("Testing GetAll returns all duplicates in order... ");

  headers::OrderedHeaders headers;
  headers::Add(headers, "Accept-Language", "en-US");
  headers::Add(headers, "Other-Header", "value");
  headers::Add(headers, "Accept-Language", "en-GB");
  headers::Add(headers, "Another-Header", "value2");
  headers::Add(headers, "Accept-Language", "fr");

  auto values = headers::GetAll(headers, "Accept-Language");
  assert(values.size() == 3);
  assert(values[0] == "en-US");
  assert(values[1] == "en-GB");
  assert(values[2] == "fr");

  // Non-existent header returns empty
  auto none = headers::GetAll(headers, "X-NonExistent");
  assert(none.empty());

  std::println("PASSED");
}

void TestIterationOrder() {
  std::print("Testing iteration order matches insertion order... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "Host", "example.com");
  headers::Set(headers, "User-Agent", "Mozilla/5.0");
  headers::Set(headers, "Accept", "text/html");
  headers::Set(headers, "Connection", "keep-alive");

  std::vector<std::string> names;
  for (const auto& h : headers.headers) {
    names.push_back(h.name);
  }

  assert(names.size() == 4);
  assert(names[0] == "Host");
  assert(names[1] == "User-Agent");
  assert(names[2] == "Accept");
  assert(names[3] == "Connection");

  std::println("PASSED");
}

void TestDeleteRemovesFromIndexAndList() {
  std::print("Testing delete removes from both index and list... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "A", "1");
  headers::Set(headers, "B", "2");
  headers::Set(headers, "C", "3");

  assert(headers::Delete(headers, "B"));
  assert(headers.headers.size() == 2);
  assert(!headers::Has(headers, "B"));

  // Verify order after deletion
  const auto& vec = headers.headers;
  assert(vec.size() == 2);
  assert(vec[0].name == "A");
  assert(vec[1].name == "C");

  std::println("PASSED");
}

void TestDeleteRemovesAllDuplicates() {
  std::print("Testing delete removes all duplicates... ");

  headers::OrderedHeaders headers;
  headers::Add(headers, "Set-Cookie", "a=1");
  headers::Add(headers, "Other", "x");
  headers::Add(headers, "Set-Cookie", "b=2");
  headers::Add(headers, "Set-Cookie", "c=3");

  assert(headers.headers.size() == 4);
  assert(headers::Delete(headers, "Set-Cookie"));
  assert(headers.headers.size() == 1);
  assert(!headers::Has(headers, "Set-Cookie"));
  assert(headers::GetAll(headers, "Set-Cookie").empty());

  const auto& vec = headers.headers;
  assert(vec.size() == 1);
  assert(vec[0].name == "Other");

  std::println("PASSED");
}

void TestFromVectorRoundTrip() {
  std::print("Testing FromVector round-trip... ");

  std::vector<Header> input = {
      {"Content-Type", "application/json"},
      {"Accept", "text/html"},
      {"X-Custom", "value"},
  };

  headers::OrderedHeaders headers = headers::FromVector(input);
  assert(headers.headers.size() == 3);
  assert(headers::Get(headers, "Content-Type") == "application/json");
  assert(headers::Get(headers, "Accept") == "text/html");
  assert(headers::Get(headers, "X-Custom") == "value");

  const auto& output = headers.headers;
  assert(output.size() == 3);
  assert(output[0].name == "Content-Type");
  assert(output[0].value == "application/json");
  assert(output[1].name == "Accept");
  assert(output[2].name == "X-Custom");

  std::println("PASSED");
}

void TestSetAtPosition() {
  std::print("Testing SetAt position... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "A", "1");
  headers::Set(headers, "C", "3");

  // Insert B at position 1 (between A and C)
  headers::SetAt(headers, 1, "B", "2");

  const auto& vec = headers.headers;
  assert(vec.size() == 3);
  assert(vec[0].name == "A");
  assert(vec[1].name == "B");
  assert(vec[2].name == "C");

  // SetAt with existing header moves it
  headers::SetAt(headers, 0, "C", "updated");
  const auto& vec2 = headers.headers;
  assert(vec2.size() == 3);
  assert(vec2[0].name == "C");
  assert(vec2[0].value == "updated");
  assert(vec2[1].name == "A");
  assert(vec2[2].name == "B");

  std::println("PASSED");
}

void TestMoveTo() {
  std::print("Testing MoveTo... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "First", "1");
  headers::Set(headers, "Second", "2");
  headers::Set(headers, "Third", "3");

  // Move Third to position 0
  headers::MoveTo(headers, "Third", 0);

  const auto& vec = headers.headers;
  assert(vec.size() == 3);
  assert(vec[0].name == "Third");
  assert(vec[1].name == "First");
  assert(vec[2].name == "Second");

  // Move non-existent does nothing
  headers::MoveTo(headers, "NonExistent", 0);
  assert(headers.headers.size() == 3);

  std::println("PASSED");
}

void TestMoveSemantics() {
  std::print("Testing move semantics... ");

  headers::OrderedHeaders original;
  headers::Set(original, "Content-Type", "text/html");
  headers::Set(original, "Server", "nginx");

  // Move construct
  headers::OrderedHeaders moved(std::move(original));
  assert(moved.headers.size() == 2);
  assert(headers::Get(moved, "Content-Type") == "text/html");
  assert(original.headers.empty());  // NOLINT: testing moved-from state

  // Move assign
  headers::OrderedHeaders another;
  headers::Set(another, "Date", "today");
  another = std::move(moved);
  assert(another.headers.size() == 2);
  assert(headers::Get(another, "Content-Type") == "text/html");
  assert(moved.headers.empty());  // NOLINT: testing moved-from state

  std::println("PASSED");
}

void TestCopySemantics() {
  std::print("Testing copy semantics... ");

  headers::OrderedHeaders original;
  headers::Set(original, "Content-Type", "text/html");
  headers::Add(original, "Set-Cookie", "a=1");
  headers::Add(original, "Set-Cookie", "b=2");

  // Copy using Copy function
  headers::OrderedHeaders copied = headers::Copy(original);
  assert(copied.headers.size() == original.headers.size());
  assert(headers::Get(copied, "Content-Type") == headers::Get(original, "Content-Type"));
  assert(headers::GetAll(copied, "Set-Cookie").size() == 2);

  // Original unchanged
  assert(original.headers.size() == 3);

  // Copy assign using Copy function
  headers::OrderedHeaders another;
  headers::Set(another, "Server", "apache");
  another = headers::Copy(original);
  assert(another.headers.size() == 3);
  assert(headers::Get(another, "Content-Type") == "text/html");

  // Original still unchanged
  assert(original.headers.size() == 3);

  std::println("PASSED");
}

void TestCopySurvivesOriginalDestruction() {
  std::print("Testing copy survives original destruction... ");

  headers::OrderedHeaders copied;
  {
    headers::OrderedHeaders original;
    headers::Set(original, "Host", "example.com");
    headers::Set(original, "User-Agent", "Test/1.0");
    headers::Add(original, "Cookie", "a=1");
    headers::Add(original, "Cookie", "b=2");
    copied = headers::Copy(original);
  }  // original destroyed here

  // copied must still work with its own data
  assert(copied.headers.size() == 4);
  assert(headers::Has(copied, "Host"));
  assert(headers::Has(copied, "User-Agent"));
  assert(headers::Get(copied, "Host") == "example.com");
  assert(headers::Get(copied, "User-Agent") == "Test/1.0");
  assert(headers::GetAll(copied, "Cookie").size() == 2);

  // Can still modify
  headers::Set(copied, "Host", "other.com");
  assert(headers::Get(copied, "Host") == "other.com");

  std::println("PASSED");
}

void TestClear() {
  std::print("Testing Clear... ");

  headers::OrderedHeaders headers;
  headers::Set(headers, "A", "1");
  headers::Set(headers, "B", "2");
  headers::Add(headers, "C", "3");
  headers::Add(headers, "C", "4");

  headers::Clear(headers);
  assert(headers.headers.empty());
  assert(headers.headers.size() == 0);
  assert(!headers::Has(headers, "A"));
  assert(!headers::Has(headers, "B"));
  assert(!headers::Has(headers, "C"));

  // Can add after clear
  headers::Set(headers, "New", "value");
  assert(headers.headers.size() == 1);
  assert(headers::Get(headers, "New") == "value");

  std::println("PASSED");
}

void TestEmptyHeaders() {
  std::print("Testing empty headers... ");

  headers::OrderedHeaders headers;
  assert(headers.headers.empty());
  assert(headers.headers.size() == 0);
  assert(!headers::Has(headers, "anything"));
  assert(headers::Get(headers, "anything") == "");
  assert(headers::GetAll(headers, "anything").empty());
  assert(!headers::Delete(headers, "anything"));

  const auto& vec = headers.headers;
  assert(vec.empty());

  // Iteration over empty
  int count = 0;
  for (const auto& h : headers.headers) {
    (void)h;
    ++count;
  }
  assert(count == 0);

  std::println("PASSED");
}

void TestLargeHeaderSet() {
  std::print("Testing with many headers... ");

  headers::OrderedHeaders headers;

  // Add 100 unique headers
  for (int i = 0; i < 100; ++i) {
    std::string name = "Header-" + std::to_string(i);
    std::string value = "Value-" + std::to_string(i);
    headers::Set(headers, name, value);
  }

  assert(headers.headers.size() == 100);

  // Verify all exist
  for (int i = 0; i < 100; ++i) {
    std::string name = "Header-" + std::to_string(i);
    std::string expected = "Value-" + std::to_string(i);
    assert(headers::Has(headers, name));
    assert(headers::Get(headers, name) == expected);
  }

  // Verify order preserved
  const auto& vec = headers.headers;
  assert(vec.size() == 100);
  for (size_t i = 0; i < 100; ++i) {
    std::string expected_name = "Header-" + std::to_string(i);
    assert(vec[i].name == expected_name);
  }

  std::println("PASSED");
}

int main() {
  std::println("=== OrderedHeaders Unit Tests ===\n");

  TestBasicSetGetHasDelete();
  TestUpsertPreservesPosition();
  TestCaseInsensitiveLookup();
  TestAddCreatesDuplicates();
  TestGetAllReturnsAllDuplicatesInOrder();
  TestIterationOrder();
  TestDeleteRemovesFromIndexAndList();
  TestDeleteRemovesAllDuplicates();
  TestFromVectorRoundTrip();
  TestSetAtPosition();
  TestMoveTo();
  TestMoveSemantics();
  TestCopySemantics();
  TestCopySurvivesOriginalDestruction();
  TestClear();
  TestEmptyHeaders();
  TestLargeHeaderSet();

  std::println("\nAll OrderedHeaders tests passed!");
  return 0;
}

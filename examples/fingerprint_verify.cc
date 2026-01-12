// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Example: Verify TLS fingerprint matches Chrome 143
//
// Fetches fingerprint from tls.peet.ws/api/all, parses with RapidJSON,
// and verifies key values match expected Chrome 143 fingerprint.
//
// Usage: ./fingerprint_verify

#include <print>
#include <string>
#include <string_view>

#include <rapidjson/document.h>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

namespace {

// Expected Chrome 143 fingerprint values
constexpr std::string_view kExpectedHttpVersion = "h2";
constexpr std::string_view kExpectedJa4Prefix = "t13d";
constexpr std::string_view kExpectedAkamaiFingerprint =
    "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
constexpr std::string_view kExpectedFirstCipher = "TLS_AES_128_GCM_SHA256";

// Test result tracking
struct TestResults {
  int passed = 0;
  int failed = 0;

  void Pass(std::string_view name) {
    std::println("  [PASS] {}", name);
    ++passed;
  }

  void Fail(std::string_view name, std::string_view expected,
            std::string_view actual) {
    std::println("  [FAIL] {}", name);
    std::println("         Expected: {}", expected);
    std::println("         Actual:   {}", actual);
    ++failed;
  }

  void Fail(std::string_view name, std::string_view reason) {
    std::println("  [FAIL] {}: {}", name, reason);
    ++failed;
  }

  bool AllPassed() const { return failed == 0; }

  void PrintSummary() const {
    std::println("\n=== Results ===");
    std::println("Passed: {}", passed);
    std::println("Failed: {}", failed);
  }
};

// Helper to get string from JSON value
std::string_view GetString(const rapidjson::Value& v) {
  if (!v.IsString()) return "";
  return {v.GetString(), v.GetStringLength()};
}

// Verify all fingerprint values
void VerifyFingerprint(std::string_view json_str, TestResults& results) {
  rapidjson::Document doc;
  doc.Parse(json_str.data(), json_str.size());

  if (doc.HasParseError()) {
    results.Fail("JSON Parse", "Failed to parse response");
    return;
  }

  // Verify http_version
  if (doc.HasMember("http_version")) {
    auto actual = GetString(doc["http_version"]);
    if (actual == kExpectedHttpVersion) {
      results.Pass("http_version");
    } else {
      results.Fail("http_version", kExpectedHttpVersion, actual);
    }
  } else {
    results.Fail("http_version", "Field not found");
  }

  // Verify tls.ja4 starts with expected prefix
  if (doc.HasMember("tls") && doc["tls"].HasMember("ja4")) {
    auto ja4 = GetString(doc["tls"]["ja4"]);
    if (ja4.starts_with(kExpectedJa4Prefix)) {
      results.Pass("tls.ja4 prefix");
    } else {
      results.Fail("tls.ja4 prefix", kExpectedJa4Prefix, ja4.substr(0, 4));
    }
  } else {
    results.Fail("tls.ja4", "Field not found");
  }

  // Verify http2.akamai_fingerprint
  if (doc.HasMember("http2") && doc["http2"].HasMember("akamai_fingerprint")) {
    auto actual = GetString(doc["http2"]["akamai_fingerprint"]);
    if (actual == kExpectedAkamaiFingerprint) {
      results.Pass("http2.akamai_fingerprint");
    } else {
      results.Fail("http2.akamai_fingerprint", kExpectedAkamaiFingerprint,
                   actual);
    }
  } else {
    results.Fail("http2.akamai_fingerprint", "Field not found");
  }

  // Verify tls.ciphers[1] (first non-GREASE cipher)
  if (doc.HasMember("tls") && doc["tls"].HasMember("ciphers") &&
      doc["tls"]["ciphers"].IsArray() && doc["tls"]["ciphers"].Size() > 1) {
    auto actual = GetString(doc["tls"]["ciphers"][1]);
    if (actual == kExpectedFirstCipher) {
      results.Pass("tls.ciphers[1]");
    } else {
      results.Fail("tls.ciphers[1]", kExpectedFirstCipher, actual);
    }
  } else {
    results.Fail("tls.ciphers[1]", "Field not found or too short");
  }

  // Verify TLS version negotiated is TLS 1.3 (772)
  if (doc.HasMember("tls") && doc["tls"].HasMember("tls_version_negotiated")) {
    auto actual = GetString(doc["tls"]["tls_version_negotiated"]);
    if (actual == "772") {
      results.Pass("tls.tls_version_negotiated (TLS 1.3)");
    } else {
      results.Fail("tls.tls_version_negotiated", "772", actual);
    }
  } else {
    results.Fail("tls.tls_version_negotiated", "Field not found");
  }
}

}  // namespace

// Store result globally for main() to access after coroutine completes
static TestResults g_results;

Task<void> Run(AsyncClient& client) {
  std::println("=== HolyTLS Fingerprint Verification ===");
  std::println("Target: https://tls.peet.ws/api/all");
  std::println("Expected: Chrome 143 fingerprint\n");

  auto result = co_await client.Get("https://tls.peet.ws/api/all");

  if (!result) {
    std::println("Request failed: {}", result.error().message);
    g_results.Fail("HTTP Request", result.error().message);
    co_return;
  }

  if (result.value().status_code != 200) {
    std::println("Unexpected status: {}", result.value().status_code);
    g_results.Fail("HTTP Status", "Expected 200");
    co_return;
  }

  std::println("Response received: {} bytes", result.value().body.size());
  std::println("\nVerifying fingerprint values...\n");

  VerifyFingerprint(result.value().body_string(), g_results);
  g_results.PrintSummary();
}

int main() {
  AsyncClient client(ClientConfig::Chrome143());
  RunAsync(client, Run(client));

  return g_results.AllPassed() ? 0 : 1;
}

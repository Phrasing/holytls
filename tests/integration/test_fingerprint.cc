// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Integration test for TLS and HTTP/2 fingerprint validation.
// This test connects to fingerprint validation services and verifies
// that the client correctly impersonates Chrome.

#include <cassert>
#include <print>

#include "holytls/client.h"
#include "holytls/config.h"
#include "holytls/http2/chrome_h2_profile.h"
#include "holytls/tls/chrome_profile.h"

void TestTlsProfile() {
  std::print("Testing TLS profile configuration... ");

  const auto& profile =
      holytls::tls::GetChromeTlsProfile(holytls::ChromeVersion::kChrome131);

  // Verify critical settings
  assert(profile.grease_enabled);
  assert(profile.permute_extensions);
  assert(profile.cipher_suites.size() >= 10);
  assert(profile.supported_groups.size() >= 3);
  assert(!profile.user_agent.empty());

  std::println("PASSED");
}

void TestH2Profile() {
  std::print("Testing HTTP/2 profile configuration... ");

  const auto& profile =
      holytls::http2::GetChromeH2Profile(holytls::ChromeVersion::kChrome131);

  // Verify Chrome SETTINGS values
  assert(profile.settings.header_table_size == 65536);
  assert(profile.settings.enable_push == 0);
  assert(profile.settings.max_concurrent_streams == 1000);
  assert(profile.settings.initial_window_size == 6291456);
  assert(profile.settings.max_frame_size == 16384);
  assert(profile.settings.max_header_list_size == 262144);

  // Verify window update
  assert(profile.connection_window_update == 15663105);

  // Verify pseudo-header order
  assert(profile.pseudo_header_order ==
         holytls::http2::ChromeH2Profile::PseudoHeaderOrder::kMASP);

  std::println("PASSED");
}

void TestCipherSuiteString() {
  std::print("Testing cipher suite string generation... ");

  std::string ciphers =
      holytls::tls::GetCipherSuiteString(holytls::ChromeVersion::kChrome131);

  // Should contain TLS 1.3 ciphers
  assert(ciphers.find("TLS_AES_128_GCM_SHA256") != std::string::npos);
  assert(ciphers.find("TLS_AES_256_GCM_SHA384") != std::string::npos);
  assert(ciphers.find("TLS_CHACHA20_POLY1305_SHA256") != std::string::npos);

  // Should contain ECDHE ciphers
  assert(ciphers.find("ECDHE-ECDSA-AES128-GCM-SHA256") != std::string::npos);
  assert(ciphers.find("ECDHE-RSA-CHACHA20-POLY1305") != std::string::npos);

  std::println("PASSED");
}

void TestClientConfig() {
  std::print("Testing client configuration... ");

  auto config = holytls::ClientConfig::Chrome131();

  assert(config.tls.chrome_version == holytls::ChromeVersion::kChrome131);
  assert(config.http2.chrome_version == holytls::ChromeVersion::kChrome131);
  assert(config.tls.permute_extensions);
  assert(config.pool.max_connections_per_host == 6);

  std::println("PASSED");
}

void TestChrome143Profile() {
  std::print("Testing Chrome 143 profile (default)... ");

  // Test TLS profile
  const auto& tls_profile =
      holytls::tls::GetChromeTlsProfile(holytls::ChromeVersion::kChrome143);

  assert(tls_profile.grease_enabled);
  assert(tls_profile.permute_extensions);  // Random extension order
  assert(tls_profile.encrypted_client_hello);
  assert(tls_profile.supported_groups.size() == 4);
  assert(tls_profile.supported_groups[0] == 0x11ec);  // X25519MLKEM768

  // Test HTTP/2 profile
  const auto& h2_profile =
      holytls::http2::GetChromeH2Profile(holytls::ChromeVersion::kChrome143);

  assert(h2_profile.settings.header_table_size == 65536);
  assert(h2_profile.settings.enable_push == 0);
  assert(h2_profile.settings.initial_window_size == 6291456);
  assert(h2_profile.settings.max_header_list_size == 262144);

  // Chrome 143 doesn't send these in SETTINGS frame
  assert(!h2_profile.settings.send_max_concurrent_streams);
  assert(!h2_profile.settings.send_max_frame_size);

  assert(h2_profile.connection_window_update == 15663105);

  // Test that latest points to Chrome 143
  auto latest_config = holytls::ClientConfig::ChromeLatest();
  assert(latest_config.tls.chrome_version == holytls::ChromeVersion::kChrome143);

  std::println("PASSED");
}

int main() {
  std::println("=== Fingerprint Integration Tests ===\n");

  TestTlsProfile();
  TestH2Profile();
  TestCipherSuiteString();
  TestClientConfig();
  TestChrome143Profile();

  std::println("\nAll fingerprint tests passed!");
  std::println("\nNote: Network fingerprint validation requires:");
  std::println("  1. Build with lexiforest/boringssl");
  std::println("  2. Connect to https://tls.peet.ws/api/all");
  std::println("  3. Verify JA3/JA4 hash matches Chrome");

  return 0;
}

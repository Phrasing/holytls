// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Chad-TLS: High-performance Chrome-impersonating HTTP/2 client
//
// This is a demonstration of the library's capabilities.
// The library impersonates Chrome's TLS (JA3/JA4) and HTTP/2 fingerprints.

#include <algorithm>
#include <iostream>

#include "chad/client.h"
#include "chad/config.h"
#include "core/reactor.h"
#include "http2/chrome_h2_profile.h"
#include "http2/h2_session.h"
#include "tls/chrome_profile.h"
#include "tls/tls_context.h"

namespace {

void PrintChromeProfile(chad::ChromeVersion version) {
  const auto& tls_profile = chad::tls::GetChromeTlsProfile(version);
  const auto& h2_profile = chad::http2::GetChromeH2Profile(version);

  std::cout << "\n=== Chrome " << static_cast<int>(version)
            << " Fingerprint Profile ===\n\n";

  std::cout << "TLS Configuration:\n";
  std::cout << "  User-Agent: " << tls_profile.user_agent << "\n";
  std::cout << "  GREASE enabled: "
            << (tls_profile.grease_enabled ? "yes" : "no") << "\n";
  std::cout << "  Extension permutation: "
            << (tls_profile.permute_extensions ? "yes" : "no") << "\n";
  std::cout << "  Record size limit: " << tls_profile.record_size_limit << "\n";
  std::cout << "  Key shares limit: "
            << static_cast<int>(tls_profile.key_shares_limit) << "\n";

  std::cout << "\n  Cipher suites (" << tls_profile.cipher_suites.size()
            << "):\n";
  for (size_t i = 0; i < std::min(tls_profile.cipher_suites.size(), size_t{5});
       ++i) {
    std::cout << "    0x" << std::hex << tls_profile.cipher_suites[i]
              << std::dec << "\n";
  }
  if (tls_profile.cipher_suites.size() > 5) {
    std::cout << "    ... and " << (tls_profile.cipher_suites.size() - 5)
              << " more\n";
  }

  std::cout << "\n  Supported groups:\n";
  for (uint16_t group : tls_profile.supported_groups) {
    std::cout << "    0x" << std::hex << group << std::dec;
    switch (group) {
      case 0x11ec:
        std::cout << " (X25519MLKEM768)";
        break;
      case 0x6399:
        std::cout << " (X25519Kyber768)";
        break;
      case 0x001d:
        std::cout << " (X25519)";
        break;
      case 0x0017:
        std::cout << " (P-256)";
        break;
      case 0x0018:
        std::cout << " (P-384)";
        break;
    }
    std::cout << "\n";
  }

  std::cout << "\nHTTP/2 Configuration:\n";
  std::cout << "  HEADER_TABLE_SIZE: " << h2_profile.settings.header_table_size
            << "\n";
  std::cout << "  ENABLE_PUSH: " << h2_profile.settings.enable_push << "\n";
  std::cout << "  MAX_CONCURRENT_STREAMS: "
            << h2_profile.settings.max_concurrent_streams << "\n";
  std::cout << "  INITIAL_WINDOW_SIZE: "
            << h2_profile.settings.initial_window_size << " ("
            << (h2_profile.settings.initial_window_size / 1024 / 1024)
            << " MB)\n";
  std::cout << "  MAX_FRAME_SIZE: " << h2_profile.settings.max_frame_size
            << "\n";
  std::cout << "  MAX_HEADER_LIST_SIZE: "
            << h2_profile.settings.max_header_list_size << "\n";
  std::cout << "  Connection WINDOW_UPDATE: "
            << h2_profile.connection_window_update << "\n";
  std::cout
      << "  Pseudo-header order: :method :authority :scheme :path (MASP)\n";
}

void DemoReactor() {
  std::cout << "\n=== Reactor Demo ===\n\n";

  chad::core::ReactorConfig config;
  config.max_events = 1024;
  config.epoll_timeout_ms = 100;
  config.use_edge_trigger = true;

  chad::core::Reactor reactor(config);
  std::cout << "Created epoll reactor (edge-triggered)\n";
  std::cout << "Max events: " << config.max_events << "\n";
  std::cout << "Handler count: " << reactor.handler_count() << "\n";
}

}  // namespace

int main(int argc, char* argv[]) {
  (void)argc;
  (void)argv;

  std::cout << "Chad-TLS: Chrome-Impersonating HTTP/2 Client\n";
  std::cout << "============================================\n";

  // Show available Chrome profiles
  PrintChromeProfile(chad::ChromeVersion::kChrome120);
  PrintChromeProfile(chad::ChromeVersion::kChrome143);

  // Demo the reactor
  DemoReactor();

  std::cout << "\n=== Client Configuration ===\n\n";

  // Create client with Chrome 143 profile (default/latest)
  auto config = chad::ClientConfig::Chrome143();
  std::cout << "Created client config for Chrome "
            << static_cast<int>(config.tls.chrome_version) << "\n";
  std::cout << "  Default timeout: " << config.default_timeout.count()
            << " ms\n";
  std::cout << "  Max connections per host: "
            << config.pool.max_connections_per_host << "\n";
  std::cout << "  Max total connections: " << config.pool.max_total_connections
            << "\n";
  std::cout << "  HTTP/2 multiplexing: "
            << (config.pool.enable_multiplexing ? "enabled" : "disabled")
            << "\n";

  // Show TLS cipher string
  std::cout << "\nTLS cipher string:\n  "
            << chad::tls::GetCipherSuiteString(chad::ChromeVersion::kChrome143)
            << "\n";

  std::cout << "\n=== Build Complete ===\n";
  std::cout << "The library is ready for use. Key features:\n";
  std::cout << "  - TLS fingerprint impersonation (JA3/JA4)\n";
  std::cout
      << "  - HTTP/2 fingerprint impersonation (SETTINGS, header order)\n";
  std::cout << "  - High-performance epoll reactor\n";
  std::cout << "  - Connection pooling with HTTP/2 multiplexing\n";
  std::cout << "  - Zero-copy I/O buffers\n";
  std::cout << "  - Pre-allocated memory pools\n";

  return 0;
}

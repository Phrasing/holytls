// Example: Using proxies with holytls
//
// This example demonstrates how to configure HTTP and SOCKS proxies.
// Supports HTTP CONNECT, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h.
//
// Usage: ./proxy_example <proxy_type> <proxy_host> <proxy_port> [username] [password]

#include <cstdlib>
#include <iostream>
#include <string>

#include "holytls/async.h"
#include "holytls/client.h"

using namespace holytls;

// Test URL to fetch through proxy
constexpr const char* kTestUrl = "https://httpbin.org/ip";

Task<void> FetchThroughProxy(AsyncClient& client) {
  std::cout << "Fetching " << kTestUrl << " through proxy...\n";

  auto result = co_await client.Get(kTestUrl);

  if (result) {
    const auto& response = result.value();
    std::cout << "Status: " << response.status_code << "\n";
    std::cout << "Body: " << response.body_string() << "\n";
  } else {
    std::cerr << "Error: " << result.error().message << "\n";
  }
}

ProxyType ParseProxyType(const std::string& type_str) {
  if (type_str == "http") return ProxyType::kHttp;
  if (type_str == "socks4") return ProxyType::kSocks4;
  if (type_str == "socks4a") return ProxyType::kSocks4a;
  if (type_str == "socks5") return ProxyType::kSocks5;
  if (type_str == "socks5h") return ProxyType::kSocks5h;
  return ProxyType::kNone;
}

const char* ProxyTypeToString(ProxyType type) {
  switch (type) {
    case ProxyType::kHttp: return "HTTP";
    case ProxyType::kSocks4: return "SOCKS4";
    case ProxyType::kSocks4a: return "SOCKS4a";
    case ProxyType::kSocks5: return "SOCKS5";
    case ProxyType::kSocks5h: return "SOCKS5h";
    default: return "Unknown";
  }
}

void PrintUsage(const char* prog) {
  std::cerr << "Usage: " << prog
            << " <proxy_type> <proxy_host> <proxy_port> [username] [password]\n";
  std::cerr << "\nProxy types:\n";
  std::cerr << "  http     - HTTP CONNECT proxy\n";
  std::cerr << "  socks4   - SOCKS4 (requires client-side DNS resolution)\n";
  std::cerr << "  socks4a  - SOCKS4a (proxy resolves DNS)\n";
  std::cerr << "  socks5   - SOCKS5 (requires client-side DNS resolution)\n";
  std::cerr << "  socks5h  - SOCKS5h (proxy resolves DNS) - RECOMMENDED\n";
  std::cerr << "\nExamples:\n";
  std::cerr << "  " << prog << " http 127.0.0.1 8080\n";
  std::cerr << "  " << prog << " socks5h 127.0.0.1 1080\n";
  std::cerr << "  " << prog << " socks5 proxy.example.com 1080 myuser mypass\n";
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    PrintUsage(argv[0]);
    return 1;
  }

  // Parse command line arguments
  ProxyType proxy_type = ParseProxyType(argv[1]);
  if (proxy_type == ProxyType::kNone) {
    std::cerr << "Error: Unknown proxy type '" << argv[1] << "'\n\n";
    PrintUsage(argv[0]);
    return 1;
  }

  std::string proxy_host = argv[2];
  uint16_t proxy_port = static_cast<uint16_t>(std::stoi(argv[3]));
  std::string proxy_user = (argc > 4) ? argv[4] : "";
  std::string proxy_pass = (argc > 5) ? argv[5] : "";

  std::cout << "Proxy: " << proxy_host << ":" << proxy_port
            << " (" << ProxyTypeToString(proxy_type) << ")";
  if (!proxy_user.empty()) {
    std::cout << " (with authentication)";
  }
  std::cout << "\n\n";

  // Configure client with proxy
  ClientConfig config = ClientConfig::ChromeLatest();
  config.proxy.type = proxy_type;
  config.proxy.host = proxy_host;
  config.proxy.port = proxy_port;
  config.proxy.username = proxy_user;
  config.proxy.password = proxy_pass;

  // Create async client with proxy configuration
  AsyncClient client(config);

  // Run the async task
  RunAsync(client, FetchThroughProxy(client));

  return 0;
}

// Example: Using HTTP proxy with holytls
//
// This example demonstrates how to configure an HTTP/HTTPS proxy.
// The proxy handles CONNECT tunneling for HTTPS requests.
//
// Usage: ./proxy_example <proxy_host> <proxy_port> [username] [password]

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

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0]
              << " <proxy_host> <proxy_port> [username] [password]\n";
    std::cerr << "\nExample:\n";
    std::cerr << "  " << argv[0] << " 127.0.0.1 8080\n";
    std::cerr << "  " << argv[0] << " proxy.example.com 3128 myuser mypass\n";
    return 1;
  }

  // Parse command line arguments
  std::string proxy_host = argv[1];
  uint16_t proxy_port = static_cast<uint16_t>(std::stoi(argv[2]));
  std::string proxy_user = (argc > 3) ? argv[3] : "";
  std::string proxy_pass = (argc > 4) ? argv[4] : "";

  std::cout << "Proxy: " << proxy_host << ":" << proxy_port;
  if (!proxy_user.empty()) {
    std::cout << " (with authentication)";
  }
  std::cout << "\n\n";

  // Configure client with proxy
  ClientConfig config = ClientConfig::ChromeLatest();
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

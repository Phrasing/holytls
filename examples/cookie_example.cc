// Example: Cookie Jar usage with holytls
//
// This example demonstrates automatic cookie handling:
// 1. First request to httpbin.org/cookies/set sets cookies
// 2. Second request to httpbin.org/cookies shows the cookies are sent back
//
// Usage: ./cookie_example

#include <iostream>

#include "holytls/async.h"
#include "holytls/client.h"
#include "holytls/http/cookie_jar.h"

using namespace holytls;

Task<void> TestCookies(AsyncClient& client, http::CookieJar& jar) {
  std::cout << "=== Cookie Jar Test ===\n\n";

  // Step 1: Set some cookies via httpbin
  std::cout << "1. Setting cookies via httpbin.org/cookies/set...\n";
  auto set_result = co_await client.Get(
      "https://httpbin.org/cookies/set?session_id=abc123&user=testuser");

  if (set_result) {
    std::cout << "   Status: " << set_result.value().status_code << "\n";
    std::cout << "   Cookies stored: " << jar.Size() << "\n\n";
  } else {
    std::cerr << "   Error: " << set_result.error().message << "\n";
    co_return;
  }

  // Step 2: Verify cookies are sent back
  std::cout << "2. Fetching httpbin.org/cookies to verify cookies sent...\n";
  auto get_result = co_await client.Get("https://httpbin.org/cookies");

  if (get_result) {
    const auto& response = get_result.value();
    std::cout << "   Status: " << response.status_code << "\n";
    std::cout << "   Response body:\n";
    std::cout << response.body_string() << "\n\n";
  } else {
    std::cerr << "   Error: " << get_result.error().message << "\n";
    co_return;
  }

  // Step 3: Show all cookies in the jar
  std::cout << "3. All cookies in jar:\n";
  auto cookies = jar.GetAllCookies();
  for (const auto& cookie : cookies) {
    std::cout << "   - " << cookie.name << "=" << cookie.value
              << " (domain: " << cookie.domain << ")\n";
  }

  std::cout << "\n=== Test Complete ===\n";
}

int main() {
  // Create a cookie jar
  http::CookieJar cookie_jar;

  // Configure client with cookie jar
  ClientConfig config = ClientConfig::ChromeLatest();
  config.cookie_jar = &cookie_jar;

  // Create async client
  AsyncClient client(config);

  // Run the test
  RunAsync(client, TestCookies(client, cookie_jar));

  return 0;
}

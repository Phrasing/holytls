# holytls

High-performance HTTP/2 client with Chrome TLS fingerprint impersonation.

## Features

- **Chrome TLS Fingerprinting** - Mimics Chrome 143 JA3/JA4 fingerprints using patched BoringSSL
- **HTTP/2** - Full HTTP/2 support via nghttp2 with Chrome-accurate header ordering
- **Async I/O** - libuv event loop with multi-threaded reactor architecture
- **Connection Pooling** - Automatic connection reuse with consistent hashing
- **C++20 Coroutines** - Optional `co_await` API for clean async code
- **Compression** - Automatic decompression (gzip, brotli, zstd)

## Quick Start

```cpp
#include <holytls/client.h>
#include <holytls/config.h>
#include <print>

int main() {
    holytls::HttpClient client(holytls::ClientConfig::Chrome143());

    client.Get("https://tls.peet.ws/api/all", [](auto response, auto error) {
        if (error) {
            std::println("Error: {}", error.message);
            return;
        }
        std::println("Status: {}", response.status_code);
        std::println("Body: {}", response.body_string());
    });

    client.Run();
}
```

### With Coroutines

```cpp
#include <holytls/async.h>
#include <holytls/config.h>

holytls::Task<void> fetch() {
    holytls::AsyncClient client(holytls::ClientConfig::Chrome143());

    auto result = co_await client.Get("https://httpbin.org/get");
    if (result) {
        std::println("Status: {}", result->status_code);
    }
}
```

## Building

### Linux

```bash
./build.sh
```

### Windows

```batch
:: From "x64 Native Tools Command Prompt for VS 2022"
build.bat
```

Requires: CMake 3.20+, Ninja, Go (for BoringSSL)

## Stress Test Results

**171K RPS peak, 166K sustained** - ~2.85 million TLS-encrypted HTTP/2 requests per minute with Chrome fingerprint intact.

| Connections | Threads | Avg RPS | Peak RPS | Success |
|-------------|---------|---------|----------|---------|
| 6000 | 16 | 165,870 | 171,184 | 100% |

P50 latency: 26ms

## Architecture

```
holytls/
├── core/           # Reactor, event loop, connections
├── tls/            # BoringSSL wrapper, Chrome profiles
├── http2/          # nghttp2 wrapper, header building
├── pool/           # Connection and host pooling
├── client/         # High-level HttpClient API
└── util/           # DNS, URL parsing, decompression
```

## Dependencies

- [BoringSSL](https://github.com/Phrasing/boringssl) (Phrasing fork with impersonation patches)
- [nghttp2](https://github.com/nghttp2/nghttp2) - HTTP/2 protocol
- [libuv](https://github.com/libuv/libuv) - Async I/O
- [zstd](https://github.com/facebook/zstd), [brotli](https://github.com/google/brotli), [zlib](https://github.com/madler/zlib) - Compression

## License

MIT

// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#ifndef CHAD_UTIL_ASYNC_DECOMPRESSOR_H_
#define CHAD_UTIL_ASYNC_DECOMPRESSOR_H_

#include <functional>
#include <string>
#include <vector>

#include <uv.h>

#include "util/decompressor.h"

namespace chad {
namespace util {

// Callback when decompression completes
// Called on the reactor thread (same thread that called DecompressAsync)
using DecompressCallback = std::function<void(
    std::vector<uint8_t> decompressed, bool success, const std::string& error)>;

// Async decompression work request
// Allocated on heap, owned by libuv during work execution
struct DecompressWork {
  uv_work_t work;

  // Input
  ContentEncoding encoding;
  std::vector<uint8_t> compressed;

  // Output
  std::vector<uint8_t> decompressed;
  bool success = false;
  std::string error;

  // Completion callback
  DecompressCallback callback;
};

// Queue decompression work to libuv's thread pool.
// The callback is invoked on the event loop thread after decompression
// completes.
//
// This allows CPU-bound decompression to run off the main event loop,
// preventing it from blocking I/O operations.
//
// Thread safety:
// - Must be called from the thread that owns the event loop
// - Callback is invoked on the same thread
// - Decompression runs on a worker thread from libuv's pool
void DecompressAsync(uv_loop_t* loop, ContentEncoding encoding,
                     std::vector<uint8_t> compressed,
                     DecompressCallback callback);

}  // namespace util
}  // namespace chad

#endif  // CHAD_UTIL_ASYNC_DECOMPRESSOR_H_

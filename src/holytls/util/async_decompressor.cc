// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/util/async_decompressor.h"

namespace holytls {
namespace util {

namespace {

// Runs on libuv thread pool worker thread
void WorkCallback(uv_work_t* req) {
  auto* work = static_cast<DecompressWork*>(req->data);

  work->success =
      Decompress(work->encoding, work->compressed.data(),
                 work->compressed.size(), work->decompressed, &work->error);

  // Only release compressed data on success
  // On failure, we preserve it to return as-is
  if (work->success) {
    work->compressed.clear();
    work->compressed.shrink_to_fit();
  }
}

// Runs on reactor thread after work completes
void AfterWorkCallback(uv_work_t* req, int status) {
  auto* work = static_cast<DecompressWork*>(req->data);

  if (status == UV_ECANCELED) {
    work->callback({}, false, "Decompression cancelled");
  } else if (work->success) {
    work->callback(std::move(work->decompressed), true, "");
  } else {
    // On failure, return the original compressed data
    work->callback(std::move(work->compressed), false, work->error);
  }

  delete work;
}

}  // namespace

void DecompressAsync(uv_loop_t* loop, ContentEncoding encoding,
                     std::vector<uint8_t> compressed,
                     DecompressCallback callback) {
  // For identity encoding or empty data, skip thread pool
  if (encoding == ContentEncoding::kIdentity ||
      encoding == ContentEncoding::kUnknown || compressed.empty()) {
    callback(std::move(compressed), true, "");
    return;
  }

  auto* work = new DecompressWork();
  work->work.data = work;
  work->encoding = encoding;
  work->compressed = std::move(compressed);
  work->callback = std::move(callback);

  int ret = uv_queue_work(loop, &work->work, WorkCallback, AfterWorkCallback);
  if (ret != 0) {
    // Failed to queue work - invoke callback with error
    work->callback({}, false, uv_strerror(ret));
    delete work;
  }
}

}  // namespace util
}  // namespace holytls

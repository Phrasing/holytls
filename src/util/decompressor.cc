// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "util/decompressor.h"

#include <algorithm>
#include <cctype>

#include <brotli/decode.h>
#include <zlib.h>
#include <zstd.h>

namespace chad {
namespace util {

namespace {

// Trim whitespace and convert to lowercase for comparison
std::string NormalizeEncoding(std::string_view value) {
  // Skip leading whitespace
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.front()))) {
    value.remove_prefix(1);
  }
  // Skip trailing whitespace
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.back()))) {
    value.remove_suffix(1);
  }

  std::string result;
  result.reserve(value.size());
  for (char c : value) {
    result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return result;
}

}  // namespace

ContentEncoding ParseContentEncoding(std::string_view value) {
  if (value.empty()) {
    return ContentEncoding::kIdentity;
  }

  std::string normalized = NormalizeEncoding(value);

  if (normalized == "br" || normalized == "brotli") {
    return ContentEncoding::kBrotli;
  }
  if (normalized == "gzip" || normalized == "x-gzip") {
    return ContentEncoding::kGzip;
  }
  if (normalized == "deflate") {
    return ContentEncoding::kDeflate;
  }
  if (normalized == "zstd") {
    return ContentEncoding::kZstd;
  }
  if (normalized == "identity") {
    return ContentEncoding::kIdentity;
  }

  return ContentEncoding::kUnknown;
}

const char* ContentEncodingToString(ContentEncoding encoding) {
  switch (encoding) {
    case ContentEncoding::kIdentity:
      return "identity";
    case ContentEncoding::kGzip:
      return "gzip";
    case ContentEncoding::kDeflate:
      return "deflate";
    case ContentEncoding::kBrotli:
      return "br";
    case ContentEncoding::kZstd:
      return "zstd";
    case ContentEncoding::kUnknown:
      return "unknown";
  }
  return "unknown";
}

bool DecompressBrotli(const uint8_t* data, size_t len,
                      std::vector<uint8_t>& output, std::string* error_msg) {
  if (len == 0) {
    output.clear();
    return true;
  }

  // Start with 4x estimate, grow if needed
  size_t decoded_size = std::min(len * 4, kMaxDecompressedSize);
  output.resize(decoded_size);

  BrotliDecoderResult result;
  size_t available_in = len;
  const uint8_t* next_in = data;
  size_t available_out = output.size();
  uint8_t* next_out = output.data();
  size_t total_out = 0;

  BrotliDecoderState* state =
      BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
  if (!state) {
    if (error_msg) *error_msg = "Failed to create Brotli decoder";
    return false;
  }

  do {
    result = BrotliDecoderDecompressStream(
        state, &available_in, &next_in, &available_out, &next_out, &total_out);

    if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
      // Need more space - double the buffer
      size_t current_size = output.size();
      size_t new_size = current_size * 2;
      if (new_size > kMaxDecompressedSize) {
        BrotliDecoderDestroyInstance(state);
        if (error_msg) *error_msg = "Decompressed size exceeds limit";
        return false;
      }
      output.resize(new_size);
      available_out = new_size - total_out;
      next_out = output.data() + total_out;
    }
  } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

  BrotliDecoderDestroyInstance(state);

  if (result != BROTLI_DECODER_RESULT_SUCCESS) {
    if (error_msg) *error_msg = "Brotli decompression failed";
    return false;
  }

  output.resize(total_out);
  return true;
}

bool DecompressZstd(const uint8_t* data, size_t len,
                    std::vector<uint8_t>& output, std::string* error_msg) {
  if (len == 0) {
    output.clear();
    return true;
  }

  // Try to get the decompressed size from frame header
  unsigned long long content_size = ZSTD_getFrameContentSize(data, len);

  size_t output_size;
  if (content_size == ZSTD_CONTENTSIZE_ERROR) {
    if (error_msg) *error_msg = "Invalid Zstd frame";
    return false;
  } else if (content_size == ZSTD_CONTENTSIZE_UNKNOWN) {
    // Size unknown, estimate
    output_size = std::min(len * 4, kMaxDecompressedSize);
  } else {
    // Check size limit
    if (content_size > kMaxDecompressedSize) {
      if (error_msg) *error_msg = "Decompressed size exceeds limit";
      return false;
    }
    output_size = static_cast<size_t>(content_size);
  }

  output.resize(output_size);

  size_t result = ZSTD_decompress(output.data(), output.size(), data, len);

  if (ZSTD_isError(result)) {
    if (error_msg) {
      *error_msg = std::string("Zstd decompression failed: ") +
                   ZSTD_getErrorName(result);
    }
    return false;
  }

  output.resize(result);
  return true;
}

bool DecompressGzip(const uint8_t* data, size_t len,
                    std::vector<uint8_t>& output, std::string* error_msg) {
  if (len == 0) {
    output.clear();
    return true;
  }

  z_stream strm = {};
  // 16 + MAX_WBITS enables gzip decoding
  int ret = inflateInit2(&strm, 16 + MAX_WBITS);
  if (ret != Z_OK) {
    if (error_msg) *error_msg = "Failed to initialize zlib for gzip";
    return false;
  }

  strm.avail_in = static_cast<uInt>(len);
  strm.next_in = const_cast<Bytef*>(data);

  // Start with 4x estimate
  size_t output_size = std::min(len * 4, kMaxDecompressedSize);
  output.resize(output_size);

  strm.avail_out = static_cast<uInt>(output.size());
  strm.next_out = output.data();

  while (true) {
    ret = inflate(&strm, Z_NO_FLUSH);

    if (ret == Z_STREAM_END) {
      break;
    }

    if (ret == Z_BUF_ERROR || (ret == Z_OK && strm.avail_out == 0)) {
      // Need more output space
      size_t current_size = output.size();
      size_t new_size = current_size * 2;
      if (new_size > kMaxDecompressedSize) {
        inflateEnd(&strm);
        if (error_msg) *error_msg = "Decompressed size exceeds limit";
        return false;
      }
      output.resize(new_size);
      strm.avail_out = static_cast<uInt>(new_size - strm.total_out);
      strm.next_out = output.data() + strm.total_out;
      continue;
    }

    if (ret != Z_OK) {
      inflateEnd(&strm);
      if (error_msg) {
        *error_msg = std::string("Gzip decompression failed: ") +
                     (strm.msg ? strm.msg : "unknown error");
      }
      return false;
    }
  }

  output.resize(strm.total_out);
  inflateEnd(&strm);
  return true;
}

bool DecompressDeflate(const uint8_t* data, size_t len,
                       std::vector<uint8_t>& output, std::string* error_msg) {
  if (len == 0) {
    output.clear();
    return true;
  }

  z_stream strm = {};
  // -MAX_WBITS for raw deflate (no zlib/gzip header)
  // Try raw deflate first, fall back to zlib wrapper
  int ret = inflateInit2(&strm, -MAX_WBITS);
  if (ret != Z_OK) {
    if (error_msg) *error_msg = "Failed to initialize zlib for deflate";
    return false;
  }

  strm.avail_in = static_cast<uInt>(len);
  strm.next_in = const_cast<Bytef*>(data);

  size_t output_size = std::min(len * 4, kMaxDecompressedSize);
  output.resize(output_size);

  strm.avail_out = static_cast<uInt>(output.size());
  strm.next_out = output.data();

  ret = inflate(&strm, Z_FINISH);

  // If raw deflate fails, try with zlib wrapper
  if (ret == Z_DATA_ERROR) {
    inflateEnd(&strm);

    strm = {};
    ret = inflateInit(&strm);  // Default: zlib wrapper
    if (ret != Z_OK) {
      if (error_msg) *error_msg = "Failed to initialize zlib";
      return false;
    }

    strm.avail_in = static_cast<uInt>(len);
    strm.next_in = const_cast<Bytef*>(data);
    strm.avail_out = static_cast<uInt>(output.size());
    strm.next_out = output.data();
  }

  while (ret != Z_STREAM_END) {
    if (ret == Z_BUF_ERROR || (ret == Z_OK && strm.avail_out == 0)) {
      size_t current_size = output.size();
      size_t new_size = current_size * 2;
      if (new_size > kMaxDecompressedSize) {
        inflateEnd(&strm);
        if (error_msg) *error_msg = "Decompressed size exceeds limit";
        return false;
      }
      output.resize(new_size);
      strm.avail_out = static_cast<uInt>(new_size - strm.total_out);
      strm.next_out = output.data() + strm.total_out;
    } else if (ret != Z_OK) {
      inflateEnd(&strm);
      if (error_msg) {
        *error_msg = std::string("Deflate decompression failed: ") +
                     (strm.msg ? strm.msg : "unknown error");
      }
      return false;
    }

    ret = inflate(&strm, Z_NO_FLUSH);
  }

  output.resize(strm.total_out);
  inflateEnd(&strm);
  return true;
}

bool Decompress(ContentEncoding encoding, const uint8_t* data, size_t len,
                std::vector<uint8_t>& output, std::string* error_msg) {
  bool result = false;
  switch (encoding) {
    case ContentEncoding::kBrotli:
      result = DecompressBrotli(data, len, output, error_msg);
      break;

    case ContentEncoding::kZstd:
      result = DecompressZstd(data, len, output, error_msg);
      break;

    case ContentEncoding::kGzip:
      return DecompressGzip(data, len, output, error_msg);

    case ContentEncoding::kDeflate:
      return DecompressDeflate(data, len, output, error_msg);

    case ContentEncoding::kIdentity:
    case ContentEncoding::kUnknown:
      // Pass-through: copy input to output
      output.assign(data, data + len);
      return true;
  }
  return result;
}

}  // namespace util
}  // namespace chad

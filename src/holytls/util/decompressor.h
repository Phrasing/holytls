// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_UTIL_DECOMPRESSOR_H_
#define HOLYTLS_UTIL_DECOMPRESSOR_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace holytls {
namespace util {

// Content-Encoding types
enum class ContentEncoding {
  kIdentity,  // No compression (pass-through)
  kGzip,
  kDeflate,
  kBrotli,
  kZstd,
  kUnknown
};

// Parse Content-Encoding header value to enum
// Handles: "br", "gzip", "deflate", "zstd", "identity"
ContentEncoding ParseContentEncoding(std::string_view value);

// Convert encoding enum to string (for debugging)
const char* ContentEncodingToString(ContentEncoding encoding);

// Maximum decompressed size (100MB) to prevent decompression bombs
inline constexpr size_t kMaxDecompressedSize = 100 * 1024 * 1024;

// Decompress data based on Content-Encoding
// Returns true on success, false on error
// On success, output contains decompressed data
// On identity/unknown encoding, copies input to output unchanged
bool Decompress(ContentEncoding encoding, const uint8_t* data, size_t len,
                std::vector<uint8_t>& output, std::string* error_msg = nullptr);

// Convenience overload for vector input
inline bool Decompress(ContentEncoding encoding,
                       const std::vector<uint8_t>& input,
                       std::vector<uint8_t>& output,
                       std::string* error_msg = nullptr) {
  return Decompress(encoding, input.data(), input.size(), output, error_msg);
}

// Individual decompression functions (for direct use if needed)
bool DecompressBrotli(const uint8_t* data, size_t len,
                      std::vector<uint8_t>& output,
                      std::string* error_msg = nullptr);

bool DecompressZstd(const uint8_t* data, size_t len,
                    std::vector<uint8_t>& output,
                    std::string* error_msg = nullptr);

bool DecompressGzip(const uint8_t* data, size_t len,
                    std::vector<uint8_t>& output,
                    std::string* error_msg = nullptr);

bool DecompressDeflate(const uint8_t* data, size_t len,
                       std::vector<uint8_t>& output,
                       std::string* error_msg = nullptr);

}  // namespace util
}  // namespace holytls

#endif  // HOLYTLS_UTIL_DECOMPRESSOR_H_

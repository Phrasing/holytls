// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Packed HTTP headers with name interning for minimal allocations.
// All header data stored in a single contiguous buffer.

#ifndef CHAD_HTTP2_PACKED_HEADERS_H_
#define CHAD_HTTP2_PACKED_HEADERS_H_

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "http2/header_ids.h"

namespace chad {
namespace http2 {

// Maximum number of headers per request/response
inline constexpr size_t kMaxPackedHeaders = 64;

// Packed header entry stored in buffer
struct PackedEntry {
  HeaderId id;            // Known header ID or kCustom
  uint8_t name_len;       // Name length (only for kCustom)
  uint16_t name_offset;   // Name offset into string area (only for kCustom)
  uint16_t value_offset;  // Value offset into string area
  uint16_t value_len;     // Value length
};

static_assert(sizeof(PackedEntry) == 8, "PackedEntry should be 8 bytes");

// Packed headers container - single allocation for all header data.
// Owns its buffer, supports both move and copy.
class PackedHeaders {
 public:
  PackedHeaders() = default;
  ~PackedHeaders() = default;

  // Move operations
  PackedHeaders(PackedHeaders&& other) noexcept;
  PackedHeaders& operator=(PackedHeaders&& other) noexcept;

  // Copy operations (deep copy of buffer)
  PackedHeaders(const PackedHeaders& other);
  PackedHeaders& operator=(const PackedHeaders& other);

  // Check if empty
  bool empty() const { return count_ == 0; }
  size_t size() const { return count_; }

  // Pseudo-header access (HTTP/2)
  int status_code() const { return status_code_; }

  // Fast lookup by known header ID - O(n) but typically small n
  std::string_view Get(HeaderId id) const;

  // Lookup by name - O(n) linear search
  std::string_view Get(std::string_view name) const;
  bool Has(std::string_view name) const;

  // Iteration
  HeaderId id(size_t index) const;
  std::string_view name(size_t index) const;
  std::string_view value(size_t index) const;

  // Range-based for loop support
  class Iterator {
   public:
    Iterator(const PackedHeaders* headers, size_t index)
        : headers_(headers), index_(index) {}

    std::pair<std::string_view, std::string_view> operator*() const {
      return {headers_->name(index_), headers_->value(index_)};
    }

    Iterator& operator++() {
      ++index_;
      return *this;
    }

    bool operator!=(const Iterator& other) const {
      return index_ != other.index_;
    }

   private:
    const PackedHeaders* headers_;
    size_t index_;
  };

  Iterator begin() const { return Iterator(this, 0); }
  Iterator end() const { return Iterator(this, count_); }

 private:
  friend class PackedHeadersBuilder;

  // Buffer layout: [PackedEntry entries...][string data...]
  std::unique_ptr<uint8_t[]> buffer_;
  uint16_t count_ = 0;
  uint16_t entry_bytes_ = 0;    // Size of entry array portion
  uint16_t string_bytes_ = 0;   // Size of string data portion

  // HTTP/2 status code
  int status_code_ = 0;

  // Helper to get entry at index
  const PackedEntry* entry(size_t index) const;

  // Helper to get string from buffer
  std::string_view GetString(uint16_t offset, uint16_t len) const;
};

// Builder for constructing PackedHeaders.
// Accumulates headers, then builds a single packed buffer.
class PackedHeadersBuilder {
 public:
  PackedHeadersBuilder() = default;

  // Add a header (name will be interned if known)
  void Add(std::string_view name, std::string_view value);

  // Set status pseudo-header
  void SetStatus(std::string_view status);

  // Build the packed headers (consumes builder state)
  PackedHeaders Build();

  // Check if any headers have been added
  bool empty() const { return pending_.empty() && status_.empty(); }

  // Clear all pending headers
  void Clear();

 private:
  struct PendingEntry {
    HeaderId id;
    std::string name;   // Own copy for kCustom
    std::string value;  // Own copy of value
  };

  std::vector<PendingEntry> pending_;
  std::string status_;  // Own copy of status
  size_t total_string_bytes_ = 0;
};

}  // namespace http2
}  // namespace chad

#endif  // CHAD_HTTP2_PACKED_HEADERS_H_

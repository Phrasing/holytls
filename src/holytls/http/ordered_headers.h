// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// OrderedHeaders - HTTP headers with O(1) lookup and insertion order preservation.
// Data-oriented design: struct with public data, free functions operate on data.

#ifndef HOLYTLS_HTTP_ORDERED_HEADERS_H_
#define HOLYTLS_HTTP_ORDERED_HEADERS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "holytls/types.h"

namespace holytls {
namespace http {
namespace headers {

// Case-insensitive hash for header names
struct CaseInsensitiveHash {
  size_t operator()(std::string_view s) const noexcept;
};

// Case-insensitive equality for header names
struct CaseInsensitiveEqual {
  bool operator()(std::string_view a, std::string_view b) const noexcept;
};

// OrderedHeaders: HTTP headers with O(1) lookup and insertion order.
//
// Design (Data-Oriented):
// - Public data: headers vector + index map
// - Free functions operate on data
// - No hidden state, data is visible and inspectable
//
// Memory: One vector + one hash map. No linked list, no scattered nodes.
struct OrderedHeaders {
  // Contiguous storage - cache-friendly iteration
  std::vector<Header> headers;

  // Index for O(1) lookup: name -> index of first occurrence
  // Uses case-insensitive hash/equal, no allocation on lookup
  std::unordered_map<std::string_view, size_t, CaseInsensitiveHash,
                     CaseInsensitiveEqual>
      index;
};

// === Single-value operations (upsert) ===

// Set header (replaces if exists, inserts at end if not)
void Set(OrderedHeaders& h, std::string_view name, std::string_view value);

// Get header value (returns empty if not found)
std::string_view Get(const OrderedHeaders& h, std::string_view name);

// Check if header exists
bool Has(const OrderedHeaders& h, std::string_view name);

// Remove header by name (returns true if removed)
bool Delete(OrderedHeaders& h, std::string_view name);

// === Multi-value operations (for Set-Cookie, etc.) ===

// Add header (allows duplicates, appends to end)
void Add(OrderedHeaders& h, std::string_view name, std::string_view value);

// Get all values for a header name
std::vector<std::string_view> GetAll(const OrderedHeaders& h,
                                     std::string_view name);

// === Order control ===

// Set header at specific position (for fingerprint control)
void SetAt(OrderedHeaders& h, size_t position, std::string_view name,
           std::string_view value);

// Move existing header to position (no-op if not found)
void MoveTo(OrderedHeaders& h, std::string_view name, size_t position);

// === Utility ===

// Clear all headers
void Clear(OrderedHeaders& h);

// Rebuild index after structural changes
void RebuildIndex(OrderedHeaders& h);

// Build from vector
OrderedHeaders FromVector(const std::vector<Header>& headers);

// Copy headers (rebuilds index to point to new strings)
OrderedHeaders Copy(const OrderedHeaders& h);

}  // namespace headers
}  // namespace http
}  // namespace holytls

#endif  // HOLYTLS_HTTP_ORDERED_HEADERS_H_

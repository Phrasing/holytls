// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http/ordered_headers.h"

#include <algorithm>
#include <cctype>

namespace holytls {
namespace http {
namespace headers {

// FNV-1a hash with case folding - no allocation
size_t CaseInsensitiveHash::operator()(std::string_view s) const noexcept {
  size_t hash = 14695981039346656037ULL;  // FNV offset basis
  for (char c : s) {
    unsigned char lower =
        static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(c)));
    hash ^= lower;
    hash *= 1099511628211ULL;  // FNV prime
  }
  return hash;
}

// Case-insensitive compare - no allocation
bool CaseInsensitiveEqual::operator()(std::string_view a,
                                      std::string_view b) const noexcept {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

void RebuildIndex(OrderedHeaders& h) {
  h.index.clear();
  for (size_t i = 0; i < h.headers.size(); ++i) {
    // Only store first occurrence of each name
    if (h.index.find(h.headers[i].name) == h.index.end()) {
      h.index[h.headers[i].name] = i;
    }
  }
}

OrderedHeaders Copy(const OrderedHeaders& h) {
  OrderedHeaders result;
  result.headers = h.headers;
  RebuildIndex(result);
  return result;
}

void Set(OrderedHeaders& h, std::string_view name, std::string_view value) {
  auto it = h.index.find(name);
  if (it != h.index.end()) {
    // Update existing - preserve position
    h.headers[it->second].value = std::string(value);
  } else {
    // Append new
    size_t idx = h.headers.size();
    h.headers.push_back({std::string(name), std::string(value)});
    // Index points to the string owned by the vector
    h.index[h.headers[idx].name] = idx;
  }
}

std::string_view Get(const OrderedHeaders& h, std::string_view name) {
  auto it = h.index.find(name);
  if (it != h.index.end()) {
    return h.headers[it->second].value;
  }
  return {};
}

bool Has(const OrderedHeaders& h, std::string_view name) {
  return h.index.find(name) != h.index.end();
}

bool Delete(OrderedHeaders& h, std::string_view name) {
  auto it = h.index.find(name);
  if (it == h.index.end()) {
    return false;
  }

  // Remove all headers with this name (case-insensitive)
  // Erase-remove idiom on contiguous storage
  CaseInsensitiveEqual eq;
  auto new_end =
      std::remove_if(h.headers.begin(), h.headers.end(),
                     [&](const Header& hdr) { return eq(hdr.name, name); });

  if (new_end == h.headers.end()) {
    return false;  // Nothing removed
  }

  h.headers.erase(new_end, h.headers.end());
  RebuildIndex(h);
  return true;
}

void Add(OrderedHeaders& h, std::string_view name, std::string_view value) {
  size_t idx = h.headers.size();
  h.headers.push_back({std::string(name), std::string(value)});

  // Only update index if this is the first with this name
  if (h.index.find(name) == h.index.end()) {
    h.index[h.headers[idx].name] = idx;
  }
}

std::vector<std::string_view> GetAll(const OrderedHeaders& h,
                                     std::string_view name) {
  std::vector<std::string_view> result;
  CaseInsensitiveEqual eq;

  for (const auto& hdr : h.headers) {
    if (eq(hdr.name, name)) {
      result.push_back(hdr.value);
    }
  }
  return result;
}

void SetAt(OrderedHeaders& h, size_t position, std::string_view name,
           std::string_view value) {
  auto it = h.index.find(name);

  if (it != h.index.end()) {
    // Existing header - update value and move to position
    size_t old_idx = it->second;
    h.headers[old_idx].value = std::string(value);

    if (old_idx == position) {
      return;  // Already at target position
    }

    // Extract the header
    Header hdr = std::move(h.headers[old_idx]);
    h.headers.erase(h.headers.begin() + static_cast<ptrdiff_t>(old_idx));

    // Adjust position if we removed from before target
    if (old_idx < position && position > 0) {
      --position;
    }

    // Insert at new position
    if (position >= h.headers.size()) {
      h.headers.push_back(std::move(hdr));
    } else {
      h.headers.insert(h.headers.begin() + static_cast<ptrdiff_t>(position),
                       std::move(hdr));
    }

    RebuildIndex(h);
  } else {
    // New header - insert at position
    Header hdr{std::string(name), std::string(value)};

    if (position >= h.headers.size()) {
      h.headers.push_back(std::move(hdr));
    } else {
      h.headers.insert(h.headers.begin() + static_cast<ptrdiff_t>(position),
                       std::move(hdr));
    }

    RebuildIndex(h);
  }
}

void MoveTo(OrderedHeaders& h, std::string_view name, size_t position) {
  auto it = h.index.find(name);
  if (it == h.index.end()) {
    return;  // Not found
  }

  size_t old_idx = it->second;
  if (old_idx == position) {
    return;  // Already there
  }

  // Extract
  Header hdr = std::move(h.headers[old_idx]);
  h.headers.erase(h.headers.begin() + static_cast<ptrdiff_t>(old_idx));

  // Adjust position
  if (old_idx < position && position > 0) {
    --position;
  }

  // Insert
  if (position >= h.headers.size()) {
    h.headers.push_back(std::move(hdr));
  } else {
    h.headers.insert(h.headers.begin() + static_cast<ptrdiff_t>(position),
                     std::move(hdr));
  }

  RebuildIndex(h);
}

OrderedHeaders FromVector(const std::vector<Header>& headers) {
  OrderedHeaders result;
  result.headers.reserve(headers.size());
  for (const auto& hdr : headers) {
    Add(result, hdr.name, hdr.value);
  }
  return result;
}

void Clear(OrderedHeaders& h) {
  h.headers.clear();
  h.index.clear();
}

}  // namespace headers
}  // namespace http
}  // namespace holytls

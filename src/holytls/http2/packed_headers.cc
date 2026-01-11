// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/http2/packed_headers.h"

#include <cstdlib>
#include <cstring>

namespace holytls {
namespace http2 {

// PackedHeaders implementation

PackedHeaders::PackedHeaders(PackedHeaders&& other) noexcept
    : buffer_(std::move(other.buffer_)),
      count_(other.count_),
      entry_bytes_(other.entry_bytes_),
      string_bytes_(other.string_bytes_),
      status_code_(other.status_code_) {
  other.count_ = 0;
  other.entry_bytes_ = 0;
  other.string_bytes_ = 0;
  other.status_code_ = 0;
}

PackedHeaders& PackedHeaders::operator=(PackedHeaders&& other) noexcept {
  if (this != &other) {
    buffer_ = std::move(other.buffer_);
    count_ = other.count_;
    entry_bytes_ = other.entry_bytes_;
    string_bytes_ = other.string_bytes_;
    status_code_ = other.status_code_;

    other.count_ = 0;
    other.entry_bytes_ = 0;
    other.string_bytes_ = 0;
    other.status_code_ = 0;
  }
  return *this;
}

PackedHeaders::PackedHeaders(const PackedHeaders& other)
    : count_(other.count_),
      entry_bytes_(other.entry_bytes_),
      string_bytes_(other.string_bytes_),
      status_code_(other.status_code_) {
  if (other.buffer_) {
    size_t total = entry_bytes_ + string_bytes_;
    buffer_ = std::make_unique<uint8_t[]>(total);
    std::memcpy(buffer_.get(), other.buffer_.get(), total);
  }
}

PackedHeaders& PackedHeaders::operator=(const PackedHeaders& other) {
  if (this != &other) {
    count_ = other.count_;
    entry_bytes_ = other.entry_bytes_;
    string_bytes_ = other.string_bytes_;
    status_code_ = other.status_code_;

    if (other.buffer_) {
      size_t total = entry_bytes_ + string_bytes_;
      buffer_ = std::make_unique<uint8_t[]>(total);
      std::memcpy(buffer_.get(), other.buffer_.get(), total);
    } else {
      buffer_.reset();
    }
  }
  return *this;
}

const PackedEntry* PackedHeaders::entry(size_t index) const {
  if (!buffer_ || index >= count_) return nullptr;
  auto* entries = reinterpret_cast<const PackedEntry*>(buffer_.get());
  return &entries[index];
}

std::string_view PackedHeaders::GetString(uint16_t offset, uint16_t len) const {
  if (!buffer_ || len == 0) return {};
  const char* str_base =
      reinterpret_cast<const char*>(buffer_.get() + entry_bytes_);
  return {str_base + offset, len};
}

std::string_view PackedHeaders::Get(HeaderId id) const {
  if (id == HeaderId::kCustom) return {};

  for (size_t i = 0; i < count_; ++i) {
    const auto* e = entry(i);
    if (e && e->id == id) {
      return GetString(e->value_offset, e->value_len);
    }
  }
  return {};
}

std::string_view PackedHeaders::Get(std::string_view name) const {
  // Try known header first
  HeaderId id = LookupHeaderId(name);
  if (id != HeaderId::kCustom) {
    return Get(id);
  }

  // Linear search for custom headers
  for (size_t i = 0; i < count_; ++i) {
    const auto* e = entry(i);
    if (e && e->id == HeaderId::kCustom) {
      auto entry_name = GetString(e->name_offset, e->name_len);
      if (entry_name == name) {
        return GetString(e->value_offset, e->value_len);
      }
    }
  }
  return {};
}

bool PackedHeaders::Has(std::string_view name) const {
  return !Get(name).empty();
}

HeaderId PackedHeaders::id(size_t index) const {
  const auto* e = entry(index);
  return e ? e->id : HeaderId::kCustom;
}

std::string_view PackedHeaders::name(size_t index) const {
  const auto* e = entry(index);
  if (!e) return {};

  if (e->id != HeaderId::kCustom) {
    return HeaderIdToName(e->id);
  }
  return GetString(e->name_offset, e->name_len);
}

std::string_view PackedHeaders::value(size_t index) const {
  const auto* e = entry(index);
  if (!e) return {};
  return GetString(e->value_offset, e->value_len);
}

// PackedHeadersBuilder implementation

void PackedHeadersBuilder::Add(std::string_view name, std::string_view value) {
  if (pending_.size() >= kMaxPackedHeaders) return;

  HeaderId id = LookupHeaderId(name);

  PendingEntry entry;
  entry.id = id;
  entry.value = value;

  if (id == HeaderId::kCustom) {
    entry.name = name;
    total_string_bytes_ += name.size();
  }
  total_string_bytes_ += value.size();

  pending_.push_back(entry);
}

void PackedHeadersBuilder::SetStatus(std::string_view status) {
  status_ = status;
}

void PackedHeadersBuilder::Clear() {
  pending_.clear();
  status_ = {};
  total_string_bytes_ = 0;
}

PackedHeaders PackedHeadersBuilder::Build() {
  PackedHeaders result;

  if (pending_.empty()) {
    // Handle status-only case
    if (!status_.empty()) {
      result.status_code_ = std::atoi(status_.data());
    }
    return result;
  }

  // Calculate buffer size
  size_t entry_bytes = pending_.size() * sizeof(PackedEntry);
  size_t total_bytes = entry_bytes + total_string_bytes_;

  // Allocate single buffer
  result.buffer_ = std::make_unique<uint8_t[]>(total_bytes);
  result.count_ = static_cast<uint16_t>(pending_.size());
  result.entry_bytes_ = static_cast<uint16_t>(entry_bytes);
  result.string_bytes_ = static_cast<uint16_t>(total_string_bytes_);

  auto* entries = reinterpret_cast<PackedEntry*>(result.buffer_.get());
  char* strings = reinterpret_cast<char*>(result.buffer_.get() + entry_bytes);

  uint16_t string_offset = 0;

  for (size_t i = 0; i < pending_.size(); ++i) {
    const auto& p = pending_[i];

    entries[i].id = p.id;

    if (p.id == HeaderId::kCustom) {
      entries[i].name_offset = string_offset;
      entries[i].name_len = static_cast<uint8_t>(p.name.size());
      std::memcpy(strings + string_offset, p.name.data(), p.name.size());
      string_offset += static_cast<uint16_t>(p.name.size());
    } else {
      entries[i].name_offset = 0;
      entries[i].name_len = 0;
    }

    entries[i].value_offset = string_offset;
    entries[i].value_len = static_cast<uint16_t>(p.value.size());
    std::memcpy(strings + string_offset, p.value.data(), p.value.size());
    string_offset += static_cast<uint16_t>(p.value.size());
  }

  // Store status code
  if (!status_.empty()) {
    result.status_code_ = std::atoi(status_.data());
  }

  // Clear builder state
  Clear();

  return result;
}

}  // namespace http2
}  // namespace holytls

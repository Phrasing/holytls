// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

#include "core/io_buffer.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace chad {
namespace core {

IoBuffer::IoBuffer() = default;

IoBuffer::IoBuffer(size_t initial_capacity) {
  if (initial_capacity > 0) {
    EnsureCapacity(initial_capacity);
  }
}

IoBuffer::~IoBuffer() = default;

IoBuffer::IoBuffer(IoBuffer&& other) noexcept
    : chunks_(std::move(other.chunks_)),
      size_(other.size_),
      capacity_(other.capacity_) {
  other.size_ = 0;
  other.capacity_ = 0;
}

IoBuffer& IoBuffer::operator=(IoBuffer&& other) noexcept {
  if (this != &other) {
    chunks_ = std::move(other.chunks_);
    size_ = other.size_;
    capacity_ = other.capacity_;
    other.size_ = 0;
    other.capacity_ = 0;
  }
  return *this;
}

void IoBuffer::Append(const uint8_t* data, size_t len) {
  if (len == 0) {
    return;
  }

  const uint8_t* src = data;
  size_t remaining = len;

  while (remaining > 0) {
    Chunk& chunk = GetWriteChunk();
    size_t writable = chunk.WritableSize();
    size_t to_write = std::min(remaining, writable);

    std::memcpy(chunk.data.get() + chunk.end, src, to_write);
    chunk.end += to_write;
    src += to_write;
    remaining -= to_write;
    size_ += to_write;
  }
}

void IoBuffer::Append(std::string_view sv) {
  Append(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
}

void IoBuffer::Append(const IoBuffer& other) {
  for (const auto& chunk : other.chunks_) {
    if (chunk.ReadableSize() > 0) {
      Append(chunk.data.get() + chunk.start, chunk.ReadableSize());
    }
  }
}

uint8_t* IoBuffer::Reserve(size_t len) {
  if (len == 0) {
    return nullptr;
  }

  // For simplicity, ensure we have a contiguous block
  // This may allocate a new chunk if needed
  EnsureCapacity(len);

  Chunk& chunk = GetWriteChunk();
  if (chunk.WritableSize() < len) {
    // Need a new chunk with enough space
    Chunk new_chunk;
    new_chunk.capacity = std::max(len, kDefaultChunkSize);
    new_chunk.data = std::make_unique<uint8_t[]>(new_chunk.capacity);
    new_chunk.start = 0;
    new_chunk.end = 0;
    capacity_ += new_chunk.capacity;
    chunks_.push_back(std::move(new_chunk));
    return chunks_.back().data.get();
  }

  return chunk.data.get() + chunk.end;
}

void IoBuffer::Commit(size_t len) {
  if (len == 0 || chunks_.empty()) {
    return;
  }

  Chunk& chunk = chunks_.back();
  size_t actual = std::min(len, chunk.WritableSize());
  chunk.end += actual;
  size_ += actual;
}

size_t IoBuffer::Read(uint8_t* dest, size_t max_len) {
  if (max_len == 0 || Empty()) {
    return 0;
  }

  size_t total_read = 0;
  uint8_t* dst = dest;

  while (total_read < max_len && !chunks_.empty()) {
    Chunk& chunk = chunks_.front();
    size_t readable = chunk.ReadableSize();
    size_t to_read = std::min(readable, max_len - total_read);

    std::memcpy(dst, chunk.data.get() + chunk.start, to_read);
    chunk.start += to_read;
    dst += to_read;
    total_read += to_read;

    if (chunk.Empty()) {
      capacity_ -= chunk.capacity;
      chunks_.pop_front();
    }
  }

  size_ -= total_read;
  return total_read;
}

size_t IoBuffer::ReadToString(std::string* dest, size_t max_len) {
  size_t to_read = std::min(max_len, size_);
  size_t original_size = dest->size();
  dest->resize(original_size + to_read);
  return Read(reinterpret_cast<uint8_t*>(dest->data() + original_size),
              to_read);
}

const uint8_t* IoBuffer::Peek(size_t* available) const {
  if (chunks_.empty()) {
    *available = 0;
    return nullptr;
  }

  const Chunk& chunk = chunks_.front();
  *available = chunk.ReadableSize();
  return chunk.data.get() + chunk.start;
}

void IoBuffer::Skip(size_t len) {
  size_t remaining = std::min(len, size_);

  while (remaining > 0 && !chunks_.empty()) {
    Chunk& chunk = chunks_.front();
    size_t to_skip = std::min(remaining, chunk.ReadableSize());

    chunk.start += to_skip;
    remaining -= to_skip;
    size_ -= to_skip;

    if (chunk.Empty()) {
      capacity_ -= chunk.capacity;
      chunks_.pop_front();
    }
  }
}

std::vector<iovec_t> IoBuffer::GetReadableIovec() const {
  std::vector<iovec_t> iovecs;
  iovecs.reserve(chunks_.size());

  for (const auto& chunk : chunks_) {
    if (chunk.ReadableSize() > 0) {
      iovec_t iov;
      iov.iov_base = chunk.data.get() + chunk.start;
      iov.iov_len = chunk.ReadableSize();
      iovecs.push_back(iov);
    }
  }

  return iovecs;
}

std::vector<iovec_t> IoBuffer::GetWritableIovec(size_t len) {
  EnsureCapacity(len);

  std::vector<iovec_t> iovecs;
  size_t remaining = len;

  for (auto& chunk : chunks_) {
    if (remaining == 0) {
      break;
    }

    size_t writable = chunk.WritableSize();
    if (writable > 0) {
      iovec_t iov;
      iov.iov_base = chunk.data.get() + chunk.end;
      iov.iov_len = std::min(writable, remaining);
      iovecs.push_back(iov);
      remaining -= iov.iov_len;
    }
  }

  return iovecs;
}

void IoBuffer::Clear() {
  chunks_.clear();
  size_ = 0;
  capacity_ = 0;
}

void IoBuffer::ShrinkToFit() {
  RemoveEmptyChunks();

  // If we have more than 2 chunks worth of excess capacity, consolidate
  if (capacity_ > size_ + 2 * kDefaultChunkSize) {
    IoBuffer new_buffer(size_);
    for (const auto& chunk : chunks_) {
      if (chunk.ReadableSize() > 0) {
        new_buffer.Append(chunk.data.get() + chunk.start, chunk.ReadableSize());
      }
    }
    *this = std::move(new_buffer);
  }
}

bool IoBuffer::IsContiguous() const {
  if (chunks_.empty()) {
    return true;
  }
  if (chunks_.size() == 1) {
    return true;
  }
  // Multiple chunks means not contiguous
  return false;
}

const uint8_t* IoBuffer::Data() const {
  if (chunks_.empty()) {
    return nullptr;
  }
  return chunks_.front().data.get() + chunks_.front().start;
}

void IoBuffer::EnsureCapacity(size_t additional) {
  size_t available = capacity_ - size_;
  if (available >= additional) {
    return;
  }

  size_t needed = additional - available;
  size_t chunk_size = std::max(needed, kDefaultChunkSize);

  Chunk new_chunk;
  new_chunk.capacity = chunk_size;
  new_chunk.data = std::make_unique<uint8_t[]>(chunk_size);
  new_chunk.start = 0;
  new_chunk.end = 0;

  capacity_ += chunk_size;
  chunks_.push_back(std::move(new_chunk));
}

IoBuffer::Chunk& IoBuffer::GetWriteChunk() {
  if (chunks_.empty() || chunks_.back().WritableSize() == 0) {
    Chunk new_chunk;
    new_chunk.capacity = kDefaultChunkSize;
    new_chunk.data = std::make_unique<uint8_t[]>(kDefaultChunkSize);
    new_chunk.start = 0;
    new_chunk.end = 0;
    capacity_ += kDefaultChunkSize;
    chunks_.push_back(std::move(new_chunk));
  }
  return chunks_.back();
}

void IoBuffer::RemoveEmptyChunks() {
  while (!chunks_.empty() && chunks_.front().Empty()) {
    capacity_ -= chunks_.front().capacity;
    chunks_.pop_front();
  }
}

}  // namespace core
}  // namespace chad

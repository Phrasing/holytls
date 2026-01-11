// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

#ifndef HOLYTLS_MEMORY_SLAB_ALLOCATOR_H_
#define HOLYTLS_MEMORY_SLAB_ALLOCATOR_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <type_traits>
#include <vector>

namespace holytls {
namespace memory {

// Fixed-size slab allocator for efficient allocation of same-sized objects.
// Reduces memory fragmentation and allocation overhead for hot paths.
//
// Usage:
//   SlabAllocator<Connection, 64> alloc;
//   Connection* conn = alloc.Allocate();
//   alloc.Deallocate(conn);
//
template <typename T, size_t SlabSize = 64>
class SlabAllocator {
 public:
  SlabAllocator() { AllocateSlab(); }

  ~SlabAllocator() {
    // Note: Destructors are NOT called for objects still in slabs
    // User must ensure all objects are deallocated before destruction
  }

  // Non-copyable, non-movable (owns memory)
  SlabAllocator(const SlabAllocator&) = delete;
  SlabAllocator& operator=(const SlabAllocator&) = delete;
  SlabAllocator(SlabAllocator&&) = delete;
  SlabAllocator& operator=(SlabAllocator&&) = delete;

  // Allocate raw memory for one object (does not construct)
  // Thread-safe: protected by mutex
  T* Allocate() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (free_list_.empty()) {
      AllocateSlab();
    }

    T* ptr = free_list_.back();
    free_list_.pop_back();
    ++allocated_count_;
    return ptr;
  }

  // Deallocate memory (does not destruct)
  // Thread-safe: protected by mutex
  void Deallocate(T* ptr) {
    if (ptr == nullptr) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    free_list_.push_back(ptr);
    --allocated_count_;
  }

  // Construct object in-place
  template <typename... Args>
  T* Construct(Args&&... args) {
    T* ptr = Allocate();
    new (ptr) T(std::forward<Args>(args)...);
    return ptr;
  }

  // Destroy and deallocate
  void Destroy(T* ptr) {
    if (ptr == nullptr) {
      return;
    }
    ptr->~T();
    Deallocate(ptr);
  }

  // Statistics
  size_t allocated_count() const { return allocated_count_; }
  size_t free_count() const { return free_list_.size(); }
  size_t slab_count() const { return slabs_.size(); }
  size_t total_capacity() const { return slabs_.size() * SlabSize; }

 private:
  // Storage type with proper alignment
  using Storage = std::aligned_storage_t<sizeof(T), alignof(T)>;
  using SlabArray = std::array<Storage, SlabSize>;

  void AllocateSlab() {
    auto slab = std::make_unique<SlabArray>();

    // Add all slots to free list
    for (size_t i = 0; i < SlabSize; ++i) {
      free_list_.push_back(reinterpret_cast<T*>(&(*slab)[i]));
    }

    slabs_.push_back(std::move(slab));
  }

  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<SlabArray>> slabs_;
  std::vector<T*> free_list_;
  size_t allocated_count_ = 0;
};

}  // namespace memory
}  // namespace holytls

#endif  // HOLYTLS_MEMORY_SLAB_ALLOCATOR_H_

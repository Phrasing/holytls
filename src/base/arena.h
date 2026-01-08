// Copyright 2024 Chad-TLS Authors
// SPDX-License-Identifier: MIT

// Simple arena allocator inspired by raddebugger.
// Provides fast bump allocation with scope-based cleanup.

#ifndef CHAD_BASE_ARENA_H_
#define CHAD_BASE_ARENA_H_

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace chad {

// Default arena block size (64KB)
inline constexpr size_t kArenaDefaultBlockSize = 64 * 1024;

// Cache line size for aligned allocations
inline constexpr size_t kCacheLineSize = 64;

// Arena - Simple bump allocator
// All allocations are 8-byte aligned by default.
// Memory is freed in bulk when the arena is destroyed or reset.
struct Arena {
  uint8_t* base;      // Start of current block
  uint8_t* pos;       // Current allocation position
  uint8_t* end;       // End of current block
  Arena* prev;        // Previous block (for chaining)
  size_t block_size;  // Size of each block

  // Create arena with specified block size
  static Arena* Create(size_t block_size = kArenaDefaultBlockSize) {
    size_t total = sizeof(Arena) + block_size;
    auto* mem = static_cast<uint8_t*>(std::malloc(total));
    if (!mem) return nullptr;

    auto* arena = reinterpret_cast<Arena*>(mem);
    arena->base = mem + sizeof(Arena);
    arena->pos = arena->base;
    arena->end = arena->base + block_size;
    arena->prev = nullptr;
    arena->block_size = block_size;
    return arena;
  }

  // Destroy arena and all chained blocks
  static void Destroy(Arena* arena) {
    while (arena) {
      Arena* prev = arena->prev;
      std::free(arena);
      arena = prev;
    }
  }
};

// Current position in arena (for temp scopes)
inline size_t ArenaPos(Arena* arena) {
  return static_cast<size_t>(arena->pos - arena->base);
}

// Reset arena to position (frees all allocations after pos)
inline void ArenaPopTo(Arena* arena, size_t pos) {
  arena->pos = arena->base + pos;
}

// Clear arena (reset to empty)
inline void ArenaClear(Arena* arena) {
  // Free chained blocks
  Arena* prev = arena->prev;
  while (prev) {
    Arena* next = prev->prev;
    std::free(prev);
    prev = next;
  }
  arena->prev = nullptr;
  arena->pos = arena->base;
}

// Allocate from arena (fully inline for maximum performance)
inline void* ArenaPush(Arena* arena, size_t size) {
  // Align to 8 bytes
  size_t aligned_size = (size + 7) & ~size_t{7};

  // Fast path: fits in current block (likely)
  uint8_t* result = arena->pos;
  uint8_t* new_pos = result + aligned_size;

  if (__builtin_expect(new_pos <= arena->end, 1)) {
    arena->pos = new_pos;
    return result;
  }

  // Slow path: need new block (inline to avoid function call overhead)
  size_t new_block_size = arena->block_size * 2;
  if (aligned_size > new_block_size) {
    new_block_size = aligned_size;
  }

  Arena* new_arena = Arena::Create(new_block_size);
  if (__builtin_expect(!new_arena, 0)) return nullptr;

  // Chain old block by swapping (keeps arena pointer stable)
  new_arena->prev = arena->prev;
  new_arena->block_size = arena->block_size;
  arena->prev = new_arena;

  // Swap memory regions
  uint8_t* old_base = arena->base;
  uint8_t* old_end = arena->end;
  uint8_t* old_pos = arena->pos;

  arena->base = new_arena->base;
  arena->end = new_arena->end;
  arena->block_size = new_block_size;

  new_arena->base = old_base;
  new_arena->end = old_end;
  new_arena->pos = old_pos;

  // Allocate from new block
  result = arena->base;
  arena->pos = arena->base + aligned_size;
  return result;
}

// Cache-line aligned allocation
inline void* ArenaPushAligned(Arena* arena, size_t size, size_t alignment) {
  // Align current position
  uintptr_t pos = reinterpret_cast<uintptr_t>(arena->pos);
  uintptr_t aligned_pos = (pos + alignment - 1) & ~(alignment - 1);
  size_t padding = aligned_pos - pos;

  return ArenaPush(arena, size + padding);
}

// Allocate and zero-initialize
inline void* ArenaPushZero(Arena* arena, size_t size) {
  void* mem = ArenaPush(arena, size);
  if (mem) {
    std::memset(mem, 0, size);
  }
  return mem;
}

// Typed allocation macros
#define PushArray(arena, T, count) \
  static_cast<T*>(ArenaPush((arena), sizeof(T) * (count)))

#define PushArrayZero(arena, T, count) \
  static_cast<T*>(ArenaPushZero((arena), sizeof(T) * (count)))

#define PushStruct(arena, T) PushArray(arena, T, 1)
#define PushStructZero(arena, T) PushArrayZero(arena, T, 1)

#define PushStructAligned(arena, T) \
  static_cast<T*>(ArenaPushAligned((arena), sizeof(T), alignof(T)))

// Temp scope - captures arena position for later restoration
struct Temp {
  Arena* arena;
  size_t pos;
};

inline Temp TempBegin(Arena* arena) {
  return Temp{arena, ArenaPos(arena)};
}

inline void TempEnd(Temp temp) {
  ArenaPopTo(temp.arena, temp.pos);
}

// RAII wrapper for temp scopes
struct TempScope {
  Temp temp;
  explicit TempScope(Arena* arena) : temp(TempBegin(arena)) {}
  ~TempScope() { TempEnd(temp); }
  TempScope(const TempScope&) = delete;
  TempScope& operator=(const TempScope&) = delete;
};

}  // namespace chad

#endif  // CHAD_BASE_ARENA_H_

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Simple arena allocator inspired by raddebugger.
// Provides fast bump allocation with scope-based cleanup.

#ifndef HOLYTLS_BASE_ARENA_H_
#define HOLYTLS_BASE_ARENA_H_

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Branch prediction hints - MSVC doesn't have __builtin_expect
#ifdef _MSC_VER
#define HOLYTLS_LIKELY(x) (x)
#define HOLYTLS_UNLIKELY(x) (x)
#else
#define HOLYTLS_LIKELY(x) __builtin_expect(!!(x), 1)
#define HOLYTLS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

namespace holytls {

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

  if (HOLYTLS_LIKELY(new_pos <= arena->end)) {
    arena->pos = new_pos;
    return result;
  }

  // Slow path: need new block (inline to avoid function call overhead)
  size_t new_block_size = arena->block_size * 2;
  if (aligned_size > new_block_size) {
    new_block_size = aligned_size;
  }

  Arena* new_arena = Arena::Create(new_block_size);
  if (HOLYTLS_UNLIKELY(!new_arena)) return nullptr;

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

inline Temp TempBegin(Arena* arena) { return Temp{arena, ArenaPos(arena)}; }

inline void TempEnd(Temp temp) { ArenaPopTo(temp.arena, temp.pos); }

// RAII wrapper for temp scopes
struct TempScope {
  Temp temp;
  explicit TempScope(Arena* arena) : temp(TempBegin(arena)) {}
  ~TempScope() { TempEnd(temp); }
  TempScope(const TempScope&) = delete;
  TempScope& operator=(const TempScope&) = delete;
};

// ============================================================================
// Scratch Arenas - Thread-local temporary allocation
// ============================================================================
// RAD-style scratch arenas for temporary allocations without manual cleanup.
// Each thread has 2 scratch arenas to handle nested usage (conflict avoidance).

namespace scratch_detail {
inline Arena*& GetScratch(int idx) {
  thread_local Arena* arenas[2] = {nullptr, nullptr};
  return arenas[idx];
}

inline void InitScratchArenas() {
  if (!GetScratch(0)) {
    GetScratch(0) = Arena::Create();
    GetScratch(1) = Arena::Create();
  }
}
}  // namespace scratch_detail

// Scratch - RAII wrapper for temporary arena allocations
// Automatically restores arena position on destruction.
struct Scratch {
  Arena* arena;
  size_t saved_pos;

  // Get arena for allocations
  Arena* operator->() { return arena; }
  Arena* get() { return arena; }

  // RAII cleanup
  ~Scratch() {
    if (arena) {
      ArenaPopTo(arena, saved_pos);
    }
  }

  // Non-copyable, movable
  Scratch(const Scratch&) = delete;
  Scratch& operator=(const Scratch&) = delete;
  Scratch(Scratch&& other) noexcept
      : arena(other.arena), saved_pos(other.saved_pos) {
    other.arena = nullptr;
  }
  Scratch& operator=(Scratch&& other) noexcept {
    if (this != &other) {
      if (arena) ArenaPopTo(arena, saved_pos);
      arena = other.arena;
      saved_pos = other.saved_pos;
      other.arena = nullptr;
    }
    return *this;
  }

 private:
  friend Scratch ScratchBegin(Arena* conflict);
  Scratch(Arena* a, size_t pos) : arena(a), saved_pos(pos) {}
};

// Begin a scratch scope. Pass a conflict arena to avoid using one that's
// already in use by a caller (prevents nested corruption).
inline Scratch ScratchBegin(Arena* conflict = nullptr) {
  scratch_detail::InitScratchArenas();
  Arena* arena = scratch_detail::GetScratch(0);
  if (arena == conflict) {
    arena = scratch_detail::GetScratch(1);
  }
  return Scratch(arena, ArenaPos(arena));
}

}  // namespace holytls

#endif  // HOLYTLS_BASE_ARENA_H_

// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

// String8 and String8List - RAD-style string building
// Accumulate strings in a linked list, join once with known final size.
// Eliminates intermediate allocations during string concatenation.

#ifndef HOLYTLS_BASE_STRING8_H_
#define HOLYTLS_BASE_STRING8_H_

#include <cstring>

#include "holytls/base/arena.h"

namespace holytls {

struct String8 {
  const char* str;
  size_t size;

  constexpr String8() : str(nullptr), size(0) {}
  constexpr String8(const char* s, size_t n) : str(s), size(n) {}
  constexpr bool empty() const { return size == 0; }
};

struct String8Node {
  String8Node* next;
  String8 string;
};

struct String8List {
  String8Node* first;
  String8Node* last;
  size_t node_count;
  size_t total_size;

  String8List() : first(nullptr), last(nullptr), node_count(0), total_size(0) {}
};

// Push a string onto the list (allocates node from arena)
inline void Str8ListPush(Arena* arena, String8List* list, String8 string) {
  auto* node = PushStruct(arena, String8Node);
  node->next = nullptr;
  node->string = string;

  if (list->last) {
    list->last->next = node;
  } else {
    list->first = node;
  }
  list->last = node;
  list->node_count++;
  list->total_size += string.size;
}

// Push a C-string literal
inline void Str8ListPushLit(Arena* arena, String8List* list, const char* lit) {
  Str8ListPush(arena, list, String8{lit, std::strlen(lit)});
}

// Join all strings into a single contiguous buffer
inline String8 Str8ListJoin(Arena* arena, String8List* list) {
  if (list->total_size == 0) return {};

  char* buf = PushArray(arena, char, list->total_size + 1);
  char* ptr = buf;

  for (String8Node* node = list->first; node; node = node->next) {
    std::memcpy(ptr, node->string.str, node->string.size);
    ptr += node->string.size;
  }
  *ptr = '\0';  // Null terminate for convenience

  return String8{buf, list->total_size};
}

// Join with separator
inline String8 Str8ListJoinSep(Arena* arena, String8List* list, String8 sep) {
  if (list->node_count == 0) return {};

  size_t total = list->total_size + sep.size * (list->node_count - 1);
  char* buf = PushArray(arena, char, total + 1);
  char* ptr = buf;

  bool first = true;
  for (String8Node* node = list->first; node; node = node->next) {
    if (!first && sep.size > 0) {
      std::memcpy(ptr, sep.str, sep.size);
      ptr += sep.size;
    }
    std::memcpy(ptr, node->string.str, node->string.size);
    ptr += node->string.size;
    first = false;
  }
  *ptr = '\0';

  return String8{buf, total};
}

}  // namespace holytls

#endif  // HOLYTLS_BASE_STRING8_H_

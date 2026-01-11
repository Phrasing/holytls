// Copyright 2024 HolyTLS Authors
// SPDX-License-Identifier: MIT

// Intrusive doubly-linked list macros inspired by raddebugger.
// Zero-allocation list operations - nodes embed the link pointers.

#ifndef HOLYTLS_BASE_LIST_H_
#define HOLYTLS_BASE_LIST_H_

#include <cstddef>

namespace holytls {

// Doubly-linked list node (embed this in your struct)
struct DLLNode {
  DLLNode* next;
  DLLNode* prev;
};

// Doubly-linked list head
struct DLLList {
  DLLNode* first;
  DLLNode* last;
  size_t count;
};

// Initialize a list
inline void DLLInit(DLLList* list) {
  list->first = nullptr;
  list->last = nullptr;
  list->count = 0;
}

inline bool DLLIsEmpty(const DLLList* list) { return list->first == nullptr; }

// Push node to back of list
inline void DLLPushBack(DLLList* list, DLLNode* node) {
  node->next = nullptr;
  node->prev = list->last;
  if (list->last) {
    list->last->next = node;
  } else {
    list->first = node;
  }
  list->last = node;
  list->count++;
}

// Push node to front of list
inline void DLLPushFront(DLLList* list, DLLNode* node) {
  node->prev = nullptr;
  node->next = list->first;
  if (list->first) {
    list->first->prev = node;
  } else {
    list->last = node;
  }
  list->first = node;
  list->count++;
}

// Remove node from list (node must be in list)
inline void DLLRemove(DLLList* list, DLLNode* node) {
  if (node->prev) {
    node->prev->next = node->next;
  } else {
    list->first = node->next;
  }
  if (node->next) {
    node->next->prev = node->prev;
  } else {
    list->last = node->prev;
  }
  node->next = nullptr;
  node->prev = nullptr;
  list->count--;
}

// Pop from front (returns nullptr if empty)
inline DLLNode* DLLPopFront(DLLList* list) {
  DLLNode* node = list->first;
  if (node) {
    DLLRemove(list, node);
  }
  return node;
}

// Pop from back (returns nullptr if empty)
inline DLLNode* DLLPopBack(DLLList* list) {
  DLLNode* node = list->last;
  if (node) {
    DLLRemove(list, node);
  }
  return node;
}

// Insert node after target (target must be in list)
inline void DLLInsertAfter(DLLList* list, DLLNode* target, DLLNode* node) {
  node->prev = target;
  node->next = target->next;
  if (target->next) {
    target->next->prev = node;
  } else {
    list->last = node;
  }
  target->next = node;
  list->count++;
}

// Insert node before target (target must be in list)
inline void DLLInsertBefore(DLLList* list, DLLNode* target, DLLNode* node) {
  node->next = target;
  node->prev = target->prev;
  if (target->prev) {
    target->prev->next = node;
  } else {
    list->first = node;
  }
  target->prev = node;
  list->count++;
}

// Singly-linked list node (embed this in your struct)
struct SLLNode {
  SLLNode* next;
};

// Singly-linked list (stack/queue)
struct SLLList {
  SLLNode* first;
  SLLNode* last;
  size_t count;
};

// Initialize singly-linked list
inline void SLLInit(SLLList* list) {
  list->first = nullptr;
  list->last = nullptr;
  list->count = 0;
}

inline bool SLLIsEmpty(const SLLList* list) { return list->first == nullptr; }

// Push to back (queue push)
inline void SLLPushBack(SLLList* list, SLLNode* node) {
  node->next = nullptr;
  if (list->last) {
    list->last->next = node;
  } else {
    list->first = node;
  }
  list->last = node;
  list->count++;
}

// Push to front (stack push)
inline void SLLPushFront(SLLList* list, SLLNode* node) {
  node->next = list->first;
  if (!list->last) {
    list->last = node;
  }
  list->first = node;
  list->count++;
}

// Pop from front (stack/queue pop)
inline SLLNode* SLLPopFront(SLLList* list) {
  SLLNode* node = list->first;
  if (node) {
    list->first = node->next;
    if (!list->first) {
      list->last = nullptr;
    }
    node->next = nullptr;
    list->count--;
  }
  return node;
}

// Helper macros to get containing struct from node pointer
#define ContainerOf(ptr, type, member) \
  reinterpret_cast<type*>(reinterpret_cast<char*>(ptr) - offsetof(type, member))

}  // namespace holytls

// Prefetch hint for better cache performance
#ifdef _MSC_VER
#include <xmmintrin.h>
#define Prefetch(ptr) \
  _mm_prefetch(reinterpret_cast<const char*>(ptr), _MM_HINT_T0)
#define PrefetchWrite(ptr) \
  _mm_prefetch(reinterpret_cast<const char*>(ptr), _MM_HINT_T0)
#else
#define Prefetch(ptr) __builtin_prefetch(ptr, 0, 3)
#define PrefetchWrite(ptr) __builtin_prefetch(ptr, 1, 3)
#endif

// Iteration macros (outside namespace for proper type resolution)
#define DLLForEach(list, node) \
  for (holytls::DLLNode* node = (list)->first; node != nullptr; node = node->next)

// Iteration with prefetch (better cache performance for large lists)
#define DLLForEachPrefetch(list, node)                       \
  for (holytls::DLLNode* node = (list)->first; node != nullptr; \
       (node->next ? Prefetch(node->next->next) : (void)0), node = node->next)

#define SLLForEach(list, node) \
  for (holytls::SLLNode* node = (list)->first; node != nullptr; node = node->next)

#define SLLForEachPrefetch(list, node)                       \
  for (holytls::SLLNode* node = (list)->first; node != nullptr; \
       (node->next ? Prefetch(node->next->next) : (void)0), node = node->next)

// Type-safe iteration (requires node member name)
#define DLLForEachType(list, type, member, var)                             \
  for (type* var = (list)->first ? ContainerOf((list)->first, type, member) \
                                 : nullptr;                                 \
       var != nullptr;                                                      \
       var = var->member.next ? ContainerOf(var->member.next, type, member) \
                              : nullptr)

#endif  // HOLYTLS_BASE_LIST_H_

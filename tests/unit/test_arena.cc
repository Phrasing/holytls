// Copyright 2026 HolyTLS Authors
// SPDX-License-Identifier: MIT

#include "holytls/base/arena.h"
#include "holytls/base/list.h"

#include <cassert>
#include <cstring>
#include <print>

void TestArenaBasic() {
  std::print("Testing arena basic allocation... ");

  holytls::Arena* arena = holytls::Arena::Create(1024);
  assert(arena != nullptr);

  // Allocate some memory
  int* a = PushStruct(arena, int);
  assert(a != nullptr);
  *a = 42;

  int* b = PushArray(arena, int, 10);
  assert(b != nullptr);
  for (int i = 0; i < 10; ++i) {
    b[i] = i;
  }

  // Verify values
  assert(*a == 42);
  for (int i = 0; i < 10; ++i) {
    assert(b[i] == i);
  }

  holytls::Arena::Destroy(arena);
  std::println("PASSED");
}

void TestArenaZero() {
  std::print("Testing arena zero allocation... ");

  holytls::Arena* arena = holytls::Arena::Create(1024);
  assert(arena != nullptr);

  // Allocate zero-initialized memory
  int* arr = PushArrayZero(arena, int, 100);
  assert(arr != nullptr);

  for (int i = 0; i < 100; ++i) {
    assert(arr[i] == 0);
  }

  holytls::Arena::Destroy(arena);
  std::println("PASSED");
}

void TestArenaGrowth() {
  std::print("Testing arena growth... ");

  // Small block size to force growth
  holytls::Arena* arena = holytls::Arena::Create(64);
  assert(arena != nullptr);

  // Allocate more than block size
  for (int i = 0; i < 100; ++i) {
    int* p = PushStruct(arena, int);
    assert(p != nullptr);
    *p = i;
  }

  holytls::Arena::Destroy(arena);
  std::println("PASSED");
}

void TestArenaLargeAllocation() {
  std::print("Testing arena large allocation... ");

  holytls::Arena* arena = holytls::Arena::Create(64);
  assert(arena != nullptr);

  // Allocate larger than block size
  char* large = PushArray(arena, char, 1024);
  assert(large != nullptr);
  std::memset(large, 'X', 1024);

  // Verify
  for (int i = 0; i < 1024; ++i) {
    assert(large[i] == 'X');
  }

  holytls::Arena::Destroy(arena);
  std::println("PASSED");
}

void TestArenaTemp() {
  std::print("Testing arena temp scopes... ");

  holytls::Arena* arena = holytls::Arena::Create(1024);
  assert(arena != nullptr);

  int* a = PushStruct(arena, int);
  *a = 1;
  size_t pos_before = holytls::ArenaPos(arena);

  {
    holytls::TempScope temp(arena);
    int* b = PushArray(arena, int, 100);
    assert(b != nullptr);
    for (int i = 0; i < 100; ++i) {
      b[i] = i;
    }
  }
  // After temp scope, position should be restored
  size_t pos_after = holytls::ArenaPos(arena);
  assert(pos_after == pos_before);

  // Original allocation should still be valid
  assert(*a == 1);

  holytls::Arena::Destroy(arena);
  std::println("PASSED");
}

void TestArenaClear() {
  std::print("Testing arena clear... ");

  holytls::Arena* arena = holytls::Arena::Create(64);
  assert(arena != nullptr);

  // Force multiple blocks
  for (int i = 0; i < 100; ++i) {
    PushStruct(arena, int);
  }

  // Clear should free chained blocks
  holytls::ArenaClear(arena);

  // Should be back to initial state
  assert(arena->pos == arena->base);
  assert(arena->prev == nullptr);

  // Should still be usable
  int* p = PushStruct(arena, int);
  assert(p != nullptr);
  *p = 123;
  assert(*p == 123);

  holytls::Arena::Destroy(arena);
  std::println("PASSED");
}

void TestDLLBasic() {
  std::print("Testing doubly-linked list... ");

  struct Item {
    int value;
    holytls::DLLNode node;
  };

  holytls::DLLList list;
  holytls::DLLInit(&list);
  assert(holytls::DLLIsEmpty(&list));

  Item items[5];
  for (int i = 0; i < 5; ++i) {
    items[i].value = i;
    holytls::DLLPushBack(&list, &items[i].node);
  }

  assert(list.count == 5);
  assert(!holytls::DLLIsEmpty(&list));

  // Verify order
  int expected = 0;
  DLLForEach(&list, n) {
    Item* item = ContainerOf(n, Item, node);
    assert(item->value == expected);
    expected++;
  }

  // Remove middle element
  holytls::DLLRemove(&list, &items[2].node);
  assert(list.count == 4);

  // Pop front
  holytls::DLLNode* front = holytls::DLLPopFront(&list);
  assert(ContainerOf(front, Item, node)->value == 0);
  assert(list.count == 3);

  // Pop back
  holytls::DLLNode* back = holytls::DLLPopBack(&list);
  assert(ContainerOf(back, Item, node)->value == 4);
  assert(list.count == 2);

  std::println("PASSED");
}

void TestSLLBasic() {
  std::print("Testing singly-linked list... ");

  struct Item {
    int value;
    holytls::SLLNode node;
  };

  holytls::SLLList list;
  holytls::SLLInit(&list);
  assert(holytls::SLLIsEmpty(&list));

  Item items[5];
  for (int i = 0; i < 5; ++i) {
    items[i].value = i;
    holytls::SLLPushBack(&list, &items[i].node);
  }

  assert(list.count == 5);

  // Pop all in order (FIFO)
  for (int i = 0; i < 5; ++i) {
    holytls::SLLNode* n = holytls::SLLPopFront(&list);
    assert(n != nullptr);
    Item* item = ContainerOf(n, Item, node);
    assert(item->value == i);
  }

  assert(holytls::SLLIsEmpty(&list));

  std::println("PASSED");
}

void TestSLLStack() {
  std::print("Testing singly-linked list as stack... ");

  struct Item {
    int value;
    holytls::SLLNode node;
  };

  holytls::SLLList stack;
  holytls::SLLInit(&stack);

  Item items[5];
  for (int i = 0; i < 5; ++i) {
    items[i].value = i;
    holytls::SLLPushFront(&stack, &items[i].node);
  }

  // Pop all in reverse order (LIFO)
  for (int i = 4; i >= 0; --i) {
    holytls::SLLNode* n = holytls::SLLPopFront(&stack);
    assert(n != nullptr);
    Item* item = ContainerOf(n, Item, node);
    assert(item->value == i);
  }

  std::println("PASSED");
}

int main() {
  std::println("=== Arena and List Unit Tests ===\n");

  TestArenaBasic();
  TestArenaZero();
  TestArenaGrowth();
  TestArenaLargeAllocation();
  TestArenaTemp();
  TestArenaClear();
  TestDLLBasic();
  TestSLLBasic();
  TestSLLStack();

  std::println("\nAll arena and list tests passed!");
  return 0;
}

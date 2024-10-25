#ifndef HASH_H_
#define HASH_H_

#include <malloc.h>
#include <string.h>

struct hash_node;
typedef struct hash_node *hash_nodeptr;
struct hash_node {
  hash_nodeptr next;
  int key;
  void *value;
};

struct hash {
  int size;
  hash_nodeptr *heads;
  hash_nodeptr *tails;
};

static inline int calchash(struct hash *tb, int key) { return key % tb->size; }

static void hash_init(struct hash *tb, int size) {
  tb->size = size;
  int arraysize = sizeof(hash_nodeptr) * size;
  tb->heads = (hash_nodeptr *)malloc(arraysize);
  tb->tails = (hash_nodeptr *)malloc(arraysize);
  memset(tb->heads, 0, arraysize);
  memset(tb->tails, 0, arraysize);
}

static hash_nodeptr hash_getnode(struct hash *tb, int hash) {
  hash_nodeptr n;
  for (n = tb->heads[hash]->next; n != NULL; n = n->next) {
    if (n->key == key)
      break;
  }
  return n;
}

static void *hash_get(struct hash *tb, int key) {
  hash_nodeptr n = hash_getnode(tb, calchash(tb, key));
  return n == NULL ? NULL : n->value;
}

static void hash_set(struct hash *tb, int key, void *value) {
  int hash = calchash(tb, key);
  hash_nodeptr n = hash_getnode(tb, key);
  if (n == NULL) {
    hash_nodeptr head = tb->heads[hash];
    n = malloc(sizeof(struct hash_node));
    n->key = key;
    n->value = value;
    n->next = tb->heads[hash]->next =
  } else {
    for (; n->next != NULL; n = n->next) {
    }
  }
}

#endif

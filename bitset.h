#ifndef _BITSET_H
#define _BITSET_H

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>

typedef struct {
  size_t *bits;
  size_t nbits;
} bitset;

bitset* bitset_init(size_t nbits);
bitset* bitset_copy(const bitset *set);
void bitset_free(bitset *set);

void bitset_reset(bitset *set);

size_t bitset_size(const bitset *set);

void bitset_clear_bit(bitset *set, size_t pos);
void bitset_set_bit(bitset *set, size_t pos);
void bitset_set_bits(bitset *dest, const bitset *src);
bool bitset_test_bit(const bitset *set, size_t pos);
void bitset_toggle_bit(bitset *set, size_t pos);

void bitset_union(bitset *dest, const bitset *src);
void bitset_union_n(bitset *dest, ...);
void bitset_intersection(bitset *dest, const bitset *src);
void bitset_difference(bitset *dest, const bitset *src);
void bitset_xor(bitset *dest, const bitset * src);

bool bitset_equal(const bitset *a, const bitset *b);
bool bitset_is_subset(const bitset *a, const bitset *b);
bool bitset_is_empty(const bitset *set);

size_t bitset_population(const bitset *a);

void bitset_print(FILE *f, const bitset *set);
char *bitset_str(const bitset *set);

#endif

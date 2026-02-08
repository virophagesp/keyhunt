/*
 *  Copyright (c) 2012-2019, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "bloom.h"
#include "../xxhash/xxhash.h"

inline static int test_bit_set_bit(uint8_t *bf, uint64_t bit, int set_bit)
{
  uint64_t byte = bit >> 3;
  uint8_t c = bf[byte];	 // expensive memory access
  uint8_t mask = 1 << (bit % 8);
  if (c & mask) {
    return 1;
  } else {
    if (set_bit) {
		bf[byte] = c | mask;
    }
    return 0;
  }
}

inline static int test_bit(uint8_t *bf, uint64_t bit)
{
  uint64_t byte = bit >> 3;
  uint8_t c = bf[byte];	 // expensive memory access
  uint8_t mask = 1 << (bit % 8);
  if (c & mask) {
    return 1;
  } else {
    return 0;
  }
}

int bloom_init2(struct bloom * bloom)
{
  memset(bloom, 0, sizeof(struct bloom));
  bloom->entries = 10000;
  bloom->error = 0.000001;

  long double num = -log(bloom->error);
  long double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = (num / denom);

  long double dentries = (long double)10000;
  long double allbits = dentries * bloom->bpe;
  bloom->bits = (uint64_t)allbits;

  bloom->bytes = (uint64_t) bloom->bits / 8;
  if (bloom->bits % 8) {
    bloom->bytes +=1;
  }

  bloom->hashes = (uint8_t)ceil(0.693147180559945 * bloom->bpe);  // ln(2)
  
  bloom->bf = (uint8_t *)calloc(bloom->bytes, sizeof(uint8_t));
  if (bloom->bf == NULL) {                                   // LCOV_EXCL_START
    return 1;
  }                                                          // LCOV_EXCL_STOP

  bloom->ready = 1;
  bloom->major = 2;
  bloom->minor = 201;
  return 0;
}

int bloom_check(struct bloom * bloom, const void * buffer)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }
  uint8_t hits = 0;
  uint64_t a = XXH64(buffer, 20, 0x59f2815b16f81798);
  uint64_t b = XXH64(buffer, 20, a);
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = (a + b*i) % bloom->bits;
    if (test_bit(bloom->bf, x)) {
      hits++;
    } else {
      return 0;
    }
  }
  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  return 0;
}


int bloom_add(struct bloom * bloom, const void * buffer)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }
  uint8_t hits = 0;
  uint64_t a = XXH64(buffer, 20, 0x59f2815b16f81798);
  uint64_t b = XXH64(buffer, 20, a);
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = (a + b*i) % bloom->bits;
    if (test_bit_set_bit(bloom->bf, x, 1)) {
      hits++;
    }
  }
  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  return 0;
}

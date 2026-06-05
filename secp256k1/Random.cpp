/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/


#include "Random.h"

#include <sys/random.h>

#define  RK_STATE_LEN 624

/* State of the RNG */
typedef struct rk_state_
{
  unsigned long key[RK_STATE_LEN];
  int pos;
} rk_state;

rk_state localState;

void rk_seed(unsigned long seed, rk_state *state)
{
  int pos;
  seed &= 0xffffffffUL;

  /* Knuth's PRNG as used in the Mersenne Twister reference implementation */
  for (pos=0; pos<RK_STATE_LEN; pos++)
  {
    state->key[pos] = seed;
    seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 1) & 0xffffffffUL;
  }

  state->pos = RK_STATE_LEN;
}

// Initialise the random generator with the specified seed
void rseed(unsigned long seed) {
	rk_seed(seed,&localState);
	//srand(seed);
}

/*
Develop by Alberto
email: albertobsd@gmail.com
*/

/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */


/*
 * 
 * Copyright (c) 2012,2015,2016,2017 Jyri J. Virkki
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <math.h>
#include <inttypes.h>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "xxhash/xxhash.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/IntGroup.h"

#include "hash/sha256.h"

#include <sys/random.h>

#define IMPORTANT "small_test"
//#define IMPORTANT "medium_test"
//#define IMPORTANT "big_test"
//#define IMPORTANT "money"

/** ***************************************************************************
 * Structure to keep track of one bloom filter.  Caller needs to
 * allocate this and pass it to the functions below. First call for
 * every struct must be to bloom_init().
 *
 */
struct bloom
{
  // These fields are part of the public interface of this structure.
  // Client code may read these values if desired. Client code MUST NOT
  // modify any of these.
  uint64_t entries;
  uint64_t bits;
  uint64_t bytes;
  uint8_t hashes;
  long double error;

  // Fields below are private to the implementation. These may go away or
  // change incompatibly at any moment. Client code MUST NOT access or rely
  // on these.
  uint8_t ready;
  uint8_t major;
  uint8_t minor;
  double bpe;
  uint8_t *bf;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	char *rs;   //range start
	char *rpt;  //rng per thread
};

int bloom_init2(struct bloom * bloom);
int bloom_check(struct bloom * bloom, const void * buffer);
int bloom_add(struct bloom * bloom, const void * buffer);

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

char *tohex(char *ptr,int length){
  char *buffer;
  int offset = 0;
  unsigned char c;
  buffer = (char *) malloc((length * 2)+1);
  for (int i = 0; i <length; i++) {
    c = ptr[i];
	sprintf((char*) (buffer + offset),"%.2x",c);
	offset+=2;
  }
  buffer[length*2] = 0;
  return buffer;
}

static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

void b58tobin(void *rawvalue, size_t *raw_value_length)
{
	// address
	size_t binsz = *raw_value_length;
	unsigned char *binu = (unsigned char *)rawvalue;
	uint32_t outi[7];
	size_t i, j;
	if (strcmp(IMPORTANT, "small_test") == 0) {
		outi[0] = 0;
		outi[1] = 1881519343;
		outi[2] = -1275116821;
		outi[3] = 1299018234;
		outi[4] = -1229636785;
		outi[5] = 1231545309;
		outi[6] = 617679621;
	} else if (strcmp(IMPORTANT, "medium_test") == 0) {
		outi[0] = 0;
		outi[1] = -153715335;
		outi[2] = -2084605883;
		outi[3] = 254368924;
		outi[4] = -1205282133;
		outi[5] = 643767290;
		outi[6] = -289356897;
	} else if (strcmp(IMPORTANT, "big_test") == 0) {
		outi[0] = 0;
		outi[1] = 1642826320;
		outi[2] = -932510332;
		outi[3] = -1150124586;
		outi[4] = 1542294820;
		outi[5] = 14079402;
		outi[6] = -852360005;
	} else if (strcmp(IMPORTANT, "money") == 0) {
		outi[0] = 0;
		outi[1] = 550669646;
		outi[2] = -2024523449;
		outi[3] = -941321925;
		outi[4] = -842094058;
		outi[5] = -487002015;
		outi[6] = -706377603;
	}
	
	*(binu++) = (outi[0] >> 0) & 0xff;
	
	for (j = 1; j < 7; ++j)
	{
		for (i = sizeof(*outi); i > 0; --i) {
			*(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
		}
	}
	
	// Count canonical base58 byte count
	binu = (unsigned char *)rawvalue;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*raw_value_length;
	}
	*raw_value_length += 1;
	
	return;
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool b58enc(char *b58, const void *data)
{
	const uint8_t *bin = (const uint8_t *)data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;
	
	while (zcount < 25 && !bin[zcount])
		++zcount;
	
	size = (25 - zcount) * 138 / 100 + 1;
	uint8_t buf[size];
	memset(buf, 0, size);
	
	for (i = zcount, high = size - 1; i < 25; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j) {
				// Otherwise j wraps to maxint which is > high
				break;
			}
		}
	}
	
	for (j = 0; j < size && !buf[j]; ++j);
	
	if (40 <= zcount + size - j)
	{
		return false;
	}
	
	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	
	return true;
}

void init_generator();

void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);

void writekey(bool compressed,Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

void writeFileIfNeeded();

std::vector<Point> Gn;
Point _2Gn;

pthread_t *tid = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX;

Int stride;

uint64_t bytes;
struct address_value *addressTable;

Int n_range_start;
Int n_range_end;

Secp256K1 *secp;

void rmd160toaddress_dst(char *rmd,char *dst){
	char digest[60];
	digest[0] = 0x00;
	memcpy(digest+1,rmd,20);
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,digest)){
		fprintf(stderr,"error b58enc\n");
	}
}

int searchbinary(struct address_value *buffer,char *data,int64_t array_length) {
	int64_t half,min,max,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data,buffer[current+half].value,20);
		if(rcmp == 0)	{
			r = 1;	//Found!!
		}
		else	{
			if(rcmp < 0) { //data < temp_read
				max = (max-half);
			}
			else	{ // data > temp_read
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

int main()	{
	struct tothread *tt;	//tothread
	int check_flag;

	int s;

	size_t raw_value_length;
	uint8_t rawvalue[50];

	Point pts[1024];

	Int dx[513];
	IntGroup *grp = new IntGroup(513);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int i,l,pp_offset,pn_offset,hLength = (511);
	uint64_t j,count;
	Point R,publickey;
	int r,thread_number,continue_flag = 1,k;
	char *hextemp = NULL;

	char publickeyhashrmd160[20];

	char publickeyhashrmd160_endomorphism[12][4][20];

	Int key_mpz,keyfound,temp_stride;
	thread_number = 0;
	grp->Set(dx);

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();

	unsigned long rseedvalue;
	getrandom(&rseedvalue, sizeof(unsigned long), GRND_NONBLOCK);
	rseed(rseedvalue);

	printf("[+] Version 0.6 bitcoin hunt, developed by virophagesp based upon 0.2.230519 Satoshi Quest by AlbertoBSD\n");

	stride.SetInt32(1);
	init_generator();

	printf("[+] Setting search for btc adddress\n");

	// sequential number option (putting this IMPORTANT here for easy finding )
	N_SEQUENTIAL_MAX = strtol("0x100000",NULL,16);
	printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
	printf("[+] Range \n");

	// range
	if (strcmp(IMPORTANT, "small_test") == 0) {
		n_range_start.SetBase16((char *)"8000");
		n_range_end.SetBase16((char *)"ffff");

		printf("[+] -- from : 0x8000\n");
		printf("[+] -- to   : 0xffff\n");
	} else if (strcmp(IMPORTANT, "medium_test") == 0) {
		n_range_start.SetBase16((char *)"200000000");
		n_range_end.SetBase16((char *)"3ffffffff");

		printf("[+] -- from : 0x200000000\n");
		printf("[+] -- to   : 0x3ffffffff\n");
	} else if (strcmp(IMPORTANT, "big_test") == 0) {
		n_range_start.SetBase16((char *)"100000000000000000");
		n_range_end.SetBase16((char *)"1fffffffffffffffff");

		printf("[+] -- from : 0x100000000000000000\n");
		printf("[+] -- to   : 0x1fffffffffffffffff\n");
	} else if (strcmp(IMPORTANT, "money") == 0) {
		n_range_start.SetBase16((char *)"200000000000000000000");
		n_range_end.SetBase16((char *)"3ffffffffffffffffffff");

		printf("[+] -- from : 0x200000000000000000000\n");
		printf("[+] -- to   : 0x3ffffffffffffffffffff\n");
	}

	printf("[+] Allocating memory for 1 element: 0.00 MB\n");
	addressTable = (struct address_value*) malloc(20);
	if((void *)addressTable == NULL)	{
		fprintf(stderr,"[E] error in file %s, malloc pointer addressTable on line %i\n",__FILE__,__LINE__ -1 ); 
		exit(EXIT_FAILURE);
	}
	printf("[+] Bloom filter for 1 elements.\n");
	if(bloom_init2(&bloom) == 1){
		fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
		printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) (&bloom)->bytes)/(double)1048576));
		fprintf(stderr,"[E] Unenexpected error\n");
		exit(EXIT_FAILURE);
	}
	printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) (&bloom)->bytes)/(double)1048576));
	memset(addressTable[0].value,0,20);

	raw_value_length = 25;
	b58tobin(rawvalue,&raw_value_length);
	if(raw_value_length == 25)	{
		bloom_add(&bloom, rawvalue+1);
		memcpy(addressTable[0].value,rawvalue+1,20);
	}
	N = 1;
	printf("[+] Sorting data ...");
	_sort(addressTable,N);
	printf(" done! %" PRIu64 " values were loaded and sorted\n",N);
	writeFileIfNeeded();

	steps = (uint64_t *) calloc(1,sizeof(uint64_t));
	checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
	ends = (unsigned int *) calloc(1,sizeof(int));
	checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
	tid = (pthread_t *) calloc(1,sizeof(pthread_t));
	checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
	tt = (tothread*) malloc(sizeof(struct tothread));
	checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
	steps[0] = 0;

	continue_flag = 1;
	do	{
		check_flag = 1 & ends[0];
		if(check_flag)	{
			continue_flag = 0;
		}

		if(n_range_start.IsLower(&n_range_end))	{
			key_mpz.Set(&n_range_start);
			n_range_start.Add(N_SEQUENTIAL_MAX);
		}
		else	{
			continue_flag = 0;
		}
		if(continue_flag)	{
			count = 0;
			hextemp = key_mpz.GetBase16();
			printf("\rBase key: %s     \r",hextemp);
			fflush(stdout);
			free(hextemp);
			do {
				temp_stride.SetInt32(512);
				temp_stride.Mult(&stride);
				key_mpz.Add(&temp_stride);
	 			startP = secp->ComputePublicKey(&key_mpz);
				key_mpz.Sub(&temp_stride);

				for(i = 0; i < hLength; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}

				dx[i].ModSub(&Gn[i].x,&startP.x);  // For the first point
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); // For the next center point
				grp->ModInv();

				pts[512].Set(startP);

				for(i = 0; i<hLength; i++) {
					pp.Set(startP);
					pn.Set(startP);

					// P = startP + i*G
					dy.ModSub(&Gn[i].y,&pp.y);

					_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
					_p.ModSquareK1(&_s);            // _p = pow2(s)

					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

					// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
					dyn.Set(&Gn[i].y);
					dyn.ModNeg();
					dyn.ModSub(&pn.y);

					_s.ModMulK1(&dyn,&dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
					_p.ModSquareK1(&_s);            // _p = pow2(s)
					pn.x.ModNeg();
					pn.x.ModAdd(&_p);
					pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

					pp_offset = 512 + (i + 1);
					pn_offset = 512 - (i + 1);

					pts[pp_offset].Set(pp);
					pts[pn_offset].Set(pn);
				}

				// First point (startP - (GRP_SZIE/2)*G)
				pn.Set(startP);
				dyn.Set(&Gn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);

				_s.ModMulK1(&dyn,&dx[i]);
				_p.ModSquareK1(&_s);

				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&Gn[i].x);

				pts[0].Set(pn);

				for(j = 0; j < 256;j++){
					secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
					secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);

					for(k = 0; k < 4;k++)	{
						for(l = 0;l < 2; l++)	{
							r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k]);
							if(r) {
								r = searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N);
								if(r) {
									keyfound.SetInt32(k);
									keyfound.Mult(&stride);
									keyfound.Add(&key_mpz);

									publickey = secp->ComputePublicKey(&keyfound);
									secp->GetHash160(P2PKH,true,publickey,(uint8_t*)publickeyhashrmd160);
									if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
										keyfound.Neg();
										keyfound.Add(&secp->order);
									}
									writekey(true,&keyfound);
								}
							}
						}
					}
					count+=4;
					temp_stride.SetInt32(4);
					temp_stride.Mult(&stride);
					key_mpz.Add(&temp_stride);
				}

				steps[thread_number]++;

				// Next start point (startP + GRP_SIZE*G)
				pp.Set(startP);
				dy.ModSub(&_2Gn.y,&pp.y);

				_s.ModMulK1(&dy,&dx[i + 1]);
				_p.ModSquareK1(&_s);

				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&_2Gn.x);

				//The Y value for the next start point always need to be calculated
				pp.y.ModSub(&_2Gn.x,&pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&_2Gn.y);
				startP.Set(pp);
			}while(count < N_SEQUENTIAL_MAX && continue_flag);
		}
	} while(continue_flag);
	ends[thread_number] = 1;
	printf("\nEnd\n");
}

void _swap(struct address_value *a,struct address_value *b)	{
	struct address_value t;
	t  = *a;
	*a = *b;
	*b =  t;
}

void _sort(struct address_value *arr,int64_t n)	{
	uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
	_introsort(arr,depthLimit,n);
}

void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n) {
	int64_t p;
	if(n > 1)	{
		if(n <= 16) {
			_insertionsort(arr,n);
		}
		else	{
			if(depthLimit == 0) {
				_myheapsort(arr,n);
			}
			else	{
				p = _partition(arr,n);
				if(p > 0) _introsort(arr , depthLimit-1 , p);
				if(p < n) _introsort(&arr[p+1],depthLimit-1,n-(p+1));
			}
		}
	}
}

void _insertionsort(struct address_value *arr, int64_t n) {
	int64_t j;
	int64_t i;
	struct address_value key;
	for(i = 1; i < n ; i++ ) {
		key = arr[i];
		j= i-1;
		while(j >= 0 && memcmp(arr[j].value,key.value,20) > 0) {
			arr[j+1] = arr[j];
			j--;
		}
		arr[j+1] = key;
	}
}

int64_t _partition(struct address_value *arr, int64_t n)	{
	struct address_value pivot;
	int64_t r,left,right;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left	< right && memcmp(arr[left].value,pivot.value,20) <= 0 )	{
			left++;
		}
		while(right >= left && memcmp(arr[right].value,pivot.value,20) > 0)	{
			right--;
		}
		if(left < right)	{
			if(left == r || right == r)	{
				if(left == r)	{
					r = right;
				}
				if(right == r)	{
					r = left;
				}
			}
			_swap(&arr[right],&arr[left]);
		}
	}while(left < right);
	if(right != r)	{
		_swap(&arr[right],&arr[r]);
	}
	return right;
}

void _heapify(struct address_value *arr, int64_t n, int64_t i) {
	int64_t largest = i;
	int64_t l = 2 * i + 1;
	int64_t r = 2 * i + 2;
	if (l < n && memcmp(arr[l].value,arr[largest].value,20) > 0)
		largest = l;
	if (r < n && memcmp(arr[r].value,arr[largest].value,20) > 0)
		largest = r;
	if (largest != i) {
		_swap(&arr[i],&arr[largest]);
		_heapify(arr, n, largest);
	}
}

void _myheapsort(struct address_value	*arr, int64_t n)	{
	int64_t i;
	for ( i = (n / 2) - 1; i >=	0; i--)	{
		_heapify(arr, n, i);
	}
	for ( i = n - 1; i > 0; i--) {
		_swap(&arr[0] , &arr[i]);
		_heapify(arr, i, 0);
	}
}

void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	g.Set(G);
	Gn.reserve(512);
	Gn[0].Set(g);
	g = secp->DoubleDirect(g);
	Gn[1].Set(g);
	for(int i = 2; i < 512; i++) {
		g = secp->AddDirect(g,G);
		Gn[i].Set(g);
	}
	_2Gn = secp->DoubleDirect(Gn[511]);
}

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

void writekey(bool compressed,Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp,*hexrmd,public_key_hex[132],address[50],rmdhash[20];
	memset(address,0,50);
	memset(public_key_hex,0,132);
	hextemp = key->GetBase16();
	publickey = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed,publickey,public_key_hex);
	secp->GetHash160(P2PKH,compressed,publickey,(uint8_t*)rmdhash);
	hexrmd = tohex(rmdhash,20);
	rmd160toaddress_dst(rmdhash,address);

	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
		fclose(keys);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);

	free(hextemp);
	free(hexrmd);
}

void writeFileIfNeeded()	{
	FILE *fileDescriptor;
	char fileBloomName[30];
	char dataChecksum[32],bloomChecksum[32];
	size_t bytesWrite;
	uint64_t dataSize;
	// file bloom name
	if (strcmp(IMPORTANT, "small_test") == 0) {
		fileBloomName[0] = 'd';
		fileBloomName[1] = 'a';
		fileBloomName[2] = 't';
		fileBloomName[3] = 'a';
		fileBloomName[4] = '_';
		fileBloomName[5] = '5';
		fileBloomName[6] = '9';
		fileBloomName[7] = '6';
		fileBloomName[8] = 'd';
		fileBloomName[9] = '6';
		fileBloomName[10] = 'f';
		fileBloomName[11] = '1';
		fileBloomName[12] = '2';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	} else if (strcmp(IMPORTANT, "medium_test") == 0) {
		fileBloomName[0] = 'd';
		fileBloomName[1] = 'a';
		fileBloomName[2] = 't';
		fileBloomName[3] = 'a';
		fileBloomName[4] = '_';
		fileBloomName[5] = '2';
		fileBloomName[6] = '4';
		fileBloomName[7] = 'f';
		fileBloomName[8] = '4';
		fileBloomName[9] = '0';
		fileBloomName[10] = '4';
		fileBloomName[11] = '9';
		fileBloomName[12] = 'c';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	} else if (strcmp(IMPORTANT, "big_test") == 0) {
		fileBloomName[0] =  'd';
		fileBloomName[1] =  'a';
		fileBloomName[2] =  't';
		fileBloomName[3] =  'a';
		fileBloomName[4] =  '_';
		fileBloomName[5] =  '9';
		fileBloomName[6] =  '5';
		fileBloomName[7] =  'a';
		fileBloomName[8] =  '7';
		fileBloomName[9] =  'd';
		fileBloomName[10] = '8';
		fileBloomName[11] = '6';
		fileBloomName[12] = '1';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	} else if (strcmp(IMPORTANT, "money") == 0) {
		fileBloomName[0] =  'd';
		fileBloomName[1] =  'a';
		fileBloomName[2] =  't';
		fileBloomName[3] =  'a';
		fileBloomName[4] =  '_';
		fileBloomName[5] =  '6';
		fileBloomName[6] =  'f';
		fileBloomName[7] =  '6';
		fileBloomName[8] =  'e';
		fileBloomName[9] =  '6';
		fileBloomName[10] = 'e';
		fileBloomName[11] = 'a';
		fileBloomName[12] = '2';
		fileBloomName[13] = '.';
		fileBloomName[14] = 'd';
		fileBloomName[15] = 'a';
		fileBloomName[16] = 't';
		fileBloomName[17] = '\0';
	}
	fileDescriptor = fopen(fileBloomName,"wb");
	dataSize = N * 20;
	printf("[D] size data %li\n",dataSize);
	if(fileDescriptor != NULL)	{
		printf("[+] Writing file %s ",fileBloomName);

		//calculate bloom checksum
		//write bloom checksum (expected value to be checked)
		//write bloom filter structure
		//write bloom filter data

		//calculate dataChecksum
		//write data checksum (expected value to be checked)
		//write data size
		//write data

		sha256((uint8_t*)bloom.bf,bloom.bytes,(uint8_t*)bloomChecksum);
		printf(".");
		bytesWrite = fwrite(bloomChecksum,1,32,fileDescriptor);
		if(bytesWrite != 32)	{
			fprintf(stderr,"[E] Errore writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(&bloom,1,sizeof(struct bloom),fileDescriptor);
		if(bytesWrite != sizeof(struct bloom))	{
			fprintf(stderr,"[E] Error writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(bloom.bf,1,bloom.bytes,fileDescriptor);
		if(bytesWrite != bloom.bytes)	{
			fprintf(stderr,"[E] Error writing file, code line %i\n",__LINE__ - 2);
			fclose(fileDescriptor);
			exit(EXIT_FAILURE);
		}
		printf(".");

		sha256((uint8_t*)addressTable,dataSize,(uint8_t*)dataChecksum);
		printf(".");

		bytesWrite = fwrite(dataChecksum,1,32,fileDescriptor);
		if(bytesWrite != 32)	{
			fprintf(stderr,"[E] Errore writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(&dataSize,1,sizeof(uint64_t),fileDescriptor);
		if(bytesWrite != sizeof(uint64_t))	{
			fprintf(stderr,"[E] Errore writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		bytesWrite = fwrite(addressTable,1,dataSize,fileDescriptor);
		if(bytesWrite != dataSize)	{
			fprintf(stderr,"[E] Error writing file, code line %i\n",__LINE__ - 2);
			exit(EXIT_FAILURE);
		}
		printf(".");

		fclose(fileDescriptor);
		printf("\n");
	}
}

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

/*
 * xxHash Library
 * Copyright (c) 2012-2020 Yann Collet
 * All rights reserved.
 * 
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * ----------------------------------------------------
 * 
 * xxhsum command line interface
 * Copyright (c) 2013-2020 Yann Collet
 * All rights reserved.
 * 
 * GPL v2 License
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <sys/random.h>
#include <vector>

#include "SECP256k1.h"

#include "sha256.h"

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
	uint8_t *bf;
};

int main()	{
	uint8_t rawvalue[21];
	Point pts[1024];
	Int dx[513];
	Int dx_inverse[513];
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int i,l;
	uint64_t j,count;
	Point R,publickey;
	int continue_flag,k;
	char *hextemp = NULL;
	char publickeyhashrmd160[20];
	char publickeyhashrmd160_endomorphism[12][4][20];
	Int key_mpz,keyfound;
	Point G,g;
	std::vector<Point> Gn;
	Point _2Gn;
	struct bloom bloom;
	uint64_t N_SEQUENTIAL_MAX;
	Int stride;
	uint8_t *addressTable;
	Int n_range_start;
	Int n_range_end;
	const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	Secp256K1 secp;

	srand(time(NULL));

	secp.Init();

	printf("[+] Version 1.1 bitcoin hunt, developed by virophagesp based upon 0.2.230519 Satoshi Quest by AlbertoBSD\n");

	stride.SetInt32(1);

	G.Set2(secp.ComputePublicKey(&stride));
	g.Set(G);
	Gn.reserve(512);
	Gn[0].Set(g);
	g.Set2(secp.DoubleDirect(g));
	Gn[1].Set(g);
	for(int i = 2; i < 512; i++) {
		g.Set2(secp.AddDirect(g,G));
		Gn[i].Set(g);
	}
	_2Gn.Set2(secp.DoubleDirect(Gn[511]));

	printf("[+] Allocating memory for addressTable\n");
	addressTable = (uint8_t *) malloc(20);
	printf("[+] Bloom filter for 1 elements.\n");
	memset((&bloom), 0, sizeof(struct bloom));
	(&bloom)->bf = (uint8_t *)calloc((uint64_t)35944, sizeof(uint8_t));
	printf("[+] Loading data to the bloomfilter total: 0.03 MB\n");
	memset(addressTable,0,20);

	printf("[+] Setting search for btc adddress\n");

	// sequential number option (putting this IMPORTANT here for easy finding )
	N_SEQUENTIAL_MAX = strtol("0x100000",NULL,16);
	printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
	printf("[+] Range \n");

	// range and address
	if (strcmp(IMPORTANT, "small_test") == 0) {
		printf("[+] -- from : 0x8000\n");
		printf("[+] -- to   : 0xffff\n");

		n_range_start.SetBase16((char *)"8000");
		n_range_end.SetBase16((char *)"ffff");

		rawvalue[0] = 0;
		rawvalue[1] = 112;
		rawvalue[2] = 37;
		rawvalue[3] = 180;
		rawvalue[4] = 239;
		rawvalue[5] = 179;
		rawvalue[6] = 255;
		rawvalue[7] = 66;
		rawvalue[8] = 235;
		rawvalue[9] = 77;
		rawvalue[10] = 109;
		rawvalue[11] = 113;
		rawvalue[12] = 250;
		rawvalue[13] = 182;
		rawvalue[14] = 181;
		rawvalue[15] = 59;
		rawvalue[16] = 79;
		rawvalue[17] = 73;
		rawvalue[18] = 103;
		rawvalue[19] = 227;
		rawvalue[20] = 221;
	} else if (strcmp(IMPORTANT, "medium_test") == 0) {
		printf("[+] -- from : 0x200000000\n");
		printf("[+] -- to   : 0x3ffffffff\n");

		n_range_start.SetBase16((char *)"200000000");
		n_range_end.SetBase16((char *)"3ffffffff");

		rawvalue[0] = 0;
		rawvalue[1] = 246;
		rawvalue[2] = 214;
		rawvalue[3] = 125;
		rawvalue[4] = 121;
		rawvalue[5] = 131;
		rawvalue[6] = 191;
		rawvalue[7] = 112;
		rawvalue[8] = 69;
		rawvalue[9] = 15;
		rawvalue[10] = 41;
		rawvalue[11] = 92;
		rawvalue[12] = 156;
		rawvalue[13] = 184;
		rawvalue[14] = 40;
		rawvalue[15] = 218;
		rawvalue[16] = 171;
		rawvalue[17] = 38;
		rawvalue[18] = 95;
		rawvalue[19] = 27;
		rawvalue[20] = 250;
	} else if (strcmp(IMPORTANT, "big_test") == 0) {
		printf("[+] -- from : 0x100000000000000000\n");
		printf("[+] -- to   : 0x1fffffffffffffffff\n");

		n_range_start.SetBase16((char *)"100000000000000000");
		n_range_end.SetBase16((char *)"1fffffffffffffffff");

		rawvalue[0] = 0;
		rawvalue[1] = 97;
		rawvalue[2] = 235;
		rawvalue[3] = 138;
		rawvalue[4] = 80;
		rawvalue[5] = 200;
		rawvalue[6] = 107;
		rawvalue[7] = 5;
		rawvalue[8] = 132;
		rawvalue[9] = 187;
		rawvalue[10] = 114;
		rawvalue[11] = 125;
		rawvalue[12] = 214;
		rawvalue[13] = 91;
		rawvalue[14] = 237;
		rawvalue[15] = 141;
		rawvalue[16] = 36;
		rawvalue[17] = 0;
		rawvalue[18] = 214;
		rawvalue[19] = 213;
		rawvalue[20] = 170;
	} else if (strcmp(IMPORTANT, "money") == 0) {
		printf("[+] -- from : 0x200000000000000000000\n");
		printf("[+] -- to   : 0x3ffffffffffffffffffff\n");

		n_range_start.SetBase16((char *)"200000000000000000000");
		n_range_end.SetBase16((char *)"3ffffffffffffffffffff");

		rawvalue[0] = 0;
		rawvalue[1] = 32;
		rawvalue[2] = 210;
		rawvalue[3] = 141;
		rawvalue[4] = 78;
		rawvalue[5] = 135;
		rawvalue[6] = 84;
		rawvalue[7] = 57;
		rawvalue[8] = 71;
		rawvalue[9] = 199;
		rawvalue[10] = 228;
		rawvalue[11] = 145;
		rawvalue[12] = 59;
		rawvalue[13] = 205;
		rawvalue[14] = 206;
		rawvalue[15] = 170;
		rawvalue[16] = 22;
		rawvalue[17] = 226;
		rawvalue[18] = 248;
		rawvalue[19] = 240;
		rawvalue[20] = 97;
	}

    uint64_t a = -9095181581730021519;
    a ^= (((*((const uint64_t*)&rawvalue[1]) * -4417276706812531889) << 31) | ((*((const uint64_t*)&rawvalue[1]) * -4417276706812531889) >> 33)) * -7046029288634856825;
    a  = ((a << 27) | (a >> 37)) * -7046029288634856825 + -8796714831421723037;
    a ^= ((*((const uint64_t*)&rawvalue[9]) * -4417276706812531889 << 31) | (*((const uint64_t*)&rawvalue[9]) * -4417276706812531889 >> 33)) * -7046029288634856825;
    a  = ((a << 27) | (a >> 37)) * -7046029288634856825 + -8796714831421723037;
    a ^= (uint64_t)(*((const uint32_t*)&rawvalue[17])) * -7046029288634856825;
    a = ((a << 23) | (a >> 41)) * -4417276706812531889 + 1609587929392839161;
    a ^= a >> 33;
    a *= -4417276706812531889;
    a ^= a >> 29;
    a *= 1609587929392839161;
    a ^= a >> 32;
    uint64_t b = a + 2870177450012600281;
    b ^= (((*((const uint64_t*)&rawvalue[1]) * -4417276706812531889) << 31) | ((*((const uint64_t*)&rawvalue[1]) * -4417276706812531889) >> 33)) * -7046029288634856825;
    b  = ((b << 27) | (b >> 37)) * -7046029288634856825 + -8796714831421723037;
    b ^= ((*((const uint64_t*)&rawvalue[9]) * -4417276706812531889 << 31) | (*((const uint64_t*)&rawvalue[9]) * -4417276706812531889 >> 33)) * -7046029288634856825;
    b  = ((b << 27) | (b >> 37)) * -7046029288634856825 + -8796714831421723037;
    b ^= (uint64_t)(*((const uint32_t*)&rawvalue[17])) * -7046029288634856825;
    b = ((b << 23) | (b >> 41)) * -4417276706812531889 + 1609587929392839161;
    b ^= b >> 33;
    b *= -4417276706812531889;
    b ^= b >> 29;
    b *= 1609587929392839161;
    b ^= b >> 32;
	uint64_t x,byte;
	uint8_t bloom_add_looper,c,mask;
	for (bloom_add_looper = 0; bloom_add_looper < 20; bloom_add_looper++) {
		x = (a + b*bloom_add_looper) % 35944;
		byte = x >> 3;
		c = (&bloom)->bf[byte];	 // expensive memory access
		mask = 1 << (x % 8);
		if (!(c & mask)) {
			(&bloom)->bf[byte] = c | mask;
		}
	}
	memcpy(addressTable,rawvalue+1,20);

	continue_flag = 1;
	do	{
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
				key_mpz.Add(512);
	 			startP.Set2(secp.ComputePublicKey(&key_mpz));
				key_mpz.Sub(512);

				for(i = 0; i < 511; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}

				dx[i].ModSub(&Gn[i].x,&startP.x);  // For the first point
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); // For the next center point

				Int newValue;
				Int inverse;

				dx_inverse[0].Set(&(dx[0]));
				for (int i = 1; i < 513; i++) {
					dx_inverse[i].ModMulK1(&(dx_inverse[i - 1]), &(dx[i]));
				}

				// Do the inversion
				inverse.Set(&(dx_inverse[513 - 1]));
				inverse.ModInv();

				for (int i = 513 - 1; i > 0; i--) {
					newValue.ModMulK1(&(dx_inverse[i - 1]), &inverse);
					inverse.ModMulK1(&(dx[i]));
					dx[i].Set(&newValue);
				}

				dx[0].Set(&inverse);

				pts[512].Set(startP);

				for(i = 0; i<511; i++) {
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

					pts[512 + (i + 1)].Set(pp);
					pts[512 - (i + 1)].Set(pn);
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
					secp.GetHash160_fromX(2,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
					secp.GetHash160_fromX(3,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);

					for(k = 0; k < 4;k++)	{
						for(l = 0;l < 2; l++)	{
							uint64_t a = -9095181581730021519;
							a ^= (((*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][0]) * -4417276706812531889) << 31) | ((*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][0]) * -4417276706812531889) >> 33)) * -7046029288634856825;
							a  = ((a << 27) | (a >> 37)) * -7046029288634856825 + -8796714831421723037;
							a ^= ((*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][8]) * -4417276706812531889 << 31) | (*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][8]) * -4417276706812531889 >> 33)) * -7046029288634856825;
							a  = ((a << 27) | (a >> 37)) * -7046029288634856825 + -8796714831421723037;
							a ^= (uint64_t)(*((const uint32_t*)&publickeyhashrmd160_endomorphism[l][k][16])) * -7046029288634856825;
							a = ((a << 23) | (a >> 41)) * -4417276706812531889 + 1609587929392839161;
							a ^= a >> 33;
							a *= -4417276706812531889;
							a ^= a >> 29;
							a *= 1609587929392839161;
							a ^= a >> 32;
							uint64_t b = a + 2870177450012600281;
							b ^= (((*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][0]) * -4417276706812531889) << 31) | ((*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][0]) * -4417276706812531889) >> 33)) * -7046029288634856825;
							b  = ((b << 27) | (b >> 37)) * -7046029288634856825 + -8796714831421723037;
							b ^= ((*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][8]) * -4417276706812531889 << 31) | (*((const uint64_t*)&publickeyhashrmd160_endomorphism[l][k][8]) * -4417276706812531889 >> 33)) * -7046029288634856825;
							b  = ((b << 27) | (b >> 37)) * -7046029288634856825 + -8796714831421723037;
							b ^= (uint64_t)(*((const uint32_t*)&publickeyhashrmd160_endomorphism[l][k][16])) * -7046029288634856825;
							b = ((b << 23) | (b >> 41)) * -4417276706812531889 + 1609587929392839161;
							b ^= b >> 33;
							b *= -4417276706812531889;
							b ^= b >> 29;
							b *= 1609587929392839161;
							b ^= b >> 32;
							uint64_t x,byte;
							uint8_t bloom_check_looper,c,mask;
							for (bloom_check_looper = 0; bloom_check_looper < 20; bloom_check_looper++) {
								x = (a + b*bloom_check_looper) % 35944;
								byte = x >> 3;
								c = (&bloom)->bf[byte];	 // expensive memory access
								mask = 1 << (x % 8);
								if (!(c & mask)) {
									break;
								}
							}

							if(bloom_check_looper == 20) {
								if(memcmp(publickeyhashrmd160_endomorphism[l][k],addressTable,20) == 0)	{
									keyfound.SetInt32(k);
									keyfound.Add(&key_mpz);

									publickey.Set2(secp.ComputePublicKey(&keyfound));
									secp.GetHash160(publickey,(uint8_t*)publickeyhashrmd160);
									if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
										keyfound.Neg();
										keyfound.Add(&secp.order);
									}

									Point publickey2;
									FILE *keys;
									char *hextemp,*hexrmd,public_key_hex[132],address[50],rmdhash[20];
									int offset = 0;
									unsigned char c2;
									char digest[60];
									memset(address,0,50);
									memset(public_key_hex,0,132);
									hextemp = (&keyfound)->GetBase16();
									publickey2.Set2(secp.ComputePublicKey(&keyfound));
									secp.GetPublicKeyHex(publickey2,public_key_hex);
									secp.GetHash160(publickey2,(uint8_t*)rmdhash);

									hexrmd = (char *) malloc(41);
									for (int i = 0; i <20; i++) {
										c2 = rmdhash[i];
										sprintf((char*) (hexrmd + offset),"%.2x",c2);
										offset+=2;
									}
									hexrmd[40] = 0;

									digest[0] = 0;
									memcpy(digest+1,rmdhash,20);
									sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
									sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);

									const uint8_t *bin = (const uint8_t *)digest;
									int carry;
									size_t i2, j2, high, zcount = 0;
									size_t size;

									while (zcount < 25 && !bin[zcount])
										++zcount;

									size = (25 - zcount) * 138 / 100 + 1;
									uint8_t buf[size];
									memset(buf, 0, size);

									for (i2 = zcount, high = size - 1; i2 < 25; ++i2, high = j2)
									{
										for (carry = bin[i2], j2 = size - 1; (j2 > high) || carry; --j2)
										{
											carry += 256 * buf[j2];
											buf[j2] = carry % 58;
											carry /= 58;
											if (!j2) {
												// Otherwise j2 wraps to maxint which is > high
												break;
											}
										}
									}

									for (j2 = 0; j2 < size && !buf[j2]; ++j2);

									if (40 <= zcount + size - j2)
									{
										fprintf(stderr,"error b58enc\n");
									}
									else
									{
										if (zcount)
											memset(address, '1', zcount);
										for (i2 = zcount; j2 < size; ++i2, ++j2)
											address[i2] = b58digits_ordered[buf[j2]];
										address[i2] = '\0';
									}

									keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
									if(keys != NULL)	{
										fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
										fclose(keys);
									}
									printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);

									free(hextemp);
									free(hexrmd);
								}
							}
						}
					}
					count+=4;
					key_mpz.Add(4);
				}

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
			}while(count < N_SEQUENTIAL_MAX);
		}
	} while(continue_flag);
	free(addressTable);
	free(bloom.bf);
	printf("\nEnd\n");
}

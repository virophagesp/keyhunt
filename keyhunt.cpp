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

#include "Point.h"
#include "sha256.h"
#include "ripemd160.h"

#define IMPORTANT "small_test"
//#define IMPORTANT "medium_test"
//#define IMPORTANT "big_test"
//#define IMPORTANT "money"

Point Add2(Point &p1, Point &p2);
Point AddDirect(Point &p1, Point &p2);
Point DoubleDirect(Point &p);

Point ComputePublicKey(Point *secp, Int *privKey) {
	int i = 0;
	uint8_t b;
	Point Q;
	Q.Clear();
	// Search first significant byte
	for (i = 0; i < 32; i++) {
		b = privKey->GetByte(i);
		if(b)
			break;
	}
	Q.Set(secp[256 * i + (b-1)]);
	i++;

	for(; i < 32; i++) {
		b = privKey->GetByte(i);
		if(b)
			Q.Set2(Add2(Q, secp[256 * i + (b-1)]));
	}
	Q.Reduce();
	return Q;
}

void tohex_dst(char *ptr,char *dst)	{
	int offset = 0;
	unsigned char c;
	for (int i = 0; i <33; i++) {
		c = ptr[i];
		sprintf((char*) (dst + offset),"%.2x",c);
		offset+=2;
	}
	dst[66] = 0;
}

void GetPublicKeyHex(Point &pubKey,char *dst){
	unsigned char publicKeyBytes[65];
	// Compressed public key
	publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
	pubKey.x.Get32Bytes(publicKeyBytes + 1);
	tohex_dst((char*)publicKeyBytes,dst);
}

Point AddDirect(Point &p1,Point &p2) {
	Int _s;
	Int _p;
	Int dy;
	Int dx;
	Point r;
	r.z.SetInt32(1);

	dy.ModSub(&p2.y,&p1.y);
	dx.ModSub(&p2.x,&p1.x);
	dx.ModInv();
	// s = (p2.y-p1.y)*inverse(p2.x-p1.x);
	_s.ModMulK1(&dy,&dx);

	// _p = pow2(s)
	_p.ModSquareK1(&_s);

	r.x.ModSub(&_p,&p1.x);
	// rx = pow2(s) - p1.x - p2.x;
	r.x.ModSub(&p2.x);

	r.y.ModSub(&p2.x,&r.x);
	r.y.ModMulK1(&_s);
	// ry = - p2.y - s*(ret.x-p2.x);
	r.y.ModSub(&p2.y);

	return r;
}

Point Add2(Point &p1, Point &p2) {
	// P2.z = 1
	Int u;
	Int v;
	Int u1;
	Int v1;
	Int vs2;
	Int vs3;
	Int us2;
	Int a;
	Int us2w;
	Int vs2v2;
	Int vs3u2;
	Int _2vs2v2;
	Point r;
	u1.ModMulK1(&p2.y, &p1.z);
	v1.ModMulK1(&p2.x, &p1.z);
	u.ModSub(&u1, &p1.y);
	v.ModSub(&v1, &p1.x);
	us2.ModSquareK1(&u);
	vs2.ModSquareK1(&v);
	vs3.ModMulK1(&vs2, &v);
	us2w.ModMulK1(&us2, &p1.z);
	vs2v2.ModMulK1(&vs2, &p1.x);
	_2vs2v2.ModAdd(&vs2v2, &vs2v2);
	a.ModSub(&us2w, &vs3);
	a.ModSub(&_2vs2v2);

	r.x.ModMulK1(&v, &a);

	vs3u2.ModMulK1(&vs3, &p1.y);
	r.y.ModSub(&vs2v2, &a);
	r.y.ModMulK1(&r.y, &u);
	r.y.ModSub(&vs3u2);

	r.z.ModMulK1(&vs3, &p1.z);

	return r;
}

Point DoubleDirect(Point &p) {
	Int _s;
	Int _p;
	Int a;
	Point r;
	r.z.SetInt32(1);
	_s.ModMulK1(&p.x,&p.x);
	_p.ModAdd(&_s,&_s);
	_p.ModAdd(&_s);

	a.ModAdd(&p.y,&p.y);
	a.ModInv();
	_s.ModMulK1(&_p,&a);     // s = (3*pow2(p.x))*inverse(2*p.y);

	_p.ModMulK1(&_s,&_s);
	a.ModAdd(&p.x,&p.x);
	a.ModNeg();
	r.x.ModAdd(&a,&_p);    // rx = pow2(s) + neg(2*p.x);

	a.ModSub(&r.x,&p.x);

	_p.ModMulK1(&a,&_s);
	r.y.ModAdd(&_p,&p.y);
	r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));
	return r;
}

void GetHash160(Point &pubKey, unsigned char *hash) {
	unsigned char shapk[64];
	unsigned char publicKeyBytes[128];

	// Compressed public key
	publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
	pubKey.x.Get32Bytes(publicKeyBytes + 1);
	sha256_33(publicKeyBytes, shapk);

	ripemd160_32(shapk, hash);
}

void GetHash160_fromX(unsigned char prefix, Int *k0, Int *k1, Int *k2, Int *k3, uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3) {
	unsigned char sh0[64] __attribute__((aligned(16)));
	unsigned char sh1[64] __attribute__((aligned(16)));
	unsigned char sh2[64] __attribute__((aligned(16)));
	unsigned char sh3[64] __attribute__((aligned(16)));

	uint32_t b0[16];
	uint32_t b1[16];
	uint32_t b2[16];
	uint32_t b3[16];

	b0[0] = (k0->bits[7] >> 8) | ((uint32_t)(prefix) << 24);
	b0[1] = (k0->bits[6] >> 8) | (k0->bits[7] <<24);
	b0[2] = (k0->bits[5] >> 8) | (k0->bits[6] <<24);
	b0[3] = (k0->bits[4] >> 8) | (k0->bits[5] <<24);
	b0[4] = (k0->bits[3] >> 8) | (k0->bits[4] <<24);
	b0[5] = (k0->bits[2] >> 8) | (k0->bits[3] <<24);
	b0[6] = (k0->bits[1] >> 8) | (k0->bits[2] <<24);
	b0[7] = (k0->bits[0] >> 8) | (k0->bits[1] <<24);
	b0[8] = 0x00800000 | (k0->bits[0] <<24);
	b0[9] = 0;
	b0[10] = 0;
	b0[11] = 0;
	b0[12] = 0;
	b0[13] = 0;
	b0[14] = 0;
	b0[15] = 0x108;
	b1[0] = (k1->bits[7] >> 8) | ((uint32_t)(prefix) << 24);
	b1[1] = (k1->bits[6] >> 8) | (k1->bits[7] <<24);
	b1[2] = (k1->bits[5] >> 8) | (k1->bits[6] <<24);
	b1[3] = (k1->bits[4] >> 8) | (k1->bits[5] <<24);
	b1[4] = (k1->bits[3] >> 8) | (k1->bits[4] <<24);
	b1[5] = (k1->bits[2] >> 8) | (k1->bits[3] <<24);
	b1[6] = (k1->bits[1] >> 8) | (k1->bits[2] <<24);
	b1[7] = (k1->bits[0] >> 8) | (k1->bits[1] <<24);
	b1[8] = 0x00800000 | (k1->bits[0] <<24);
	b1[9] = 0;
	b1[10] = 0;
	b1[11] = 0;
	b1[12] = 0;
	b1[13] = 0;
	b1[14] = 0;
	b1[15] = 0x108;
	b2[0] = (k2->bits[7] >> 8) | ((uint32_t)(prefix) << 24);
	b2[1] = (k2->bits[6] >> 8) | (k2->bits[7] <<24);
	b2[2] = (k2->bits[5] >> 8) | (k2->bits[6] <<24);
	b2[3] = (k2->bits[4] >> 8) | (k2->bits[5] <<24);
	b2[4] = (k2->bits[3] >> 8) | (k2->bits[4] <<24);
	b2[5] = (k2->bits[2] >> 8) | (k2->bits[3] <<24);
	b2[6] = (k2->bits[1] >> 8) | (k2->bits[2] <<24);
	b2[7] = (k2->bits[0] >> 8) | (k2->bits[1] <<24);
	b2[8] = 0x00800000 | (k2->bits[0] <<24);
	b2[9] = 0;
	b2[10] = 0;
	b2[11] = 0;
	b2[12] = 0;
	b2[13] = 0;
	b2[14] = 0;
	b2[15] = 0x108;
	b3[0] = (k3->bits[7] >> 8) | ((uint32_t)(prefix) << 24);
	b3[1] = (k3->bits[6] >> 8) | (k3->bits[7] <<24);
	b3[2] = (k3->bits[5] >> 8) | (k3->bits[6] <<24);
	b3[3] = (k3->bits[4] >> 8) | (k3->bits[5] <<24);
	b3[4] = (k3->bits[3] >> 8) | (k3->bits[4] <<24);
	b3[5] = (k3->bits[2] >> 8) | (k3->bits[3] <<24);
	b3[6] = (k3->bits[1] >> 8) | (k3->bits[2] <<24);
	b3[7] = (k3->bits[0] >> 8) | (k3->bits[1] <<24);
	b3[8] = 0x00800000 | (k3->bits[0] <<24);
	b3[9] = 0;
	b3[10] = 0;
	b3[11] = 0;
	b3[12] = 0;
	b3[13] = 0;
	b3[14] = 0;
	b3[15] = 0x108;

	sha256sse_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
	ripemd160sse_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
}

int main()	{
	uint8_t rawvalue[21];
	Point pts[1024];
	Int dx[513];
	Int dx_inverse[513];
	Point startP,pp,pn,R,publickey,G,G2,g,_2Gn,N,publickey2;
	Int dy,dyn,_s,_p,key_mpz,keyfound,stride,n_range_start,n_range_end,curve_order,P,newValue,inverse;
	int i,l,continue_flag,k,offset,carry;
	uint64_t j,count,N_SEQUENTIAL_MAX,a,b,x,byte;
	char *hextemp = NULL;
	char publickeyhashrmd160[20];
	char publickeyhashrmd160_endomorphism[12][4][20];
	std::vector<Point> Gn;
	uint8_t *bloom_bf;
	uint8_t addressTable[20];
	const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	Point secp[256*32];
	uint8_t bloom_add_looper,c,mask,bloom_check_looper;
	char *hexrmd,public_key_hex[132],address[50],rmdhash[20];
	unsigned char c2;
	char digest[60];
	const uint8_t *bin;
	size_t i2, j2, high, zcount,size;

	srand(time(NULL));

	// Prime for the finite field
	P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	// Set up field
	Int::SetupField(&P);
	// Generator point
	G2.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	G2.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
	G2.z.SetInt32(1);
	// Compute Generator table
	N.Set(G2);
	for(i = 0; i < 32; i++) {
		secp[i * 256].Set(N);
		N.Set2(DoubleDirect(N));
		for (j = 1; j < 255; j++) {
			secp[i * 256 + j].Set(N);
			N.Set2(AddDirect(N, secp[i * 256]));
		}
		secp[i * 256 + 255].Set(N); // Dummy point for check function
	}
	// Generator order
	curve_order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
	Int::InitK1(&curve_order);

	printf("[+] Version 1.3 bitcoin hunt, developed by virophagesp based upon 0.2.230519 Satoshi Quest by AlbertoBSD\n");

	stride.SetInt32(1);

	G.Set2(ComputePublicKey(secp,&stride));
	g.Set(G);
	Gn.reserve(512);
	Gn[0].Set(g);
	g.Set2(DoubleDirect(g));
	Gn[1].Set(g);
	for(i = 2; i < 512; i++) {
		g.Set2(AddDirect(g,G));
		Gn[i].Set(g);
	}
	_2Gn.Set2(DoubleDirect(Gn[511]));

	printf("[+] Bloom filter for 1 elements.\n");
	bloom_bf = (uint8_t *)calloc((uint64_t)35944, sizeof(uint8_t));
	printf("[+] Loading data to the bloomfilter total: 0.03 MB\n");

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

    a = -9095181581730021519;
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
    b = a + 2870177450012600281;
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
	for (bloom_add_looper = 0; bloom_add_looper < 20; bloom_add_looper++) {
		x = (a + b*bloom_add_looper) % 35944;
		byte = x >> 3;
		c = bloom_bf[byte];	 // expensive memory access
		mask = 1 << (x % 8);
		if (!(c & mask)) {
			bloom_bf[byte] = c | mask;
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
	 			startP.Set2(ComputePublicKey(secp,&key_mpz));
				key_mpz.Sub(512);

				for(i = 0; i < 511; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}

				dx[i].ModSub(&Gn[i].x,&startP.x);  // For the first point
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); // For the next center point

				dx_inverse[0].Set(&(dx[0]));
				for (i = 1; i < 513; i++) {
					dx_inverse[i].ModMulK1(&(dx_inverse[i - 1]), &(dx[i]));
				}

				// Do the inversion
				inverse.Set(&(dx_inverse[513 - 1]));
				inverse.ModInv();

				for (i = 513 - 1; i > 0; i--) {
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
					GetHash160_fromX(2,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
					GetHash160_fromX(3,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);

					for(k = 0; k < 4;k++)	{
						for(l = 0;l < 2; l++)	{
							if(memcmp(publickeyhashrmd160_endomorphism[l][k],addressTable,20) == 0) {
								a = -9095181581730021519;
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
								b = a + 2870177450012600281;
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
								for (bloom_check_looper = 0; bloom_check_looper < 20; bloom_check_looper++) {
									x = (a + b*bloom_check_looper) % 35944;
									byte = x >> 3;
									c = bloom_bf[byte];	 // expensive memory access
									mask = 1 << (x % 8);
									if (!(c & mask)) {
										break;
									}
								}

								if(bloom_check_looper == 20)	{
									keyfound.SetInt32(k);
									keyfound.Add(&key_mpz);

									publickey.Set2(ComputePublicKey(secp,&keyfound));
									GetHash160(publickey,(uint8_t*)publickeyhashrmd160);
									if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
										keyfound.Neg();
										keyfound.Add(&curve_order);
									}

									offset = 0;
									memset(public_key_hex,0,132);
									hextemp = (&keyfound)->GetBase16();
									publickey2.Set2(ComputePublicKey(secp,&keyfound));
									GetPublicKeyHex(publickey2,public_key_hex);
									GetHash160(publickey2,(uint8_t*)rmdhash);

									hexrmd = (char *) malloc(41);
									for (i = 0; i <20; i++) {
										c2 = rmdhash[i];
										sprintf((char*) (hexrmd + offset),"%.2x",c2);
										offset+=2;
									}
									hexrmd[40] = 0;

									digest[0] = 0;
									memcpy(digest+1,rmdhash,20);
									sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
									sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);

									bin = (const uint8_t *)digest;
									zcount = 0;

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
	free(bloom_bf);
	printf("\nEnd\n");
}

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

#include "SECP256k1.h"
#include "Point.h"
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"

Secp256K1::Secp256K1() {
}

void Secp256K1::Init() {
  // Prime for the finite field
  P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

  // Set up field
  Int::SetupField(&P);

  // Generator point and order
  G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
  G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  G.z.SetInt32(1);
  order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  Int::InitK1(&order);

  // Compute Generator table
  Point N(G);
  for(int i = 0; i < 32; i++) {
    GTable[i * 256].Set(N);
    N.Set2(DoubleDirect(N));
    for (int j = 1; j < 255; j++) {
      GTable[i * 256 + j].Set(N);
      N.Set2(AddDirect(N, GTable[i * 256]));
    }
    GTable[i * 256 + 255].Set(N); // Dummy point for check function
  }

}

Secp256K1::~Secp256K1() {
}

Point Secp256K1::ComputePublicKey(Int *privKey) {
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
  Q.Set(GTable[256 * i + (b-1)]);
  i++;

  for(; i < 32; i++) {
    b = privKey->GetByte(i);
    if(b)
      Q.Set2(Add2(Q, GTable[256 * i + (b-1)]));
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


void Secp256K1::GetPublicKeyHex(Point &pubKey,char *dst){
  unsigned char publicKeyBytes[65];
  // Compressed public key
  publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
  pubKey.x.Get32Bytes(publicKeyBytes + 1);
	tohex_dst((char*)publicKeyBytes,dst);
}

Point Secp256K1::AddDirect(Point &p1,Point &p2) {
  Int _s;
  Int _p;
  Int dy;
  Int dx;
  Point r;
  r.z.SetInt32(1);

  dy.ModSub(&p2.y,&p1.y);
  dx.ModSub(&p2.x,&p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy,&dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  _p.ModSquareK1(&_s);       // _p = pow2(s)

  r.x.ModSub(&_p,&p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x,&r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;
}


Point Secp256K1::Add2(Point &p1, Point &p2) {
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

Point Secp256K1::Add(Point &p1,Point &p2) {
  Int u;
  Int v;
  Int u1;
  Int u2;
  Int v1;
  Int v2;
  Int vs2;
  Int vs3;
  Int us2;
  Int w;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Int x3;
  Int vs3y1;
  Point r;

  /*
  U1 = Y2 * Z1
  U2 = Y1 * Z2
  V1 = X2 * Z1
  V2 = X1 * Z2
  if (V1 == V2)
    if (U1 != U2)
      return POINT_AT_INFINITY
    else
      return POINT_DOUBLE(X1, Y1, Z1)
  U = U1 - U2
  V = V1 - V2
  W = Z1 * Z2
  A = U ^ 2 * W - V ^ 3 - 2 * V ^ 2 * V2
  X3 = V * A
  Y3 = U * (V ^ 2 * V2 - A) - V ^ 3 * U2
  Z3 = V ^ 3 * W
  return (X3, Y3, Z3)
  */

  u1.ModMulK1(&p2.y,&p1.z);
  u2.ModMulK1(&p1.y,&p2.z);
  v1.ModMulK1(&p2.x,&p1.z);
  v2.ModMulK1(&p1.x,&p2.z);
  u.ModSub(&u1,&u2);
  v.ModSub(&v1,&v2);
  w.ModMulK1(&p1.z,&p2.z);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2,&v);
  us2w.ModMulK1(&us2,&w);
  vs2v2.ModMulK1(&vs2,&v2);
  _2vs2v2.ModAdd(&vs2v2,&vs2v2);
  a.ModSub(&us2w,&vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v,&a);

  vs3u2.ModMulK1(&vs3,&u2);
  r.y.ModSub(&vs2v2,&a);
  r.y.ModMulK1(&r.y,&u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3,&w);

  return r;
}

Point Secp256K1::DoubleDirect(Point &p) {
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



void Secp256K1::GetHash160(Point &pubKey, unsigned char *hash) {

  unsigned char shapk[64];
  unsigned char publicKeyBytes[128];

  // Compressed public key
  publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
  pubKey.x.Get32Bytes(publicKeyBytes + 1);
  sha256_33(publicKeyBytes, shapk);

  ripemd160_32(shapk, hash);

}


#define KEYBUFFPREFIX(buff,k,fix) \
(buff)[0] = (k->bits[7] >> 8) | ((uint32_t)(fix) << 24); \
(buff)[1] = (k->bits[6] >> 8) | (k->bits[7] <<24); \
(buff)[2] = (k->bits[5] >> 8) | (k->bits[6] <<24); \
(buff)[3] = (k->bits[4] >> 8) | (k->bits[5] <<24); \
(buff)[4] = (k->bits[3] >> 8) | (k->bits[4] <<24); \
(buff)[5] = (k->bits[2] >> 8) | (k->bits[3] <<24); \
(buff)[6] = (k->bits[1] >> 8) | (k->bits[2] <<24); \
(buff)[7] = (k->bits[0] >> 8) | (k->bits[1] <<24); \
(buff)[8] = 0x00800000 | (k->bits[0] <<24); \
(buff)[9] = 0; \
(buff)[10] = 0; \
(buff)[11] = 0; \
(buff)[12] = 0; \
(buff)[13] = 0; \
(buff)[14] = 0; \
(buff)[15] = 0x108;



void Secp256K1::GetHash160_fromX(unsigned char prefix,
  Int *k0,Int *k1,Int *k2,Int *k3,
  uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3) {

  unsigned char sh0[64] __attribute__((aligned(16)));
  unsigned char sh1[64] __attribute__((aligned(16)));
  unsigned char sh2[64] __attribute__((aligned(16)));
  unsigned char sh3[64] __attribute__((aligned(16)));

  uint32_t b0[16];
  uint32_t b1[16];
  uint32_t b2[16];
  uint32_t b3[16];

  KEYBUFFPREFIX(b0, k0, prefix);
  KEYBUFFPREFIX(b1, k1, prefix);
  KEYBUFFPREFIX(b2, k2, prefix);
  KEYBUFFPREFIX(b3, k3, prefix);

  sha256sse_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
  ripemd160sse_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
}


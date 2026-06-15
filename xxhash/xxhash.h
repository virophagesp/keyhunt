/*
 * xxHash - Extremely Fast Hash algorithm
 * Header File
 * Copyright (C) 2012-2020 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

#define XXH_rotl64(x,r) (((x) << (r)) | ((x) >> (64 - (r))))

typedef union { uint32_t u32; } __attribute__((packed)) xxh_unalign;

typedef union { uint32_t u32; uint64_t u64; } __attribute__((packed)) xxh_unalign64;

uint64_t XXH64(const void* input, uint64_t seed)
{
    uint64_t h64 = seed + 0x27D4EB2F165667C5ULL + (uint64_t) 20;
    uint8_t* ptr = (uint8_t*)input;
    h64 ^= XXH_rotl64(((const xxh_unalign64*)ptr)->u64 * 0xC2B2AE3D27D4EB4FULL, 31) * 0x9E3779B185EBCA87ULL;
    h64  = XXH_rotl64(h64,27) * 0x9E3779B185EBCA87ULL + 0x85EBCA77C2B2AE63ULL;
    ptr += 8;
    h64 ^= XXH_rotl64(((const xxh_unalign64*)ptr)->u64 * 0xC2B2AE3D27D4EB4FULL, 31) * 0x9E3779B185EBCA87ULL;
    h64  = XXH_rotl64(h64,27) * 0x9E3779B185EBCA87ULL + 0x85EBCA77C2B2AE63ULL;
    ptr += 8;
    h64 ^= (uint64_t)(((const xxh_unalign*)ptr)->u32) * 0x9E3779B185EBCA87ULL;
    h64 = XXH_rotl64(h64, 23) * 0xC2B2AE3D27D4EB4FULL + 0x165667B19E3779F9ULL;
    ptr += 4;
    h64 ^= h64 >> 33;
    h64 *= 0xC2B2AE3D27D4EB4FULL;
    h64 ^= h64 >> 29;
    h64 *= 0x165667B19E3779F9ULL;
    h64 ^= h64 >> 32;
    return h64;
}

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
/*!
 * @mainpage xxHash
 *
 * @file xxhash.h
 * xxHash prototypes and implementation
 */
/* TODO: update */
/* Notice extracted from xxHash homepage:

xxHash is an extremely fast hash algorithm, running at RAM speed limits.
It also successfully passes all tests from the SMHasher suite.

Comparison (single thread, Windows Seven 32 bits, using SMHasher on a Core 2 Duo @3GHz)

Name            Speed       Q.Score   Author
xxHash          5.4 GB/s     10
CrapWow         3.2 GB/s      2       Andrew
MurmurHash 3a   2.7 GB/s     10       Austin Appleby
SpookyHash      2.0 GB/s     10       Bob Jenkins
SBox            1.4 GB/s      9       Bret Mulvey
Lookup3         1.2 GB/s      9       Bob Jenkins
SuperFastHash   1.2 GB/s      1       Paul Hsieh
CityHash64      1.05 GB/s    10       Pike & Alakuijala
FNV             0.55 GB/s     5       Fowler, Noll, Vo
CRC32           0.43 GB/s     9
MD5-32          0.33 GB/s    10       Ronald L. Rivest
SHA1-32         0.28 GB/s    10

Q.Score is a measure of quality of the hash function.
It depends on successfully passing SMHasher test set.
10 is a perfect score.

Note: SMHasher's CRC32 implementation is not the fastest one.
Other speed-oriented implementations can be faster,
especially in combination with PCLMUL instruction:
https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html?showComment=1552696407071#c3490092340461170735

A 64-bit version, named XXH64, is available since r35.
It offers much better speed, but for 64-bit applications only.
Name     Speed on 64 bits    Speed on 32 bits
XXH64       13.8 GB/s            1.9 GB/s
XXH32        6.8 GB/s            6.0 GB/s
*/

#if defined (__cplusplus)
extern "C" {
#endif


/* ****************************************************************
 *  Stable API
 *****************************************************************/


/* ****************************
*  Definitions
******************************/
#include <stddef.h>   /* size_t */
typedef enum { XXH_OK=0, XXH_ERROR } XXH_errorcode;


/*-**********************************************************************
*  32-bit hash
************************************************************************/
#if !defined (__VMS) \
  && (defined (__cplusplus) \
  || (defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) /* C99 */) )
#   include <stdint.h>
    typedef uint32_t XXH32_hash_t;
#else
#   include <limits.h>
#   if UINT_MAX == 0xFFFFFFFFUL
      typedef unsigned int XXH32_hash_t;
#   else
#     if ULONG_MAX == 0xFFFFFFFFUL
        typedef unsigned long XXH32_hash_t;
#     else
#       error "unsupported platform: need a 32-bit type"
#     endif
#   endif
#endif

/*!
 * @}
 *
 * @defgroup xxh32_family XXH32 family
 * @ingroup public
 * Contains functions used in the classic 32-bit xxHash algorithm.
 *
 * @note
 *   XXH32 is considered rather weak by today's standards.
 *   The @ref xxh3_family provides competitive speed for both 32-bit and 64-bit
 *   systems, and offers true 64/128 bit hash results. It provides a superior
 *   level of dispersion, and greatly reduces the risks of collisions.
 *
 * @see @ref xxh64_family, @ref xxh3_family : Other xxHash families
 * @see @ref xxh32_impl for implementation details
 * @{
 */

/*!
 * Streaming functions generate the xxHash value from an incremental input.
 * This method is slower than single-call functions, due to state management.
 * For small inputs, prefer `XXH32()` and `XXH64()`, which are better optimized.
 *
 * An XXH state must first be allocated using `XXH*_createState()`.
 *
 * Start a new hash by initializing the state with a seed using `XXH*_reset()`.
 *
 * Then, feed the hash state by calling `XXH*_update()` as many times as necessary.
 *
 * The function returns an error code, with 0 meaning OK, and any other value
 * meaning there is an error.
 *
 * Finally, a hash value can be produced anytime, by using `XXH*_digest()`.
 * This function returns the nn-bits hash as an int or long long.
 *
 * It's still possible to continue inserting input into the hash state after a
 * digest, and generate new hash values later on by invoking `XXH*_digest()`.
 *
 * When done, release the state using `XXH*_freeState()`.
 *
 * Example code for incrementally hashing a file:
 * @code{.c}
 *    #include <stdio.h>
 *    #include <xxhash.h>
 *    #define BUFFER_SIZE 256
 *
 *    // Note: XXH64 and XXH3 use the same interface.
 *    XXH32_hash_t
 *    hashFile(FILE* stream)
 *    {
 *        XXH32_state_t* state;
 *        unsigned char buf[BUFFER_SIZE];
 *        size_t amt;
 *        XXH32_hash_t hash;
 *
 *        state = XXH32_createState();       // Create a state
 *        assert(state != NULL);             // Error check here
 *        XXH32_reset(state, 0xbaad5eed);    // Reset state with our seed
 *        while ((amt = fread(buf, 1, sizeof(buf), stream)) != 0) {
 *            XXH32_update(state, buf, amt); // Hash the file in chunks
 *        }
 *        hash = XXH32_digest(state);        // Finalize the hash
 *        XXH32_freeState(state);            // Clean up
 *        return hash;
 *    }
 * @endcode
 */

/*!
 * @typedef struct XXH32_state_s XXH32_state_t
 * @brief The opaque state struct for the XXH32 streaming API.
 *
 * @see XXH32_state_s for details.
 */
typedef struct XXH32_state_s XXH32_state_t;

/*******   Canonical representation   *******/

/*
 * The default return values from XXH functions are unsigned 32 and 64 bit
 * integers.
 * This the simplest and fastest format for further post-processing.
 *
 * However, this leaves open the question of what is the order on the byte level,
 * since little and big endian conventions will store the same number differently.
 *
 * The canonical representation settles this issue by mandating big-endian
 * convention, the same convention as human-readable numbers (large digits first).
 *
 * When writing hash values to storage, sending them over a network, or printing
 * them, it's highly recommended to use the canonical representation to ensure
 * portability across a wider range of systems, present and future.
 *
 * The following functions allow transformation of hash values to and from
 * canonical format.
 */

/*!
 * @brief Canonical (big endian) representation of @ref XXH32_hash_t.
 */
typedef struct {
    unsigned char digest[4]; /*!< Hash bytes, big endian */
} XXH32_canonical_t;


/*!
 * @}
 * @ingroup public
 * @{
 */

/*-**********************************************************************
*  64-bit hash
************************************************************************/
#include <stdint.h>
typedef uint64_t XXH64_hash_t;

/*!
 * @}
 *
 * @defgroup xxh64_family XXH64 family
 * @ingroup public
 * @{
 * Contains functions used in the classic 64-bit xxHash algorithm.
 *
 * @note
 *   XXH3 provides competitive speed for both 32-bit and 64-bit systems,
 *   and offers true 64/128 bit hash results. It provides a superior level of
 *   dispersion, and greatly reduces the risks of collisions.
 */


/*!
 * @brief Calculates the 64-bit hash of @p input using xxHash64.
 *
 * This function usually runs faster on 64-bit systems, but slower on 32-bit
 * systems (see benchmark).
 *
 * @param input The block of data to be hashed, at least @p length bytes in size.
 * @param length The length of @p input, in bytes.
 * @param seed The 64-bit seed to alter the hash's output predictably.
 *
 * @pre
 *   The memory between @p input and @p input + @p length must be valid,
 *   readable, contiguous memory. However, if @p length is `0`, @p input may be
 *   `NULL`. In C++, this also must be *TriviallyCopyable*.
 *
 * @return The calculated 64-bit hash.
 *
 * @see
 *    XXH32(), XXH3_64bits_withSeed(), XXH3_128bits_withSeed(), XXH128():
 *    Direct equivalents for the other variants of xxHash.
 * @see
 *    XXH64_createState(), XXH64_update(), XXH64_digest(): Streaming version.
 */
XXH64_hash_t XXH64(const void* input, size_t length, XXH64_hash_t seed);

/*******   Streaming   *******/
/*!
 * @brief The opaque state struct for the XXH64 streaming API.
 *
 * @see XXH64_state_s for details.
 */
typedef struct XXH64_state_s XXH64_state_t;   /* incomplete type */
XXH64_state_t* XXH64_createState(void);
XXH_errorcode  XXH64_freeState(XXH64_state_t* statePtr);
void XXH64_copyState(XXH64_state_t* dst_state, const XXH64_state_t* src_state);

XXH_errorcode XXH64_reset  (XXH64_state_t* statePtr, XXH64_hash_t seed);
XXH_errorcode XXH64_update (XXH64_state_t* statePtr, const void* input, size_t length);
XXH64_hash_t  XXH64_digest (const XXH64_state_t* statePtr);

/*******   Canonical representation   *******/
typedef struct { unsigned char digest[sizeof(XXH64_hash_t)]; } XXH64_canonical_t;
void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash);
XXH64_hash_t XXH64_hashFromCanonical(const XXH64_canonical_t* src);

/*!
 * @}
 * ************************************************************************
 * @defgroup xxh3_family XXH3 family
 * @ingroup public
 * @{
 *
 * XXH3 is a more recent hash algorithm featuring:
 *  - Improved speed for both small and large inputs
 *  - True 64-bit and 128-bit outputs
 *  - SIMD acceleration
 *  - Improved 32-bit viability
 *
 * Speed analysis methodology is explained here:
 *
 *    https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html
 *
 * Compared to XXH64, expect XXH3 to run approximately
 * ~2x faster on large inputs and >3x faster on small ones,
 * exact differences vary depending on platform.
 *
 * XXH3's speed benefits greatly from SIMD and 64-bit arithmetic,
 * but does not require it.
 * Any 32-bit and 64-bit targets that can run XXH32 smoothly
 * can run XXH3 at competitive speeds, even without vector support.
 * Further details are explained in the implementation.
 *
 * Optimized implementations are provided for AVX512, AVX2, SSE2, NEON, POWER8,
 * ZVector and scalar targets. This can be controlled via the XXH_VECTOR macro.
 *
 * XXH3 implementation is portable:
 * it has a generic C90 formulation that can be compiled on any platform,
 * all implementations generage exactly the same hash value on all platforms.
 * Starting from v0.8.0, it's also labelled "stable", meaning that
 * any future version will also generate the same hash value.
 *
 * XXH3 offers 2 variants, _64bits and _128bits.
 *
 * When only 64 bits are needed, prefer invoking the _64bits variant, as it
 * reduces the amount of mixing, resulting in faster speed on small inputs.
 * It's also generally simpler to manipulate a scalar return type than a struct.
 *
 * The API supports one-shot hashing, streaming mode, and custom secrets.
 */

/*-**********************************************************************
*  XXH3 64-bit variant
************************************************************************/

/* XXH3_64bits():
 * default 64-bit variant, using default secret and default seed of 0.
 * It's the fastest variant. */
XXH64_hash_t XXH3_64bits(const void* data, size_t len);

/*
 * XXH3_64bits_withSeed():
 * This variant generates a custom secret on the fly
 * based on default secret altered using the `seed` value.
 * While this operation is decently fast, note that it's not completely free.
 * Note: seed==0 produces the same results as XXH3_64bits().
 */
XXH64_hash_t XXH3_64bits_withSeed(const void* data, size_t len, XXH64_hash_t seed);

/*!
 * The bare minimum size for a custom secret.
 *
 * @see
 *  XXH3_64bits_withSecret(), XXH3_64bits_reset_withSecret(),
 *  XXH3_128bits_withSecret(), XXH3_128bits_reset_withSecret().
 */
#define XXH3_SECRET_SIZE_MIN 136

/*
 * XXH3_64bits_withSecret():
 * It's possible to provide any blob of bytes as a "secret" to generate the hash.
 * This makes it more difficult for an external actor to prepare an intentional collision.
 * The main condition is that secretSize *must* be large enough (>= XXH3_SECRET_SIZE_MIN).
 * However, the quality of produced hash values depends on secret's entropy.
 * Technically, the secret must look like a bunch of random bytes.
 * Avoid "trivial" or structured data such as repeated sequences or a text document.
 * Whenever unsure about the "randomness" of the blob of bytes,
 * consider relabelling it as a "custom seed" instead,
 * and employ "XXH3_generateSecret()" (see below)
 * to generate a high entropy secret derived from the custom seed.
 */
XXH64_hash_t XXH3_64bits_withSecret(const void* data, size_t len, const void* secret, size_t secretSize);


/*******   Streaming   *******/
/*
 * Streaming requires state maintenance.
 * This operation costs memory and CPU.
 * As a consequence, streaming is slower than one-shot hashing.
 * For better performance, prefer one-shot functions whenever applicable.
 */

/*!
 * @brief The state struct for the XXH3 streaming API.
 *
 * @see XXH3_state_s for details.
 */
typedef struct XXH3_state_s XXH3_state_t;
XXH3_state_t* XXH3_createState(void);
XXH_errorcode XXH3_freeState(XXH3_state_t* statePtr);
void XXH3_copyState(XXH3_state_t* dst_state, const XXH3_state_t* src_state);

/*
 * XXH3_64bits_reset():
 * Initialize with default parameters.
 * digest will be equivalent to `XXH3_64bits()`.
 */
XXH_errorcode XXH3_64bits_reset(XXH3_state_t* statePtr);
/*
 * XXH3_64bits_reset_withSeed():
 * Generate a custom secret from `seed`, and store it into `statePtr`.
 * digest will be equivalent to `XXH3_64bits_withSeed()`.
 */
XXH_errorcode XXH3_64bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed);
/*
 * XXH3_64bits_reset_withSecret():
 * `secret` is referenced, it _must outlive_ the hash streaming session.
 * Similar to one-shot API, `secretSize` must be >= `XXH3_SECRET_SIZE_MIN`,
 * and the quality of produced hash values depends on secret's entropy
 * (secret's content should look like a bunch of random bytes).
 * When in doubt about the randomness of a candidate `secret`,
 * consider employing `XXH3_generateSecret()` instead (see below).
 */
XXH_errorcode XXH3_64bits_reset_withSecret(XXH3_state_t* statePtr, const void* secret, size_t secretSize);

/* note : canonical representation of XXH3 is the same as XXH64
 * since they both produce XXH64_hash_t values */


/*-**********************************************************************
*  XXH3 128-bit variant
************************************************************************/

/*!
 * @brief The return value from 128-bit hashes.
 *
 * Stored in little endian order, although the fields themselves are in native
 * endianness.
 */
typedef struct {
    XXH64_hash_t low64;   /*!< `value & 0xFFFFFFFFFFFFFFFF` */
    XXH64_hash_t high64;  /*!< `value >> 64` */
} XXH128_hash_t;



#define XXHASH_H_STATIC_13879238742
/* ****************************************************************************
 * This section contains declarations which are not guaranteed to remain stable.
 * They may change in future versions, becoming incompatible with a different
 * version of the library.
 * These declarations should only be used with static linking.
 * Never use them in association with dynamic linking!
 ***************************************************************************** */

/*
 * These definitions are only present to allow static allocation
 * of XXH states, on stack or in a struct, for example.
 * Never **ever** access their members directly.
 */

/*!
 * @internal
 * @brief Structure for XXH32 streaming API.
 *
 * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
 * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
 * an opaque type. This allows fields to safely be changed.
 *
 * Typedef'd to @ref XXH32_state_t.
 * Do not access the members of this struct directly.
 * @see XXH64_state_s, XXH3_state_s
 */
struct XXH32_state_s {
   XXH32_hash_t total_len_32; /*!< Total length hashed, modulo 2^32 */
   XXH32_hash_t large_len;    /*!< Whether the hash is >= 16 (handles @ref total_len_32 overflow) */
   XXH32_hash_t v1;           /*!< First accumulator lane */
   XXH32_hash_t v2;           /*!< Second accumulator lane */
   XXH32_hash_t v3;           /*!< Third accumulator lane */
   XXH32_hash_t v4;           /*!< Fourth accumulator lane */
   XXH32_hash_t mem32[4];     /*!< Internal buffer for partial reads. Treated as unsigned char[16]. */
   XXH32_hash_t memsize;      /*!< Amount of data in @ref mem32 */
   XXH32_hash_t reserved;     /*!< Reserved field. Do not read or write to it, it may be removed. */
};   /* typedef'd to XXH32_state_t */


/*!
 * @internal
 * @brief Structure for XXH64 streaming API.
 *
 * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
 * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
 * an opaque type. This allows fields to safely be changed.
 *
 * Typedef'd to @ref XXH64_state_t.
 * Do not access the members of this struct directly.
 * @see XXH32_state_s, XXH3_state_s
 */
struct XXH64_state_s {
   XXH64_hash_t total_len;    /*!< Total length hashed. This is always 64-bit. */
   XXH64_hash_t v1;           /*!< First accumulator lane */
   XXH64_hash_t v2;           /*!< Second accumulator lane */
   XXH64_hash_t v3;           /*!< Third accumulator lane */
   XXH64_hash_t v4;           /*!< Fourth accumulator lane */
   XXH64_hash_t mem64[4];     /*!< Internal buffer for partial reads. Treated as unsigned char[32]. */
   XXH32_hash_t memsize;      /*!< Amount of data in @ref mem64 */
   XXH32_hash_t reserved32;   /*!< Reserved field, needed for padding anyways*/
   XXH64_hash_t reserved64;   /*!< Reserved field. Do not read or write to it, it may be removed. */
};   /* typedef'd to XXH64_state_t */

#if defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)   /* C11+ */
#  include <stdalign.h>
#  define XXH_ALIGN(n)      alignas(n)
#elif defined(__GNUC__)
#  define XXH_ALIGN(n)      __attribute__ ((aligned(n)))
#elif defined(_MSC_VER)
#  define XXH_ALIGN(n)      __declspec(align(n))
#else
#  define XXH_ALIGN(n)   /* disabled */
#endif

/* Old GCC versions only accept the attribute after the type in structures. */
#if !(defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L))   /* C11+ */ \
    && defined(__GNUC__)
#   define XXH_ALIGN_MEMBER(align, type) type XXH_ALIGN(align)
#else
#   define XXH_ALIGN_MEMBER(align, type) XXH_ALIGN(align) type
#endif

/*!
 * @brief The size of the internal XXH3 buffer.
 *
 * This is the optimal update size for incremental hashing.
 *
 * @see XXH3_64b_update(), XXH3_128b_update().
 */
#define XXH3_INTERNALBUFFER_SIZE 256

/*!
 * @brief Default size of the secret buffer (and @ref XXH3_kSecret).
 *
 * This is the size used in @ref XXH3_kSecret and the seeded functions.
 *
 * Not to be confused with @ref XXH3_SECRET_SIZE_MIN.
 */
#define XXH3_SECRET_DEFAULT_SIZE 192

/*!
 * @internal
 * @brief Structure for XXH3 streaming API.
 *
 * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
 * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
 * an opaque type. This allows fields to safely be changed.
 *
 * @note **This structure has a strict alignment requirement of 64 bytes.** Do
 * not allocate this with `malloc()` or `new`, it will not be sufficiently
 * aligned. Use @ref XXH3_createState() and @ref XXH3_freeState(), or stack
 * allocation.
 *
 * Typedef'd to @ref XXH3_state_t.
 * Do not access the members of this struct directly.
 *
 * @see XXH3_INITSTATE() for stack initialization.
 * @see XXH3_createState(), XXH3_freeState().
 * @see XXH32_state_s, XXH64_state_s
 */
struct XXH3_state_s {
   XXH_ALIGN_MEMBER(64, XXH64_hash_t acc[8]);
       /*!< The 8 accumulators. Similar to `vN` in @ref XXH32_state_s::v1 and @ref XXH64_state_s */
   XXH_ALIGN_MEMBER(64, unsigned char customSecret[XXH3_SECRET_DEFAULT_SIZE]);
       /*!< Used to store a custom secret generated from a seed. */
   XXH_ALIGN_MEMBER(64, unsigned char buffer[XXH3_INTERNALBUFFER_SIZE]);
       /*!< The internal buffer. @see XXH32_state_s::mem32 */
   XXH32_hash_t bufferedSize;
       /*!< The amount of memory in @ref buffer, @see XXH32_state_s::memsize */
   XXH32_hash_t reserved32;
       /*!< Reserved field. Needed for padding on 64-bit. */
   size_t nbStripesSoFar;
       /*!< Number or stripes processed. */
   XXH64_hash_t totalLen;
       /*!< Total length hashed. 64-bit even on 32-bit targets. */
   size_t nbStripesPerBlock;
       /*!< Number of stripes per block. */
   size_t secretLimit;
       /*!< Size of @ref customSecret or @ref extSecret */
   XXH64_hash_t seed;
       /*!< Seed for _withSeed variants. Must be zero otherwise, @see XXH3_INITSTATE() */
   XXH64_hash_t reserved64;
       /*!< Reserved field. */
   const unsigned char* extSecret;
       /*!< Reference to an external secret for the _withSecret variants, NULL
        *   for other variants. */
   /* note: there may be some padding at the end due to alignment on 64 bytes */
}; /* typedef'd to XXH3_state_t */

#undef XXH_ALIGN_MEMBER

/*!
 * @brief Initializes a stack-allocated `XXH3_state_s`.
 *
 * When the @ref XXH3_state_t structure is merely emplaced on stack,
 * it should be initialized with XXH3_INITSTATE() or a memset()
 * in case its first reset uses XXH3_NNbits_reset_withSeed().
 * This init can be omitted if the first reset uses default or _withSecret mode.
 * This operation isn't necessary when the state is created with XXH3_createState().
 * Note that this doesn't prepare the state for a streaming operation,
 * it's still necessary to use XXH3_NNbits_reset*() afterwards.
 */
#define XXH3_INITSTATE(XXH3_state_ptr)   { (XXH3_state_ptr)->seed = 0; }


/* simple short-cut to pre-selected XXH3_128bits variant */
XXH128_hash_t XXH128(const void* data, size_t len, XXH64_hash_t seed);


/* ======================================================================== */
/* ======================================================================== */
/* ======================================================================== */


/*-**********************************************************************
 * xxHash implementation
 *-**********************************************************************
 * xxHash's implementation used to be hosted inside xxhash.c.
 *
 * However, inlining requires implementation to be visible to the compiler,
 * hence be included alongside the header.
 * Previously, implementation was hosted inside xxhash.c,
 * which was then #included when inlining was activated.
 * This construction created issues with a few build and install systems,
 * as it required xxhash.c to be stored in /include directory.
 *
 * xxHash implementation is now directly integrated within xxhash.h.
 * As a consequence, xxhash.c is no longer needed in /include.
 *
 * xxhash.c is still available and is still useful.
 * In a "normal" setup, when xxhash is not inlined,
 * xxhash.h only exposes the prototypes and public symbols,
 * while xxhash.c can be built into an object file xxhash.o
 * which can then be linked into the final binary.
 ************************************************************************/

/*!
 * @}
 */

#define XXH_FORCE_MEMORY_ACCESS 1

#ifndef XXH_ACCEPT_NULL_INPUT_POINTER   /* can be defined externally */
#  define XXH_ACCEPT_NULL_INPUT_POINTER 0
#endif

#ifndef XXH_FORCE_ALIGN_CHECK  /* can be defined externally */
#  if defined(__i386)  || defined(__x86_64__) || defined(__aarch64__) \
   || defined(_M_IX86) || defined(_M_X64)     || defined(_M_ARM64) /* visual */
#    define XXH_FORCE_ALIGN_CHECK 0
#  else
#    define XXH_FORCE_ALIGN_CHECK 1
#  endif
#endif

#ifndef XXH_NO_INLINE_HINTS
#  if defined(__OPTIMIZE_SIZE__) /* -Os, -Oz */ \
   || defined(__NO_INLINE__)     /* -O0, -fno-inline */
#    define XXH_NO_INLINE_HINTS 1
#  else
#    define XXH_NO_INLINE_HINTS 0
#  endif
#endif

#ifndef XXH_REROLL
#  if defined(__OPTIMIZE_SIZE__)
#    define XXH_REROLL 1
#  else
#    define XXH_REROLL 0
#  endif
#endif

/*!
 * @defgroup impl Implementation
 * @{
 */


/* *************************************
*  Compiler Specific Options
***************************************/
#if XXH_NO_INLINE_HINTS  /* disable inlining hints */
#  if defined(__GNUC__)
#    define XXH_FORCE_INLINE static __attribute__((unused))
#  else
#    define XXH_FORCE_INLINE static
#  endif
#  define XXH_NO_INLINE static
/* enable inlining hints */
#elif defined(_MSC_VER)  /* Visual Studio */
#  define XXH_FORCE_INLINE static __forceinline
#  define XXH_NO_INLINE static __declspec(noinline)
#elif defined(__GNUC__)
#  define XXH_FORCE_INLINE static __inline__ __attribute__((always_inline, unused))
#  define XXH_NO_INLINE static __attribute__((noinline))
#elif defined (__cplusplus) \
  || (defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L))   /* C99 */
#  define XXH_FORCE_INLINE static inline
#  define XXH_NO_INLINE static
#else
#  define XXH_FORCE_INLINE static
#  define XXH_NO_INLINE static
#endif



/* *************************************
*  Debug
***************************************/
/*!
 * @ingroup tuning
 * @def XXH_DEBUGLEVEL
 * @brief Sets the debugging level.
 *
 * XXH_DEBUGLEVEL is expected to be defined externally, typically via the
 * compiler's command line options. The value must be a number.
 */
#ifndef XXH_DEBUGLEVEL
#  ifdef DEBUGLEVEL /* backwards compat */
#    define XXH_DEBUGLEVEL DEBUGLEVEL
#  else
#    define XXH_DEBUGLEVEL 0
#  endif
#endif

#if (XXH_DEBUGLEVEL>=1)
#  include <assert.h>   /* note: can still be disabled with NDEBUG */
#  define XXH_ASSERT(c)   assert(c)
#else
#  define XXH_ASSERT(c)   ((void)0)
#endif

/* note: use after variable declarations */
#define XXH_STATIC_ASSERT(c)  do { enum { XXH_sa = 1/(int)(!!(c)) }; } while (0)


/* *************************************
*  Basic Types
***************************************/
#if !defined (__VMS) \
 && (defined (__cplusplus) \
 || (defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) /* C99 */) )
# include <stdint.h>
  typedef uint8_t xxh_u8;
#else
  typedef unsigned char xxh_u8;
#endif
typedef XXH32_hash_t xxh_u32;

/* ***   Memory access   *** */

/*!
 * @internal
 * @fn xxh_u32 XXH_read32(const void* ptr)
 * @brief Reads an unaligned 32-bit integer from @p ptr in native endianness.
 *
 * Affected by @ref XXH_FORCE_MEMORY_ACCESS.
 *
 * @param ptr The pointer to read from.
 * @return The 32-bit native endian integer from the bytes at @p ptr.
 */

/*!
 * @internal
 * @fn xxh_u32 XXH_readLE32(const void* ptr)
 * @brief Reads an unaligned 32-bit little endian integer from @p ptr.
 *
 * Affected by @ref XXH_FORCE_MEMORY_ACCESS.
 *
 * @param ptr The pointer to read from.
 * @return The 32-bit little endian integer from the bytes at @p ptr.
 */

/*!
 * @internal
 * @fn xxh_u32 XXH_readBE32(const void* ptr)
 * @brief Reads an unaligned 32-bit big endian integer from @p ptr.
 *
 * Affected by @ref XXH_FORCE_MEMORY_ACCESS.
 *
 * @param ptr The pointer to read from.
 * @return The 32-bit big endian integer from the bytes at @p ptr.
 */

/*!
 * @internal
 * @fn xxh_u32 XXH_readLE32_align(const void* ptr, XXH_alignment align)
 * @brief Like @ref XXH_readLE32(), but has an option for aligned reads.
 *
 * Affected by @ref XXH_FORCE_MEMORY_ACCESS.
 * Note that when @ref XXH_FORCE_ALIGN_CHECK == 0, the @p align parameter is
 * always @ref XXH_alignment::XXH_unaligned.
 *
 * @param ptr The pointer to read from.
 * @param align Whether @p ptr is aligned.
 * @pre
 *   If @p align == @ref XXH_alignment::XXH_aligned, @p ptr must be 4 byte
 *   aligned.
 * @return The 32-bit little endian integer from the bytes at @p ptr.
 */

#if (defined(XXH_FORCE_MEMORY_ACCESS) && (XXH_FORCE_MEMORY_ACCESS==1))

/*
 * __pack instructions are safer but compiler specific, hence potentially
 * problematic for some compilers.
 *
 * Currently only defined for GCC and ICC.
 */
static xxh_u32 XXH_read32(const void* ptr)
{
    typedef union { xxh_u32 u32; } __attribute__((packed)) xxh_unalign;
    return ((const xxh_unalign*)ptr)->u32;
}

#else

/*
 * Portable and safe solution. Generally efficient.
 * see: https://stackoverflow.com/a/32095106/646947
 */
static xxh_u32 XXH_read32(const void* memPtr)
{
    xxh_u32 val;
    memcpy(&val, memPtr, sizeof(val));
    return val;
}

#endif   /* XXH_FORCE_DIRECT_MEMORY_ACCESS */


/* ***   Endianness   *** */
typedef enum { XXH_bigEndian=0, XXH_littleEndian=1 } XXH_endianess;

/*!
 * @ingroup tuning
 * @def XXH_CPU_LITTLE_ENDIAN
 * @brief Whether the target is little endian.
 *
 * Defined to 1 if the target is little endian, or 0 if it is big endian.
 * It can be defined externally, for example on the compiler command line.
 *
 * If it is not defined, a runtime check (which is usually constant folded)
 * is used instead.
 *
 * @note
 *   This is not necessarily defined to an integer constant.
 *
 * @see XXH_isLittleEndian() for the runtime check.
 */
#ifndef XXH_CPU_LITTLE_ENDIAN
/*
 * Try to detect endianness automatically, to avoid the nonstandard behavior
 * in `XXH_isLittleEndian()`
 */
#  if defined(_WIN32) /* Windows is always little endian */ \
     || defined(__LITTLE_ENDIAN__) \
     || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#    define XXH_CPU_LITTLE_ENDIAN 1
#  elif defined(__BIG_ENDIAN__) \
     || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#    define XXH_CPU_LITTLE_ENDIAN 0
#  else
/*!
 * @internal
 * @brief Runtime check for @ref XXH_CPU_LITTLE_ENDIAN.
 *
 * Most compilers will constant fold this.
 */
static int XXH_isLittleEndian(void)
{
    /*
     * Portable and well-defined behavior.
     * Don't use static: it is detrimental to performance.
     */
    const union { xxh_u32 u; xxh_u8 c[4]; } one = { 1 };
    return one.c[0];
}
#   define XXH_CPU_LITTLE_ENDIAN   XXH_isLittleEndian()
#  endif
#endif




/* ****************************************
*  Compiler-specific Functions and Macros
******************************************/
#define XXH_GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)

#ifdef __has_builtin
#  define XXH_HAS_BUILTIN(x) __has_builtin(x)
#else
#  define XXH_HAS_BUILTIN(x) 0
#endif

/*!
 * @internal
 * @def XXH_rotl32(x,r)
 * @brief 32-bit rotate left.
 *
 * @param x The 32-bit integer to be rotated.
 * @param r The number of bits to rotate.
 * @pre
 *   @p r > 0 && @p r < 32
 * @note
 *   @p x and @p r may be evaluated multiple times.
 * @return The rotated result.
 */
#if !defined(NO_CLANG_BUILTIN) && XXH_HAS_BUILTIN(__builtin_rotateleft32) \
                               && XXH_HAS_BUILTIN(__builtin_rotateleft64)
#  define XXH_rotl32 __builtin_rotateleft32
#  define XXH_rotl64 __builtin_rotateleft64
/* Note: although _rotl exists for minGW (GCC under windows), performance seems poor */
#elif defined(_MSC_VER)
#  define XXH_rotl32(x,r) _rotl(x,r)
#  define XXH_rotl64(x,r) _rotl64(x,r)
#else
#  define XXH_rotl32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#  define XXH_rotl64(x,r) (((x) << (r)) | ((x) >> (64 - (r))))
#endif

/*!
 * @internal
 * @fn xxh_u32 XXH_swap32(xxh_u32 x)
 * @brief A 32-bit byteswap.
 *
 * @param x The 32-bit integer to byteswap.
 * @return @p x, byteswapped.
 */
#if defined(_MSC_VER)     /* Visual Studio */
#  define XXH_swap32 _byteswap_ulong
#elif XXH_GCC_VERSION >= 403
#  define XXH_swap32 __builtin_bswap32
#else
static xxh_u32 XXH_swap32 (xxh_u32 x)
{
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff );
}
#endif


/* ***************************
*  Memory reads
*****************************/

/*!
 * @internal
 * @brief Enum to indicate whether a pointer is aligned.
 */
typedef enum {
    XXH_aligned,  /*!< Aligned */
    XXH_unaligned /*!< Possibly unaligned */
} XXH_alignment;

XXH_FORCE_INLINE xxh_u32 XXH_readLE32(const void* ptr)
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_read32(ptr) : XXH_swap32(XXH_read32(ptr));
}

XXH_FORCE_INLINE xxh_u32
XXH_readLE32_align(const void* ptr, XXH_alignment align)
{
    if (align==XXH_unaligned) {
        return XXH_readLE32(ptr);
    } else {
        return XXH_CPU_LITTLE_ENDIAN ? *(const xxh_u32*)ptr : XXH_swap32(*(const xxh_u32*)ptr);
    }
}



/* *******************************************************************
*  64-bit hash functions
*********************************************************************/
/*!
 * @}
 * @ingroup impl
 * @{
 */
/*******   Memory access   *******/

typedef XXH64_hash_t xxh_u64;

/*
 * __pack instructions are safer, but compiler specific, hence potentially
 * problematic for some compilers.
 *
 * Currently only defined for GCC and ICC.
 */
static xxh_u64 XXH_read64(const void* ptr)
{
    typedef union { xxh_u32 u32; xxh_u64 u64; } __attribute__((packed)) xxh_unalign64;
    return ((const xxh_unalign64*)ptr)->u64;
}


XXH_FORCE_INLINE xxh_u64 XXH_readLE64(const void* ptr)
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_read64(ptr) : __builtin_bswap64(XXH_read64(ptr));
}

XXH_FORCE_INLINE xxh_u64
XXH_readLE64_align(const void* ptr, XXH_alignment align)
{
    if (align==XXH_unaligned)
        return XXH_readLE64(ptr);
    else
        return XXH_CPU_LITTLE_ENDIAN ? *(const xxh_u64*)ptr : __builtin_bswap64(*(const xxh_u64*)ptr);
}


/*******   xxh64   *******/
/*!
 * @}
 * @defgroup xxh64_impl XXH64 implementation
 * @ingroup impl
 * @{
 */
/* #define rather that static const, to be used as initializers */
#define XXH_PRIME64_1  0x9E3779B185EBCA87ULL  /*!< 0b1001111000110111011110011011000110000101111010111100101010000111 */
#define XXH_PRIME64_2  0xC2B2AE3D27D4EB4FULL  /*!< 0b1100001010110010101011100011110100100111110101001110101101001111 */
#define XXH_PRIME64_3  0x165667B19E3779F9ULL  /*!< 0b0001011001010110011001111011000110011110001101110111100111111001 */
#define XXH_PRIME64_4  0x85EBCA77C2B2AE63ULL  /*!< 0b1000010111101011110010100111011111000010101100101010111001100011 */
#define XXH_PRIME64_5  0x27D4EB2F165667C5ULL  /*!< 0b0010011111010100111010110010111100010110010101100110011111000101 */

static xxh_u64 XXH64_round(xxh_u64 acc, xxh_u64 input)
{
    acc += input * XXH_PRIME64_2;
    acc  = XXH_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static xxh_u64 XXH64_mergeRound(xxh_u64 acc, xxh_u64 val)
{
    val  = XXH64_round(0, val);
    acc ^= val;
    acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static xxh_u64 XXH64_avalanche(xxh_u64 h64)
{
    h64 ^= h64 >> 33;
    h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}


#define XXH_get64bits(p) XXH_readLE64_align(p, align)

static xxh_u64
XXH64_finalize(xxh_u64 h64, const xxh_u8* ptr, size_t len, XXH_alignment align)
{
#define XXH_PROCESS1_64 do {                                   \
    h64 ^= (*ptr++) * XXH_PRIME64_5;                           \
    h64 = XXH_rotl64(h64, 11) * XXH_PRIME64_1;                 \
} while (0)

#define XXH_PROCESS4_64 do {                                   \
    h64 ^= (xxh_u64)(XXH_readLE32_align(ptr, align)) * XXH_PRIME64_1;      \
    ptr += 4;                                              \
    h64 = XXH_rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;     \
} while (0)

#define XXH_PROCESS8_64 do {                                   \
    xxh_u64 const k1 = XXH64_round(0, XXH_get64bits(ptr)); \
    ptr += 8;                                              \
    h64 ^= k1;                                             \
    h64  = XXH_rotl64(h64,27) * XXH_PRIME64_1 + XXH_PRIME64_4;     \
} while (0)

    /* Rerolled version for 32-bit targets is faster and much smaller. */
    if (XXH_REROLL) {
        len &= 31;
        while (len >= 8) {
            XXH_PROCESS8_64;
            len -= 8;
        }
        if (len >= 4) {
            XXH_PROCESS4_64;
            len -= 4;
        }
        while (len > 0) {
            XXH_PROCESS1_64;
            --len;
        }
         return  XXH64_avalanche(h64);
    } else {
        switch(len & 31) {
           case 24: XXH_PROCESS8_64;
                         /* fallthrough */
           case 16: XXH_PROCESS8_64;
                         /* fallthrough */
           case  8: XXH_PROCESS8_64;
                    return XXH64_avalanche(h64);

           case 28: XXH_PROCESS8_64;
                         /* fallthrough */
           case 20: XXH_PROCESS8_64;
                         /* fallthrough */
           case 12: XXH_PROCESS8_64;
                         /* fallthrough */
           case  4: XXH_PROCESS4_64;
                    return XXH64_avalanche(h64);

           case 25: XXH_PROCESS8_64;
                         /* fallthrough */
           case 17: XXH_PROCESS8_64;
                         /* fallthrough */
           case  9: XXH_PROCESS8_64;
                    XXH_PROCESS1_64;
                    return XXH64_avalanche(h64);

           case 29: XXH_PROCESS8_64;
                         /* fallthrough */
           case 21: XXH_PROCESS8_64;
                         /* fallthrough */
           case 13: XXH_PROCESS8_64;
                         /* fallthrough */
           case  5: XXH_PROCESS4_64;
                    XXH_PROCESS1_64;
                    return XXH64_avalanche(h64);

           case 26: XXH_PROCESS8_64;
                         /* fallthrough */
           case 18: XXH_PROCESS8_64;
                         /* fallthrough */
           case 10: XXH_PROCESS8_64;
                    XXH_PROCESS1_64;
                    XXH_PROCESS1_64;
                    return XXH64_avalanche(h64);

           case 30: XXH_PROCESS8_64;
                         /* fallthrough */
           case 22: XXH_PROCESS8_64;
                         /* fallthrough */
           case 14: XXH_PROCESS8_64;
                         /* fallthrough */
           case  6: XXH_PROCESS4_64;
                    XXH_PROCESS1_64;
                    XXH_PROCESS1_64;
                    return XXH64_avalanche(h64);

           case 27: XXH_PROCESS8_64;
                         /* fallthrough */
           case 19: XXH_PROCESS8_64;
                         /* fallthrough */
           case 11: XXH_PROCESS8_64;
                    XXH_PROCESS1_64;
                    XXH_PROCESS1_64;
                    XXH_PROCESS1_64;
                    return XXH64_avalanche(h64);

           case 31: XXH_PROCESS8_64;
                         /* fallthrough */
           case 23: XXH_PROCESS8_64;
                         /* fallthrough */
           case 15: XXH_PROCESS8_64;
                         /* fallthrough */
           case  7: XXH_PROCESS4_64;
                         /* fallthrough */
           case  3: XXH_PROCESS1_64;
                         /* fallthrough */
           case  2: XXH_PROCESS1_64;
                         /* fallthrough */
           case  1: XXH_PROCESS1_64;
                         /* fallthrough */
           case  0: return XXH64_avalanche(h64);
        }
    }
    /* impossible to reach */
    XXH_ASSERT(0);
    return 0;  /* unreachable, but some compilers complain without it */
}

#undef XXH_PROCESS1_64
#undef XXH_PROCESS4_64
#undef XXH_PROCESS8_64

XXH_FORCE_INLINE xxh_u64
XXH64_endian_align(const xxh_u8* input, size_t len, xxh_u64 seed, XXH_alignment align)
{
    const xxh_u8* bEnd = input + len;
    xxh_u64 h64;

#if defined(XXH_ACCEPT_NULL_INPUT_POINTER) && (XXH_ACCEPT_NULL_INPUT_POINTER>=1)
    if (input==NULL) {
        len=0;
        bEnd=input=(const xxh_u8*)(size_t)32;
    }
#endif

    if (len>=32) {
        const xxh_u8* const limit = bEnd - 32;
        xxh_u64 v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        xxh_u64 v2 = seed + XXH_PRIME64_2;
        xxh_u64 v3 = seed + 0;
        xxh_u64 v4 = seed - XXH_PRIME64_1;

        do {
            v1 = XXH64_round(v1, XXH_get64bits(input)); input+=8;
            v2 = XXH64_round(v2, XXH_get64bits(input)); input+=8;
            v3 = XXH64_round(v3, XXH_get64bits(input)); input+=8;
            v4 = XXH64_round(v4, XXH_get64bits(input)); input+=8;
        } while (input<=limit);

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4);

    } else {
        h64  = seed + XXH_PRIME64_5;
    }

    h64 += (xxh_u64) len;

    return XXH64_finalize(h64, input, len, align);
}


/*! @ingroup xxh64_family */
XXH64_hash_t XXH64 (const void* input, size_t len, XXH64_hash_t seed)
{
    if (XXH_FORCE_ALIGN_CHECK) {
        if ((((size_t)input) & 7)==0) {  /* Input is aligned, let's leverage the speed advantage */
            return XXH64_endian_align((const xxh_u8*)input, len, seed, XXH_aligned);
    }   }

    return XXH64_endian_align((const xxh_u8*)input, len, seed, XXH_unaligned);
}


#if defined (__cplusplus)
}
#endif

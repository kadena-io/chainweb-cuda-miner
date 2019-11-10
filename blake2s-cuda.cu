// -*- c++ -*-

#define NATIVE_LITTLE_ENDIAN 1

#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <getopt.h>
#include <thread>
#include <vector>

#include "kadena-mine.hpp"
#include "optional.hpp"

namespace kadena {
namespace crypto {
namespace mining {
namespace cuda {

#define BLAKE2_INLINE inline

enum blake2s_constant
{
  BLAKE2S_BLOCKBYTES = 64,
  BLAKE2S_OUTBYTES   = 32,
  BLAKE2S_KEYBYTES   = 32,
  BLAKE2S_SALTBYTES  = 8,
  BLAKE2S_PERSONALBYTES = 8
};

//------------------------------------------------------------------------------
// kadena code

__device__
inline void memcpy__(void* dest0, const void* src0, uint32_t len) {
  const unsigned char* src = (const unsigned char*) src0;
  unsigned char* dest = (unsigned char*) dest0;

  while (len--) {
    *dest++ = *src++;
  }
}

__device__
inline void
memset__(void* buffer0, int c, size_t len) {
  char* buffer = (char*) buffer0;
  const char* end = buffer + len;
  for (char* p = buffer; p != end; ++p) {
    *p = c;
  }
}

__device__
inline void
secure_zero_memory(void* buffer0, size_t len) {
  return memset__(buffer0, 0, len);
}

// divide state into buffers puts contexts, so we can fit contexts into __shared__
typedef struct blake2s_context_gpu__
{
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
} blake2s_gpu_context;

typedef struct blake2s_buffer_gpu__
{
  uint8_t  buf[BLAKE2S_BLOCKBYTES];
  uint32_t   buflen;
  uint32_t   outlen;
  uint64_t  last_node;   // 8 bits in original code but we need to make it word
                         // sized for padding.
} blake2s_gpu_buffer;

//------------------------------------------------------------------------------


/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef BLAKE2_IMPL_H
#define BLAKE2_IMPL_H

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define BLAKE2_INLINE __inline
  #elif defined(__GNUC__)
    #define BLAKE2_INLINE __inline__
  #else
    #define BLAKE2_INLINE
  #endif
#else
  #define BLAKE2_INLINE inline
#endif

__device__
static BLAKE2_INLINE uint32_t load32_( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint32_t w;
  memcpy__(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = ( const uint8_t * )src;
  return (( uint32_t )( p[0] ) <<  0) |
         (( uint32_t )( p[1] ) <<  8) |
         (( uint32_t )( p[2] ) << 16) |
         (( uint32_t )( p[3] ) << 24) ;
#endif
}

__device__
static BLAKE2_INLINE void store16( void *dst, uint16_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy__(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w;
#endif
}

__device__
static BLAKE2_INLINE void store32( void *dst, uint32_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy__(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  p[0] = (uint8_t)(w >>  0);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

__device__
static BLAKE2_INLINE uint32_t rotr32( const uint32_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 32 - c ) );
}

#endif

//------------------------------------------------------------------------------

/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef BLAKE2_H
#define BLAKE2_H

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

enum blake2b_constant
{
  BLAKE2B_BLOCKBYTES = 128,
  BLAKE2B_OUTBYTES   = 64,
  BLAKE2B_KEYBYTES   = 64,
  BLAKE2B_SALTBYTES  = 16,
  BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2s_state__
{
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t  buf[BLAKE2S_BLOCKBYTES];
  size_t   buflen;
  size_t   outlen;
  uint8_t  last_node;
} blake2s_state;

typedef struct blake2b_state__
{
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t  buf[BLAKE2B_BLOCKBYTES];
  size_t   buflen;
  size_t   outlen;
  uint8_t  last_node;
} blake2b_state;

typedef struct blake2sp_state__
{
  blake2s_state S[8][1];
  blake2s_state R[1];
  uint8_t       buf[8 * BLAKE2S_BLOCKBYTES];
  size_t        buflen;
  size_t        outlen;
} blake2sp_state;

typedef struct blake2bp_state__
{
  blake2b_state S[4][1];
  blake2b_state R[1];
  uint8_t       buf[4 * BLAKE2B_BLOCKBYTES];
  size_t        buflen;
  size_t        outlen;
} blake2bp_state;


BLAKE2_PACKED(struct blake2s_param__
              {
                uint8_t  digest_length; /* 1 */
                uint8_t  key_length;    /* 2 */
                uint8_t  fanout;        /* 3 */
                uint8_t  depth;         /* 4 */
                uint32_t leaf_length;   /* 8 */
                uint32_t node_offset;  /* 12 */
                uint16_t xof_length;    /* 14 */
                uint8_t  node_depth;    /* 15 */
                uint8_t  inner_length;  /* 16 */
                /* uint8_t  reserved[0]; */
                uint8_t  salt[BLAKE2S_SALTBYTES]; /* 24 */
                uint8_t  personal[BLAKE2S_PERSONALBYTES];  /* 32 */
});

typedef struct blake2s_param__ blake2s_param;

BLAKE2_PACKED(struct blake2b_param__
              {
                uint8_t  digest_length; /* 1 */
                uint8_t  key_length;    /* 2 */
                uint8_t  fanout;        /* 3 */
                uint8_t  depth;         /* 4 */
                uint32_t leaf_length;   /* 8 */
                uint32_t node_offset;   /* 12 */
                uint32_t xof_length;    /* 16 */
                uint8_t  node_depth;    /* 17 */
                uint8_t  inner_length;  /* 18 */
                uint8_t  reserved[14];  /* 32 */
                uint8_t  salt[BLAKE2B_SALTBYTES]; /* 48 */
                uint8_t  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
});

typedef struct blake2b_param__ blake2b_param;

typedef struct blake2xs_state__
{
  blake2s_state S[1];
  blake2s_param P[1];
} blake2xs_state;

typedef struct blake2xb_state__
{
  blake2b_state S[1];
  blake2b_param P[1];
} blake2xb_state;

/* Padded structs result in a compile-time error */
enum {
  BLAKE2_DUMMY_1 = 1/(sizeof(blake2s_param) == BLAKE2S_OUTBYTES),
  BLAKE2_DUMMY_2 = 1/(sizeof(blake2b_param) == BLAKE2B_OUTBYTES)
};

#endif


//------------------------------------------------------------------------------
/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

static __constant__ const uint32_t blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static __constant__ const uint8_t blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

__device__
static void blake2s_set_lastnode( blake2s_gpu_context *S )
{
  S->f[1] = (uint32_t)-1;
}

/* Some helper functions, not necessarily useful */
__device__
static int blake2s_is_lastblock( const blake2s_gpu_context *S )
{
  return S->f[0] != 0;
}

__device__
static void blake2s_set_lastblock( blake2s_gpu_context* S,
                                   blake2s_gpu_buffer *B )
{
  if( B->last_node ) blake2s_set_lastnode( S );
  S->f[0] = (uint32_t)-1;
}

__device__
static void blake2s_increment_counter( blake2s_gpu_context *S, const uint32_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

__device__
static void blake2s_init0( blake2s_gpu_context *S, blake2s_gpu_buffer* B )
{
  secure_zero_memory(S, sizeof(blake2s_gpu_context));
  secure_zero_memory(B, sizeof(blake2s_gpu_buffer));
  for(size_t i = 0; i < 8; ++i ) S->h[i] = blake2s_IV[i];
}

/* init2 xors IV with input parameter block */
__device__
int blake2s_init_param( blake2s_gpu_context *S, blake2s_gpu_buffer* B, const blake2s_param *P )
{
  const unsigned char *p = ( const unsigned char * )( P );
  size_t i;

  blake2s_init0( S, B );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
    S->h[i] ^= load32_( &p[i * 4] );

  B->outlen = P->digest_length;
  return 0;
}


/* Sequential blake2s initialization */
__device__
int blake2s_init( blake2s_gpu_context *S, blake2s_gpu_buffer* B, size_t outlen )
{
  blake2s_param P[1];

  /* Move interval verification here? */
  if ( ( !outlen ) || ( outlen > BLAKE2S_OUTBYTES ) ) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store32( &P->node_offset, 0 );
  store16( &P->xof_length, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2s_init_param( S, B, P );
}

__device__
int blake2s_update( blake2s_gpu_context *S, blake2s_gpu_buffer* B,
                    const void *pin, size_t inlen );

#define G(r,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[blake2s_sigma[r][2*i+0]]; \
    d = rotr32(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr32(b ^ c, 12);                  \
    a = a + b + m[blake2s_sigma[r][2*i+1]]; \
    d = rotr32(d ^ a, 8);                   \
    c = c + d;                              \
    b = rotr32(b ^ c, 7);                   \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

#define COMPRESS(S, in, cst)                            \
  do {                                                  \
    uint32_t m[16];                                     \
    uint32_t v[16];                                     \
    size_t i;                                           \
                                                        \
    for( i = 0; i < 16; ++i ) {                         \
      m[i] = load32 ## cst( in + i * sizeof( m[i] ) );  \
    }                                                   \
                                                        \
    for( i = 0; i < 8; ++i ) {                          \
      v[i] = S->h[i];                                   \
    }                                                   \
                                                        \
    v[ 8] = blake2s_IV[0];                              \
    v[ 9] = blake2s_IV[1];                              \
    v[10] = blake2s_IV[2];                              \
    v[11] = blake2s_IV[3];                              \
    v[12] = S->t[0] ^ blake2s_IV[4];                    \
    v[13] = S->t[1] ^ blake2s_IV[5];                    \
    v[14] = S->f[0] ^ blake2s_IV[6];                    \
    v[15] = S->f[1] ^ blake2s_IV[7];                    \
                                                        \
    ROUND( 0 );                                         \
    ROUND( 1 );                                         \
    ROUND( 2 );                                         \
    ROUND( 3 );                                         \
    ROUND( 4 );                                         \
    ROUND( 5 );                                         \
    ROUND( 6 );                                         \
    ROUND( 7 );                                         \
    ROUND( 8 );                                         \
    ROUND( 9 );                                         \
                                                        \
    for( i = 0; i < 8; ++i ) {                          \
      S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];              \
    }                                                   \
  } while(0)
__device__
static void blake2s_compress_( blake2s_gpu_context *S, const uint8_t* in)
{
  COMPRESS(S, in, _);
}

#undef G
#undef ROUND
#undef COMPRESS

#define UPD(S, B, in, inlen, cst_)                                     \
  if( inlen > 0 )                                                      \
  {                                                                    \
    size_t left = B->buflen;                                           \
    size_t fill = BLAKE2S_BLOCKBYTES - left;                           \
    if( inlen > fill )                                                 \
    {                                                                  \
      B->buflen = 0;                                                   \
      memcpy_ ## cst_( B->buf + left, in, fill ); /* Fill buffer */    \
      blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );              \
      blake2s_compress_( S, B->buf ); /* Compress */                   \
      in += fill; inlen -= fill;                                       \
      while(inlen > BLAKE2S_BLOCKBYTES) {                              \
        blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);              \
        blake2s_compress ## cst_( S, in );                             \
        in += BLAKE2S_BLOCKBYTES;                                      \
        inlen -= BLAKE2S_BLOCKBYTES;                                   \
      }                                                                \
    }                                                                  \
    memcpy_ ## cst_( B->buf + B->buflen, in, inlen );                  \
    B->buflen += inlen;                                                \
  }

__device__
int blake2s_update( blake2s_gpu_context *S, blake2s_gpu_buffer* B,
                    const void *pin, size_t inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  UPD(S, B, in, inlen, _);
  return 0;
}

#undef UPD

__device__
int blake2s_final( blake2s_gpu_context *S, blake2s_gpu_buffer* B,
                   void *out, size_t outlen )
{
  uint8_t buffer[BLAKE2S_OUTBYTES] = {0};
  size_t i;

  if( out == NULL || outlen < B->outlen )
    return -1;

  if( blake2s_is_lastblock( S ) )
    return -1;

  blake2s_increment_counter( S, ( uint32_t )B->buflen );
  blake2s_set_lastblock( S, B );
  memset( B->buf + B->buflen, 0, BLAKE2S_BLOCKBYTES - B->buflen ); /* Padding */
  blake2s_compress_( S, B->buf );

  for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
    store32( buffer + sizeof( S->h[i] ) * i, S->h[i] );

  memcpy__( out, buffer, outlen );
  secure_zero_memory(buffer, sizeof(buffer));
  return 0;
}

//------------------------------------------------------------------------------
// kadena code
// kernel to test correctness of hash algo

__device__
void blake2s_one(const uint8_t* in, const size_t n,
                 uint8_t* out,
                 blake2s_gpu_context* ctx,
                 blake2s_gpu_buffer* buffer) {
  (void) blake2s_init(ctx, buffer, BLAKE2S_OUTBYTES);
  blake2s_update(ctx, buffer, in, n);
  blake2s_final(ctx, buffer, out, BLAKE2S_OUTBYTES);
}

__device__ void blake2s_kernel(
    const uint8_t* inputs,
    size_t* input_offsets,
    uint8_t* result_hashes,

    // these buffers have blockDim.x entries
    blake2s_gpu_context* contexts,
    blake2s_gpu_buffer* buffers) {
  const size_t local_id = threadIdx.x;
  const size_t global_id = blockIdx.x * blockDim.x + threadIdx.x;
  const size_t input_sz = input_offsets[global_id + 1] - input_offsets[global_id];

  blake2s_gpu_buffer* buffer = &buffers[local_id];
  blake2s_gpu_context* ctx = &contexts[local_id];
  uint8_t* hash_out = result_hashes + (BLAKE2S_OUTBYTES * global_id);
  const uint8_t* in = &inputs[input_offsets[global_id]];
  blake2s_one(in, input_sz, hash_out, ctx, buffer);
}

static constexpr size_t INPUT_MAX = 1UL << 14;
__constant__ uint8_t g_target_hash[BLAKE2S_OUTBYTES];
__constant__ uint8_t g_input[INPUT_MAX];

// numbers stored little-endian, so compare from the end
__device__
inline bool lex_compare(uint8_t* hash0) {
  uint8_t* h = hash0 + BLAKE2S_OUTBYTES;
  const uint8_t* t = g_target_hash + BLAKE2S_OUTBYTES;
  bool ok = true;
  while (h != hash0) {
    --h; --t;
    ok &= (*h <= *t);
    if (*h != *t) break;
  }
  return ok;
}


__device__
inline uint8_t BLAKE2s_one_mine(const size_t n,
                                const uint64_t nonce,
                                blake2s_gpu_context* ctx,
                                blake2s_gpu_buffer* buffer) {
  uint8_t hash_out[BLAKE2S_OUTBYTES];
  (void) blake2s_init(ctx, buffer, BLAKE2S_OUTBYTES);
  {
    union {
      uint64_t as_val;
      uint8_t as_chars[sizeof(uint64_t)];
    } nonce_buf;
    nonce_buf.as_val = nonce;
    blake2s_update(ctx, buffer, nonce_buf.as_chars, sizeof(uint64_t));
  }
  size_t n_rest = n >= sizeof(uint64_t) ? n - sizeof(uint64_t) : 0;
  if (n_rest > 0) {
    blake2s_update(ctx, buffer, g_input + 8, n_rest);
  }
  blake2s_final(ctx, buffer, hash_out, BLAKE2S_OUTBYTES);
  return lex_compare(hash_out);
}

__global__ void BLAKE2s_mine(
    /* input length in bytes */
    const size_t input_length,

    /* starting nonce for the block */
    const uint64_t nonce_start,

    /* two words: is_found + nonce */
    uint64_t* results_buf,
    int num_nonces) {
  extern __shared__ uint8_t shared_bufs[];
  __shared__ uint8_t found;

  blake2s_gpu_context* contexts = (blake2s_gpu_context*) shared_bufs;
  blake2s_gpu_buffer* buffers;
  {
    blake2s_gpu_context* end_contexts = contexts + blockDim.x;
    buffers = (blake2s_gpu_buffer*) end_contexts;
  }

  const size_t local_id = threadIdx.x;
  if (local_id == 0) {
    found = 0;
  }

  __syncthreads();

  blake2s_gpu_buffer* buffer = &buffers[local_id];
  blake2s_gpu_context* ctx = &contexts[local_id];
  for (uint64_t global_id = blockDim.x * blockIdx.x + local_id;
       global_id < num_nonces;
       global_id += gridDim.x * blockDim.x) {
    if (found) {
      return;
    } else {
      bool ok = BLAKE2s_one_mine(
        input_length, nonce_start + global_id, ctx, buffer);
      if (ok) {
        results_buf[0] = 1;
        results_buf[1] = nonce_start + global_id;
        found = 1;
        return;
      }
    }
  }
}

namespace {
struct options {
  enum class mode { IMMEDIATE, CLIENT, SERVER };
  mode mode = mode::IMMEDIATE;
  // N.B. we use abstract namespace unix domain sockets, which are a big
  // improvement over the fs-based ones
  std::string unix_socket_namespace = "chainweb-gpu-miner0";
  std::string target_hash;
  nonstd::optional<uint64_t> starting_nonce;
  int local_workgroup_size = 380;
  int global_workgroup_size = 200000000UL;
  uint64_t starting_device = 0;
  uint64_t num_devices = 0;

  void fill_defaults() {
    auto r = []() -> uint32_t {
               return static_cast<uint32_t>(mrand48());
             };
    if (!starting_nonce) {
      const uint64_t nonce_a = r();
      const uint64_t nonce_b = r();
      const uint64_t nonce = (nonce_a << 32) | nonce_b;
      starting_nonce.emplace(nonce);
    }
  }
};

void usage(char** argv) {
  std::cout << "Usage: " << argv[0] << " {target_hash}\n" << R"raw(
Mine a block using blake2s. The block bytes will be accepted on stdin, with
the first eight bytes of the block left unspecified (the "nonce"). The miner
will search for a nonce that will make the total block hash (evaluated as a
little-endian 256-bit integer) lower than the target_hash.

The target hash may also be passed via environment variable as TARGET_HASH.
Note that {target_hash} is ignored in --server mode: the target hash is passed
to a server over the socket.

Upon success, the miner will output the nonce to stdout as a hexified string.

Options:

  --help                 print this message
  --starting-nonce k     start nonce search at (decimal integer).
  --local-wg-size k      size of local work group (default 380)
  --global-wg-size k     size of global work group (default 200000000)
  --starting-device i    start at device i
  --num-devices n        operate on n devices
  --server               start in server mode (see --unix-domain-ns)
  --client               start in client mode
  --unix-domain-ns ns    use unix domain namespace 'ns' for client/server mode

)raw";
  exit(1);
}

options parse_options(int argc, char** argv) {
  options out;
  {
    const char* env = getenv("TARGET_HASH");
    if (env != nullptr) out.target_hash = env;
  }
  int c = 0;

  while (true) {
    int option_index = 0;
    static struct option long_options[] = {
      {"help",            no_argument,       0,  0 },
      {"starting-nonce",  required_argument, 0,  0 },
      {"local-wg-size",   required_argument, 0,  0 },
      {"global-wg-size",  required_argument, 0,  0 },
      {"starting-device", required_argument, 0,  0 },
      {"num-devices",     required_argument, 0,  0 },
      {"client",          no_argument,       0,  0 },
      {"server",          no_argument,       0,  0 },
      {"unix-domain-ns",  required_argument, 0,  0 },
      {0,                 0,                 0,  0 }
    };

    c = getopt_long(argc, argv, "", long_options, &option_index);
    if (c == -1) break;

    switch (c) {
    case 0:
      switch (option_index) {
      case 0: usage(argv); break;
      case 1:
        out.starting_nonce.emplace(parse_nonce(optarg));
        break;
      case 2:
        out.local_workgroup_size = atoi(optarg);
        break;
      case 3:
        out.global_workgroup_size = atoi(optarg);
        break;
      case 4:
        out.starting_device = atoi(optarg);
        break;
      case 5:
        out.num_devices = atoi(optarg);
        break;
      case 6:
        out.mode = options::mode::CLIENT;
        break;
      case 7:
        out.mode = options::mode::SERVER;
        break;
      case 8:
        out.unix_socket_namespace = optarg;
        break;
      default:  // impossible
        break;
      }
      break;

    default:
      break;
    }
  }

  if (optind == argc - 1) {
    out.target_hash = argv[optind];
  }

  out.fill_defaults();
  std::string s = hex_decode(out.target_hash);
  out.target_hash = std::move(s);
  return out;
}

static constexpr int NSTREAMS = 3;
struct mining_buffers {
  std::array<uint8_t*, NSTREAMS> results_bufs = {};
  std::array<uint8_t*, NSTREAMS> results_host_bufs = {};
  std::array<cudaStream_t, NSTREAMS> stream;
  std::array<nonstd::optional<uint64_t>, NSTREAMS> active;
  int which = 0;

  mining_buffers() {
    for (int i = 0; i < NSTREAMS; ++i) {
      cudaStreamCreate(&stream[i]);
    }
  }
  mining_buffers(const mining_buffers&) = delete;
  mining_buffers(mining_buffers&& o) {
    results_bufs = std::move(o.results_bufs);
    results_host_bufs = std::move(o.results_host_bufs);
    stream = std::move(o.stream);
    o.clear();
  }

  void flip() {
    int n = next();
    which = n;
  }

  int next() {
    return (which + 1) % NSTREAMS;
  }

  uint8_t* buf(int i) { return results_bufs[i]; }
  uint8_t* host_buf(int i) { return results_host_bufs[i]; }

  mining_buffers& operator=(const mining_buffers&) = delete;
  mining_buffers& operator=(mining_buffers&& o) = delete;

  ~mining_buffers() {
    free_and_clear();
  }

private:
  void free_and_clear() {
    for (auto* p : results_bufs) if (p) cudaFree(p);
    for (auto* p : results_host_bufs) if (p) cudaFreeHost(p);
    for (auto s : stream) if (s) cudaStreamDestroy(s);
    clear();
  }

  void clear() {
    for (auto& s : stream) s = nullptr;
    for (auto& p : results_bufs) p = nullptr;
    for (auto& p : results_host_bufs) p = nullptr;
  }
};

mining_buffers
alloc_buffers(const std::string& input,
              const std::string& target_hash) {
  mining_buffers out;
  if (input.size() > INPUT_MAX) {
    throw std::runtime_error("input too large");
  }
  cudaMemcpyToSymbol(g_target_hash, target_hash.data(), target_hash.size());
  cudaMemcpyToSymbol(g_input, input.data(), input.size());
  for (int i = 0; i < NSTREAMS; ++i) {
    cudaMallocHost(&out.results_host_bufs[i], 2 * sizeof(uint64_t));
    cudaMalloc(&out.results_bufs[i], 2 * sizeof(uint64_t));
  }
  return out;
}

std::mutex g_mutex;

void
cpu_thread(const options& options,
           const std::string& target_hash,
           const std::string& blockbytes,
           mining_synchronization& sync,
           int device_number) {
  auto fail_with_msg =
    [&](const std::string& msg) {
      std::lock_guard<std::mutex> l(g_mutex);
      DBG() << "GPU " << device_number
            << ": got exception (exiting): "
            << msg
            << "\n";
      sync.terminate_cancelled();
    };
  try {
    {
      std::lock_guard<std::mutex> l(g_mutex);
      DBG() << "GPU "
            << device_number
            << ": starting mining\n";
    }
    cudaSetDevice(device_number);

    mining_buffers buffers = alloc_buffers(
      blockbytes,
      target_hash);
    uint64_t group_size = options.local_workgroup_size;
    uint64_t num_per_thread = 256;

    const dim3 grid(
      (options.global_workgroup_size +
       (num_per_thread*group_size)-1)/(num_per_thread*group_size));
    const dim3 block(group_size);

    while (!sync.finished()) {
      buffers.flip();             // flip double buffer
      uint64_t nonce_start = sync.next_nonce();
      buffers.active[buffers.which] = nonce_start;
      cudaMemsetAsync(buffers.buf(buffers.which),
                      0,
                      2 * sizeof(uint64_t),
                      buffers.stream[buffers.which]);
      auto cuda_err = cudaGetLastError();
      if (cuda_err) {
        throw std::runtime_error(cudaGetErrorString(cuda_err));
      }
      BLAKE2s_mine<<<
        grid, block,
          sizeof(blake2s_gpu_context)*group_size +
          sizeof(blake2s_gpu_buffer)*group_size,
          buffers.stream[buffers.which]
          >>>(
            blockbytes.size(),
            nonce_start,
            reinterpret_cast<uint64_t*>(buffers.buf(buffers.which)),
            options.global_workgroup_size);
      cuda_err = cudaGetLastError();
      if (cuda_err) {
        throw std::runtime_error(cudaGetErrorString(cuda_err));
      }
      cudaMemcpyAsync(buffers.host_buf(buffers.which),
                      buffers.buf(buffers.which),
                      2 * sizeof(uint64_t),
                      cudaMemcpyDeviceToHost,
                      buffers.stream[buffers.which]);
      int next = buffers.next();
      if (buffers.active[next]) {
        // wait on previously enqueued work
        cudaStreamSynchronize(buffers.stream[next]);
        uint64_t* buf = reinterpret_cast<uint64_t*>(buffers.host_buf(next));
        uint64_t found = buf[0];
        if (found) {
          std::lock_guard<std::mutex> l(g_mutex);
          DBG() << "GPU " << device_number
                << ": found winning nonce "
                << std::hex
                << buf[1]
                << "\n";
          // sync device before we tear down state.
          cudaDeviceSynchronize();
          sync.terminate_success(buf[1]);
          return;
        } else {
          std::lock_guard<std::mutex> l(g_mutex);
          DBG() << "GPU " << device_number
                << ": no matching nonces starting at "
                << nonce_to_string(*buffers.active[next])
                << "\n";
        }
        buffers.active[next] = {};
      }
    }
  } catch (const std::exception& e) {
    fail_with_msg(e.what());
  } catch (...) {
    fail_with_msg("unknown exception");
  }
}
}   // namespace
}   // namespace cuda
}   // namespace mining
}   // namespace crypto
}   // namespace kadena


int
main(int argc, char** argv) {
  try {
    using namespace kadena::crypto;
    using namespace kadena::crypto::mining;
    using namespace kadena::crypto::mining::cuda;
    srand48_seeder seed;
    options options = parse_options(argc, argv);
    if (options.mode == options::mode::SERVER ||
        options.mode == options::mode::IMMEDIATE) {
      set_debug_timestamps(false);
      int num_devices = 0;
      (void) cudaGetDeviceCount(&num_devices);
      DBG() << "Cuda reports " << num_devices << " devices.\n";
      if (options.num_devices != 0) {
        num_devices = std::min(
          num_devices - options.starting_device,
          options.num_devices);
      }

      if (num_devices == 0) {
        throw std::runtime_error("No devices found.");
      }
      options.num_devices = num_devices;

      DBG() << "Running " << num_devices << " devices, starting at "
            << options.starting_device << "\n";
    }

    if (options.mode == options::mode::IMMEDIATE) {
      run_immediate_mode(argc, argv, options, &usage, &cpu_thread);
    } else if (options.mode == options::mode::SERVER) {
      run_server_mode(options, &cpu_thread);
    } else {
      run_client_mode(argc, argv, options, &usage, &cpu_thread);
    }
  } catch (const std::exception& err) {
    std::cerr << "Caught exception at top level: "
              << err.what()
              << "\n";
    exit(1);
  }
  return 0;
}

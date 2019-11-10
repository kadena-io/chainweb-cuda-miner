#define NATIVE_LITTLE_ENDIAN 1
#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <ctime>
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
namespace cpu {
namespace {

// here follows blake2s reference code
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
#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

  enum blake2s_constant
  {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

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

  /* Streaming API */
  int blake2s_init( blake2s_state *S, size_t outlen );
  int blake2s_init_key( blake2s_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2s_init_param( blake2s_state *S, const blake2s_param *P );
  int blake2s_update( blake2s_state *S, const void *in, size_t inlen );
  int blake2s_final( blake2s_state *S, void *out, size_t outlen );

  int blake2b_init( blake2b_state *S, size_t outlen );
  int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2b_init_param( blake2b_state *S, const blake2b_param *P );
  int blake2b_update( blake2b_state *S, const void *in, size_t inlen );
  int blake2b_final( blake2b_state *S, void *out, size_t outlen );

  int blake2sp_init( blake2sp_state *S, size_t outlen );
  int blake2sp_init_key( blake2sp_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2sp_update( blake2sp_state *S, const void *in, size_t inlen );
  int blake2sp_final( blake2sp_state *S, void *out, size_t outlen );

  int blake2bp_init( blake2bp_state *S, size_t outlen );
  int blake2bp_init_key( blake2bp_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2bp_update( blake2bp_state *S, const void *in, size_t inlen );
  int blake2bp_final( blake2bp_state *S, void *out, size_t outlen );

  /* Variable output length API */
  int blake2xs_init( blake2xs_state *S, const size_t outlen );
  int blake2xs_init_key( blake2xs_state *S, const size_t outlen, const void *key, size_t keylen );
  int blake2xs_update( blake2xs_state *S, const void *in, size_t inlen );
  int blake2xs_final(blake2xs_state *S, void *out, size_t outlen);

  int blake2xb_init( blake2xb_state *S, const size_t outlen );
  int blake2xb_init_key( blake2xb_state *S, const size_t outlen, const void *key, size_t keylen );
  int blake2xb_update( blake2xb_state *S, const void *in, size_t inlen );
  int blake2xb_final(blake2xb_state *S, void *out, size_t outlen);

  /* Simple API */
  int blake2s( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2b( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int blake2sp( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2bp( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int blake2xs( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2xb( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  /* This is simply an alias for blake2b */
  int blake2( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

#if defined(__cplusplus)
}
#endif

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

static BLAKE2_INLINE uint32_t load32( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = ( const uint8_t * )src;
  return (( uint32_t )( p[0] ) <<  0) |
         (( uint32_t )( p[1] ) <<  8) |
         (( uint32_t )( p[2] ) << 16) |
         (( uint32_t )( p[3] ) << 24) ;
#endif
}

static BLAKE2_INLINE uint64_t load64( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = ( const uint8_t * )src;
  return (( uint64_t )( p[0] ) <<  0) |
         (( uint64_t )( p[1] ) <<  8) |
         (( uint64_t )( p[2] ) << 16) |
         (( uint64_t )( p[3] ) << 24) |
         (( uint64_t )( p[4] ) << 32) |
         (( uint64_t )( p[5] ) << 40) |
         (( uint64_t )( p[6] ) << 48) |
         (( uint64_t )( p[7] ) << 56) ;
#endif
}

static BLAKE2_INLINE uint16_t load16( const void *src )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint16_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = ( const uint8_t * )src;
  return ( uint16_t )((( uint32_t )( p[0] ) <<  0) |
                      (( uint32_t )( p[1] ) <<  8));
#endif
}

static BLAKE2_INLINE void store16( void *dst, uint16_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  *p++ = ( uint8_t )w; w >>= 8;
  *p++ = ( uint8_t )w;
#endif
}

static BLAKE2_INLINE void store32( void *dst, uint32_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  p[0] = (uint8_t)(w >>  0);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

static BLAKE2_INLINE void store64( void *dst, uint64_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = ( uint8_t * )dst;
  p[0] = (uint8_t)(w >>  0);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
  p[6] = (uint8_t)(w >> 48);
  p[7] = (uint8_t)(w >> 56);
#endif
}

static BLAKE2_INLINE uint64_t load48( const void *src )
{
  const uint8_t *p = ( const uint8_t * )src;
  return (( uint64_t )( p[0] ) <<  0) |
         (( uint64_t )( p[1] ) <<  8) |
         (( uint64_t )( p[2] ) << 16) |
         (( uint64_t )( p[3] ) << 24) |
         (( uint64_t )( p[4] ) << 32) |
         (( uint64_t )( p[5] ) << 40) ;
}

static BLAKE2_INLINE void store48( void *dst, uint64_t w )
{
  uint8_t *p = ( uint8_t * )dst;
  p[0] = (uint8_t)(w >>  0);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
}

static BLAKE2_INLINE uint32_t rotr32( const uint32_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 32 - c ) );
}

static BLAKE2_INLINE uint64_t rotr64( const uint64_t w, const unsigned c )
{
  return ( w >> c ) | ( w << ( 64 - c ) );
}

/* prevents compiler optimizing out memset() */
static BLAKE2_INLINE void secure_zero_memory(void *v, size_t n)
{
  static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
}

#endif



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

static const uint32_t blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] =
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

static void blake2s_set_lastnode( blake2s_state *S )
{
  S->f[1] = (uint32_t)-1;
}

/* Some helper functions, not necessarily useful */
static int blake2s_is_lastblock( const blake2s_state *S )
{
  return S->f[0] != 0;
}

static void blake2s_set_lastblock( blake2s_state *S )
{
  if( S->last_node ) blake2s_set_lastnode( S );

  S->f[0] = (uint32_t)-1;
}

static void blake2s_increment_counter( blake2s_state *S, const uint32_t inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}

static void blake2s_init0( blake2s_state *S )
{
  size_t i;
  memset( S, 0, sizeof( blake2s_state ) );

  for( i = 0; i < 8; ++i ) S->h[i] = blake2s_IV[i];
}

/* init2 xors IV with input parameter block */
int blake2s_init_param( blake2s_state *S, const blake2s_param *P )
{
  const unsigned char *p = ( const unsigned char * )( P );
  size_t i;

  blake2s_init0( S );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
    S->h[i] ^= load32( &p[i * 4] );

  S->outlen = P->digest_length;
  return 0;
}


/* Sequential blake2s initialization */
int blake2s_init( blake2s_state *S, size_t outlen )
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
  return blake2s_init_param( S, P );
}

int blake2s_init_key( blake2s_state *S, size_t outlen, const void *key, size_t keylen )
{
  blake2s_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2S_OUTBYTES ) ) return -1;

  if ( !key || !keylen || keylen > BLAKE2S_KEYBYTES ) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length    = (uint8_t)keylen;
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

  if( blake2s_init_param( S, P ) < 0 ) return -1;

  {
    uint8_t block[BLAKE2S_BLOCKBYTES];
    memset( block, 0, BLAKE2S_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2s_update( S, block, BLAKE2S_BLOCKBYTES );
    secure_zero_memory( block, BLAKE2S_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

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

static void blake2s_compress( blake2s_state *S, const uint8_t in[BLAKE2S_BLOCKBYTES] )
{
  uint32_t m[16];
  uint32_t v[16];
  size_t i;

  for( i = 0; i < 16; ++i ) {
    m[i] = load32( in + i * sizeof( m[i] ) );
  }

  for( i = 0; i < 8; ++i ) {
    v[i] = S->h[i];
  }

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = S->t[0] ^ blake2s_IV[4];
  v[13] = S->t[1] ^ blake2s_IV[5];
  v[14] = S->f[0] ^ blake2s_IV[6];
  v[15] = S->f[1] ^ blake2s_IV[7];

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );

  for( i = 0; i < 8; ++i ) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND

int blake2s_update( blake2s_state *S, const void *pin, size_t inlen )
{
  const unsigned char * in = (const unsigned char *)pin;
  if( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;
    if( inlen > fill )
    {
      S->buflen = 0;
      memcpy( S->buf + left, in, fill ); /* Fill buffer */
      blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );
      blake2s_compress( S, S->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > BLAKE2S_BLOCKBYTES) {
        blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
        blake2s_compress( S, in );
        in += BLAKE2S_BLOCKBYTES;
        inlen -= BLAKE2S_BLOCKBYTES;
      }
    }
    memcpy( S->buf + S->buflen, in, inlen );
    S->buflen += inlen;
  }
  return 0;
}

int blake2s_final( blake2s_state *S, void *out, size_t outlen )
{
  uint8_t buffer[BLAKE2S_OUTBYTES] = {0};
  size_t i;

  if( out == NULL || outlen < S->outlen )
    return -1;

  if( blake2s_is_lastblock( S ) )
    return -1;

  blake2s_increment_counter( S, ( uint32_t )S->buflen );
  blake2s_set_lastblock( S );
  memset( S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen ); /* Padding */
  blake2s_compress( S, S->buf );

  for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
    store32( buffer + sizeof( S->h[i] ) * i, S->h[i] );

  memcpy( out, buffer, outlen );
  secure_zero_memory(buffer, sizeof(buffer));
  return 0;
}

int blake2s( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen )
{
  blake2s_state S[1];

  /* Verify parameters */
  if ( NULL == in && inlen > 0 ) return -1;

  if ( NULL == out ) return -1;

  if ( NULL == key && keylen > 0) return -1;

  if( !outlen || outlen > BLAKE2S_OUTBYTES ) return -1;

  if( keylen > BLAKE2S_KEYBYTES ) return -1;

  if( keylen > 0 )
  {
    if( blake2s_init_key( S, outlen, key, keylen ) < 0 ) return -1;
  }
  else
  {
    if( blake2s_init( S, outlen ) < 0 ) return -1;
  }

  blake2s_update( S, ( const uint8_t * )in, inlen );
  blake2s_final( S, out, outlen );
  return 0;
}

#if defined(SUPERCOP)
int crypto_hash( unsigned char *out, unsigned char *in, unsigned long long inlen )
{
  return blake2s( out, BLAKE2S_OUTBYTES, in, inlen, NULL, 0 );
}
#endif

#if defined(BLAKE2S_SELFTEST)
#include <string.h>
#include "blake2-kat.h"
int main( void )
{
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  size_t i, step;

  for( i = 0; i < BLAKE2S_KEYBYTES; ++i )
    key[i] = ( uint8_t )i;

  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
    buf[i] = ( uint8_t )i;

  /* Test simple API */
  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
  {
    uint8_t hash[BLAKE2S_OUTBYTES];
    blake2s( hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES );

    if( 0 != memcmp( hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API */
  for(step = 1; step < BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2S_OUTBYTES];
      blake2s_state S;
      uint8_t * p = buf;
      size_t mlen = i;
      int err = 0;

      if( (err = blake2s_init_key(&S, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = blake2s_update(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = blake2s_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = blake2s_final(&S, hash, BLAKE2S_OUTBYTES)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        goto fail;
      }
    }
  }

  puts( "ok" );
  return 0;
fail:
  puts("error");
  return -1;
}
#endif

//------------------------------------------------------------------------------
// numbers stored little-endian, so compare from the end
inline bool lex_compare(uint8_t* target0, uint8_t* hash0) {
  uint8_t* h = hash0 + BLAKE2S_OUTBYTES;
  const uint8_t* t = target0 + BLAKE2S_OUTBYTES;
  bool ok = true;
  while (h != hash0) {
    --h; --t;
    ok &= (*h <= *t);
    if (*h != *t) break;
  }
  return ok;
}

bool
BLAKE2s_one_mine(const std::string& target, const std::string& input, const uint64_t nonce) {
  blake2s_state state;
  uint8_t hash_out[BLAKE2S_OUTBYTES];
  (void) blake2s_init(&state, BLAKE2S_OUTBYTES);
  {
    union {
      uint64_t as_val;
      uint8_t as_chars[sizeof(uint64_t)];
    } nonce_buf;
    nonce_buf.as_val = nonce;
    blake2s_update(&state, nonce_buf.as_chars, sizeof(uint64_t));
  }
  const size_t n = input.size();
  size_t n_rest = n >= sizeof(uint64_t) ? n - sizeof(uint64_t) : 0;
  if (n_rest > 0) {
    blake2s_update(&state, input.data() + 8, n_rest);
  }
  blake2s_final(&state, hash_out, BLAKE2S_OUTBYTES);
  return lex_compare((uint8_t*)target.data(), hash_out);
}

nonstd::optional<uint64_t>
BLAKE2s_mine(const std::string& target,
             const std::string& input,
             const uint64_t nonce_start,
             int num_nonces) {
  nonstd::optional<uint64_t> out;
  for (uint64_t nonce = nonce_start; num_nonces > 0; ++nonce, --num_nonces) {
    bool ok = BLAKE2s_one_mine(target, input, nonce);
    if (ok) {
      out.emplace(nonce);
      break;
    }
  }
  return out;
}

struct options {
  enum class mode { IMMEDIATE, CLIENT, SERVER };
  std::string target_hash;
  nonstd::optional<uint64_t> starting_nonce;
  uint64_t num_threads = 1;
  uint64_t workgroup_size = 2000000;
  mode mode = mode::IMMEDIATE;
  // N.B. we use abstract namespace unix domain sockets, which are a big
  // improvement over the fs-based ones
  std::string unix_socket_namespace = "kadena-miner";

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

Upon success, the miner will output the nonce to stdout as a hexified string.

Options:

  --help                print this message
  --starting-nonce k    start nonce search at (decimal integer).
  --num-threads n       operate on n threads (default 1)
  --client              unix socket client mode. Input is read on stdin and
                        sent to remote listening server.
  --server              unix socket server mode
  --unix-domain-ns ns   linux unix domain namespace to use (default
                        "kadena-miner")

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
      {"num-threads",     required_argument, 0,  0 },
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
        out.num_threads = atoi(optarg);
        break;
      case 3:
        out.mode = options::mode::CLIENT;
        break;
      case 4:
        out.mode = options::mode::SERVER;
        break;
      case 5:
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

std::mutex g_mutex;

void
cpu_thread(const options& options,
           const std::string& target_hash,
           const std::string& blockbytes,
           mining_synchronization& sync,
           int device_number) {
  {
    std::lock_guard<std::mutex> l(g_mutex);
    DBG() << "CPU thread "
          << device_number
          << ": starting mining\n";
  }

  while (!sync.finished()) {
    uint64_t nonce_start = sync.next_nonce();
    auto out = BLAKE2s_mine(target_hash, blockbytes, nonce_start,
                            options.workgroup_size);
    if (out) {
      sync.terminate_success(*out);
      return;
    } else {
      std::lock_guard<std::mutex> l(g_mutex);
      DBG() << "CPU thread " << device_number
              << ": no matching nonces starting at "
              << nonce_to_string(nonce_start)
              << "\n";
    }
  }
}

void server(const options& options) {
  using namespace kadena::crypto;
  using namespace kadena::crypto::mining;
  using namespace kadena::crypto::mining::cpu;
  mining_synchronization sync;
  DBG() << "Running " << options.num_threads << " threads.\n";
  unix_domain_server server(
    options.unix_socket_namespace,
    0,
    options.num_threads,
    options.workgroup_size,
    [&](const std::string& target_hash, const std::string& blockbytes,
        mining_synchronization& s, int d) {
      cpu_thread(options, target_hash, blockbytes, s, d);
    });
  server.run();
}

void client_mode(int argc, char** argv, const options& options) {
  if (options.target_hash.empty()) {
    DBG() << "Error: must supply target hash. \n\n";
    usage(argv);
  } else {
    DBG() << "Read target hash of "
          << hex_encode_bigendian(options.target_hash)
          << ".\n";
  }
  unix_domain_client client(options.unix_socket_namespace);
  std::string blockbytes = slurp_input(std::cin);
  DBG() << "Read " << blockbytes.size() << " bytes of input.\n";
  if (blockbytes.size() <= 8) {
    throw std::runtime_error("Input too short for mining.");
  }
  auto stats = client.run(options.target_hash, blockbytes, *options.starting_nonce);
  print_out_nonce(stats.winning_nonce, stats.num_nonces,
                  static_cast<uint64_t>(
                    static_cast<double>(stats.num_nonces) / stats.elapsed));
  exit(0);
}

void immediate_mode(int argc, char** argv, const options& options) {
  if (options.target_hash.empty()) {
    DBG() << "Error: must supply target hash. \n\n";
    usage(argv);
  } else {
    DBG() << "Read target hash of " << options.target_hash << ".\n";
  }
  mining_synchronization sync;
  std::string blockbytes = slurp_input(std::cin);
  DBG() << "Read " << blockbytes.size() << " bytes of input.\n";
  if (blockbytes.size() <= 8) {
    throw std::runtime_error("Input too short for mining.");
  }

  sync.set_nonce_skip(options.workgroup_size);
  auto stats = mining_session(
    sync, *options.starting_nonce, 0, options.num_threads,
    [&](mining_synchronization& s, int d) {
      cpu_thread(options, options.target_hash, blockbytes, s, d);
    });
  print_out_nonce(sync.winning_nonce(), stats.num_nonces,
                  static_cast<uint64_t>(
                    static_cast<double>(stats.num_nonces) / stats.elapsed));
  exit(0);
}

}  // namespace

}  // namespace cpu
}  // namespace mining
}  // namespace crypto
}  // namespace kadena

int
main(int argc, char** argv) {
  try {
    using namespace kadena::crypto;
    using namespace kadena::crypto::mining;
    using namespace kadena::crypto::mining::cpu;

    srand48_seeder seed;
    options options = parse_options(argc, argv);
    if (options.mode == options::mode::IMMEDIATE) {
      immediate_mode(argc, argv, options);
    } else if (options.mode == options::mode::SERVER) {
      server(options);
    } else {
      client_mode(argc, argv, options);
    }
  } catch (const std::exception& err) {
    std::cerr << "Caught exception at top level: "
              << err.what()
              << "\n";
    exit(1);
  }
  return 0;
}

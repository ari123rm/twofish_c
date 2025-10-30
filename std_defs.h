/* std_defs.h - Tipos, macros e protótipos auxiliares para twofish.c
 *
 * Versão defensiva: include guard, typedefs, funções inline para rotação,
 * macros seguras para operações de byte-swap e macros multilinha envoltas
 * em do { ... } while(0). Também inclui protótipos que evitam declarações
 * implícitas quando compilando twofish.c.
 */

#ifndef _STD_DEFS_H
#define _STD_DEFS_H

/* Fixed-width integer types */
#include <stdint.h>

/* --- Typedefs --- */
typedef uint8_t   u1byte;   /* 8-bit  */
typedef uint16_t  u2byte;   /* 16-bit */
typedef uint32_t  u4byte;   /* 32-bit */
typedef uint64_t  u8byte;   /* 64-bit */

/* --- byte extraction --- */
/* Extract byte n (0..3) from 32-bit word, little-endian notion */
#ifndef byte
#define byte(x, n) ((u1byte)((((u4byte)(x)) >> (8u * (unsigned)(n))) & 0xFFu))
#endif

/* --- rotate operations --- */
/* Implement as static inline to avoid macro expansion surprises */
#ifndef rotl
static inline u4byte _rotl32(u4byte v, unsigned n) {
    n &= 31u;
    return (u4byte)((v << n) | (v >> (32u - n)));
}
#define rotl(x,n) _rotl32((u4byte)(x),(unsigned)(n))
#endif

#ifndef rotr
static inline u4byte _rotr32(u4byte v, unsigned n) {
    n &= 31u;
    return (u4byte)((v >> n) | (v << (32u - n)));
}
#define rotr(x,n) _rotr32((u4byte)(x),(unsigned)(n))
#endif

/* --- NULL fallback --- */
#ifndef NULL
#define NULL 0
#endif

/* --- Optional byte/word swapping control --- */
/* If you want to enable swaps for a platform, define BLOCK_SWAP before include */
#ifdef BLOCK_SWAP
#  define BYTE_SWAP
#  define WORD_SWAP
#endif

/* io_swap: swap bytes in 32-bit word if BYTE_SWAP defined, else identity */
#ifdef BYTE_SWAP
#define io_swap(x) ( (u4byte)( ((u4byte)(x) << 24) | \
                               (((u4byte)(x) & 0x0000FF00u) << 8) | \
                               (((u4byte)(x) & 0x00FF0000u) >> 8) | \
                               ((u4byte)(x) >> 24) ) )
#else
#define io_swap(x) ((u4byte)(x))
#endif

/* --- get_block / put_block / get_key macros --- */
/* These macros assume caller has variables named in_blk[] and out_blk[] as in twofish.c.
   They are wrapped in do { ... } while(0) so they behave like single statements. */

#ifdef WORD_SWAP

#define get_block(x)                            \
    do {                                        \
        ((u4byte*)(x))[0] = io_swap(in_blk[3]); \
        ((u4byte*)(x))[1] = io_swap(in_blk[2]); \
        ((u4byte*)(x))[2] = io_swap(in_blk[1]); \
        ((u4byte*)(x))[3] = io_swap(in_blk[0]); \
    } while(0)

#define put_block(x)                            \
    do {                                        \
        out_blk[3] = io_swap(((u4byte*)(x))[0]);\
        out_blk[2] = io_swap(((u4byte*)(x))[1]);\
        out_blk[1] = io_swap(((u4byte*)(x))[2]);\
        out_blk[0] = io_swap(((u4byte*)(x))[3]);\
    } while(0)

#define get_key(x,len)                          \
    do {                                        \
        ((u4byte*)(x))[4] = ((u4byte*)(x))[5] = \
        ((u4byte*)(x))[6] = ((u4byte*)(x))[7] = 0; \
        switch((((len) + 63) / 64)) {           \
        case 2:                                 \
            ((u4byte*)(x))[0] = io_swap(in_key[3]); \
            ((u4byte*)(x))[1] = io_swap(in_key[2]); \
            ((u4byte*)(x))[2] = io_swap(in_key[1]); \
            ((u4byte*)(x))[3] = io_swap(in_key[0]); \
            break;                              \
        case 3:                                 \
            ((u4byte*)(x))[0] = io_swap(in_key[5]); \
            ((u4byte*)(x))[1] = io_swap(in_key[4]); \
            ((u4byte*)(x))[2] = io_swap(in_key[3]); \
            ((u4byte*)(x))[3] = io_swap(in_key[2]); \
            ((u4byte*)(x))[4] = io_swap(in_key[1]); \
            ((u4byte*)(x))[5] = io_swap(in_key[0]); \
            break;                              \
        case 4:                                 \
            ((u4byte*)(x))[0] = io_swap(in_key[7]); \
            ((u4byte*)(x))[1] = io_swap(in_key[6]); \
            ((u4byte*)(x))[2] = io_swap(in_key[5]); \
            ((u4byte*)(x))[3] = io_swap(in_key[4]); \
            ((u4byte*)(x))[4] = io_swap(in_key[3]); \
            ((u4byte*)(x))[5] = io_swap(in_key[2]); \
            ((u4byte*)(x))[6] = io_swap(in_key[1]); \
            ((u4byte*)(x))[7] = io_swap(in_key[0]); \
            break;                              \
        }                                       \
    } while(0)

#else /* no WORD_SWAP */

#define get_block(x)                            \
    do {                                        \
        ((u4byte*)(x))[0] = io_swap(in_blk[0]); \
        ((u4byte*)(x))[1] = io_swap(in_blk[1]); \
        ((u4byte*)(x))[2] = io_swap(in_blk[2]); \
        ((u4byte*)(x))[3] = io_swap(in_blk[3]); \
    } while(0)

#define put_block(x)                            \
    do {                                        \
        out_blk[0] = io_swap(((u4byte*)(x))[0]);\
        out_blk[1] = io_swap(((u4byte*)(x))[1]);\
        out_blk[2] = io_swap(((u4byte*)(x))[2]);\
        out_blk[3] = io_swap(((u4byte*)(x))[3]);\
    } while(0)

#define get_key(x,len)                          \
    do {                                        \
        ((u4byte*)(x))[4] = ((u4byte*)(x))[5] = \
        ((u4byte*)(x))[6] = ((u4byte*)(x))[7] = 0; \
        switch((((len) + 63) / 64)) {           \
        case 4:                                 \
            ((u4byte*)(x))[6] = io_swap(in_key[6]); \
            ((u4byte*)(x))[7] = io_swap(in_key[7]); \
            /* fall-through */                  \
        case 3:                                 \
            ((u4byte*)(x))[4] = io_swap(in_key[4]); \
            ((u4byte*)(x))[5] = io_swap(in_key[5]); \
            /* fall-through */                  \
        case 2:                                 \
            ((u4byte*)(x))[0] = io_swap(in_key[0]); \
            ((u4byte*)(x))[1] = io_swap(in_key[1]); \
            ((u4byte*)(x))[2] = io_swap(in_key[2]); \
            ((u4byte*)(x))[3] = io_swap(in_key[3]); \
            break;                              \
        }                                       \
    } while(0)

#endif /* WORD_SWAP */

/* --- Useful prototypes to avoid implicit-declaration errors when compiling twofish.c.
   These declarations are the minimal set referenced earlier in errors; if twofish.c uses
   different signatures, adjust accordingly. */
#ifdef __cplusplus
extern "C" {
#endif

/* core functions in twofish.c (signatures from the original implementation) */
u4byte mds_rem(u4byte p0, u4byte p1);
void gen_mk_tab(u4byte key[]);       /* generator for mk table */
void gen_qtab(void);
void gen_mtab(void);

/* main API (may already exist in twofish.c, but having prototypes here is harmless) */
char **cipher_name(void);
u4byte *set_key(const u4byte in_key[], const u4byte key_len);
void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);

#ifdef __cplusplus
}
#endif

#endif /* _STD_DEFS_H */


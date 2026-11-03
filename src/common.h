#ifndef IPSWARC_COMMON_H
#define IPSWARC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define IPSWARC_MAGIC "IPSWARC1"
#define IPSWARC_VERSION 3
/* hdr.flags bit0: STORE rebuild (v1). bit1: bit-exact ZIP scaffold (v2).
 * bit2: zlib 1.2.8 reflat available (v3). bit3: Info-ZIP 3.0 -6 reflat available. */
#define IPSWARC_FLAG_STORE    0x1u
#define IPSWARC_FLAG_EXACT    0x2u
#define IPSWARC_FLAG_ZLIB128  0x4u
#define IPSWARC_FLAG_INFOZIP6 0x8u

#define SHA256_LEN 32
#define AES_BLOCK 16

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  /* Vista */
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

typedef struct {
    uint8_t dig[SHA256_LEN];
} sha256_t;

static inline void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory (%zu)\n", n);
        exit(1);
    }
    return p;
}

static inline void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fprintf(stderr, "out of memory (%zu)\n", n);
        exit(1);
    }
    return q;
}

static inline char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static inline int sha256_eq(const sha256_t *a, const sha256_t *b) {
    return memcmp(a->dig, b->dig, SHA256_LEN) == 0;
}

void die(const char *fmt, ...);
void warnx(const char *fmt, ...);

int read_file(const char *path, uint8_t **out, size_t *out_len);
int write_file(const char *path, const uint8_t *data, size_t len);
/* 64-bit file size (-1 on error). Uses _ftelli64 on Windows. */
int64_t file_size64(const char *path);
/* Append/copy an on-disk file to an open stream (for multi-GB blobs). */
int stream_copy_path_to_file(FILE *out, const char *path, uint64_t *out_len);
/* Copy exactly `len` bytes from `in` to path. */
int stream_copy_file_to_path(FILE *in, uint64_t len, const char *path);
int hex_decode(const char *hex, uint8_t *out, size_t out_len);
void hex_encode(const uint8_t *in, size_t len, char *out /* 2*len+1 */);

int sha256_buf(const uint8_t *data, size_t len, sha256_t *out);
int sha256_file(const char *path, sha256_t *out);

int aes_cbc_crypt(int encrypt, const uint8_t *key, size_t key_len,
                  const uint8_t *iv, const uint8_t *in, size_t len, uint8_t *out);
int hmac_sha1(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len, uint8_t out[20]);

#endif

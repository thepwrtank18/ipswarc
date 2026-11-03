#ifndef IPSWARC_STORE_H
#define IPSWARC_STORE_H

#include "common.h"

typedef struct {
    sha256_t id;
    uint64_t offset;       /* in blob file */
    uint64_t comp_size;
    uint64_t raw_size;
    uint8_t method;        /* 0=raw 2=LZMA (7-Zip LzmaLib; props+payload) */
} store_obj_t;

/* Optional abstract reader for embedded archives (e.g. 7-Zip IInStream). */
typedef struct store_reader {
    int (*seek)(void *ctx, uint64_t abs_off);           /* SEEK_SET; 0=ok */
    int (*read)(void *ctx, void *buf, size_t len);      /* exact len; 0=ok */
    void *ctx;
} store_reader_t;

typedef struct {
    store_obj_t *objs;
    size_t count;
    size_t cap;
    FILE *blob;            /* append-only data (or parent .ipswarc for embedded) */
    store_reader_t reader; /* if reader.seek != NULL, used instead of blob FILE* */
    uint64_t blob_base;    /* byte offset of blob region inside blob/reader */
    uint64_t blob_end;     /* tracked size; avoid 32-bit ftell on Win64 */
    int blob_owned;        /* fclose blob in store_close when non-zero */
    char blob_path[MAX_PATH];
    char index_path[MAX_PATH];
} objstore_t;

int store_create(objstore_t *s, const char *dir);
int store_open(objstore_t *s, const char *dir);
/* Open against an already-open archive: index in memory, blob at blob_off. */
int store_open_embedded(objstore_t *s, FILE *arc, uint64_t blob_off, uint64_t blob_len,
                        const uint8_t *index_data, size_t index_len);
int store_open_embedded_reader(objstore_t *s, const store_reader_t *reader,
                               uint64_t blob_off, uint64_t blob_len,
                               const uint8_t *index_data, size_t index_len);
void store_close(objstore_t *s);

/* Insert bytes; may LZMA-compress when profitable. Dedups by full-hash. */
int store_put(objstore_t *s, const uint8_t *data, size_t len, sha256_t *out_id);
/* Insert bytes with no compression attempt (for already-compressed / scaffold data). */
int store_put_raw(objstore_t *s, const uint8_t *data, size_t len, sha256_t *out_id);
/* Insert with FastCDC chunking into a chunk-list object; returns list id. */
int store_put_cdc(objstore_t *s, const uint8_t *data, size_t len, sha256_t *out_id);
int store_get(objstore_t *s, const sha256_t *id, uint8_t **out, size_t *out_len);
int store_get_cdc(objstore_t *s, const sha256_t *id, uint8_t **out, size_t *out_len);

int store_has(objstore_t *s, const sha256_t *id);
int store_flush_index(objstore_t *s);

#endif

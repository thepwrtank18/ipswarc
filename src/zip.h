#ifndef IPSWARC_ZIP_H
#define IPSWARC_ZIP_H

#include "common.h"

typedef struct {
    char *name;
    uint16_t method;         /* original method (0 or 8) */
    uint32_t crc32;
    uint32_t comp_size;      /* original compressed size */
    uint32_t uncomp_size;
    uint16_t gp_flag;
    uint16_t mod_time;
    uint16_t mod_date;
    uint16_t ver_extract;
    uint16_t ver_made;
    uint16_t internal_attr;
    uint32_t external_attr;
    uint32_t local_header_off;
    uint64_t payload_file_off;

    uint8_t *local_header;
    size_t local_header_len;

    /* Original compressed payload bytes (ZIP storage). Owned. */
    uint8_t *comp;
    size_t comp_len;

    /* Uncompressed entry bytes (inflated if method 8). Owned. */
    uint8_t *payload;
    size_t payload_len;

    uint8_t *data_desc;
    size_t data_desc_len;
    uint8_t *cd_header;
    size_t cd_header_len;
} zip_entry_t;

typedef struct {
    zip_entry_t *entries;
    size_t count;
    uint8_t *eocd;
    size_t eocd_len;
    uint8_t *prefix;
    size_t prefix_len;
    size_t total_size;
} zip_file_t;

void zip_free(zip_file_t *z);
int zip_parse(const uint8_t *data, size_t len, zip_file_t *z);

/* Bit-exact rebuild from preserved local headers, compressed payloads,
 * data descriptors, central directory headers, EOCD, and optional prefix. */
int zip_rebuild_exact(const zip_file_t *z, uint8_t **out, size_t *out_len);

/* Rebuild IPSW as STORE (method 0) with current entry payloads (uncompressed). */
int zip_rebuild_store(const zip_file_t *z, uint8_t **out, size_t *out_len);

uint32_t zip_crc32(const uint8_t *data, size_t len);

/* Require classic zlib 1.2.8 (Apple IPSW bit-exact raw DEFLATE). */
void zip_require_zlib128(void);

/* Raw DEFLATE with Apple-matching params: level 6, windowBits -15, memLevel 8. */
int zip_deflate_raw_apple(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

/* 1 if zip_deflate_raw_apple(in) equals expect byte-for-byte. */
int zip_deflate_matches(const uint8_t *in, size_t in_len,
                        const uint8_t *expect, size_t expect_len);

#endif

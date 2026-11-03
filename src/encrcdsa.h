#ifndef IPSWARC_ENCRCDSA_H
#define IPSWARC_ENCRCDSA_H

#include "common.h"

typedef struct {
    uint32_t blocksize;
    uint64_t datasize;
    uint64_t dataoffset;
    uint8_t aes_key[16];
    uint8_t hmac_key[20];
    uint8_t *header;      /* bytes [0, dataoffset) */
    size_t header_len;
    uint8_t *trailer;     /* bytes after encrypted payload, if any */
    size_t trailer_len;
    size_t total_len;     /* original file size */
    /* Decrypted bytes past datasize in the final chunk (non-zero Apple padding). */
    uint8_t *tail_pad;
    size_t tail_pad_len;
} encrcdsa_info_t;

void encrcdsa_info_free(encrcdsa_info_t *info);

int encrcdsa_is(const uint8_t *data, size_t len);

/* Parse header; does not decrypt. vfkey is 36-byte -k material. */
int encrcdsa_parse(const uint8_t *data, size_t len, const uint8_t vfkey[36],
                   encrcdsa_info_t *info);

/* Decrypt encrypted body to *plain (datasize bytes). */
int encrcdsa_decrypt_body(const uint8_t *file, size_t file_len,
                          encrcdsa_info_t *info,
                          uint8_t **plain, size_t *plain_len);

/* Re-encrypt plain body and rebuild full file. */
int encrcdsa_encrypt_file(const encrcdsa_info_t *info,
                          const uint8_t *plain, size_t plain_len,
                          uint8_t **out, size_t *out_len);

#endif

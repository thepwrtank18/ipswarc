#ifndef IPSWARC_IMG3_H
#define IPSWARC_IMG3_H

#include "common.h"

typedef struct {
    uint8_t *plain;       /* decrypted DATA payload (owned) */
    size_t plain_len;
    uint8_t *shell;       /* full img3 with DATA ciphertext zeroed or omitted? */
    size_t shell_len;     /* we store original img3 bytes with DATA replaced by zeros marker */
    size_t data_off;      /* offset of ciphertext within original */
    size_t data_len;      /* ciphertext length (== plain_len) */
    uint8_t iv[16];
    uint8_t key[32];
} img3_dec_t;

void img3_dec_free(img3_dec_t *d);

/* Decrypt IMG3 DATA tag. shell is a copy of original with ciphertext intact
 * (we keep original and re-encrypt into place on rebuild). */
int img3_decrypt(const uint8_t *img3, size_t len,
                 const uint8_t iv[16], const uint8_t key[32],
                 img3_dec_t *out);

/* Re-encrypt plain into a full IMG3 image identical to original layout. */
int img3_encrypt(const img3_dec_t *d, const uint8_t *plain, size_t plain_len,
                 uint8_t **out_img3, size_t *out_len);

int img3_is(const uint8_t *data, size_t len);

#endif

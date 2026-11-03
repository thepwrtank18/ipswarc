#include "img3.h"

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int img3_is(const uint8_t *data, size_t len) {
    return len >= 20 && memcmp(data, "3gmI", 4) == 0;
}

void img3_dec_free(img3_dec_t *d) {
    if (!d) return;
    free(d->plain);
    free(d->shell);
    memset(d, 0, sizeof(*d));
}

int img3_decrypt(const uint8_t *img3, size_t len,
                 const uint8_t iv[16], const uint8_t key[32],
                 img3_dec_t *out) {
    memset(out, 0, sizeof(*out));
    if (!img3_is(img3, len)) return -1;

    size_t off = 20;
    size_t data_off = 0, data_full = 0;
    while (off + 12 <= len) {
        const uint8_t *t = img3 + off;
        uint32_t full = rd32(t + 4);
        if (full < 12 || off + full > len) return -1;
        if (memcmp(t, "ATAD", 4) == 0) {
            data_off = off + 12;
            data_full = full - 12;
            break;
        }
        off += full;
    }
    if (!data_full || (data_full % AES_BLOCK) != 0) return -1;

    uint8_t *plain = (uint8_t *)xmalloc(data_full);
    if (aes_cbc_crypt(0, key, 32, iv, img3 + data_off, data_full, plain) != 0) {
        free(plain);
        return -1;
    }

    out->plain = plain;
    out->plain_len = data_full;
    out->shell = (uint8_t *)xmalloc(len);
    memcpy(out->shell, img3, len);
    out->shell_len = len;
    out->data_off = data_off;
    out->data_len = data_full;
    memcpy(out->iv, iv, 16);
    memcpy(out->key, key, 32);
    return 0;
}

int img3_encrypt(const img3_dec_t *d, const uint8_t *plain, size_t plain_len,
                 uint8_t **out_img3, size_t *out_len) {
    if (plain_len != d->data_len) return -1;
    uint8_t *img = (uint8_t *)xmalloc(d->shell_len);
    memcpy(img, d->shell, d->shell_len);
    if (aes_cbc_crypt(1, d->key, 32, d->iv, plain, plain_len, img + d->data_off) != 0) {
        free(img);
        return -1;
    }
    *out_img3 = img;
    *out_len = d->shell_len;
    return 0;
}

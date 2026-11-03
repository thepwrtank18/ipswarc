#include "encrcdsa.h"

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t be64(const uint8_t *p) {
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

void encrcdsa_info_free(encrcdsa_info_t *info) {
    if (!info) return;
    free(info->header);
    free(info->trailer);
    free(info->tail_pad);
    memset(info, 0, sizeof(*info));
}

int encrcdsa_is(const uint8_t *data, size_t len) {
    return len >= 0x50 && memcmp(data, "encrcdsa", 8) == 0 && be32(data + 8) == 2;
}

int encrcdsa_parse(const uint8_t *data, size_t len, const uint8_t vfkey[36],
                   encrcdsa_info_t *info) {
    memset(info, 0, sizeof(*info));
    if (!encrcdsa_is(data, len)) return -1;
    info->blocksize = be32(data + 0x34);
    info->datasize = be64(data + 0x38);
    info->dataoffset = be64(data + 0x40);
    if (info->blocksize == 0 || info->blocksize > (1u << 24)) return -1;
    if (info->dataoffset > len) return -1;
    if (info->dataoffset + info->datasize > len) return -1;

    memcpy(info->aes_key, vfkey, 16);
    memcpy(info->hmac_key, vfkey + 16, 20);

    /* Ciphertext fork is block-aligned from dataoffset to EOF (or to an optional
     * trailing region after the last full/partial chunk). Apple images typically
     * pad the last chunk to blocksize and end the file there — no separate trailer. */
    info->header_len = (size_t)info->dataoffset;
    info->header = (uint8_t *)xmalloc(info->header_len);
    memcpy(info->header, data, info->header_len);
    info->trailer_len = 0;
    info->trailer = NULL;
    info->total_len = len;
    return 0;
}

static void compute_iv(const uint8_t hmac_key[20], uint32_t chunk_no, uint8_t iv[16]) {
    uint8_t be[4] = {
        (uint8_t)(chunk_no >> 24), (uint8_t)(chunk_no >> 16),
        (uint8_t)(chunk_no >> 8), (uint8_t)chunk_no
    };
    uint8_t md[20];
    if (hmac_sha1(hmac_key, 20, be, 4, md) != 0)
        die("hmac_sha1 failed");
    memcpy(iv, md, 16);
}

int encrcdsa_decrypt_body(const uint8_t *file, size_t file_len,
                          encrcdsa_info_t *info,
                          uint8_t **plain, size_t *plain_len) {
    if (info->dataoffset + info->datasize > file_len) return -1;
    size_t bs = info->blocksize;
    uint8_t *out = (uint8_t *)xmalloc((size_t)info->datasize);
    const uint8_t *cin = file + info->dataoffset;
    size_t remaining = (size_t)info->datasize;
    uint32_t chunk = 0;
    size_t off = 0;
    uint8_t *tmp_in = (uint8_t *)xmalloc(bs);
    uint8_t *tmp_out = (uint8_t *)xmalloc(bs);

    while (remaining > 0) {
        size_t n = remaining < bs ? remaining : bs;
        /* Always decrypt a full blocksize of ciphertext (vfdecrypt style). */
        size_t file_off = (size_t)info->dataoffset + (size_t)chunk * bs;
        if (file_off + bs > file_len) {
            free(tmp_in); free(tmp_out); free(out); return -1;
        }
        memcpy(tmp_in, file + file_off, bs);
        uint8_t iv[16];
        compute_iv(info->hmac_key, chunk, iv);
        if (aes_cbc_crypt(0, info->aes_key, 16, iv, tmp_in, bs, tmp_out) != 0) {
            free(tmp_in); free(tmp_out); free(out); return -1;
        }
        memcpy(out + off, tmp_out, n);
        if (n < bs) {
            /* Preserve decrypted padding past datasize for bit-perfect re-encrypt. */
            size_t pad = bs - n;
            free(info->tail_pad);
            info->tail_pad = (uint8_t *)xmalloc(pad);
            memcpy(info->tail_pad, tmp_out + n, pad);
            info->tail_pad_len = pad;
        }
        off += n;
        remaining -= n;
        chunk++;
    }
    free(tmp_in);
    free(tmp_out);
    *plain = out;
    *plain_len = (size_t)info->datasize;
    return 0;
}

int encrcdsa_encrypt_file(const encrcdsa_info_t *info,
                          const uint8_t *plain, size_t plain_len,
                          uint8_t **out, size_t *out_len) {
    if (plain_len != (size_t)info->datasize) return -1;
    size_t bs = info->blocksize;

    /* Ciphertext length: block-aligned covering datasize; prefer original total. */
    size_t enc_len = ((plain_len + bs - 1) / bs) * bs;
    size_t file_len = info->header_len + enc_len + info->trailer_len;
    if (info->total_len >= info->header_len + info->trailer_len) {
        size_t body_room = info->total_len - info->header_len - info->trailer_len;
        if (body_room > enc_len) enc_len = body_room;
        file_len = info->total_len;
    }

    uint8_t *file = (uint8_t *)xmalloc(file_len);
    memset(file, 0, file_len);
    memcpy(file, info->header, info->header_len);

    uint8_t *tmp_in = (uint8_t *)xmalloc(bs);
    uint8_t *tmp_out = (uint8_t *)xmalloc(bs);
    uint32_t nchunks = (uint32_t)((enc_len + bs - 1) / bs);
    for (uint32_t chunk = 0; chunk < nchunks; chunk++) {
        size_t plain_off = (size_t)chunk * bs;
        memset(tmp_in, 0, bs);
        if (plain_off < plain_len) {
            size_t n_plain = plain_len - plain_off;
            if (n_plain > bs) n_plain = bs;
            memcpy(tmp_in, plain + plain_off, n_plain);
            if (n_plain < bs && info->tail_pad_len) {
                size_t copy = info->tail_pad_len;
                if (copy > bs - n_plain) copy = bs - n_plain;
                memcpy(tmp_in + n_plain, info->tail_pad, copy);
            }
        }
        uint8_t iv[16];
        compute_iv(info->hmac_key, chunk, iv);
        if (aes_cbc_crypt(1, info->aes_key, 16, iv, tmp_in, bs, tmp_out) != 0) {
            free(tmp_in); free(tmp_out); free(file); return -1;
        }
        memcpy(file + info->header_len + plain_off, tmp_out, bs);
    }
    free(tmp_in);
    free(tmp_out);

    if (info->trailer_len)
        memcpy(file + file_len - info->trailer_len, info->trailer, info->trailer_len);

    *out = file;
    *out_len = file_len;
    return 0;
}

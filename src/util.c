#include "common.h"
#include <stdarg.h>
#include <stdint.h>
#include <windows.h>
#include <bcrypt.h>

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("error: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("warning: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

int64_t file_size64(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    int64_t sz = (int64_t)_ftelli64(f);
    fclose(f);
    return sz;
}

int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    int64_t sz = (int64_t)_ftelli64(f);
    if (sz < 0) { fclose(f); return -1; }
    /* IPSWs can be ~1–1.2 GiB; keep a headroom cap. Multi-GB archive blobs
     * must use stream_copy_* instead of this helper. */
    if (sz < 0 || (uint64_t)sz > 4ULL * 1024 * 1024 * 1024 ||
        (uint64_t)sz > (uint64_t)SIZE_MAX / 2) {
        fclose(f);
        return -1;
    }
    if (_fseeki64(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    uint8_t *buf = (uint8_t *)xmalloc((size_t)sz ? (size_t)sz : 1);
    if (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int stream_copy_path_to_file(FILE *out, const char *path, uint64_t *out_len) {
    FILE *in = fopen(path, "rb");
    if (!in) {
        warnx("open %s for stream copy: %s", path, strerror(errno));
        return -1;
    }
    uint8_t *buf = (uint8_t *)xmalloc(8 * 1024 * 1024);
    uint64_t total = 0;
    for (;;) {
        size_t n = fread(buf, 1, 8 * 1024 * 1024, in);
        if (n == 0) break;
        if (fwrite(buf, 1, n, out) != n) {
            warnx("stream copy write failed after %llu bytes (disk full?): %s",
                  (unsigned long long)total, strerror(errno));
            free(buf); fclose(in); return -1;
        }
        total += n;
    }
    if (ferror(in)) {
        warnx("stream copy read failed: %s", strerror(errno));
        free(buf); fclose(in); return -1;
    }
    free(buf);
    fclose(in);
    if (out_len) *out_len = total;
    return 0;
}

int stream_copy_file_to_path(FILE *in, uint64_t len, const char *path) {
    FILE *out = fopen(path, "wb");
    if (!out) return -1;
    uint8_t *buf = (uint8_t *)xmalloc(8 * 1024 * 1024);
    uint64_t left = len;
    while (left > 0) {
        size_t chunk = left > 8 * 1024 * 1024 ? 8 * 1024 * 1024 : (size_t)left;
        size_t n = fread(buf, 1, chunk, in);
        if (n != chunk) { free(buf); fclose(out); return -1; }
        if (fwrite(buf, 1, n, out) != n) { free(buf); fclose(out); return -1; }
        left -= n;
    }
    free(buf);
    fclose(out);
    return 0;
}

int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t n = strlen(hex);
    if (n != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%02x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

void hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 0xf];
    }
    out[len * 2] = 0;
}

int sha256_buf(const uint8_t *data, size_t len, sha256_t *out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    DWORD obj_len = 0, cb = 0;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st < 0) return -1;
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return -1; }
    uint8_t *obj = (uint8_t *)xmalloc(obj_len);
    st = BCryptCreateHash(alg, &hash, obj, obj_len, NULL, 0, 0);
    if (st < 0) { free(obj); BCryptCloseAlgorithmProvider(alg, 0); return -1; }
    if (len) {
        st = BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
        if (st < 0) goto fail;
    }
    st = BCryptFinishHash(hash, out->dig, SHA256_LEN, 0);
    if (st < 0) goto fail;
    BCryptDestroyHash(hash);
    free(obj);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
fail:
    BCryptDestroyHash(hash);
    free(obj);
    BCryptCloseAlgorithmProvider(alg, 0);
    return -1;
}

int sha256_file(const char *path, sha256_t *out) {
    uint8_t *data = NULL;
    size_t len = 0;
    if (read_file(path, &data, &len) != 0) return -1;
    int rc = sha256_buf(data, len, out);
    free(data);
    return rc;
}

int aes_cbc_crypt(int encrypt, const uint8_t *key, size_t key_len,
                  const uint8_t *iv, const uint8_t *in, size_t len, uint8_t *out) {
    if (len % AES_BLOCK) return -1;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    DWORD obj_len = 0, cb = 0;
    uint8_t iv_copy[AES_BLOCK];
    memcpy(iv_copy, iv, AES_BLOCK);

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return -1;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return -1; }
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return -1; }
    uint8_t *obj = (uint8_t *)xmalloc(obj_len);
    st = BCryptGenerateSymmetricKey(alg, &hkey, obj, obj_len, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { free(obj); BCryptCloseAlgorithmProvider(alg, 0); return -1; }

    ULONG out_len = 0;
    if (encrypt) {
        st = BCryptEncrypt(hkey, (PUCHAR)in, (ULONG)len, NULL, iv_copy, AES_BLOCK,
                           out, (ULONG)len, &out_len, 0);
    } else {
        st = BCryptDecrypt(hkey, (PUCHAR)in, (ULONG)len, NULL, iv_copy, AES_BLOCK,
                           out, (ULONG)len, &out_len, 0);
    }
    BCryptDestroyKey(hkey);
    free(obj);
    BCryptCloseAlgorithmProvider(alg, 0);
    return (st < 0 || out_len != len) ? -1 : 0;
}

int hmac_sha1(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len, uint8_t out[20]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    DWORD obj_len = 0, hash_len = 0, cb = 0;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0) return -1;
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
    if (st < 0) goto fail;
    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0);
    if (st < 0 || hash_len != 20) goto fail;
    uint8_t *obj = (uint8_t *)xmalloc(obj_len);
    st = BCryptCreateHash(alg, &hash, obj, obj_len, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { free(obj); goto fail; }
    if (data_len) {
        st = BCryptHashData(hash, (PUCHAR)data, (ULONG)data_len, 0);
        if (st < 0) { BCryptDestroyHash(hash); free(obj); goto fail; }
    }
    st = BCryptFinishHash(hash, out, 20, 0);
    BCryptDestroyHash(hash);
    free(obj);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st < 0 ? -1 : 0;
fail:
    BCryptCloseAlgorithmProvider(alg, 0);
    return -1;
}

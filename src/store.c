#include "store.h"
#include <windows.h>
#include <errno.h>

#include "LzmaLib.h"

/* Chunk wire format for method==2 (LZMA): 5-byte props + compressed payload. */
#define STORE_METHOD_RAW  0
#define STORE_METHOD_LZMA 2

/* Windows long is 32-bit; blob grows past 2GiB while packing multiple rootfs images. */
static int blob_seek(FILE *f, uint64_t off) {
    return _fseeki64(f, (__int64)off, SEEK_SET);
}
static int64_t blob_tell(FILE *f) {
    return (int64_t)_ftelli64(f);
}

/* ---- FastCDC-ish gear hash ---- */
#define CDC_MIN (8 * 1024)
#define CDC_AVG (16 * 1024)
#define CDC_MAX (32 * 1024)
#define CDC_MASK ((uint32_t)(CDC_AVG - 1))

static uint32_t gear[256];
static int gear_ready = 0;
static void gear_init(void) {
    uint32_t s = 0x9e3779b9u;
    for (int i = 0; i < 256; i++) {
        s = s * 1664525u + 1013904223u;
        gear[i] = s;
    }
    gear_ready = 1;
}

static void cdc_cut_points(const uint8_t *data, size_t len, size_t **cuts, size_t *ncuts) {
    if (!gear_ready) gear_init();
    size_t cap = 64, n = 0;
    size_t *c = (size_t *)xmalloc(cap * sizeof(size_t));
    size_t start = 0;
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) {
        h = (h << 1) + gear[data[i]];
        size_t size = i - start + 1;
        if (size < CDC_MIN) continue;
        if ((h & CDC_MASK) == 0 || size >= CDC_MAX || i + 1 == len) {
            if (n == cap) { cap *= 2; c = (size_t *)xrealloc(c, cap * sizeof(size_t)); }
            c[n++] = i + 1; /* end exclusive */
            start = i + 1;
            h = 0;
        }
    }
    if (start < len) {
        if (n == cap) { c = (size_t *)xrealloc(c, (cap + 1) * sizeof(size_t)); }
        c[n++] = len;
    }
    *cuts = c;
    *ncuts = n;
}

static int lzma_buf(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    /* dest bound: source + source/3 + 128 is a common LZMA upper estimate */
    size_t bound = in_len + in_len / 3 + 128 + LZMA_PROPS_SIZE;
    if (bound < in_len) bound = in_len + 1024 + LZMA_PROPS_SIZE;
    uint8_t *buf = (uint8_t *)xmalloc(bound);
    size_t props_sz = LZMA_PROPS_SIZE;
    size_t dest_len = bound - LZMA_PROPS_SIZE;
    /* level 5, dict 16MB (or smaller for tiny inputs), lc/lp/pb/fb defaults, 1 thread */
    unsigned dict = 1u << 24;
    while (dict > 1u << 12 && dict > in_len * 2) dict >>= 1;
    int rc = LzmaCompress(buf + LZMA_PROPS_SIZE, &dest_len, in, in_len,
                          buf, &props_sz,
                          5, dict, -1, -1, -1, -1, 1);
    if (rc != 0 || props_sz != LZMA_PROPS_SIZE) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = LZMA_PROPS_SIZE + dest_len;
    return 0;
}

static int unlzma_buf(const uint8_t *in, size_t in_len, size_t raw_size, uint8_t **out) {
    if (in_len < LZMA_PROPS_SIZE) return -1;
    uint8_t *buf = (uint8_t *)xmalloc(raw_size ? raw_size : 1);
    size_t dest_len = raw_size;
    size_t src_len = in_len - LZMA_PROPS_SIZE;
    int rc = LzmaUncompress(buf, &dest_len, in + LZMA_PROPS_SIZE, &src_len,
                            in, LZMA_PROPS_SIZE);
    if (rc != 0 || dest_len != raw_size) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

static store_obj_t *store_find(objstore_t *s, const sha256_t *id) {
    for (size_t i = 0; i < s->count; i++)
        if (sha256_eq(&s->objs[i].id, id)) return &s->objs[i];
    return NULL;
}

int store_has(objstore_t *s, const sha256_t *id) {
    return store_find(s, id) != NULL;
}

static int store_write_index(objstore_t *s) {
    FILE *f = fopen(s->index_path, "wb");
    if (!f) return -1;
    uint32_t n = (uint32_t)s->count;
    if (fwrite(&n, 4, 1, f) != 1) { fclose(f); return -1; }
    for (size_t i = 0; i < s->count; i++) {
        store_obj_t *o = &s->objs[i];
        if (fwrite(o->id.dig, 32, 1, f) != 1 ||
            fwrite(&o->offset, 8, 1, f) != 1 ||
            fwrite(&o->comp_size, 8, 1, f) != 1 ||
            fwrite(&o->raw_size, 8, 1, f) != 1 ||
            fwrite(&o->method, 1, 1, f) != 1) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

int store_flush_index(objstore_t *s) {
    if (s->blob) fflush(s->blob);
    return store_write_index(s);
}

static int store_read_index_mem(objstore_t *s, const uint8_t *data, size_t len) {
    if (len < 4) return -1;
    uint32_t n = 0;
    memcpy(&n, data, 4);
    size_t need = 4u + (size_t)n * (32u + 8u + 8u + 8u + 1u);
    if (len < need) return -1;
    s->count = 0;
    s->cap = n ? n : 8;
    s->objs = (store_obj_t *)xmalloc(s->cap * sizeof(store_obj_t));
    size_t off = 4;
    for (uint32_t i = 0; i < n; i++) {
        store_obj_t o;
        memset(&o, 0, sizeof(o));
        memcpy(o.id.dig, data + off, 32); off += 32;
        memcpy(&o.offset, data + off, 8); off += 8;
        memcpy(&o.comp_size, data + off, 8); off += 8;
        memcpy(&o.raw_size, data + off, 8); off += 8;
        o.method = data[off++];
        s->objs[s->count++] = o;
    }
    return 0;
}

static int store_read_index(objstore_t *s) {
    FILE *f = fopen(s->index_path, "rb");
    if (!f) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    int64_t sz = blob_tell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (blob_seek(f, 0) != 0) { fclose(f); return -1; }
    uint8_t *buf = (uint8_t *)xmalloc((size_t)sz ? (size_t)sz : 1);
    if ((size_t)sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    int rc = store_read_index_mem(s, buf, (size_t)sz);
    free(buf);
    return rc;
}

int store_create(objstore_t *s, const char *dir) {
    memset(s, 0, sizeof(*s));
    CreateDirectoryA(dir, NULL);
    snprintf(s->blob_path, sizeof(s->blob_path), "%s\\blob.bin", dir);
    snprintf(s->index_path, sizeof(s->index_path), "%s\\index.bin", dir);
    s->blob = fopen(s->blob_path, "wb+");
    if (!s->blob) return -1;
    s->blob_owned = 1;
    s->blob_base = 0;
    s->blob_end = 0;
    s->cap = 64;
    s->objs = (store_obj_t *)xmalloc(s->cap * sizeof(store_obj_t));
    return 0;
}

int store_open(objstore_t *s, const char *dir) {
    memset(s, 0, sizeof(*s));
    snprintf(s->blob_path, sizeof(s->blob_path), "%s\\blob.bin", dir);
    snprintf(s->index_path, sizeof(s->index_path), "%s\\index.bin", dir);
    if (store_read_index(s) != 0) return -1;
    s->blob = fopen(s->blob_path, "rb");
    if (!s->blob) return -1;
    s->blob_owned = 1;
    s->blob_base = 0;
    if (blob_seek(s->blob, 0) != 0) return -1;
    if (_fseeki64(s->blob, 0, SEEK_END) != 0) return -1;
    int64_t end = blob_tell(s->blob);
    if (end < 0) return -1;
    s->blob_end = (uint64_t)end;
    if (blob_seek(s->blob, 0) != 0) return -1;
    return 0;
}

int store_open_embedded(objstore_t *s, FILE *arc, uint64_t blob_off, uint64_t blob_len,
                        const uint8_t *index_data, size_t index_len) {
    memset(s, 0, sizeof(*s));
    if (!arc || !index_data) return -1;
    if (store_read_index_mem(s, index_data, index_len) != 0) return -1;
    s->blob = arc;
    s->blob_owned = 0;
    s->blob_base = blob_off;
    s->blob_end = blob_len;
    return 0;
}

int store_open_embedded_reader(objstore_t *s, const store_reader_t *reader,
                               uint64_t blob_off, uint64_t blob_len,
                               const uint8_t *index_data, size_t index_len) {
    memset(s, 0, sizeof(*s));
    if (!reader || !reader->seek || !reader->read || !index_data) return -1;
    if (store_read_index_mem(s, index_data, index_len) != 0) return -1;
    s->reader = *reader;
    s->blob = NULL;
    s->blob_owned = 0;
    s->blob_base = blob_off;
    s->blob_end = blob_len;
    return 0;
}

static int store_blob_seek_read(objstore_t *s, uint64_t rel_off, void *buf, size_t len) {
    uint64_t abs = s->blob_base + rel_off;
    if (s->reader.seek) {
        if (s->reader.seek(s->reader.ctx, abs) != 0) return -1;
        if (len && s->reader.read(s->reader.ctx, buf, len) != 0) return -1;
        return 0;
    }
    if (!s->blob) return -1;
    if (blob_seek(s->blob, abs) != 0) return -1;
    if (len && fread(buf, 1, len, s->blob) != len) return -1;
    return 0;
}

void store_close(objstore_t *s) {
    if (!s) return;
    if (s->blob && s->blob_owned) fclose(s->blob);
    free(s->objs);
    memset(s, 0, sizeof(*s));
}

/* Cap whole-buffer LZMA: CDC chunks are <=32KiB; never LZMA multi-MB blobs
 * (e.g. already-deflated IPSW entry payloads) — that hangs for minutes/hours. */
#define STORE_LZMA_MAX (256 * 1024)

static int store_put_ex(objstore_t *s, const uint8_t *data, size_t len,
                        sha256_t *out_id, int try_lzma) {
    sha256_t id;
    if (sha256_buf(data, len, &id) != 0) return -1;
    if (store_find(s, &id)) {
        *out_id = id;
        return 0;
    }
    uint8_t *comp = NULL;
    size_t comp_len = 0;
    uint8_t method = STORE_METHOD_RAW;
    if (try_lzma && len >= 64 && len <= STORE_LZMA_MAX) {
        if (lzma_buf(data, len, &comp, &comp_len) == 0 && comp_len < len) {
            method = STORE_METHOD_LZMA;
        } else {
            free(comp);
            comp = NULL;
        }
    }
    if (!comp) {
        comp = (uint8_t *)xmalloc(len ? len : 1);
        if (len) memcpy(comp, data, len);
        comp_len = len;
        method = STORE_METHOD_RAW;
    }

    /* Append using tracked end — do not rely on 32-bit ftell. */
    if (blob_seek(s->blob, s->blob_base + s->blob_end) != 0) {
        warnx("blob seek to end (%llu) failed: %s",
              (unsigned long long)(s->blob_base + s->blob_end), strerror(errno));
        free(comp);
        return -1;
    }
    uint64_t off = s->blob_end;
    if (comp_len && fwrite(comp, 1, comp_len, s->blob) != comp_len) {
        warnx("blob write %zu bytes at %llu failed: %s",
              comp_len, (unsigned long long)off, strerror(errno));
        free(comp);
        return -1;
    }
    if (fflush(s->blob) != 0) {
        warnx("blob fflush failed: %s", strerror(errno));
        free(comp);
        return -1;
    }
    free(comp);
    s->blob_end = off + comp_len;

    if (s->count == s->cap) {
        s->cap *= 2;
        s->objs = (store_obj_t *)xrealloc(s->objs, s->cap * sizeof(store_obj_t));
    }
    store_obj_t *o = &s->objs[s->count++];
    o->id = id;
    o->offset = off;
    o->comp_size = comp_len;
    o->raw_size = len;
    o->method = method;
    *out_id = id;
    return 0;
}

int store_put(objstore_t *s, const uint8_t *data, size_t len, sha256_t *out_id) {
    return store_put_ex(s, data, len, out_id, 1);
}

int store_put_raw(objstore_t *s, const uint8_t *data, size_t len, sha256_t *out_id) {
    return store_put_ex(s, data, len, out_id, 0);
}

int store_get(objstore_t *s, const sha256_t *id, uint8_t **out, size_t *out_len) {
    store_obj_t *o = store_find(s, id);
    if (!o) return -1;
    uint8_t *comp = (uint8_t *)xmalloc(o->comp_size ? (size_t)o->comp_size : 1);
    if (store_blob_seek_read(s, o->offset, comp, (size_t)o->comp_size) != 0) {
        free(comp); return -1;
    }
    if (o->method == STORE_METHOD_RAW) {
        *out = comp;
        *out_len = (size_t)o->raw_size;
        return 0;
    }
    if (o->method != STORE_METHOD_LZMA) {
        free(comp);
        return -1;
    }
    uint8_t *raw = NULL;
    if (unlzma_buf(comp, (size_t)o->comp_size, (size_t)o->raw_size, &raw) != 0) {
        free(comp);
        return -1;
    }
    free(comp);
    *out = raw;
    *out_len = (size_t)o->raw_size;
    return 0;
}

/* Chunk-list format: magic "CHLK" + u32 count + count * sha256 + (implicit concat) */
int store_put_cdc(objstore_t *s, const uint8_t *data, size_t len, sha256_t *out_id) {
    if (len < CDC_MIN * 2) {
        return store_put(s, data, len, out_id);
    }
    size_t *cuts = NULL, ncuts = 0;
    cdc_cut_points(data, len, &cuts, &ncuts);
    size_t list_len = 4 + 4 + ncuts * SHA256_LEN;
    uint8_t *list = (uint8_t *)xmalloc(list_len);
    memcpy(list, "CHLK", 4);
    uint32_t n = (uint32_t)ncuts;
    memcpy(list + 4, &n, 4);
    size_t prev = 0;
    for (size_t i = 0; i < ncuts; i++) {
        size_t end = cuts[i];
        sha256_t cid;
        if (store_put(s, data + prev, end - prev, &cid) != 0) {
            free(cuts); free(list); return -1;
        }
        memcpy(list + 8 + i * SHA256_LEN, cid.dig, SHA256_LEN);
        prev = end;
    }
    free(cuts);
    int rc = store_put(s, list, list_len, out_id);
    free(list);
    return rc;
}

int store_get_cdc(objstore_t *s, const sha256_t *id, uint8_t **out, size_t *out_len) {
    uint8_t *list = NULL;
    size_t list_len = 0;
    if (store_get(s, id, &list, &list_len) != 0) return -1;
    if (list_len >= 8 && memcmp(list, "CHLK", 4) == 0) {
        uint32_t n = 0;
        memcpy(&n, list + 4, 4);
        if (list_len != 8u + n * SHA256_LEN) { free(list); return -1; }
        size_t total = 0, cap = 0;
        uint8_t *acc = NULL;
        for (uint32_t i = 0; i < n; i++) {
            sha256_t cid;
            memcpy(cid.dig, list + 8 + i * SHA256_LEN, SHA256_LEN);
            uint8_t *chunk = NULL;
            size_t clen = 0;
            if (store_get(s, &cid, &chunk, &clen) != 0) {
                free(acc); free(list); return -1;
            }
            if (total + clen > cap) {
                cap = (total + clen) * 2 + 16;
                acc = (uint8_t *)xrealloc(acc, cap);
            }
            memcpy(acc + total, chunk, clen);
            total += clen;
            free(chunk);
        }
        free(list);
        *out = acc ? acc : (uint8_t *)xmalloc(1);
        *out_len = total;
        return 0;
    }
    /* not a chunk list — raw object */
    *out = list;
    *out_len = list_len;
    return 0;
}

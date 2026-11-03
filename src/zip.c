#include "zip.h"
#include <zlib.h>

/* zlib's crc32 macro collides with our zip_entry field name usage in some builds */
#ifdef crc32
#undef crc32
#endif

static uint32_t rd16(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t crc_table[256];
static int crc_ready = 0;
static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc_table[i] = c;
    }
    crc_ready = 1;
}
uint32_t zip_crc32(const uint8_t *data, size_t len) {
    if (!crc_ready) crc_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc_table[(c ^ data[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

void zip_free(zip_file_t *z) {
    if (!z) return;
    for (size_t i = 0; i < z->count; i++) {
        free(z->entries[i].name);
        free(z->entries[i].local_header);
        free(z->entries[i].comp);
        free(z->entries[i].payload);
        free(z->entries[i].data_desc);
        free(z->entries[i].cd_header);
    }
    free(z->entries);
    free(z->eocd);
    free(z->prefix);
    memset(z, 0, sizeof(*z));
}

static int find_eocd(const uint8_t *data, size_t len, size_t *eocd_off) {
    if (len < 22) return -1;
    size_t max_back = len > 65536 + 22 ? 65536 + 22 : len;
    for (size_t i = 22; i <= max_back; i++) {
        size_t off = len - i;
        if (rd32(data + off) == 0x06054b50) {
            *eocd_off = off;
            return 0;
        }
    }
    return -1;
}

void zip_require_zlib128(void) {
    const char *v = zlibVersion();
    if (!v || strncmp(v, "1.2.8", 5) != 0)
        die("classic zlib 1.2.8 required for Apple IPSW bit-exact DEFLATE (got %s)",
            v ? v : "(null)");
}

static int inflate_raw(const uint8_t *src, size_t src_len, size_t dst_len, uint8_t **out) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, -15) != Z_OK) return -1;
    uint8_t *dst = (uint8_t *)xmalloc(dst_len ? dst_len : 1);
    strm.next_in = (Bytef *)src;
    strm.avail_in = (uInt)src_len;
    strm.next_out = dst;
    strm.avail_out = (uInt)dst_len;
    int rc = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (rc != Z_STREAM_END || strm.total_out != dst_len) {
        free(dst);
        return -1;
    }
    *out = dst;
    return 0;
}

/* Apple IPSW-compatible raw DEFLATE: zlib 1.2.8 level=6 memLevel=8. */
int zip_deflate_raw_apple(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    zip_require_zlib128();
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;

    /* Bound: uncompressed + ~0.1% + zlib overhead; grow if needed. */
    size_t cap = in_len + (in_len >> 10) + 64;
    if (cap < 64) cap = 64;
    uint8_t *dst = (uint8_t *)xmalloc(cap);

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = dst;
    strm.avail_out = (uInt)cap;

    for (;;) {
        int flush = (strm.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;
        int rc = deflate(&strm, flush);
        if (rc == Z_STREAM_END)
            break;
        if (rc == Z_OK && strm.avail_out == 0) {
            size_t produced = (size_t)strm.total_out;
            cap *= 2;
            dst = (uint8_t *)xrealloc(dst, cap);
            strm.next_out = dst + produced;
            strm.avail_out = (uInt)(cap - produced);
            continue;
        }
        if (rc != Z_OK) {
            deflateEnd(&strm);
            free(dst);
            return -1;
        }
        /* More input remains and output still has room — keep going. */
    }
    deflateEnd(&strm);
    *out = dst;
    *out_len = (size_t)strm.total_out;
    return 0;
}

int zip_deflate_matches(const uint8_t *in, size_t in_len,
                        const uint8_t *expect, size_t expect_len) {
    uint8_t *got = NULL;
    size_t got_len = 0;
    if (zip_deflate_raw_apple(in, in_len, &got, &got_len) != 0)
        return 0;
    int ok = (got_len == expect_len && memcmp(got, expect, expect_len) == 0);
    free(got);
    return ok;
}

int zip_parse(const uint8_t *data, size_t len, zip_file_t *z) {
    memset(z, 0, sizeof(*z));
    z->total_size = len;
    size_t eocd_off = 0;
    if (find_eocd(data, len, &eocd_off) != 0) return -1;

    uint32_t cd_off = rd32(data + eocd_off + 16);
    uint16_t nentries = (uint16_t)rd16(data + eocd_off + 10);
    if ((size_t)cd_off > eocd_off) return -1;

    z->eocd_len = len - eocd_off;
    z->eocd = (uint8_t *)xmalloc(z->eocd_len);
    memcpy(z->eocd, data + eocd_off, z->eocd_len);

    z->entries = (zip_entry_t *)xmalloc(nentries * sizeof(zip_entry_t));
    memset(z->entries, 0, nentries * sizeof(zip_entry_t));
    z->count = nentries;

    size_t p = cd_off;
    size_t min_local = len;
    for (uint16_t i = 0; i < nentries; i++) {
        if (p + 46 > eocd_off) return -1;
        if (rd32(data + p) != 0x02014b50) return -1;
        zip_entry_t *e = &z->entries[i];
        e->ver_made = (uint16_t)rd16(data + p + 4);
        e->ver_extract = (uint16_t)rd16(data + p + 6);
        e->gp_flag = (uint16_t)rd16(data + p + 8);
        e->method = (uint16_t)rd16(data + p + 10);
        e->mod_time = (uint16_t)rd16(data + p + 12);
        e->mod_date = (uint16_t)rd16(data + p + 14);
        e->crc32 = rd32(data + p + 16);
        e->comp_size = rd32(data + p + 20);
        e->uncomp_size = rd32(data + p + 24);
        uint16_t namelen = (uint16_t)rd16(data + p + 28);
        uint16_t extralen = (uint16_t)rd16(data + p + 30);
        uint16_t commentlen = (uint16_t)rd16(data + p + 32);
        e->internal_attr = (uint16_t)rd16(data + p + 36);
        e->external_attr = rd32(data + p + 38);
        e->local_header_off = rd32(data + p + 42);
        size_t cd_rec_len = 46u + namelen + extralen + commentlen;
        if (p + cd_rec_len > eocd_off) return -1;
        e->cd_header_len = cd_rec_len;
        e->cd_header = (uint8_t *)xmalloc(cd_rec_len);
        memcpy(e->cd_header, data + p, cd_rec_len);
        e->name = (char *)xmalloc(namelen + 1);
        memcpy(e->name, data + p + 46, namelen);
        e->name[namelen] = 0;
        p += cd_rec_len;

        size_t loff = e->local_header_off;
        if (loff + 30 > len) return -1;
        if (rd32(data + loff) != 0x04034b50) return -1;
        uint16_t lname = (uint16_t)rd16(data + loff + 26);
        uint16_t lextra = (uint16_t)rd16(data + loff + 28);
        size_t lh_len = 30u + lname + lextra;
        if (loff + lh_len > len) return -1;
        e->local_header_len = lh_len;
        e->local_header = (uint8_t *)xmalloc(lh_len);
        memcpy(e->local_header, data + loff, lh_len);

        uint32_t csize = e->comp_size;
        size_t poff = loff + lh_len;
        if (poff + csize > len) return -1;
        e->payload_file_off = poff;

        const uint8_t *comp = data + poff;
        e->comp_len = csize;
        e->comp = (uint8_t *)xmalloc(csize ? csize : 1);
        if (csize) memcpy(e->comp, comp, csize);

        if (e->method == 0) {
            e->payload_len = e->uncomp_size;
            e->payload = (uint8_t *)xmalloc(e->payload_len ? e->payload_len : 1);
            if (e->payload_len) memcpy(e->payload, comp, e->payload_len);
        } else if (e->method == 8) {
            if (inflate_raw(comp, csize, e->uncomp_size, &e->payload) != 0) {
                warnx("inflate failed for %s", e->name);
                return -1;
            }
            e->payload_len = e->uncomp_size;
        } else {
            warnx("unsupported zip method %u for %s", e->method, e->name);
            return -1;
        }

        /* verify CRC */
        if (e->payload_len && zip_crc32(e->payload, e->payload_len) != e->crc32) {
            warnx("CRC mismatch for %s", e->name);
            return -1;
        }

        size_t after = poff + csize;
        if (e->gp_flag & 0x8) {
            size_t dd = 0;
            if (after + 16 <= len && rd32(data + after) == 0x08074b50) dd = 16;
            else if (after + 12 <= len) dd = 12;
            if (dd) {
                e->data_desc_len = dd;
                e->data_desc = (uint8_t *)xmalloc(dd);
                memcpy(e->data_desc, data + after, dd);
            }
        }
        if (loff < min_local) min_local = loff;
    }

    if (min_local > 0 && min_local < len) {
        z->prefix_len = min_local;
        z->prefix = (uint8_t *)xmalloc(min_local);
        memcpy(z->prefix, data, min_local);
    }
    return 0;
}

int zip_rebuild_exact(const zip_file_t *z, uint8_t **out, size_t *out_len) {
    if (!z || !z->count) return -1;

    typedef struct { size_t idx; uint32_t off; } ord_t;
    ord_t *ord = (ord_t *)xmalloc(z->count * sizeof(ord_t));
    for (size_t i = 0; i < z->count; i++) {
        ord[i].idx = i;
        ord[i].off = z->entries[i].local_header_off;
        if (!z->entries[i].local_header || !z->entries[i].cd_header) {
            free(ord);
            return -1;
        }
        if (z->entries[i].comp_len != z->entries[i].comp_size) {
            free(ord);
            return -1;
        }
        if (z->entries[i].comp_len && !z->entries[i].comp) {
            free(ord);
            return -1;
        }
    }
    for (size_t i = 0; i < z->count; i++) {
        for (size_t j = i + 1; j < z->count; j++) {
            if (ord[j].off < ord[i].off) {
                ord_t t = ord[i];
                ord[i] = ord[j];
                ord[j] = t;
            }
        }
    }

    size_t sz = z->prefix_len + z->eocd_len;
    for (size_t i = 0; i < z->count; i++) {
        const zip_entry_t *e = &z->entries[i];
        sz += e->local_header_len + e->comp_len + e->data_desc_len + e->cd_header_len;
    }

    uint8_t *buf = (uint8_t *)xmalloc(sz);
    size_t w = 0;
    if (z->prefix_len) {
        memcpy(buf + w, z->prefix, z->prefix_len);
        w += z->prefix_len;
    }

    for (size_t i = 0; i < z->count; i++) {
        const zip_entry_t *e = &z->entries[ord[i].idx];
        /* Preserved CD local offsets require an identical layout. */
        if (w != (size_t)e->local_header_off) {
            free(ord);
            free(buf);
            warnx("zip local offset mismatch for %s (at %zu, expected %u)",
                  e->name, w, e->local_header_off);
            return -1;
        }
        memcpy(buf + w, e->local_header, e->local_header_len);
        w += e->local_header_len;
        if (e->comp_len) {
            memcpy(buf + w, e->comp, e->comp_len);
            w += e->comp_len;
        }
        if (e->data_desc_len) {
            memcpy(buf + w, e->data_desc, e->data_desc_len);
            w += e->data_desc_len;
        }
    }
    free(ord);

    for (size_t i = 0; i < z->count; i++) {
        const zip_entry_t *e = &z->entries[i];
        memcpy(buf + w, e->cd_header, e->cd_header_len);
        w += e->cd_header_len;
    }
    if (!z->eocd || !z->eocd_len) {
        free(buf);
        return -1;
    }
    memcpy(buf + w, z->eocd, z->eocd_len);
    w += z->eocd_len;

    if (w != sz) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = w;
    return 0;
}

int zip_rebuild_store(const zip_file_t *z, uint8_t **out, size_t *out_len) {
    /* Compute size: local headers (30+name, no extra) + payloads + CD + EOCD */
    size_t sz = 0;
    for (size_t i = 0; i < z->count; i++) {
        size_t namelen = strlen(z->entries[i].name);
        sz += 30 + namelen + z->entries[i].payload_len;
        sz += 46 + namelen; /* CD without extra/comment */
    }
    sz += 22; /* EOCD */

    uint8_t *buf = (uint8_t *)xmalloc(sz);
    size_t w = 0;
    uint32_t *local_offs = (uint32_t *)xmalloc(z->count * sizeof(uint32_t));

    for (size_t i = 0; i < z->count; i++) {
        const zip_entry_t *e = &z->entries[i];
        size_t namelen = strlen(e->name);
        local_offs[i] = (uint32_t)w;
        /* local file header */
        wr32(buf + w, 0x04034b50); w += 4;
        wr16(buf + w, 20); w += 2;              /* ver extract */
        wr16(buf + w, 0); w += 2;               /* gp flag */
        wr16(buf + w, 0); w += 2;               /* method STORE */
        wr16(buf + w, e->mod_time); w += 2;
        wr16(buf + w, e->mod_date); w += 2;
        wr32(buf + w, e->crc32); w += 4;
        wr32(buf + w, (uint32_t)e->payload_len); w += 4;
        wr32(buf + w, (uint32_t)e->payload_len); w += 4;
        wr16(buf + w, (uint16_t)namelen); w += 2;
        wr16(buf + w, 0); w += 2;               /* no extra */
        memcpy(buf + w, e->name, namelen); w += namelen;
        if (e->payload_len) {
            memcpy(buf + w, e->payload, e->payload_len);
            w += e->payload_len;
        }
    }

    uint32_t cd_start = (uint32_t)w;
    for (size_t i = 0; i < z->count; i++) {
        const zip_entry_t *e = &z->entries[i];
        size_t namelen = strlen(e->name);
        wr32(buf + w, 0x02014b50); w += 4;
        wr16(buf + w, 0x314); w += 2;           /* ver made */
        wr16(buf + w, 20); w += 2;              /* ver extract */
        wr16(buf + w, 0); w += 2;               /* gp */
        wr16(buf + w, 0); w += 2;               /* STORE */
        wr16(buf + w, e->mod_time); w += 2;
        wr16(buf + w, e->mod_date); w += 2;
        wr32(buf + w, e->crc32); w += 4;
        wr32(buf + w, (uint32_t)e->payload_len); w += 4;
        wr32(buf + w, (uint32_t)e->payload_len); w += 4;
        wr16(buf + w, (uint16_t)namelen); w += 2;
        wr16(buf + w, 0); w += 2;               /* extra */
        wr16(buf + w, 0); w += 2;               /* comment */
        wr16(buf + w, 0); w += 2;               /* disk start */
        wr16(buf + w, e->internal_attr); w += 2;
        wr32(buf + w, e->external_attr); w += 4;
        wr32(buf + w, local_offs[i]); w += 4;
        memcpy(buf + w, e->name, namelen); w += namelen;
    }
    uint32_t cd_size = (uint32_t)(w - cd_start);
    free(local_offs);

    wr32(buf + w, 0x06054b50); w += 4;
    wr16(buf + w, 0); w += 2;
    wr16(buf + w, 0); w += 2;
    wr16(buf + w, (uint16_t)z->count); w += 2;
    wr16(buf + w, (uint16_t)z->count); w += 2;
    wr32(buf + w, cd_size); w += 4;
    wr32(buf + w, cd_start); w += 4;
    wr16(buf + w, 0); w += 2; /* comment len */

    *out = buf;
    *out_len = w;
    return 0;
}

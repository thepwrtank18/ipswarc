#include "ipswarc_lib.h"
#include "arcfmt.h"
#include "store.h"
#include "keys.h"
#include "zip.h"
#include "infozip.h"
#include "img3.h"
#include "encrcdsa.h"

#include <stdarg.h>

typedef struct {
    char name[256];
    char plist_name[256];
    uint64_t orig_size;
    uint16_t mod_time;
    uint16_t mod_date;
    sha256_t orig_sha;
    size_t man_off;
    char *plist_xml;
    size_t plist_xml_len;
} ipswarc_item_t;

struct ipswarc_archive {
    FILE *fp;                 /* owned when opened via path; NULL for reader */
    int fp_owned;
    ipswarc_reader_t reader;  /* used when fp == NULL */
    uint8_t *man;
    size_t man_len;
    arc_header_t hdr;
    objstore_t store;
    keydb_t keys;
    ipswarc_item_t *items;
    uint32_t num_ipsw;
    int exact;
    int zlib128;
};

static int file_seek(void *ctx, uint64_t abs_off) {
    return _fseeki64((FILE *)ctx, (__int64)abs_off, SEEK_SET) == 0 ? 0 : -1;
}
static int file_read(void *ctx, void *buf, size_t len) {
    return (!len || fread(buf, 1, len, (FILE *)ctx) == len) ? 0 : -1;
}

static int reader_seek(const ipswarc_reader_t *r, uint64_t abs_off) {
    return r->seek(r->ctx, abs_off);
}
static int reader_read(const ipswarc_reader_t *r, void *buf, size_t len) {
    return r->read(r->ctx, buf, len);
}

static char g_err[512];

static void set_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof(g_err), fmt, ap);
    va_end(ap);
}

const char *ipswarc_last_error(void) {
    return g_err[0] ? g_err : "unknown error";
}

static void keydb_push_owned(keydb_t *db, key_entry_t *e) {
    if (db->count == db->cap) {
        db->cap = db->cap ? db->cap * 2 : 32;
        db->items = (key_entry_t *)xrealloc(db->items, db->cap * sizeof(key_entry_t));
    }
    db->items[db->count++] = *e;
}

static int load_keys_from_manifest(keydb_t *db, const uint8_t *man, size_t man_len,
                                   size_t *offp, uint32_t num_keys) {
    size_t off = *offp;
    for (uint32_t i = 0; i < num_keys; i++) {
        uint16_t bl, dl, fl, cl;
        if (off + 2 > man_len) return -1;
        memcpy(&bl, man + off, 2); off += 2;
        if (off + bl > man_len) return -1;
        char *build = (char *)xmalloc(bl + 1);
        memcpy(build, man + off, bl); build[bl] = 0; off += bl;

        if (off + 2 > man_len) { free(build); return -1; }
        memcpy(&dl, man + off, 2); off += 2;
        if (off + dl > man_len) { free(build); return -1; }
        char *device = (char *)xmalloc(dl + 1);
        memcpy(device, man + off, dl); device[dl] = 0; off += dl;

        if (off + 2 > man_len) { free(build); free(device); return -1; }
        memcpy(&fl, man + off, 2); off += 2;
        if (off + fl > man_len) { free(build); free(device); return -1; }
        char *filename = (char *)xmalloc(fl + 1);
        memcpy(filename, man + off, fl); filename[fl] = 0; off += fl;

        if (off + 2 > man_len) { free(build); free(device); free(filename); return -1; }
        memcpy(&cl, man + off, 2); off += 2;
        if (off + cl > man_len) { free(build); free(device); free(filename); return -1; }
        char *component = (char *)xmalloc(cl + 1);
        memcpy(component, man + off, cl); component[cl] = 0; off += cl;

        if (off + 1 + 1 + 16 + 1 > man_len) {
            free(build); free(device); free(filename); free(component); return -1;
        }
        key_entry_t e;
        memset(&e, 0, sizeof(e));
        e.build = build;
        e.device = device;
        e.filename = filename;
        e.component = component;
        e.kind = (key_kind_t)man[off++];
        e.has_iv = man[off++];
        memcpy(e.iv, man + off, 16); off += 16;
        uint8_t klen = man[off++];
        if (off + klen > man_len || klen > sizeof(e.key)) {
            free(build); free(device); free(filename); free(component); return -1;
        }
        e.key_len = klen;
        memcpy(e.key, man + off, klen); off += klen;
        keydb_push_owned(db, &e);
    }
    *offp = off;
    return 0;
}

static int rebuild_entry_bytes(objstore_t *store, const arc_entry_t *ae,
                               uint8_t **out, size_t *out_len) {
    if (ae->kind == PAY_RAW)
        return store_get_cdc(store, &ae->body_id, out, out_len);

    if (ae->kind == PAY_IMG3) {
        uint8_t *shell = NULL, *plain = NULL;
        size_t shell_len = 0, plain_len = 0;
        if (store_get(store, &ae->meta_id, &shell, &shell_len) != 0) return -1;
        if (store_get_cdc(store, &ae->body_id, &plain, &plain_len) != 0) {
            free(shell); return -1;
        }
        img3_dec_t d;
        memset(&d, 0, sizeof(d));
        d.shell = shell;
        d.shell_len = shell_len;
        d.data_off = (size_t)ae->data_off;
        d.data_len = (size_t)ae->data_len;
        memcpy(d.iv, ae->iv, 16);
        memcpy(d.key, ae->key, 32);
        int rc = img3_encrypt(&d, plain, plain_len, out, out_len);
        free(shell);
        free(plain);
        return rc;
    }

    if (ae->kind == PAY_ENCRCDSA) {
        uint8_t *meta = NULL, *plain = NULL;
        size_t meta_len = 0, plain_len = 0;
        if (store_get(store, &ae->meta_id, &meta, &meta_len) != 0) return -1;
        if (store_get_cdc(store, &ae->body_id, &plain, &plain_len) != 0) {
            free(meta); return -1;
        }
        if (meta_len < 20 || memcmp(meta, "ENCMETA2", 8) != 0) {
            free(meta); free(plain); return -1;
        }
        uint32_t hl = 0, tl = 0, pl = 0;
        memcpy(&hl, meta + 8, 4);
        memcpy(&tl, meta + 12, 4);
        memcpy(&pl, meta + 16, 4);
        if (20u + hl + tl + pl != meta_len) { free(meta); free(plain); return -1; }
        encrcdsa_info_t info;
        memset(&info, 0, sizeof(info));
        info.blocksize = ae->blocksize;
        info.datasize = ae->datasize;
        info.dataoffset = ae->data_off;
        info.total_len = ae->total_len;
        memcpy(info.aes_key, ae->key, 16);
        memcpy(info.hmac_key, ae->key + 16, 20);
        size_t mo = 20;
        info.header_len = hl;
        info.header = (uint8_t *)xmalloc(hl ? hl : 1);
        memcpy(info.header, meta + mo, hl); mo += hl;
        if (tl) {
            info.trailer_len = tl;
            info.trailer = (uint8_t *)xmalloc(tl);
            memcpy(info.trailer, meta + mo, tl); mo += tl;
        }
        if (pl) {
            info.tail_pad_len = pl;
            info.tail_pad = (uint8_t *)xmalloc(pl);
            memcpy(info.tail_pad, meta + mo, pl);
        }
        free(meta);
        int rc = encrcdsa_encrypt_file(&info, plain, plain_len, out, out_len);
        free(plain);
        encrcdsa_info_free(&info);
        return rc;
    }
    return -1;
}

static int load_scaffold_entry(objstore_t *store, const arc_entry_t *ae,
                               zip_entry_t *ze, int load_comp) {
    memset(ze, 0, sizeof(*ze));
    ze->name = xstrdup(ae->name);
    ze->method = ae->method;
    ze->gp_flag = ae->gp_flag;
    ze->ver_extract = ae->ver_extract;
    ze->ver_made = ae->ver_made;
    ze->crc32 = ae->crc32;
    ze->mod_time = ae->mod_time;
    ze->mod_date = ae->mod_date;
    ze->internal_attr = ae->internal_attr;
    ze->external_attr = ae->external_attr;
    ze->uncomp_size = ae->uncomp_size;
    ze->comp_size = ae->orig_comp_size;
    ze->local_header_off = 0;

    if (store_get(store, &ae->lh_id, &ze->local_header, &ze->local_header_len) != 0)
        return -1;
    if (store_get(store, &ae->cd_id, &ze->cd_header, &ze->cd_header_len) != 0)
        return -1;
    if (ae->has_dd) {
        if (store_get(store, &ae->dd_id, &ze->data_desc, &ze->data_desc_len) != 0)
            return -1;
    }
    if (load_comp) {
        if (store_get(store, &ae->comp_id, &ze->comp, &ze->comp_len) != 0)
            return -1;
        if (ze->comp_len != ae->orig_comp_size)
            return -1;
    }

    if (ze->cd_header_len >= 46) {
        ze->local_header_off =
            (uint32_t)ze->cd_header[42] |
            ((uint32_t)ze->cd_header[43] << 8) |
            ((uint32_t)ze->cd_header[44] << 16) |
            ((uint32_t)ze->cd_header[45] << 24);
    }
    return 0;
}

static int rebuild_one_ipsw(ipswarc_archive_t *a, const arc_ipsw_t *ia, size_t *offp,
                            uint8_t **out_ipsw, size_t *out_len) {
    size_t off = *offp;
    const uint8_t *man = a->man;
    size_t man_len = a->man_len;
    int exact = a->exact;
    int zlib128 = a->zlib128;

    zip_file_t z;
    memset(&z, 0, sizeof(z));
    z.count = ia->num_entries;
    z.entries = (zip_entry_t *)xmalloc(z.count * sizeof(zip_entry_t));
    memset(z.entries, 0, z.count * sizeof(zip_entry_t));

    size_t fp_len = z.count * SHA256_LEN;
    uint8_t *fp = (uint8_t *)xmalloc(fp_len ? fp_len : 1);

    if (exact) {
        if (store_get(&a->store, &ia->eocd_id, &z.eocd, &z.eocd_len) != 0) {
            set_err("load eocd for %s", ia->name);
            free(fp); zip_free(&z); return -1;
        }
        if (ia->prefix_len) {
            if (store_get(&a->store, &ia->prefix_id, &z.prefix, &z.prefix_len) != 0) {
                set_err("load prefix for %s", ia->name);
                free(fp); zip_free(&z); return -1;
            }
            if (z.prefix_len != ia->prefix_len) {
                set_err("prefix len mismatch for %s", ia->name);
                free(fp); zip_free(&z); return -1;
            }
        }
    }

    for (uint32_t j = 0; j < ia->num_entries; j++) {
        if (off + sizeof(arc_entry_t) > man_len) {
            set_err("entry truncated in %s", ia->name);
            free(fp); zip_free(&z); return -1;
        }
        arc_entry_t ae;
        memcpy(&ae, man + off, sizeof(ae));
        off += sizeof(ae);

        zip_entry_t *ze = &z.entries[j];

        if (exact && ae.has_scaffold && !zlib128) {
            if (load_scaffold_entry(&a->store, &ae, ze, 1) != 0) {
                set_err("load scaffold for %s", ae.name);
                free(fp); zip_free(&z); return -1;
            }
            memcpy(fp + j * SHA256_LEN, ae.entry_sha.dig, SHA256_LEN);
            continue;
        }

        if (exact && ae.has_scaffold) {
            if (load_scaffold_entry(&a->store, &ae, ze,
                                    ae.reflat != REFLAT_NONE ? 0 : 1) != 0) {
                set_err("load scaffold headers for %s", ae.name);
                free(fp); zip_free(&z); return -1;
            }
        } else {
            memset(ze, 0, sizeof(*ze));
            ze->name = xstrdup(ae.name);
            ze->crc32 = ae.crc32;
            ze->mod_time = ae.mod_time;
            ze->mod_date = ae.mod_date;
            ze->internal_attr = ae.internal_attr;
            ze->external_attr = ae.external_attr;
        }

        uint8_t *payload = NULL;
        size_t plen = 0;
        if (rebuild_entry_bytes(&a->store, &ae, &payload, &plen) != 0) {
            set_err("rebuild entry %s", ae.name);
            free(fp); zip_free(&z); return -1;
        }

        sha256_t got;
        sha256_buf(payload, plen, &got);
        if (!sha256_eq(&got, &ae.entry_sha)) {
            set_err("entry content SHA256 mismatch: %s", ae.name);
            free(payload); free(fp); zip_free(&z); return -1;
        }
        if (zip_crc32(payload, plen) != ae.crc32) {
            set_err("entry CRC mismatch: %s", ae.name);
            free(payload); free(fp); zip_free(&z); return -1;
        }

        ze->payload = payload;
        ze->payload_len = plen;
        ze->uncomp_size = (uint32_t)plen;

        if (exact && ae.has_scaffold && ae.reflat != REFLAT_NONE) {
            if (ae.method == 8) {
                uint8_t *comp = NULL;
                size_t clen = 0;
                int drc = -1;
                if (ae.reflat == REFLAT_ZLIB128)
                    drc = zip_deflate_raw_apple(payload, plen, &comp, &clen);
                else if (ae.reflat == REFLAT_INFOZIP6)
                    drc = zip_deflate_raw_infozip6(payload, plen, &comp, &clen);
                if (drc != 0) {
                    set_err("reflat deflate failed: %s (codec=%u)", ae.name, ae.reflat);
                    free(fp); zip_free(&z); return -1;
                }
                if (clen != ae.orig_comp_size) {
                    set_err("reflat size mismatch %s: got %zu expected %u",
                            ae.name, clen, ae.orig_comp_size);
                    free(comp); free(fp); zip_free(&z); return -1;
                }
                ze->comp = comp;
                ze->comp_len = clen;
                ze->comp_size = (uint32_t)clen;
            } else {
                ze->comp = (uint8_t *)xmalloc(plen ? plen : 1);
                if (plen) memcpy(ze->comp, payload, plen);
                ze->comp_len = plen;
                ze->comp_size = (uint32_t)plen;
            }
        } else if (!(exact && ae.has_scaffold)) {
            ze->comp_size = (uint32_t)plen;
        }
        memcpy(fp + j * SHA256_LEN, ae.entry_sha.dig, SHA256_LEN);
    }

    sha256_t content_sha;
    sha256_buf(fp, fp_len, &content_sha);
    free(fp);
    if (!sha256_eq(&content_sha, &ia->content_sha)) {
        set_err("content fingerprint mismatch for %s", ia->name);
        zip_free(&z); return -1;
    }

    uint8_t *built = NULL;
    size_t blen = 0;
    if (exact) {
        if (zip_rebuild_exact(&z, &built, &blen) != 0) {
            set_err("exact zip rebuild failed for %s", ia->name);
            zip_free(&z); return -1;
        }
    } else {
        if (zip_rebuild_store(&z, &built, &blen) != 0) {
            set_err("zip rebuild failed for %s", ia->name);
            zip_free(&z); return -1;
        }
    }
    zip_free(&z);

    sha256_t out_sha;
    sha256_buf(built, blen, &out_sha);
    if (!sha256_eq(&out_sha, &ia->orig_sha)) {
        set_err("IPSW SHA256 mismatch after rebuild: %s", ia->name);
        free(built); return -1;
    }

    *offp = off;
    *out_ipsw = built;
    *out_len = blen;
    return 0;
}

static int ipswarc_open_with_reader(const ipswarc_reader_t *r, int own_fp, FILE *fp,
                                    ipswarc_archive_t **out) {
    *out = NULL;
    if (!r || !r->seek || !r->read) { set_err("bad reader"); return -1; }

    if (reader_seek(r, 0) != 0) {
        set_err("seek start failed");
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    char magic[IPSWARC_WRAP_MAGIC_LEN];
    if (reader_read(r, magic, IPSWARC_WRAP_MAGIC_LEN) != 0 ||
        memcmp(magic, IPSWARC_WRAP_MAGIC, IPSWARC_WRAP_MAGIC_LEN) != 0) {
        set_err("bad wrapper magic");
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    uint64_t man_len = 0, blob_len = 0, idx_len = 0;
    if (reader_read(r, &man_len, 8) != 0 || man_len == 0 || man_len > (1ull << 30)) {
        set_err("bad manifest length");
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    uint8_t *man = (uint8_t *)malloc((size_t)man_len);
    if (!man) {
        set_err("out of memory");
        if (own_fp && fp) fclose(fp);
        return -1;
    }
    if (reader_read(r, man, (size_t)man_len) != 0) {
        set_err("short manifest read");
        free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    if (reader_read(r, &blob_len, 8) != 0) {
        set_err("bad blob length");
        free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }
    /* Absolute offset of blob payload = 9 + 8 + man_len + 8 */
    uint64_t blob_off = (uint64_t)IPSWARC_WRAP_MAGIC_LEN + 8ull + man_len + 8ull;
    if (reader_seek(r, blob_off + blob_len) != 0) {
        set_err("seek past blob failed");
        free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    if (reader_read(r, &idx_len, 8) != 0 || idx_len == 0 || idx_len > (1ull << 28)) {
        set_err("bad index length");
        free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }
    uint8_t *idx = (uint8_t *)malloc((size_t)idx_len);
    if (!idx) {
        set_err("out of memory");
        free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }
    if (reader_read(r, idx, (size_t)idx_len) != 0) {
        set_err("short index read");
        free(idx); free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    if (man_len < sizeof(arc_header_t)) {
        set_err("short manifest");
        free(idx); free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }
    arc_header_t hdr;
    memcpy(&hdr, man, sizeof(hdr));
    if (memcmp(hdr.magic, IPSWARC_MAGIC, 8) != 0) {
        set_err("bad manifest magic");
        free(idx); free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }

    ipswarc_archive_t *a = (ipswarc_archive_t *)calloc(1, sizeof(*a));
    if (!a) {
        set_err("out of memory");
        free(idx); free(man);
        if (own_fp && fp) fclose(fp);
        return -1;
    }
    a->fp = fp;
    a->fp_owned = own_fp;
    a->reader = *r;
    a->man = man;
    a->man_len = (size_t)man_len;
    a->hdr = hdr;
    a->exact = (hdr.flags & IPSWARC_FLAG_EXACT) != 0;
    a->zlib128 = (hdr.flags & IPSWARC_FLAG_ZLIB128) != 0;
    keydb_init(&a->keys);

    store_reader_t sr;
    sr.seek = r->seek;
    sr.read = r->read;
    sr.ctx = r->ctx;
    if (store_open_embedded_reader(&a->store, &sr, blob_off, blob_len, idx, (size_t)idx_len) != 0) {
        set_err("open embedded store failed");
        free(idx); ipswarc_close(a); return -1;
    }
    free(idx);

    size_t off = sizeof(arc_header_t);
    if (load_keys_from_manifest(&a->keys, man, (size_t)man_len, &off, hdr.num_keys) != 0) {
        set_err("truncated keydb in manifest");
        ipswarc_close(a); return -1;
    }

    a->num_ipsw = hdr.num_ipsw;
    a->items = (ipswarc_item_t *)calloc(a->num_ipsw ? a->num_ipsw : 1, sizeof(ipswarc_item_t));
    if (!a->items) { set_err("out of memory"); ipswarc_close(a); return -1; }

    for (uint32_t i = 0; i < hdr.num_ipsw; i++) {
        if (off + sizeof(arc_ipsw_t) > (size_t)man_len) {
            set_err("manifest truncated at IPSW %u", i);
            ipswarc_close(a); return -1;
        }
        arc_ipsw_t ia;
        memcpy(&ia, man + off, sizeof(ia));
        a->items[i].man_off = off;
        memcpy(a->items[i].name, ia.name, sizeof(ia.name));
        a->items[i].name[sizeof(a->items[i].name) - 1] = 0;
        a->items[i].orig_size = ia.orig_size;
        a->items[i].mod_time = ia.mod_time0;
        a->items[i].mod_date = ia.mod_date0;
        a->items[i].orig_sha = ia.orig_sha;
        ipsw_plist_name(a->items[i].name, a->items[i].plist_name,
                        sizeof(a->items[i].plist_name));

        char device[64] = {0}, build[32] = {0};
        ipsw_parse_name(a->items[i].name, device, sizeof(device), build, sizeof(build));
        if (keydb_to_plist_xml(&a->keys, device, build,
                               &a->items[i].plist_xml, &a->items[i].plist_xml_len) != 0) {
            a->items[i].plist_xml = xstrdup(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<plist version=\"1.0\"><dict/></plist>\n");
            a->items[i].plist_xml_len = strlen(a->items[i].plist_xml);
        }

        off += sizeof(arc_ipsw_t);
        size_t ent_bytes = (size_t)ia.num_entries * sizeof(arc_entry_t);
        if (off + ent_bytes > (size_t)man_len) {
            set_err("manifest truncated in entries for %s", ia.name);
            ipswarc_close(a); return -1;
        }
        off += ent_bytes;
    }

    if (a->zlib128)
        zip_require_zlib128();

    *out = a;
    return 0;
}

int ipswarc_open_reader(const ipswarc_reader_t *reader, ipswarc_archive_t **out) {
    g_err[0] = 0;
    return ipswarc_open_with_reader(reader, 0, NULL, out);
}

int ipswarc_open(const char *path, ipswarc_archive_t **out) {
    g_err[0] = 0;
    *out = NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) { set_err("cannot open %s", path); return -1; }
    ipswarc_reader_t r = { file_seek, file_read, fp };
    return ipswarc_open_with_reader(&r, 1, fp, out);
}

#ifdef _WIN32
int ipswarc_open_w(const wchar_t *path, ipswarc_archive_t **out) {
    g_err[0] = 0;
    *out = NULL;
    FILE *fp = _wfopen(path, L"rb");
    if (!fp) { set_err("cannot open archive"); return -1; }
    ipswarc_reader_t r = { file_seek, file_read, fp };
    return ipswarc_open_with_reader(&r, 1, fp, out);
}
#endif

void ipswarc_close(ipswarc_archive_t *a) {
    if (!a) return;
    store_close(&a->store);
    keydb_free(&a->keys);
    if (a->fp && a->fp_owned) fclose(a->fp);
    if (a->items) {
        for (uint32_t i = 0; i < a->num_ipsw; i++)
            free(a->items[i].plist_xml);
    }
    free(a->man);
    free(a->items);
    free(a);
}

uint32_t ipswarc_num_ipsw(const ipswarc_archive_t *a) {
    return a ? a->num_ipsw : 0;
}

uint32_t ipswarc_num_items(const ipswarc_archive_t *a) {
    return a ? a->num_ipsw * 2u : 0;
}

int ipswarc_item_is_plist(const ipswarc_archive_t *a, uint32_t index) {
    return a && (index & 1u) != 0;
}

int ipswarc_item_info(const ipswarc_archive_t *a, uint32_t index,
                      const char **name, uint64_t *orig_size,
                      uint16_t *mod_time, uint16_t *mod_date) {
    if (!a || index >= a->num_ipsw * 2u) return -1;
    uint32_t ip = index / 2u;
    int is_plist = (index & 1u) != 0;
    const ipswarc_item_t *it = &a->items[ip];
    if (name) *name = is_plist ? it->plist_name : it->name;
    if (orig_size) *orig_size = is_plist ? (uint64_t)it->plist_xml_len : it->orig_size;
    if (mod_time) *mod_time = it->mod_time;
    if (mod_date) *mod_date = it->mod_date;
    return 0;
}

int ipswarc_extract_mem(ipswarc_archive_t *a, uint32_t index,
                        uint8_t **out_data, size_t *out_len) {
    g_err[0] = 0;
    if (!a || index >= a->num_ipsw * 2u || !out_data || !out_len) {
        set_err("invalid extract arguments");
        return -1;
    }
    *out_data = NULL;
    *out_len = 0;

    uint32_t ip = index / 2u;
    if (index & 1u) {
        const ipswarc_item_t *it = &a->items[ip];
        size_t n = it->plist_xml_len;
        uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
        if (!buf) { set_err("out of memory"); return -1; }
        if (n && it->plist_xml) memcpy(buf, it->plist_xml, n);
        *out_data = buf;
        *out_len = n;
        return 0;
    }

    size_t off = a->items[ip].man_off;
    arc_ipsw_t ia;
    memcpy(&ia, a->man + off, sizeof(ia));
    off += sizeof(ia);

    return rebuild_one_ipsw(a, &ia, &off, out_data, out_len);
}

int ipswarc_extract_to(ipswarc_archive_t *a, uint32_t index,
                       ipswarc_write_fn write_fn, void *ctx) {
    uint8_t *data = NULL;
    size_t len = 0;
    if (ipswarc_extract_mem(a, index, &data, &len) != 0)
        return -1;
    int rc = write_fn(data, len, ctx);
    free(data);
    return rc;
}

int ipswarc_extract_file(ipswarc_archive_t *a, uint32_t index, const char *out_path) {
    uint8_t *data = NULL;
    size_t len = 0;
    if (ipswarc_extract_mem(a, index, &data, &len) != 0)
        return -1;
    int rc = write_file(out_path, data, len);
    free(data);
    if (rc != 0) set_err("write %s failed", out_path);
    return rc;
}

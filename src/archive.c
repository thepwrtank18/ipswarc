#include "archive.h"
#include "arcfmt.h"
#include "ipswarc_lib.h"
#include "zip.h"
#include "infozip.h"
#include "img3.h"
#include "encrcdsa.h"
#include "store.h"
#include <windows.h>

static void path_join(char *dst, size_t dst_sz, const char *a, const char *b) {
    snprintf(dst, dst_sz, "%s\\%s", a, b);
}

static int ensure_dir(const char *path) {
    return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

int cmd_keys(const char *input_dir) {
    keydb_t keys;
    keydb_init(&keys);
    keydb_load_dir(&keys, input_dir);
    if (keys.count == 0) {
        /* One-shot migration: scrape wiki HTML if no plists yet. */
        keydb_load_dir_htm(&keys, input_dir);
        if (keys.count)
            fprintf(stderr, "loaded %zu keys from HTML (writing plists)\n", keys.count);
    } else {
        fprintf(stderr, "loaded %zu keys from plist\n", keys.count);
    }

    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.ipsw", input_dir);
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        keydb_dump(&keys, stdout);
        keydb_free(&keys);
        return keys.count ? 0 : 1;
    }
    int wrote = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char device[64] = {0}, build[32] = {0};
        ipsw_parse_name(fd.cFileName, device, sizeof(device), build, sizeof(build));
        char plist_name[MAX_PATH], outp[MAX_PATH];
        ipsw_plist_name(fd.cFileName, plist_name, sizeof(plist_name));
        path_join(outp, sizeof(outp), input_dir, plist_name);
        if (keydb_write_plist(&keys, device, build, outp) != 0)
            warnx("failed to write %s", outp);
        else {
            fprintf(stderr, "wrote %s\n", outp);
            wrote++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    keydb_free(&keys);
    if (!wrote)
        fprintf(stderr, "no IPSWs found to write plists for\n");
    return wrote ? 0 : 1;
}

int cmd_pack(const char *input_dir, const char *arc_path) {
    zip_require_zlib128();
    keydb_t keys;
    keydb_init(&keys);
    keydb_load_dir(&keys, input_dir);
    fprintf(stderr, "loaded %zu firmware keys from plist\n", keys.count);

    /* pack -o expects a file. If the user passes a directory, write out.ipswarc inside it. */
    char arc_resolved[MAX_PATH];
    {
        size_t n = strlen(arc_path);
        DWORD attr = GetFileAttributesA(arc_path);
        int is_dir = (attr != INVALID_FILE_ATTRIBUTES &&
                      (attr & FILE_ATTRIBUTE_DIRECTORY)) ||
                     (n > 0 && (arc_path[n - 1] == '\\' || arc_path[n - 1] == '/'));
        if (is_dir) {
            if (n > 0 && (arc_path[n - 1] == '\\' || arc_path[n - 1] == '/'))
                snprintf(arc_resolved, sizeof(arc_resolved), "%sout.ipswarc", arc_path);
            else
                snprintf(arc_resolved, sizeof(arc_resolved), "%s\\out.ipswarc", arc_path);
            arc_path = arc_resolved;
            fprintf(stderr, "pack -o is a directory; writing %s\n", arc_path);
        }
    }

    char tmpdir[MAX_PATH];
    snprintf(tmpdir, sizeof(tmpdir), "%s.store", arc_path);
    ensure_dir(tmpdir);

    objstore_t store;
    if (store_create(&store, tmpdir) != 0)
        die("cannot create object store at %s", tmpdir);

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.ipsw", input_dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) die("no .ipsw files in %s", input_dir);

    arc_ipsw_t *ipsws = NULL;
    size_t nipsw = 0, cap_ipsw = 0;
    arc_entry_t *all_entries = NULL;
    size_t nentries = 0, cap_ent = 0;
    uint32_t *ent_counts = NULL;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char ipath[MAX_PATH];
        path_join(ipath, sizeof(ipath), input_dir, fd.cFileName);
        fprintf(stderr, "packing %s ...\n", fd.cFileName);

        uint8_t *raw = NULL;
        size_t raw_len = 0;
        if (read_file(ipath, &raw, &raw_len) != 0) die("read %s", ipath);

        sha256_t file_sha;
        sha256_buf(raw, raw_len, &file_sha);

        zip_file_t z;
        if (zip_parse(raw, raw_len, &z) != 0)
            die("zip parse/inflate failed: %s", ipath);

        char device[64], build[32];
        ipsw_parse_name(fd.cFileName, device, sizeof(device), build, sizeof(build));
        fprintf(stderr, "  device=%s build=%s entries=%zu\n", device, build, z.count);

        if (nipsw == cap_ipsw) {
            cap_ipsw = cap_ipsw ? cap_ipsw * 2 : 8;
            ipsws = (arc_ipsw_t *)xrealloc(ipsws, cap_ipsw * sizeof(arc_ipsw_t));
            ent_counts = (uint32_t *)xrealloc(ent_counts, cap_ipsw * sizeof(uint32_t));
        }
        arc_ipsw_t *ia = &ipsws[nipsw];
        memset(ia, 0, sizeof(*ia));
        snprintf(ia->name, sizeof(ia->name), "%s", fd.cFileName);
        ia->orig_sha = file_sha;
        ia->orig_size = raw_len;

        /* Scaffold (headers) + regenerable payloads via zlib 1.2.8 / decrypt CDC. */
        if (store_put_raw(&store, z.eocd, z.eocd_len, &ia->eocd_id) != 0)
            die("store eocd");
        ia->prefix_len = (uint32_t)z.prefix_len;
        if (z.prefix_len) {
            if (store_put_raw(&store, z.prefix, z.prefix_len, &ia->prefix_id) != 0)
                die("store prefix");
        }

        size_t fp_len = z.count * SHA256_LEN;
        uint8_t *fp = (uint8_t *)xmalloc(fp_len ? fp_len : 1);

        uint32_t local_ents = 0;
        for (size_t ei = 0; ei < z.count; ei++) {
            zip_entry_t *ze = &z.entries[ei];
            if (nentries == cap_ent) {
                cap_ent = cap_ent ? cap_ent * 2 : 64;
                all_entries = (arc_entry_t *)xrealloc(all_entries, cap_ent * sizeof(arc_entry_t));
            }
            arc_entry_t *ae = &all_entries[nentries];
            memset(ae, 0, sizeof(*ae));
            snprintf(ae->name, sizeof(ae->name), "%s", ze->name);
            ae->crc32 = ze->crc32;
            ae->uncomp_size = (uint32_t)ze->payload_len;
            ae->mod_time = ze->mod_time;
            ae->mod_date = ze->mod_date;
            ae->internal_attr = ze->internal_attr;
            ae->external_attr = ze->external_attr;
            ae->method = ze->method;
            ae->gp_flag = ze->gp_flag;
            ae->ver_extract = ze->ver_extract;
            ae->ver_made = ze->ver_made;
            ae->orig_comp_size = ze->comp_size;
            sha256_buf(ze->payload, ze->payload_len, &ae->entry_sha);
            memcpy(fp + ei * SHA256_LEN, ae->entry_sha.dig, SHA256_LEN);

            if (store_put_raw(&store, ze->local_header, ze->local_header_len, &ae->lh_id) != 0)
                die("store local header");
            if (store_put_raw(&store, ze->cd_header, ze->cd_header_len, &ae->cd_id) != 0)
                die("store cd header");
            if (ze->data_desc_len) {
                if (store_put_raw(&store, ze->data_desc, ze->data_desc_len, &ae->dd_id) != 0)
                    die("store data desc");
                ae->has_dd = 1;
            }
            ae->has_scaffold = 1;

            /* Prefer regenerating method-8. Classic non-Darwin iPod_* IPSWs use
             * Info-ZIP 3.0 -6; Darwin IPSWs use zlib 1.2.8. */
            if (ze->method == 8) {
                int prefer_infozip = (strncmp(fd.cFileName, "iPod_", 5) == 0 &&
                                      strchr(fd.cFileName, ',') == NULL);
                if (ze->comp_len >= (16u * 1024u * 1024u))
                    fprintf(stderr, "  verifying reflat %s (%.1f MB)...\n",
                            ze->name, ze->payload_len / (1024.0 * 1024.0));
                int matched = 0;
                if (prefer_infozip) {
                    if (zip_deflate_matches_infozip6(ze->payload, ze->payload_len,
                                                     ze->comp, ze->comp_len)) {
                        ae->reflat = REFLAT_INFOZIP6;
                        fprintf(stderr, "  infozip6 match %s\n", ze->name);
                        matched = 1;
                    } else if (zip_deflate_matches(ze->payload, ze->payload_len,
                                                   ze->comp, ze->comp_len)) {
                        ae->reflat = REFLAT_ZLIB128;
                        matched = 1;
                    }
                } else {
                    if (zip_deflate_matches(ze->payload, ze->payload_len,
                                            ze->comp, ze->comp_len)) {
                        ae->reflat = REFLAT_ZLIB128;
                        matched = 1;
                    } else if (zip_deflate_matches_infozip6(ze->payload, ze->payload_len,
                                                            ze->comp, ze->comp_len)) {
                        ae->reflat = REFLAT_INFOZIP6;
                        fprintf(stderr, "  infozip6 match %s\n", ze->name);
                        matched = 1;
                    }
                }
                if (!matched) {
                    warnx("no reflat match for %s — storing original DEFLATE", ze->name);
                    if (store_put_raw(&store, ze->comp, ze->comp_len, &ae->comp_id) != 0)
                        die("store comp fallback");
                    ae->reflat = REFLAT_NONE;
                }
            } else {
                /* method 0: payload bytes are the ZIP payload */
                ae->reflat = REFLAT_ZLIB128;
            }

            const key_entry_t *ke = keydb_find(&keys, build, ze->name);
            int handled = 0;

            if (ke && ke->kind == KEY_KIND_IMG3 && ze->payload_len > 0 &&
                img3_is(ze->payload, ze->payload_len)) {
                img3_dec_t dec;
                if (img3_decrypt(ze->payload, ze->payload_len, ke->iv, ke->key, &dec) == 0) {
                    ae->kind = PAY_IMG3;
                    memcpy(ae->iv, ke->iv, 16);
                    memcpy(ae->key, ke->key, 32);
                    ae->key_len = 32;
                    ae->has_iv = 1;
                    ae->data_off = dec.data_off;
                    ae->data_len = dec.data_len;
                    ae->total_len = dec.shell_len;
                    memset(dec.shell + dec.data_off, 0, dec.data_len);
                    sha256_t meta_id, body_id;
                    if (store_put(&store, dec.shell, dec.shell_len, &meta_id) != 0)
                        die("store img3 meta");
                    if (store_put_cdc(&store, dec.plain, dec.plain_len, &body_id) != 0)
                        die("store img3 body");
                    ae->meta_id = meta_id;
                    ae->body_id = body_id;
                    img3_dec_free(&dec);
                    handled = 1;
                    fprintf(stderr, "  img3 %s (%u bytes)\n", ze->name, ae->uncomp_size);
                } else {
                    warnx("img3 decrypt failed for %s — storing raw", ze->name);
                }
            } else if (ke && ke->kind == KEY_KIND_ROOTFS && ze->payload_len > 0 &&
                       encrcdsa_is(ze->payload, ze->payload_len)) {
                encrcdsa_info_t info;
                if (encrcdsa_parse(ze->payload, ze->payload_len, ke->key, &info) == 0) {
                    uint8_t *plain = NULL;
                    size_t plain_len = 0;
                    fprintf(stderr, "  decrypting rootfs %s (%.1f MB)...\n",
                            ze->name, ze->payload_len / (1024.0 * 1024.0));
                    if (encrcdsa_decrypt_body(ze->payload, ze->payload_len, &info,
                                              &plain, &plain_len) != 0)
                        die("rootfs decrypt failed: %s", ze->name);

                    size_t meta_len = 20 + info.header_len + info.trailer_len + info.tail_pad_len;
                    uint8_t *meta = (uint8_t *)xmalloc(meta_len);
                    memcpy(meta, "ENCMETA2", 8);
                    uint32_t hl = (uint32_t)info.header_len;
                    uint32_t tl = (uint32_t)info.trailer_len;
                    uint32_t pl = (uint32_t)info.tail_pad_len;
                    memcpy(meta + 8, &hl, 4);
                    memcpy(meta + 12, &tl, 4);
                    memcpy(meta + 16, &pl, 4);
                    size_t mo = 20;
                    memcpy(meta + mo, info.header, info.header_len); mo += info.header_len;
                    if (info.trailer_len) {
                        memcpy(meta + mo, info.trailer, info.trailer_len);
                        mo += info.trailer_len;
                    }
                    if (info.tail_pad_len)
                        memcpy(meta + mo, info.tail_pad, info.tail_pad_len);

                    sha256_t meta_id, body_id;
                    if (store_put(&store, meta, meta_len, &meta_id) != 0) die("store encr meta");
                    free(meta);
                    fprintf(stderr, "  compressing rootfs plaintext (%.1f MB, CDC+LZMA)...\n",
                            plain_len / (1024.0 * 1024.0));
                    if (store_put_cdc(&store, plain, plain_len, &body_id) != 0)
                        die("store rootfs body");
                    free(plain);

                    ae->kind = PAY_ENCRCDSA;
                    memcpy(ae->key, ke->key, 36);
                    ae->key_len = 36;
                    ae->meta_id = meta_id;
                    ae->body_id = body_id;
                    ae->blocksize = info.blocksize;
                    ae->datasize = info.datasize;
                    ae->data_off = info.dataoffset;
                    ae->data_len = info.datasize;
                    ae->total_len = info.total_len;
                    encrcdsa_info_free(&info);
                    handled = 1;
                    fprintf(stderr, "  encrcdsa %s ok\n", ze->name);
                } else {
                    warnx("encrcdsa parse failed for %s — storing raw", ze->name);
                }
            }

            if (!handled) {
                ae->kind = PAY_RAW;
                sha256_t body_id;
                if (store_put_cdc(&store, ze->payload, ze->payload_len, &body_id) != 0)
                    die("store raw");
                ae->body_id = body_id;
            }

            nentries++;
            local_ents++;
        }

        sha256_buf(fp, fp_len, &ia->content_sha);
        free(fp);
        ent_counts[nipsw] = local_ents;
        ia->num_entries = local_ents;
        nipsw++;
        zip_free(&z);
        free(raw);
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (store_flush_index(&store) != 0) die("flush store index");

    char man_path[MAX_PATH];
    path_join(man_path, sizeof(man_path), tmpdir, "manifest.bin");
    FILE *mf = fopen(man_path, "wb");
    if (!mf) die("manifest");

    arc_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, IPSWARC_MAGIC, 8);
    hdr.version = IPSWARC_VERSION;
    hdr.flags = IPSWARC_FLAG_EXACT | IPSWARC_FLAG_ZLIB128 | IPSWARC_FLAG_INFOZIP6;
    hdr.num_ipsw = (uint32_t)nipsw;
    hdr.num_keys = (uint32_t)keys.count;
    fwrite(&hdr, sizeof(hdr), 1, mf);

    for (size_t i = 0; i < keys.count; i++) {
        key_entry_t *ke = &keys.items[i];
        uint16_t bl = (uint16_t)strlen(ke->build);
        uint16_t dl = (uint16_t)strlen(ke->device);
        uint16_t fl = (uint16_t)strlen(ke->filename);
        uint16_t cl = (uint16_t)strlen(ke->component);
        fwrite(&bl, 2, 1, mf); fwrite(ke->build, 1, bl, mf);
        fwrite(&dl, 2, 1, mf); fwrite(ke->device, 1, dl, mf);
        fwrite(&fl, 2, 1, mf); fwrite(ke->filename, 1, fl, mf);
        fwrite(&cl, 2, 1, mf); fwrite(ke->component, 1, cl, mf);
        uint8_t kind = (uint8_t)ke->kind;
        fwrite(&kind, 1, 1, mf);
        fwrite(&ke->has_iv, 1, 1, mf);
        fwrite(ke->iv, 16, 1, mf);
        uint8_t klen = (uint8_t)ke->key_len;
        fwrite(&klen, 1, 1, mf);
        fwrite(ke->key, 1, ke->key_len, mf);
    }

    size_t ent_cursor = 0;
    for (size_t i = 0; i < nipsw; i++) {
        fwrite(&ipsws[i], sizeof(arc_ipsw_t), 1, mf);
        for (uint32_t j = 0; j < ent_counts[i]; j++)
            fwrite(&all_entries[ent_cursor + j], sizeof(arc_entry_t), 1, mf);
        ent_cursor += ent_counts[i];
    }
    fclose(mf);

    char blob_path[MAX_PATH], idx_path[MAX_PATH];
    snprintf(blob_path, sizeof(blob_path), "%s", store.blob_path);
    snprintf(idx_path, sizeof(idx_path), "%s", store.index_path);
    uint64_t blob_len = store.blob_end;
    if (store.blob) { fflush(store.blob); fclose(store.blob); store.blob = NULL; }

    uint8_t *man = NULL;
    size_t man_len = 0;
    if (read_file(man_path, &man, &man_len) != 0) die("read manifest");
    int64_t idx_sz = file_size64(idx_path);
    if (idx_sz < 0) die("stat index");
    uint64_t idx_len = (uint64_t)idx_sz;

    fprintf(stderr, "wrapping archive (blob %.2f GB)...\n",
            blob_len / (1024.0 * 1024.0 * 1024.0));

    FILE *out = fopen(arc_path, "wb");
    if (!out) die("write %s", arc_path);
    if (fwrite(IPSWARC_WRAP_MAGIC, IPSWARC_WRAP_MAGIC_LEN, 1, out) != 1) die("write magic");

    uint64_t u = man_len;
    if (fwrite(&u, 8, 1, out) != 1 || fwrite(man, 1, man_len, out) != man_len)
        die("write manifest");
    free(man);

    u = blob_len;
    if (fwrite(&u, 8, 1, out) != 1) die("write blob size");
    uint64_t copied = 0;
    if (stream_copy_path_to_file(out, blob_path, &copied) != 0 || copied != blob_len)
        die("stream blob into archive (copied %llu / %llu)",
            (unsigned long long)copied, (unsigned long long)blob_len);

    u = idx_len;
    if (fwrite(&u, 8, 1, out) != 1) die("write index size");
    copied = 0;
    if (stream_copy_path_to_file(out, idx_path, &copied) != 0 || copied != idx_len)
        die("stream index into archive");
    fclose(out);

    store_close(&store);
    /* Reclaim the temporary object store now that the archive is self-contained. */
    {
        char delcmd[MAX_PATH * 2];
        snprintf(delcmd, sizeof(delcmd), "cmd /c rmdir /s /q \"%s\"", tmpdir);
        system(delcmd);
    }
    keydb_free(&keys);
    free(ipsws); free(all_entries); free(ent_counts);

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(arc_path, GetFileExInfoStandard, &fad)) {
        double mb = ((double)fad.nFileSizeHigh * 4294967296.0 + (double)fad.nFileSizeLow)
                    / (1024.0 * 1024.0);
        fprintf(stderr, "wrote %s (%.2f MB)\n", arc_path, mb);
    } else {
        fprintf(stderr, "wrote %s\n", arc_path);
    }
    return 0;
}

int cmd_unpack(const char *arc_path, const char *output_dir) {
    ensure_dir(output_dir);
    ipswarc_archive_t *a = NULL;
    if (ipswarc_open(arc_path, &a) != 0)
        die("%s", ipswarc_last_error());

    uint32_t n = ipswarc_num_items(a);
    fprintf(stderr, "unpacking %u IPSW(s) (+ key plists) from %s...\n",
            ipswarc_num_ipsw(a), arc_path);
    for (uint32_t i = 0; i < n; i++) {
        const char *name = NULL;
        uint64_t sz = 0;
        ipswarc_item_info(a, i, &name, &sz, NULL, NULL);
        if (ipswarc_item_is_plist(a, i))
            fprintf(stderr, "writing keys %s...\n", name);
        else
            fprintf(stderr, "unpacking %s (%.2f MB)...\n", name, sz / (1024.0 * 1024.0));
        char outp[MAX_PATH];
        path_join(outp, sizeof(outp), output_dir, name);
        if (ipswarc_extract_file(a, i, outp) != 0)
            die("%s", ipswarc_last_error());
        fprintf(stderr, "  wrote %s%s\n", name,
                ipswarc_item_is_plist(a, i) ? "" : " SHA256 OK");
    }
    ipswarc_close(a);
    fprintf(stderr, "unpack complete -> %s\n", output_dir);
    return 0;
}

int cmd_verify(const char *arc_path, const char *input_dir) {
    char tmpout[MAX_PATH];
    snprintf(tmpout, sizeof(tmpout), "%s\\_verify_out", input_dir);
    ensure_dir(tmpout);
    if (cmd_unpack(arc_path, tmpout) != 0) return 1;

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.ipsw", input_dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) die("no ipsw");
    int ok = 1;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char a[MAX_PATH], b[MAX_PATH];
        path_join(a, sizeof(a), input_dir, fd.cFileName);
        path_join(b, sizeof(b), tmpout, fd.cFileName);

        sha256_t sa, sb;
        if (sha256_file(a, &sa) != 0 || sha256_file(b, &sb) != 0) {
            fprintf(stderr, "FAIL missing %s\n", fd.cFileName);
            ok = 0;
            continue;
        }
        if (!sha256_eq(&sa, &sb)) {
            char ha[65], hb[65];
            hex_encode(sa.dig, 32, ha);
            hex_encode(sb.dig, 32, hb);
            fprintf(stderr, "FAIL SHA256 %s\n  orig %s\n  out  %s\n", fd.cFileName, ha, hb);
            ok = 0;
        } else {
            fprintf(stderr, "OK SHA256 %s\n", fd.cFileName);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return ok ? 0 : 1;
}

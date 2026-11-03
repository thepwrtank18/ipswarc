#include "keys.h"
#include <ctype.h>
#include <windows.h>

void keydb_init(keydb_t *db) {
    memset(db, 0, sizeof(*db));
}

void keydb_free(keydb_t *db) {
    for (size_t i = 0; i < db->count; i++) {
        free(db->items[i].build);
        free(db->items[i].device);
        free(db->items[i].filename);
        free(db->items[i].component);
    }
    free(db->items);
    memset(db, 0, sizeof(*db));
}

static void keydb_push(keydb_t *db, key_entry_t *e) {
    if (db->count == db->cap) {
        db->cap = db->cap ? db->cap * 2 : 32;
        db->items = (key_entry_t *)xrealloc(db->items, db->cap * sizeof(key_entry_t));
    }
    db->items[db->count++] = *e;
}

static void strip_tags(const char *html, char **out_text) {
    size_t n = strlen(html);
    char *buf = (char *)xmalloc(n + 1);
    size_t w = 0;
    int in_tag = 0, in_script = 0, in_style = 0;
    for (size_t i = 0; i < n; i++) {
        if (!in_tag && html[i] == '<') {
            if (_strnicmp(html + i, "<script", 7) == 0) in_script = 1;
            if (_strnicmp(html + i, "<style", 6) == 0) in_style = 1;
            if (_strnicmp(html + i, "</script", 8) == 0) { in_script = 0; }
            if (_strnicmp(html + i, "</style", 7) == 0) { in_style = 0; }
            in_tag = 1;
            if (!in_script && !in_style) buf[w++] = '\n';
            continue;
        }
        if (in_tag) {
            if (html[i] == '>') in_tag = 0;
            continue;
        }
        if (in_script || in_style) continue;
        if (html[i] == '&') {
            if (_strnicmp(html + i, "&nbsp;", 6) == 0) { buf[w++] = ' '; i += 5; continue; }
            if (_strnicmp(html + i, "&amp;", 5) == 0) { buf[w++] = '&'; i += 4; continue; }
            if (_strnicmp(html + i, "&#183;", 6) == 0) { buf[w++] = ' '; i += 5; continue; }
        }
        buf[w++] = html[i];
    }
    buf[w] = 0;
    *out_text = buf;
}

static int is_hex_str(const char *s, size_t want) {
    if (strlen(s) != want) return 0;
    for (size_t i = 0; i < want; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

static char **split_lines(char *text, size_t *nout) {
    size_t cap = 256, n = 0;
    char **lines = (char **)xmalloc(cap * sizeof(char *));
    char *p = text;
    while (*p) {
        while (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        char *start = p;
        while (*p && *p != '\n' && *p != '\r') p++;
        if (*p) { *p = 0; p++; }
        /* trim trailing */
        size_t L = strlen(start);
        while (L && (start[L - 1] == ' ' || start[L - 1] == '\t')) start[--L] = 0;
        if (!L) continue;
        if (n == cap) { cap *= 2; lines = (char **)xrealloc(lines, cap * sizeof(char *)); }
        lines[n++] = start;
    }
    *nout = n;
    return lines;
}

static int looks_component(const char *s) {
    return strcmp(s, "Root Filesystem") == 0 ||
           strcmp(s, "Update Ramdisk") == 0 ||
           strcmp(s, "Restore Ramdisk") == 0 ||
           strcmp(s, "Kernelcache") == 0 ||
           strcmp(s, "AppleLogo") == 0 ||
           strcmp(s, "BatteryCharging0") == 0 ||
           strcmp(s, "BatteryCharging1") == 0 ||
           strcmp(s, "BatteryFull") == 0 ||
           strcmp(s, "BatteryLow0") == 0 ||
           strcmp(s, "BatteryLow1") == 0 ||
           strcmp(s, "DeviceTree") == 0 ||
           strcmp(s, "GlyphCharging") == 0 ||
           strcmp(s, "GlyphPlugin") == 0 ||
           strcmp(s, "iBEC") == 0 ||
           strcmp(s, "iBoot") == 0 ||
           strcmp(s, "iBSS") == 0 ||
           strcmp(s, "LLB") == 0 ||
           strcmp(s, "RecoveryMode") == 0 ||
           strncmp(s, "Battery", 7) == 0 ||
           strncmp(s, "Glyph", 5) == 0;
}

int keydb_load_htm(keydb_t *db, const char *path) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_file(path, &raw, &raw_len) != 0) return -1;
    /* ensure NUL */
    raw = (uint8_t *)xrealloc(raw, raw_len + 1);
    raw[raw_len] = 0;

    char device[64] = {0}, build[32] = {0};
    /* Filename: Keys_BrightonMaps 10B329 (iPad2,6) - The Apple Wiki.htm */
    const char *base = path;
    for (const char *q = path; *q; q++) if (*q == '/' || *q == '\\') base = q + 1;
    const char *lp = strchr(base, '(');
    const char *rp = lp ? strchr(lp, ')') : NULL;
    if (lp && rp && rp > lp + 1) {
        size_t n = (size_t)(rp - lp - 1);
        if (n >= sizeof(device)) n = sizeof(device) - 1;
        memcpy(device, lp + 1, n);
    }
    for (const char *q = base; *q && *q != '('; q++) {
        if (isdigit((unsigned char)*q) && isdigit((unsigned char)q[1]) &&
            isalpha((unsigned char)q[2]) && isdigit((unsigned char)q[3])) {
            /* 10B329 style */
            size_t i = 0;
            while (q[i] && i < sizeof(build) - 1 && isalnum((unsigned char)q[i])) {
                build[i] = q[i];
                i++;
            }
            build[i] = 0;
            break;
        }
    }

    char *text = NULL;
    strip_tags((char *)raw, &text);
    free(raw);

    size_t nlines = 0;
    char **lines = split_lines(text, &nlines);

    for (size_t i = 0; i < nlines; i++) {
        if (!looks_component(lines[i])) continue;
        const char *comp = lines[i];
        const char *filename = NULL;
        const char *ivhex = NULL;
        const char *keyhex = NULL;
        size_t j = i + 1;
        for (; j < nlines && j < i + 16; j++) {
            if (looks_component(lines[j]) && j > i + 1) break;
            if (strcmp(lines[j], "Filename:") == 0 && j + 1 < nlines) {
                filename = lines[j + 1];
            } else if (strcmp(lines[j], "IV") == 0 && j + 2 < nlines && strcmp(lines[j + 1], ":") == 0) {
                ivhex = lines[j + 2];
            } else if (strcmp(lines[j], "Key") == 0 && j + 2 < nlines && strcmp(lines[j + 1], ":") == 0) {
                keyhex = lines[j + 2];
            }
        }
        if (!filename || !keyhex) continue;

        key_entry_t e;
        memset(&e, 0, sizeof(e));
        e.build = xstrdup(build);
        e.device = xstrdup(device);
        e.filename = xstrdup(filename);
        e.component = xstrdup(comp);

        if (strcmp(comp, "Root Filesystem") == 0) {
            if (!is_hex_str(keyhex, 72)) continue;
            e.kind = KEY_KIND_ROOTFS;
            e.key_len = 36;
            e.has_iv = 0;
            if (hex_decode(keyhex, e.key, 36) != 0) continue;
        } else {
            if (!ivhex || !is_hex_str(ivhex, 32) || !is_hex_str(keyhex, 64)) continue;
            e.kind = KEY_KIND_IMG3;
            e.key_len = 32;
            e.has_iv = 1;
            if (hex_decode(ivhex, e.iv, 16) != 0) continue;
            if (hex_decode(keyhex, e.key, 32) != 0) continue;
        }
        keydb_push(db, &e);
    }

    free(lines);
    free(text);
    return 0;
}

int keydb_load_dir_htm(keydb_t *db, const char *dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.htm", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        snprintf(pattern, sizeof(pattern), "%s\\*.html", dir);
        h = FindFirstFileA(pattern, &fd);
        if (h == INVALID_HANDLE_VALUE) return 0;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
        if (keydb_load_htm(db, path) != 0)
            warnx("failed to parse keys from %s", path);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return 0;
}

/* ---- XML plist I/O ---- */

static void xml_append(char **buf, size_t *len, size_t *cap, const char *s) {
    size_t n = strlen(s);
    if (*len + n + 1 > *cap) {
        size_t nc = *cap ? *cap : 256;
        while (nc < *len + n + 1) nc *= 2;
        *buf = (char *)xrealloc(*buf, nc);
        *cap = nc;
    }
    memcpy(*buf + *len, s, n + 1);
    *len += n;
}

static void xml_append_esc(char **buf, size_t *len, size_t *cap, const char *s) {
    for (; *s; s++) {
        const char *rep = NULL;
        char one[2] = { *s, 0 };
        if (*s == '&') rep = "&amp;";
        else if (*s == '<') rep = "&lt;";
        else if (*s == '>') rep = "&gt;";
        else if (*s == '"') rep = "&quot;";
        else rep = one;
        xml_append(buf, len, cap, rep);
    }
}

static int key_matches(const key_entry_t *e, const char *device, const char *build) {
    if (build && build[0] && e->build && e->build[0] && strcmp(e->build, build) != 0)
        return 0;
    if (device && device[0] && e->device && e->device[0] && strcmp(e->device, device) != 0)
        return 0;
    return 1;
}

int keydb_to_plist_xml(const keydb_t *db, const char *device, const char *build,
                       char **out_xml, size_t *out_len) {
    char *buf = NULL;
    size_t len = 0, cap = 0;
    xml_append(&buf, &len, &cap,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n");
    if (device && device[0]) {
        xml_append(&buf, &len, &cap, "\t<key>device</key>\n\t<string>");
        xml_append_esc(&buf, &len, &cap, device);
        xml_append(&buf, &len, &cap, "</string>\n");
    }
    if (build && build[0]) {
        xml_append(&buf, &len, &cap, "\t<key>build</key>\n\t<string>");
        xml_append_esc(&buf, &len, &cap, build);
        xml_append(&buf, &len, &cap, "</string>\n");
    }
    xml_append(&buf, &len, &cap, "\t<key>filenames</key>\n\t<dict>\n");

    for (size_t i = 0; i < db->count; i++) {
        const key_entry_t *e = &db->items[i];
        if (!key_matches(e, device, build)) continue;
        if (!e->filename || !e->filename[0]) continue;

        xml_append(&buf, &len, &cap, "\t\t<key>");
        xml_append_esc(&buf, &len, &cap, e->filename);
        xml_append(&buf, &len, &cap, "</key>\n\t\t<dict>\n");
        if (e->component && e->component[0]) {
            xml_append(&buf, &len, &cap, "\t\t\t<key>Name</key>\n\t\t\t<string>");
            xml_append_esc(&buf, &len, &cap, e->component);
            xml_append(&buf, &len, &cap, "</string>\n");
        }
        if (e->has_iv) {
            char hex[33];
            hex_encode(e->iv, 16, hex);
            xml_append(&buf, &len, &cap, "\t\t\t<key>IV</key>\n\t\t\t<string>");
            xml_append(&buf, &len, &cap, hex);
            xml_append(&buf, &len, &cap, "</string>\n");
        }
        {
            char hex[73];
            hex_encode(e->key, e->key_len, hex);
            xml_append(&buf, &len, &cap, "\t\t\t<key>Key</key>\n\t\t\t<string>");
            xml_append(&buf, &len, &cap, hex);
            xml_append(&buf, &len, &cap, "</string>\n");
        }
        xml_append(&buf, &len, &cap, "\t\t</dict>\n");
    }

    xml_append(&buf, &len, &cap, "\t</dict>\n</dict>\n</plist>\n");
    *out_xml = buf;
    *out_len = len;
    return 0;
}

int keydb_write_plist(const keydb_t *db, const char *device, const char *build,
                      const char *path) {
    char *xml = NULL;
    size_t len = 0;
    if (keydb_to_plist_xml(db, device, build, &xml, &len) != 0) return -1;
    int rc = write_file(path, (const uint8_t *)xml, len);
    free(xml);
    return rc;
}

static const char *plist_find_tag(const char *p, const char *tag) {
    char open[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    return strstr(p, open);
}

static int plist_read_string_after_key(const char *body, const char *key,
                                       char *out, size_t out_sz) {
    char pat[128];
    snprintf(pat, sizeof(pat), "<key>%s</key>", key);
    const char *k = strstr(body, pat);
    if (!k) return -1;
    const char *s = plist_find_tag(k + strlen(pat), "string");
    if (!s) return -1;
    s += 8; /* skip <string> */
    const char *e = strstr(s, "</string>");
    if (!e || e <= s) return -1;
    size_t n = (size_t)(e - s);
    if (n >= out_sz) n = out_sz - 1;
    memcpy(out, s, n);
    out[n] = 0;
    return 0;
}

/* Walk <key>filename</key><dict>...</dict> entries inside filenames dict. */
static int plist_parse_filenames(keydb_t *db, const char *device, const char *build,
                                 const char *dict_body, const char *dict_end) {
    const char *p = dict_body;
    while (p < dict_end) {
        const char *k = strstr(p, "<key>");
        if (!k || k >= dict_end) break;
        k += 5;
        const char *ke = strstr(k, "</key>");
        if (!ke || ke >= dict_end) break;
        char filename[512];
        size_t fn = (size_t)(ke - k);
        if (fn >= sizeof(filename)) fn = sizeof(filename) - 1;
        memcpy(filename, k, fn);
        filename[fn] = 0;

        const char *d = strstr(ke, "<dict>");
        if (!d || d >= dict_end) break;
        d += 6;
        const char *de = strstr(d, "</dict>");
        if (!de || de > dict_end) break;

        char name[128] = {0}, ivhex[64] = {0}, keyhex[80] = {0};
        char slice[4096];
        size_t sl = (size_t)(de - d);
        if (sl >= sizeof(slice)) sl = sizeof(slice) - 1;
        memcpy(slice, d, sl);
        slice[sl] = 0;

        plist_read_string_after_key(slice, "Name", name, sizeof(name));
        plist_read_string_after_key(slice, "IV", ivhex, sizeof(ivhex));
        if (plist_read_string_after_key(slice, "Key", keyhex, sizeof(keyhex)) != 0) {
            p = de + 7;
            continue;
        }

        key_entry_t e;
        memset(&e, 0, sizeof(e));
        e.build = xstrdup(build ? build : "");
        e.device = xstrdup(device ? device : "");
        e.filename = xstrdup(filename);
        e.component = xstrdup(name[0] ? name : "");

        if (strcmp(name, "Root Filesystem") == 0 ||
            (ivhex[0] == 0 && is_hex_str(keyhex, 72))) {
            if (!is_hex_str(keyhex, 72)) { p = de + 7; continue; }
            e.kind = KEY_KIND_ROOTFS;
            e.key_len = 36;
            e.has_iv = 0;
            if (hex_decode(keyhex, e.key, 36) != 0) { p = de + 7; continue; }
        } else {
            if (!is_hex_str(ivhex, 32) || !is_hex_str(keyhex, 64)) { p = de + 7; continue; }
            e.kind = KEY_KIND_IMG3;
            e.key_len = 32;
            e.has_iv = 1;
            if (hex_decode(ivhex, e.iv, 16) != 0) { p = de + 7; continue; }
            if (hex_decode(keyhex, e.key, 32) != 0) { p = de + 7; continue; }
        }
        keydb_push(db, &e);
        p = de + 7;
    }
    return 0;
}

int keydb_load_plist(keydb_t *db, const char *path) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_file(path, &raw, &raw_len) != 0) return -1;
    raw = (uint8_t *)xrealloc(raw, raw_len + 1);
    raw[raw_len] = 0;
    char *xml = (char *)raw;

    char device[64] = {0}, build[32] = {0};
    plist_read_string_after_key(xml, "device", device, sizeof(device));
    plist_read_string_after_key(xml, "build", build, sizeof(build));

    /* If device/build missing, try infer from filename. */
    if (!device[0] || !build[0]) {
        char d2[64] = {0}, b2[32] = {0};
        ipsw_parse_name(path, d2, sizeof(d2), b2, sizeof(b2));
        if (!device[0] && d2[0]) memcpy(device, d2, sizeof(device));
        if (!build[0] && b2[0]) memcpy(build, b2, sizeof(build));
    }

    const char *fk = strstr(xml, "<key>filenames</key>");
    if (!fk) { free(raw); return -1; }
    const char *dict = strstr(fk, "<dict>");
    if (!dict) { free(raw); return -1; }
    dict += 6;
    /* Find matching </dict> at filenames level — first </dict></dict> before </plist> */
    const char *end = strstr(dict, "</dict>");
    if (!end) { free(raw); return -1; }
    /* filenames dict may contain nested dicts; find the closing one that balances */
    int depth = 1;
    const char *scan = dict;
    const char *dict_end = NULL;
    while (*scan && depth) {
        const char *a = strstr(scan, "<dict>");
        const char *b = strstr(scan, "</dict>");
        if (!b) break;
        if (a && a < b) { depth++; scan = a + 6; }
        else {
            depth--;
            if (depth == 0) { dict_end = b; break; }
            scan = b + 7;
        }
    }
    if (!dict_end) { free(raw); return -1; }

    int rc = plist_parse_filenames(db, device, build, dict, dict_end);
    free(raw);
    return rc;
}

int keydb_load_dir(keydb_t *db, const char *dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.plist", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
        if (keydb_load_plist(db, path) != 0)
            warnx("failed to parse keys from %s", path);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return 0;
}

void ipsw_plist_name(const char *ipsw_name, char *dst, size_t dst_sz) {
    const char *base = ipsw_name;
    for (const char *q = ipsw_name; *q; q++)
        if (*q == '/' || *q == '\\') base = q + 1;
    snprintf(dst, dst_sz, "%s", base);
    size_t n = strlen(dst);
    if (n >= 5 && _stricmp(dst + n - 5, ".ipsw") == 0)
        snprintf(dst + n - 5, dst_sz - (n - 5), ".plist");
    else {
        if (n + 7 < dst_sz) memcpy(dst + n, ".plist", 7);
        else dst[dst_sz - 1] = 0;
    }
}

const key_entry_t *keydb_find(const keydb_t *db, const char *build,
                              const char *filename) {
    const char *base = filename;
    for (const char *q = filename; *q; q++) if (*q == '/' || *q == '\\') base = q + 1;
    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->items[i].filename, base) != 0) continue;
        if (build && build[0] && db->items[i].build[0] &&
            strcmp(db->items[i].build, build) != 0)
            continue;
        return &db->items[i];
    }
    return NULL;
}

void keydb_dump(const keydb_t *db, FILE *out) {
    fprintf(out, "%zu keys\n", db->count);
    for (size_t i = 0; i < db->count; i++) {
        const key_entry_t *e = &db->items[i];
        fprintf(out, "  [%s/%s] %s (%s) kind=%d key_len=%zu iv=%d\n",
                e->device, e->build, e->filename, e->component,
                (int)e->kind, e->key_len, e->has_iv);
    }
}

int ipsw_parse_name(const char *ipsw_name, char *device_out, size_t dlen,
                    char *build_out, size_t blen) {
    const char *base = ipsw_name;
    for (const char *q = ipsw_name; *q; q++) if (*q == '/' || *q == '\\') base = q + 1;
    device_out[0] = 0;
    build_out[0] = 0;
    /* device_version_BUILD_Restore.ipsw or device_version_BUILD.ipsw */
    const char *p = base;
    const char *us1 = strchr(p, '_');
    if (!us1) return -1;
    size_t dn = (size_t)(us1 - p);
    if (dn >= dlen) dn = dlen - 1;
    memcpy(device_out, p, dn);
    device_out[dn] = 0;

    /* find build token containing digit+letter+digit pattern near end */
    const char *best = NULL;
    for (const char *q = us1 + 1; *q; q++) {
        if (isdigit((unsigned char)q[0]) && isdigit((unsigned char)q[1]) &&
            isalpha((unsigned char)q[2])) {
            const char *end = q;
            while (*end && *end != '_' && *end != '.') end++;
            /* prefer tokens like 10B329 */
            if ((size_t)(end - q) >= 5) best = q;
        }
    }
    if (!best) return 0;
    size_t bn = 0;
    while (best[bn] && best[bn] != '_' && best[bn] != '.') bn++;
    if (bn >= blen) bn = blen - 1;
    memcpy(build_out, best, bn);
    build_out[bn] = 0;
    return 0;
}

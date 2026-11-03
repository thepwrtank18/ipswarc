#ifndef IPSWARC_KEYS_H
#define IPSWARC_KEYS_H

#include "common.h"

typedef enum {
    KEY_KIND_NONE = 0,
    KEY_KIND_IMG3,      /* IV(16) + AES-256 key(32) */
    KEY_KIND_ROOTFS     /* AES-128(16) + HMAC-SHA1(20) = 36 bytes vfdecrypt -k */
} key_kind_t;

typedef struct {
    char *build;       /* e.g. 10B329 */
    char *device;      /* e.g. iPad2,6 */
    char *filename;    /* basename inside IPSW */
    char *component;   /* Root Filesystem, Kernelcache, ... */
    key_kind_t kind;
    uint8_t iv[16];
    int has_iv;
    uint8_t key[36];   /* 32 for img3, 36 for rootfs */
    size_t key_len;
} key_entry_t;

typedef struct {
    key_entry_t *items;
    size_t count;
    size_t cap;
} keydb_t;

void keydb_init(keydb_t *db);
void keydb_free(keydb_t *db);

/* Load firmware keys from an IPSW-sidecar XML plist (preferred). */
int keydb_load_plist(keydb_t *db, const char *path);
/* Load all *.plist in a directory. */
int keydb_load_dir(keydb_t *db, const char *dir);

/* Legacy HTML scrape (The Apple Wiki .htm) — migration only. */
int keydb_load_htm(keydb_t *db, const char *path);
int keydb_load_dir_htm(keydb_t *db, const char *dir);

const key_entry_t *keydb_find(const keydb_t *db, const char *build,
                              const char *filename);
void keydb_dump(const keydb_t *db, FILE *out);

/* Build XML plist for keys matching device+build. Caller frees *out_xml. */
int keydb_to_plist_xml(const keydb_t *db, const char *device, const char *build,
                       char **out_xml, size_t *out_len);
/* Write that plist to path. */
int keydb_write_plist(const keydb_t *db, const char *device, const char *build,
                      const char *path);

/* Infer build/device from IPSW filename like iPad2,6_6.1.3_10B329_Restore.ipsw */
int ipsw_parse_name(const char *ipsw_name, char *device_out, size_t dlen,
                    char *build_out, size_t blen);

/* Replace .ipsw with .plist (or append .plist). dst_sz must be >= strlen+8. */
void ipsw_plist_name(const char *ipsw_name, char *dst, size_t dst_sz);

#endif

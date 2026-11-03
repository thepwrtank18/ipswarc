#ifndef IPSWARC_ARCFMT_H
#define IPSWARC_ARCFMT_H

#include "common.h"

typedef enum {
    PAY_RAW = 0,
    PAY_IMG3 = 1,
    PAY_ENCRCDSA = 2
} pay_kind_t;

#pragma pack(push, 1)
typedef struct {
    char magic[8];
    uint32_t version;
    uint32_t flags;
    uint32_t num_ipsw;
    uint32_t num_keys;
} arc_header_t;
#pragma pack(pop)

typedef struct {
    char name[256];
    sha256_t orig_sha;       /* original IPSW file hash */
    uint64_t orig_size;
    sha256_t content_sha;    /* sha256 of concatenation of entry payload hashes */
    uint32_t num_entries;
    uint16_t mod_time0;
    uint16_t mod_date0;
    sha256_t eocd_id;
    sha256_t prefix_id;
    uint32_t prefix_len;
    uint32_t reserved0;
} arc_ipsw_t;

typedef struct {
    char name[512];
    uint32_t kind;
    uint32_t crc32;          /* CRC of uncompressed entry content */
    uint32_t uncomp_size;
    uint16_t mod_time;
    uint16_t mod_date;
    uint16_t internal_attr;
    uint16_t pad0;
    uint32_t external_attr;
    sha256_t body_id;        /* plaintext or raw uncompressed */
    sha256_t entry_sha;      /* sha256 of original uncompressed entry bytes */
    uint8_t iv[16];
    uint8_t key[36];
    uint8_t key_len;
    uint8_t has_iv;
    uint8_t reserved[2];
    sha256_t meta_id;
    uint64_t data_off;
    uint64_t data_len;
    uint32_t blocksize;
    uint64_t datasize;
    uint64_t total_len;
    /* v2 exact-ZIP scaffold */
    uint16_t method;
    uint16_t gp_flag;
    uint16_t ver_extract;
    uint16_t ver_made;
    uint32_t orig_comp_size;
    sha256_t lh_id;
    sha256_t cd_id;
    sha256_t dd_id;
    sha256_t comp_id;
    uint8_t has_dd;
    uint8_t has_scaffold;
    uint8_t reflat;          /* REFLAT_*: 0=comp_id, 1=zlib128, 2=Info-ZIP 3.0 -6 */
    uint8_t reserved2;
} arc_entry_t;

#define IPSWARC_WRAP_MAGIC "4stal4evr"
#define IPSWARC_WRAP_MAGIC_LEN 9

#endif

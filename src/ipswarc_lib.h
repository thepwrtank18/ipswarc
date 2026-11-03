#ifndef IPSWARC_LIB_H
#define IPSWARC_LIB_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ipswarc_archive ipswarc_archive_t;

typedef int (*ipswarc_write_fn)(const void *data, size_t len, void *ctx);

/* Seek/read callbacks for opening without a filesystem path (7-Zip IInStream). */
typedef struct ipswarc_reader {
    int (*seek)(void *ctx, uint64_t abs_off);      /* absolute SEEK_SET; 0=ok */
    int (*read)(void *ctx, void *buf, size_t len); /* exact read; 0=ok */
    void *ctx;
} ipswarc_reader_t;

/* Open .ipswarc: loads manifest + index only; blob stays in-place via seeks. */
int ipswarc_open(const char *path, ipswarc_archive_t **out);
#ifdef _WIN32
int ipswarc_open_w(const wchar_t *path, ipswarc_archive_t **out);
#endif
int ipswarc_open_reader(const ipswarc_reader_t *reader, ipswarc_archive_t **out);
void ipswarc_close(ipswarc_archive_t *a);

/* Items are interleaved: [0]=IPSW0, [1]=IPSW0.plist, [2]=IPSW1, ... */
uint32_t ipswarc_num_items(const ipswarc_archive_t *a);

/* name points into archive-owned storage (valid until close). */
int ipswarc_item_info(const ipswarc_archive_t *a, uint32_t index,
                      const char **name, uint64_t *orig_size,
                      uint16_t *mod_time, uint16_t *mod_date);

/* 1 if item is a keys plist sidecar, 0 if IPSW. */
int ipswarc_item_is_plist(const ipswarc_archive_t *a, uint32_t index);

/* Extract IPSW bytes or plist XML into a newly allocated buffer. Caller frees. */
int ipswarc_extract_mem(ipswarc_archive_t *a, uint32_t index,
                        uint8_t **out_data, size_t *out_len);

/* Number of IPSWs only (half of num_items when plists present). */
uint32_t ipswarc_num_ipsw(const ipswarc_archive_t *a);

/* Rebuild and write via callback (may be called once with full buffer). */
int ipswarc_extract_to(ipswarc_archive_t *a, uint32_t index,
                       ipswarc_write_fn write_fn, void *ctx);

/* Write rebuilt IPSW to path. */
int ipswarc_extract_file(ipswarc_archive_t *a, uint32_t index, const char *out_path);

const char *ipswarc_last_error(void);

#ifdef __cplusplus
}
#endif

#endif

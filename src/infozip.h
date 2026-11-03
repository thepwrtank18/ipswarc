#ifndef IPSWARC_INFOZIP_H
#define IPSWARC_INFOZIP_H

#include "common.h"

/* Per-entry reflat codec (arc_entry_t.reflat). */
#define REFLAT_NONE     0  /* stored original DEFLATE in comp_id */
#define REFLAT_ZLIB128  1  /* classic zlib 1.2.8 level 6 raw */
#define REFLAT_INFOZIP6 2  /* Info-ZIP 3.0 classic level 6 (static) */

/* Raw DEFLATE via embedded Info-ZIP 3.0 classic compressor at level 6. */
int zip_deflate_raw_infozip6(const uint8_t *in, size_t in_len,
                             uint8_t **out, size_t *out_len);

/* 1 if Info-ZIP 3.0 -6 output equals expect. */
int zip_deflate_matches_infozip6(const uint8_t *in, size_t in_len,
                                 const uint8_t *expect, size_t expect_len);

#endif

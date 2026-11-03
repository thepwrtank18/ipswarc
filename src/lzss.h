#ifndef IPSWARC_LZSS_H
#define IPSWARC_LZSS_H

#include "common.h"

int complzss_is(const uint8_t *data, size_t len);
/* Inflate Apple complzss wrapper to mach-o (or raw). Caller frees *out. */
int complzss_inflate(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len);

#endif

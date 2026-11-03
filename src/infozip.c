#include "infozip.h"
#include "iz_compat.h"
#include <setjmp.h>

/* Classic deflate.c is built with -Ddeflate=iz_deflate to avoid zlib clash. */
extern uzoff_t iz_deflate(void);

/* ---- Info-ZIP globals expected by classic deflate.c / trees.c ---- */
int level = 6;
uzoff_t isize = 0;
unsigned (*read_buf)(char *buf, unsigned size) = NULL;
char *key = NULL;
int noisy = 0;
int verbose = 0;
zoff_t dot_size = 0;
zoff_t dot_count = 0;
int display_globaldots = 0;
int mesg_line_started = 0;
int use_descriptors = 0;
FILE *mesg = NULL;

/* In-memory compression is always "seekable" (Info-ZIP memcompress path). */
int seekable(void) { return 1; }

/* window_size lives in classic/deflate.c */

static jmp_buf iz_jmp;
static volatile int iz_failed;

static const uint8_t *iz_in;
static size_t iz_in_len;
static size_t iz_in_off;

static uint8_t *iz_out;
static size_t iz_out_len;
static size_t iz_out_cap;

static char iz_bitbuf[16384];

void error(ZCONST char *h) {
    (void)h;
    iz_failed = 1;
    longjmp(iz_jmp, 1);
}

void ziperr(int c, ZCONST char *h) {
    (void)c;
    (void)h;
    iz_failed = 1;
    longjmp(iz_jmp, 1);
}

void flush_outbuf(char *o_buf, unsigned *o_idx) {
    unsigned n = *o_idx;
    if (n == 0) return;
    if (iz_out_len + n > iz_out_cap) {
        size_t nc = iz_out_cap ? iz_out_cap : 4096;
        while (nc < iz_out_len + n) nc *= 2;
        iz_out = (uint8_t *)xrealloc(iz_out, nc);
        iz_out_cap = nc;
    }
    memcpy(iz_out + iz_out_len, o_buf, n);
    iz_out_len += n;
    *o_idx = 0;
}

static unsigned iz_mem_read(char *buf, unsigned size) {
    size_t left = (iz_in_off < iz_in_len) ? (iz_in_len - iz_in_off) : 0;
    if (left == 0) return 0;
    if ((size_t)size > left) size = (unsigned)left;
    memcpy(buf, iz_in + iz_in_off, size);
    iz_in_off += size;
    return size;
}

int zip_deflate_raw_infozip6(const uint8_t *in, size_t in_len,
                             uint8_t **out, size_t *out_len) {
    ush att = (ush)UNKNOWN;
    ush flags = 0;
    int method = DEFLATE;
    uzoff_t clen;

    iz_in = in;
    iz_in_len = in_len;
    iz_in_off = 0;
    iz_out = NULL;
    iz_out_len = 0;
    iz_out_cap = 0;
    iz_failed = 0;

    if (mesg == NULL) mesg = stderr;

    level = 6;
    key = NULL;
    isize = (uzoff_t)in_len;
    window_size = 0L;
    read_buf = iz_mem_read;
    noisy = 0;
    verbose = 0;
    dot_size = 0;
    dot_count = 0;
    display_globaldots = 0;

    if (setjmp(iz_jmp) != 0) {
        free(iz_out);
        iz_out = NULL;
        window_size = 0L;
        return -1;
    }

    bi_init(iz_bitbuf, (unsigned)sizeof(iz_bitbuf), TRUE);
    ct_init(&att, &method);
    lm_init(level != 0 ? level : 1, &flags);
    clen = iz_deflate();
    (void)clen;
    window_size = 0L;
    lm_free();

    if (iz_failed || iz_out == NULL) {
        free(iz_out);
        return -1;
    }

    *out = iz_out;
    *out_len = iz_out_len;
    iz_out = NULL;
    return 0;
}

int zip_deflate_matches_infozip6(const uint8_t *in, size_t in_len,
                                 const uint8_t *expect, size_t expect_len) {
    uint8_t *got = NULL;
    size_t got_len = 0;
    if (zip_deflate_raw_infozip6(in, in_len, &got, &got_len) != 0)
        return 0;
    int ok = (got_len == expect_len &&
              (expect_len == 0 || memcmp(got, expect, expect_len) == 0));
    free(got);
    return ok;
}

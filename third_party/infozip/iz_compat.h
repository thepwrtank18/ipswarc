/*
 * Minimal stand-in for Info-ZIP 3.0 zip.h / tailor.h so classic
 * deflate.c + trees.c can be embedded without the full zip application.
 * Altered version of Info-ZIP interfaces — not an Info-ZIP release.
 */
#ifndef IZ_COMPAT_H
#define IZ_COMPAT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define local static

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;
typedef long           zoff_t;
typedef unsigned long  uzoff_t;
typedef void           zvoid;
typedef size_t         extent;

#ifndef OF
#  define OF(a) a
#endif

#ifndef ZCONST
#  define ZCONST const
#endif

#ifndef far
#  define far
#endif
#ifndef near
#  define near
#endif
#ifndef Far
#  define Far far
#endif
#ifndef huge
#  define huge
#endif

#ifndef WSIZE
#  define WSIZE (0x8000)
#endif

#define MIN_MATCH  3
#define MAX_MATCH  258
#define MIN_LOOKAHEAD (MAX_MATCH+MIN_MATCH+1)
#define MAX_DIST  (WSIZE-MIN_LOOKAHEAD)

#define STORE    0
#define DEFLATE  8
#define UNKNOWN  (-1)
#define BINARY   0
#define ASCII    1

#define ZE_OK    0
#define ZE_MEM   4
#define ZE_LOGIC 5

#ifndef TRUE
#  define TRUE 1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

/* No DEBUG asserts/traces — keep classic output deterministic and quiet. */
#define Assert(cond,msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c,x)
#define Tracecv(c,x)
#define diag(where)

#if (!defined(USE_ZLIB) && !defined(MY_ZCALLOC))
#  define zcalloc(items,size) \
          (zvoid far *)calloc((unsigned)(items), (unsigned)(size))
#  define zcfree    free
#endif

/* Globals / hooks provided by src/infozip.c */
extern int level;
extern uzoff_t isize;
extern ulg window_size;
extern unsigned (*read_buf) OF((char *buf, unsigned size));
extern char *key;
extern int noisy;
extern int verbose;
extern zoff_t dot_size;
extern zoff_t dot_count;
extern int display_globaldots;
extern int mesg_line_started;
extern int use_descriptors;
extern FILE *mesg;

void error OF((ZCONST char *h));
void ziperr OF((int c, ZCONST char *h));
void flush_outbuf OF((char *o_buf, unsigned *o_idx));
int seekable OF((void));

void lm_init OF((int pack_level, ush *flags));
void lm_free OF((void));
/* Built as iz_deflate via -Ddeflate=iz_deflate (avoids zlib clash). */
uzoff_t iz_deflate OF((void));

void     ct_init      OF((ush *attr, int *method));
int      ct_tally     OF((int dist, int lc));
uzoff_t  flush_block  OF((char far *buf, ulg stored_len, int eof));
void     bi_init      OF((char *tgt_buf, unsigned tgt_size, int flsh_allowed));

#endif /* IZ_COMPAT_H */

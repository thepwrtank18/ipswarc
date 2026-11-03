CLANG ?= C:/clang-dos-windows-x86_64/bin/clang.exe
# BCrypt needs Vista+; win2003/xp link but won't run without crypto rewrite.
CFG   ?= --config=vista-x64.cfg

CFLAGS = $(CFG) -O2 -g -Wall -Wextra -Wno-unused-parameter \
	-I src -I third_party \
	-I third_party/7zip/C -I third_party/zlib \
	-I third_party/infozip/shim -I third_party/infozip \
	-DZ7_ST
LDFLAGS = $(CFG) -lbcrypt

SRC = \
	src/main.c \
	src/util.c \
	src/keys.c \
	src/zip.c \
	src/infozip.c \
	src/img3.c \
	src/lzss.c \
	src/encrcdsa.c \
	src/store.c \
	src/archive.c \
	src/ipswarc_lib.c

LZMA_SRC = \
	third_party/7zip/C/Alloc.c \
	third_party/7zip/C/CpuArch.c \
	third_party/7zip/C/LzFind.c \
	third_party/7zip/C/LzmaDec.c \
	third_party/7zip/C/LzmaEnc.c \
	third_party/7zip/C/LzmaLib.c

# Classic zlib 1.2.8 — required for Apple IPSW bit-exact raw DEFLATE.
ZLIB_SRC = \
	third_party/zlib/adler32.c \
	third_party/zlib/crc32.c \
	third_party/zlib/deflate.c \
	third_party/zlib/inflate.c \
	third_party/zlib/inftrees.c \
	third_party/zlib/inffast.c \
	third_party/zlib/trees.c \
	third_party/zlib/zutil.c

# Info-ZIP 3.0 classic DEFLATE (not USE_ZLIB) — iPod/classic IPSW bit-exact.
# Rename deflate -> iz_deflate so it does not collide with zlib.
INFOZIP_SRC = \
	third_party/infozip/zip/deflate.c \
	third_party/infozip/zip/trees.c

INFOZIP_CFLAGS = $(CFLAGS) -DNO_ASM -Ddeflate=iz_deflate -Wno-all

OBJ = $(SRC:.c=.o) $(LZMA_SRC:.c=.o) $(ZLIB_SRC:.c=.o) $(INFOZIP_SRC:.c=.o)

.PHONY: all clean plugin

all: ipswarc.exe

plugin:
	mingw32-make -C plugin

ipswarc.exe: $(OBJ)
	$(CLANG) $(LDFLAGS) -o $@ $(OBJ)

src/%.o: src/%.c
	$(CLANG) $(CFLAGS) -c -o $@ $<

third_party/7zip/C/%.o: third_party/7zip/C/%.c
	$(CLANG) $(CFLAGS) -Wno-all -c -o $@ $<

third_party/zlib/%.o: third_party/zlib/%.c
	$(CLANG) $(CFLAGS) -Wno-all -c -o $@ $<

third_party/infozip/zip/%.o: third_party/infozip/zip/%.c
	$(CLANG) $(INFOZIP_CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) ipswarc.exe

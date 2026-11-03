# Build ipswarc.dll — drop into 7-Zip\Formats\
# Usage: make -C plugin   (from repo root: make plugin)

CLANG ?= C:/clang-dos-windows-x86_64/bin/clang.exe
CFG   ?= --config=vista-x64.cfg

ROOT := ..
Z7   := $(ROOT)/third_party/7zip
Z7CPP := $(Z7)/CPP
Z7C   := $(Z7)/C

CFLAGS_C = $(CFG) -O2 -g -Wall -Wextra -Wno-unused-parameter \
	-I $(ROOT)/src -I $(ROOT)/third_party \
	-I $(ROOT)/third_party/7zip/C -I $(ROOT)/third_party/zlib \
	-I $(ROOT)/third_party/infozip/shim -I $(ROOT)/third_party/infozip \
	-DZ7_ST

CXXFLAGS = $(CFG) -O2 -g -fno-rtti -Wall -Wno-unused-parameter \
	-I . -I $(ROOT)/src \
	-I $(Z7CPP) -I $(Z7CPP)/7zip -I $(Z7C) \
	-D_UNICODE -DUNICODE -DZ7_EXTRACT_ONLY

LDFLAGS = $(CFG) -shared -lc++ -lc++abi -lbcrypt -loleaut32 -luuid -ladvapi32 -lkernel32 -luser32

INFOZIP_CFLAGS = $(CFLAGS_C) -DNO_ASM -Ddeflate=iz_deflate -Wno-all

# ---- extract library (C) ----
LIB_SRC = \
	$(ROOT)/src/util.c \
	$(ROOT)/src/keys.c \
	$(ROOT)/src/zip.c \
	$(ROOT)/src/infozip.c \
	$(ROOT)/src/img3.c \
	$(ROOT)/src/lzss.c \
	$(ROOT)/src/encrcdsa.c \
	$(ROOT)/src/store.c \
	$(ROOT)/src/ipswarc_lib.c

LZMA_SRC = \
	$(ROOT)/third_party/7zip/C/Alloc.c \
	$(ROOT)/third_party/7zip/C/CpuArch.c \
	$(ROOT)/third_party/7zip/C/LzFind.c \
	$(ROOT)/third_party/7zip/C/LzmaDec.c \
	$(ROOT)/third_party/7zip/C/LzmaEnc.c \
	$(ROOT)/third_party/7zip/C/LzmaLib.c

ZLIB_SRC = \
	$(ROOT)/third_party/zlib/adler32.c \
	$(ROOT)/third_party/zlib/crc32.c \
	$(ROOT)/third_party/zlib/deflate.c \
	$(ROOT)/third_party/zlib/inflate.c \
	$(ROOT)/third_party/zlib/inftrees.c \
	$(ROOT)/third_party/zlib/inffast.c \
	$(ROOT)/third_party/zlib/trees.c \
	$(ROOT)/third_party/zlib/zutil.c

INFOZIP_SRC = \
	$(ROOT)/third_party/infozip/zip/deflate.c \
	$(ROOT)/third_party/infozip/zip/trees.c

# ---- 7-Zip glue (C++) ----
Z7_CXX_SRC = \
	DllExports.cpp \
	IpswArcHandler.cpp \
	StdAfx.cpp \
	$(Z7CPP)/7zip/Archive/ArchiveExports.cpp \
	$(Z7CPP)/7zip/Common/StreamUtils.cpp \
	$(Z7CPP)/7zip/Common/ProgressUtils.cpp \
	$(Z7CPP)/7zip/Common/PropId.cpp \
	$(Z7CPP)/Common/IntToString.cpp \
	$(Z7CPP)/Common/MyString.cpp \
	$(Z7CPP)/Common/MyVector.cpp \
	$(Z7CPP)/Common/MyWindows.cpp \
	$(Z7CPP)/Common/NewHandler.cpp \
	$(Z7CPP)/Common/StringConvert.cpp \
	$(Z7CPP)/Common/StringToInt.cpp \
	$(Z7CPP)/Common/Wildcard.cpp \
	$(Z7CPP)/Windows/PropVariant.cpp \
	$(Z7CPP)/Windows/PropVariantConv.cpp \
	$(Z7CPP)/Windows/System.cpp \
	$(Z7CPP)/Windows/TimeUtils.cpp

LIB_OBJ = $(LIB_SRC:.c=.plugin.o)
LZMA_OBJ = $(LZMA_SRC:.c=.plugin.o)
ZLIB_OBJ = $(ZLIB_SRC:.c=.plugin.o)
INFOZIP_OBJ = $(INFOZIP_SRC:.c=.plugin.o)
Z7_OBJ = $(addsuffix .plugin.o,$(basename $(notdir $(Z7_CXX_SRC))))

# Map basenames of 7z sources that live outside plugin/ back to paths
vpath %.cpp $(Z7CPP)/7zip/Archive $(Z7CPP)/7zip/Common $(Z7CPP)/Common $(Z7CPP)/Windows .

.PHONY: all clean

all: ipswarc.dll

ipswarc.dll: $(LIB_OBJ) $(LZMA_OBJ) $(ZLIB_OBJ) $(INFOZIP_OBJ) $(Z7_OBJ)
	$(CLANG) $(LDFLAGS) -o $@ $^ ipswarc.def

$(ROOT)/src/%.plugin.o: $(ROOT)/src/%.c
	$(CLANG) $(CFLAGS_C) -c -o $@ $<

$(ROOT)/third_party/7zip/C/%.plugin.o: $(ROOT)/third_party/7zip/C/%.c
	$(CLANG) $(CFLAGS_C) -Wno-all -c -o $@ $<

$(ROOT)/third_party/zlib/%.plugin.o: $(ROOT)/third_party/zlib/%.c
	$(CLANG) $(CFLAGS_C) -Wno-all -c -o $@ $<

$(ROOT)/third_party/infozip/zip/%.plugin.o: $(ROOT)/third_party/infozip/zip/%.c
	$(CLANG) $(INFOZIP_CFLAGS) -c -o $@ $<

%.plugin.o: %.cpp
	$(CLANG) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(LIB_OBJ) $(LZMA_OBJ) $(ZLIB_OBJ) $(INFOZIP_OBJ) $(Z7_OBJ) ipswarc.dll

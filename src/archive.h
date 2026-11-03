#ifndef IPSWARC_ARCHIVE_H
#define IPSWARC_ARCHIVE_H

#include "common.h"
#include "keys.h"

int cmd_pack(const char *input_dir, const char *arc_path);
int cmd_unpack(const char *arc_path, const char *output_dir);
int cmd_verify(const char *arc_path, const char *input_dir);
int cmd_keys(const char *input_dir);

#endif

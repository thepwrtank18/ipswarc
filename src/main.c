#include "archive.h"

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s keys <ipsw-dir>          write <ipsw>.plist key files (from plist/HTML)\n"
        "  %s pack <ipsw-dir> -o <out.ipswarc>\n"
        "  %s unpack <in.ipswarc> -o <out-dir>\n"
        "  %s verify <in.ipswarc> <ipsw-dir>\n",
        argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "keys") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmd_keys(argv[2]);
    }
    if (strcmp(cmd, "pack") == 0) {
        const char *dir = NULL, *out = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) out = argv[++i];
            else if (argv[i][0] != '-') dir = argv[i];
        }
        if (!dir || !out) { usage(argv[0]); return 1; }
        return cmd_pack(dir, out);
    }
    if (strcmp(cmd, "unpack") == 0) {
        const char *arc = NULL, *out = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) out = argv[++i];
            else if (argv[i][0] != '-') arc = argv[i];
        }
        if (!arc || !out) { usage(argv[0]); return 1; }
        return cmd_unpack(arc, out);
    }
    if (strcmp(cmd, "verify") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        return cmd_verify(argv[2], argv[3]);
    }
    usage(argv[0]);
    return 1;
}

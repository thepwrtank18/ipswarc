#include "lzss.h"

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

int complzss_is(const uint8_t *data, size_t len) {
    return len >= 0x180 && memcmp(data, "complzss", 8) == 0;
}

int complzss_inflate(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len) {
    if (!complzss_is(data, len)) return -1;
    uint32_t unc = be32(data + 12);
    size_t src = 0x180;
    uint8_t *dst = (uint8_t *)xmalloc(unc ? unc : 1);
    const size_t N = 4096, F = 18, threshold = 2;
    uint8_t text_buf[4096 + 18];
    memset(text_buf, ' ', N - F);
    size_t r = N - F;
    size_t dst_pos = 0;
    unsigned flags = 0;

    while (dst_pos < unc && src < len) {
        flags >>= 1;
        if ((flags & 0x100) == 0) {
            if (src >= len) break;
            flags = data[src++] | 0xFF00;
        }
        if (flags & 1) {
            if (src >= len || dst_pos >= unc) break;
            uint8_t c = data[src++];
            dst[dst_pos++] = c;
            text_buf[r] = c;
            r = (r + 1) & (N - 1);
        } else {
            if (src + 1 >= len) break;
            size_t i = data[src++];
            size_t j = data[src++];
            i |= (j & 0xF0) << 4;
            j = (j & 0x0F) + threshold;
            for (size_t k = 0; k <= j; k++) {
                uint8_t c = text_buf[(i + k) & (N - 1)];
                if (dst_pos >= unc) break;
                dst[dst_pos++] = c;
                text_buf[r] = c;
                r = (r + 1) & (N - 1);
            }
        }
    }
    if (dst_pos != unc) {
        free(dst);
        return -1;
    }
    *out = dst;
    *out_len = unc;
    return 0;
}

#ifndef SHA256_HPP
#define SHA256_HPP


#include <cstdint>
#include <cstring>

#include "sha256.core.hpp"

#include "../const.hpp"
#include "../utils.hpp"


namespace SHA256 {
    /** 432 bytes of CTX */
    struct CTX {
        uint32_t h[8];
        uint8_t  buf[64];
        uint32_t m[16];
        uint32_t w[64];
        uint64_t bitlen;
        size_t   buf_len;
    };

    /** safe transform to Big-Endian words and running core after */
    inline void transform(CTX &ctx) {
        #pragma unroll
        for (size_t i = 0; i < 16; ++i) {
            /** (i * 4) ~ (i << 2) */
            ctx.m[i] = Utils::to32BE(ctx.buf + (i << 2));
        };

        SHA256::Core::core(ctx.h, ctx.m, ctx.w);
    };

    inline void update(CTX &ctx, const uint8_t *message, size_t len) {
        ctx.bitlen += len * 8;

        while (len > 0) {
            size_t take = std::min(len, 64 - ctx.buf_len);

            memcpy(ctx.buf + ctx.buf_len, message, take);
            ctx.buf_len += take;
            message += take;
            len -= take;

            if (ctx.buf_len == 64) {
                transform(ctx);
                ctx.buf_len = 0;
            };
        };
    };

    inline void digest(CTX &ctx, uint8_t *out) {
        ctx.buf[ctx.buf_len++] = 0x80;

        if (ctx.buf_len > 56) {
            memset(ctx.buf + ctx.buf_len, 0, 64 - ctx.buf_len);
            transform(ctx);
            ctx.buf_len = 0;
        };

        memset(ctx.buf + ctx.buf_len, 0, 56 - ctx.buf_len);
        ctx.buf_len = 56;

        uint64_t bitlen = ctx.bitlen;
        ctx.buf[56] = (uint8_t)(bitlen >> 56);
        ctx.buf[57] = (uint8_t)(bitlen >> 48);
        ctx.buf[58] = (uint8_t)(bitlen >> 40);
        ctx.buf[59] = (uint8_t)(bitlen >> 32);
        ctx.buf[60] = (uint8_t)(bitlen >> 24);
        ctx.buf[61] = (uint8_t)(bitlen >> 16);
        ctx.buf[62] = (uint8_t)(bitlen >>  8);
        ctx.buf[63] = (uint8_t)(bitlen      );

        transform(ctx);

        for (size_t i = 0; i < 32; ++i) {
            out[i] = Utils::from32BE(ctx.h, i);
        };
    };

    inline void init(CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV256, sizeof(ctx.h));
        ctx.bitlen = 0;
        ctx.buf_len = 0;
    };

    inline void destroy(CTX &ctx) {
        /** secure zeroization of &ctx */
        explicit_bzero(&ctx, sizeof(ctx));
    };
};  // namespace SHA256


#endif  // SHA256_HPP
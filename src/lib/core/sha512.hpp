#ifndef SHA512_HPP
#define SHA512_HPP


#include <cstdint>
#include <cstring>

#include "sha512.core.hpp"

#include "../const.hpp"
#include "../utils.hpp"


namespace SHA512 {
    /** 336 bytes of CTX */
    struct CTX {
        uint64_t h[8];
        uint8_t  buf[128];
        uint64_t m[16];
        uint64_t bitlen;
        size_t   buf_len;
    };

    /** safe transform to Big-Endian words and running core after */
    inline void transform(CTX &ctx) {
        #pragma unroll
        for (size_t i = 0; i < 16; ++i) {
            /** (i * 8) ~ (i << 3) */
            ctx.m[i] = Utils::BE::to64(ctx.buf + (i << 3));
        };

        SHA512::Core::core(ctx.h, ctx.m);
    };

    inline void update(CTX &ctx, const uint8_t *message, size_t len) {
        ctx.bitlen += len * 8;

        while (len > 0) {
            size_t take = std::min(len, 128 - ctx.buf_len);

            memcpy(ctx.buf + ctx.buf_len, message, take);
            ctx.buf_len += take;
            message += take;
            len -= take;

            if (ctx.buf_len == 128) {
                transform(ctx);
                ctx.buf_len = 0;
            };
        };
    };

    inline void digest(CTX &ctx, uint8_t *out) {
        ctx.buf[ctx.buf_len++] = 0x80;

        if (ctx.buf_len > 120) {
            memset(ctx.buf + ctx.buf_len, 0, 128 - ctx.buf_len);
            transform(ctx);
            ctx.buf_len = 0;
        };

        memset(ctx.buf + ctx.buf_len, 0, 120 - ctx.buf_len);
        ctx.buf_len = 120;

        uint64_t bitlen = ctx.bitlen;
        ctx.buf[120] = (uint8_t)(bitlen >> 56);
        ctx.buf[121] = (uint8_t)(bitlen >> 48);
        ctx.buf[122] = (uint8_t)(bitlen >> 40);
        ctx.buf[123] = (uint8_t)(bitlen >> 32);
        ctx.buf[124] = (uint8_t)(bitlen >> 24);
        ctx.buf[125] = (uint8_t)(bitlen >> 16);
        ctx.buf[126] = (uint8_t)(bitlen >>  8);
        ctx.buf[127] = (uint8_t)(bitlen      );

        transform(ctx);

        for (size_t i = 0; i < 64; ++i) {
            out[i] = Utils::BE::from64(ctx.h, i);
        };
    };

    inline void init(CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV512, sizeof(ctx.h));
        ctx.bitlen = 0;
        ctx.buf_len = 0;
    };

    inline void destroy(CTX &ctx) {
        volatile uint8_t *p = (volatile uint8_t *)&ctx;
        for (size_t i = 0; i < sizeof(ctx); ++i) {
            p[i] = 0;
        };

        /** secure zeroization of CTX */
        explicit_bzero(&ctx, sizeof(ctx));
    };
};  // namespace SHA512


#endif  // SHA512_HPP
#ifndef SHA256_HPP
#define SHA256_HPP


#include <cstdint>
#include <cstring>

#include "sha256.core.hpp"

#include "../const.hpp"
#include "../utils.hpp"


namespace SHA256 {
    /** 112 bytes of CTX */
    struct ctx {
        uint32_t h[8];
        uint8_t  buffer[64];
        uint64_t bitlen;
        size_t   buf_len;
    };

    /** safe transform to Big-Endian words and running core after */
    inline void transform(ctx& ctx, const uint8_t* buf) {
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) {
            m[i] = Utils::to32BE(buf + i * 4);
        };

        SHA256::Core::core(ctx.h, m);
    };

    inline void update(ctx& ctx, const uint8_t* message, size_t len) {
        ctx.bitlen += len * 8;

        while (len > 0) {
            size_t take = std::min(len, 64 - ctx.buf_len);

            memcpy(ctx.buffer + ctx.buf_len, message, take);
            ctx.buf_len += take;
            message += take;
            len -= take;

            if (ctx.buf_len == 64) {
                transform(ctx, ctx.buffer);
                ctx.buf_len = 0;
            };
        };
    };

    inline void digest(ctx& ctx, uint8_t* out) {
        ctx.buffer[ctx.buf_len++] = 0x80;

        if (ctx.buf_len > 56) {
            while (ctx.buf_len < 64) {
                ctx.buffer[ctx.buf_len++] = 0;
            };

            transform(ctx, ctx.buffer);
            ctx.buf_len = 0;
        };

        while (ctx.buf_len < 56) {
            ctx.buffer[ctx.buf_len++] = 0;
        };

        uint64_t bitlen = ctx.bitlen;
        for (int i = 7; i >= 0; --i) {
            ctx.buffer[ctx.buf_len++] = (bitlen >> (i * 8)) & 0xFF;
        };

        transform(ctx, ctx.buffer);

        for (int i = 0; i < 32; ++i) {
            out[i] = Utils::from32BE(ctx.h, i);
        };
    };

    inline void init(ctx& ctx) {
        memcpy(ctx.h, SHA2::CONST::IV256, 8 * sizeof(uint32_t));
        ctx.bitlen = 0;
        ctx.buf_len = 0;
    };

    inline void destroy(ctx& ctx) {
        volatile uint8_t *p = (volatile uint8_t *)&ctx;
        for (size_t i = 0; i < sizeof(ctx); ++i) {
            p[i] = 0;
        };
        
        /** secure zeroization of &ctx */
        explicit_bzero(&ctx, sizeof(ctx));
    };
};  // namespace SHA256


#endif  // SHA256_HPP
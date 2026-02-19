#ifndef SHA512_HPP
#define SHA512_HPP


#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>

#include "const.hpp"
#include "utils.hpp"


namespace SHA512 {
  ////////////////////////////////////////////////////////////////
 ///////////////////////// PRIVATE BLOCK ////////////////////////
////////////////////////////////////////////////////////////////

    /** local Sigma0 (SHA-384/512) */
    inline uint64_t S0(uint64_t x) {
        return (
            (x << 36 | x >> 28) ^   // right rotate (28)
            (x << 30 | x >> 34) ^   // right rotate (34)
            (x << 25 | x >> 39)     // right rotate (39)
        );
    };

    /** local Sigma1 (SHA-384/512) */
    inline uint64_t S1(uint64_t x) {
        return (
            (x << 50 | x >> 14) ^  // right rotate (14)
            (x << 46 | x >> 18) ^  // right rotate (18)
            (x << 23 | x >> 41)    // right rotate (41)
        );
    };

    /** local sigma0 (SHA-384/512) */
    inline uint64_t s0(uint64_t x) {
        return (
            (x << 63 | x >>  1) ^   // right rotate (1)
            (x << 56 | x >>  8) ^   // right rotate (8)
            (          x >>  7)     // right shift (7)
        );
    };

    /** local sigma1 (SHA-384/512) */
    inline uint64_t s1(uint64_t x) {
        return (
            (x << 45 | x >> 19) ^   // right rotate (19)
            (x <<  3 | x >> 61) ^   // right rotate (61)
            (          x >>  6)     // right shift (6)
        );
    };

    /** local Majority (SHA-384/512) */
    inline uint64_t maj(
        uint64_t x,
        uint64_t y,
        uint64_t z
    ) {
        return (
            (x & y) ^
            (x & z) ^
            (y & z)
        );
    };

    /** local Choose (SHA-384/512) */
    inline uint64_t ch(
        uint64_t x,
        uint64_t y,
        uint64_t z
    ) {
        return (
            ( x & y) ^ 
            (~x & z)
        );
    };

    /** 
     * compression function for sha2
     * @param h - current hash-functioin state
     * @param m - message block in Big-endian fromat
     */
    inline void core(uint64_t *__restrict h, const uint64_t *__restrict m) {
        /** to modify copy of state */
        uint64_t A = h[0];
        uint64_t B = h[1];
        uint64_t C = h[2];
        uint64_t D = h[3];
        uint64_t E = h[4];
        uint64_t F = h[5];
        uint64_t G = h[6];
        uint64_t H = h[7];
        
        /** extend the first 16 words to 80 */
        uint64_t w[80] = {0};
        memcpy(w, m, 16 * sizeof(uint64_t));

        /** extend + compress (80 rounds) */
        for (size_t i = 0; i < 80; ++i) {
            /** 1) extend */
            if(i >= 16) {
                w[i] = (
                    s0(w[i - 15]) +
                    s1(w[i - 2]) +
                    w[i - 7] +
                    w[i - 16]
                );
            };

            /** 2) compress */
            uint64_t T1 = (H + S1(E) + ch(E, F, G) + SHA2::CONST::K512[i] + w[i]);
            uint64_t T2 = (S0(A) + maj(A, B, C));

            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        };

        /** add result to state */
        h[0] += A; 
        h[1] += B; 
        h[2] += C; 
        h[3] += D;
        h[4] += E; 
        h[5] += F;
        h[6] += G; 
        h[7] += H;
    };

  ////////////////////////////////////////////////////////////////
 ///////////////////////// PUBLIC BLOCK /////////////////////////
////////////////////////////////////////////////////////////////

    /** 337 bytes of CTX */
    struct CTX {
        uint64_t h[8];
        uint8_t  buf[128];
        uint64_t m[16];
        uint64_t bitlen;
        size_t   buf_len;
        bool     finalized;
    };

    /** safe transform to Big-Endian words and running core after */
    inline void transform(CTX &ctx) {
        for (size_t i = 0; i < 16; ++i) {
            /** (i * 8) ~ (i << 3) */
            ctx.m[i] = Utils::BE::to64(ctx.buf + (i << 3));
        };

        SHA512::core(ctx.h, ctx.m);
    };

    inline void update(CTX &ctx, const uint8_t *message, size_t len) {
        /** verify if NOT finalized */
        if (ctx.finalized) {
            throw std::runtime_error("already finalized");
        };

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
        /** verify if NOT finalized */
        if (ctx.finalized) {
            throw std::runtime_error("already finalized");
        };

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

        ctx.finalized = true;
    };

    inline void init(CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV512, sizeof(ctx.h));
        ctx.bitlen = 0;
        ctx.buf_len = 0;
        ctx.finalized = false;
    };

    inline void destroy(CTX &ctx) {
        /** secure zeroization of CTX */
        Utils::Clean::secure_zero(&ctx, sizeof(ctx));
    };
};  // namespace SHA512


#endif  // SHA512_HPP
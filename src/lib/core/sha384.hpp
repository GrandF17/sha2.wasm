#ifndef SHA224_HPP
#define SHA224_HPP


#include <cstdint>
#include <cstring>

#include "sha512.hpp"


namespace SHA384 {
    inline void init(SHA512::CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV384, 32);
        ctx.bitlen = 0;
        ctx.buf_len = 0;
    };

    inline void update(
        SHA512::CTX &ctx,
        const uint8_t* message,
        size_t len
    ) {
        SHA512::update(ctx, message, len);
    };

    inline void digest(SHA512::CTX &ctx, uint8_t out[28]) {
        uint8_t tmp[32];
        SHA512::digest(ctx, tmp);
        memcpy(out, tmp, 28 * sizeof(uint8_t));
    };

    inline void destroy(SHA512::CTX &ctx) {
        SHA512::destroy(ctx);
    };
};  // namespace SHA224


#endif  // SHA224_HPP
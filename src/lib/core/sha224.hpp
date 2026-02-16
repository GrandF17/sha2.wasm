#ifndef SHA224_HPP
#define SHA224_HPP


#include <cstdint>
#include <cstring>

#include "sha256.hpp"


namespace SHA224 {
    /** renaming the structure name */
    using CTX = SHA256::CTX;

    inline void init(CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV224, 32);
        ctx.bitlen = 0;
        ctx.buf_len = 0;
        ctx.finalized = false;
    };

    inline void update(
        CTX &ctx,
        const uint8_t* message,
        size_t len
    ) {
        SHA256::update(ctx, message, len);
    };

    inline void digest(CTX &ctx, uint8_t out[28]) {
        uint8_t tmp[32];
        SHA256::digest(ctx, tmp);
        memcpy(out, tmp, 28 * sizeof(uint8_t));
    };

    inline void destroy(CTX &ctx) {
        SHA256::destroy(ctx);
    };
};  // namespace SHA224


#endif  // SHA224_HPP
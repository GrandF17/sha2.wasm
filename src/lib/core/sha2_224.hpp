#ifndef SHA2_224_HPP
#define SHA2_224_HPP


#include <cstdint>
#include <cstring>

#include "sha2_256.hpp"


namespace SHA2_224 {
    /** renaming the structure name */
    using CTX = SHA2_256::CTX;

    inline void init(CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV224, sizeof(ctx.h));
        ctx.bit_len = 0;
        ctx.buf_len = 0;
        ctx.finalized = false;
    };

    inline void update(
        CTX &ctx,
        const uint8_t* message,
        size_t len
    ) {
        SHA2_256::update(ctx, message, len);
    };

    inline void digest(CTX &ctx, uint8_t *out) {
        uint8_t tmp[32];
        SHA2_256::digest(ctx, tmp);
        memcpy(out, tmp, 28 * sizeof(uint8_t));
    };

    inline void destroy(CTX &ctx) {
        SHA2_256::destroy(ctx);
    };
};  // namespace SHA2_224


#endif  // SHA2_224_HPP
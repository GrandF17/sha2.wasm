#ifndef SHA384_HPP
#define SHA384_HPP


#include <cstdint>
#include <cstring>

#include "sha512.hpp"


namespace SHA384 {
    /** renaming the structure name */
    using CTX = SHA512::CTX;

    inline void init(CTX &ctx) {
        memcpy(ctx.h, SHA2::CONST::IV384, sizeof(ctx.h));
        ctx.bitlen = 0;
        ctx.buf_len = 0;
        ctx.finalized = false;
    };

    inline void update(
        CTX &ctx,
        const uint8_t* message,
        size_t len
    ) {
        SHA512::update(ctx, message, len);
    };

    inline void digest(CTX &ctx, uint8_t out[48]) {
        uint8_t tmp[64];
        SHA512::digest(ctx, tmp);
        memcpy(out, tmp, 48 * sizeof(uint8_t));
    };

    inline void destroy(CTX &ctx) {
        SHA512::destroy(ctx);
    };
};  // namespace SHA384


#endif  // SHA384_HPP
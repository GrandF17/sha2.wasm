#ifndef SHA512_CLASS_CPP
#define SHA512_CLASS_CPP


#include "core/sha512.hpp"


class SHA512_HASH {
private:
    using CTX = SHA512::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 128;
    static constexpr size_t digest_size = 64;

    inline void init() {
        SHA512::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA512::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA512::digest(ctx, out);
    };

    inline void destroy() {
        SHA512::destroy(ctx);
    };
};  // class SHA512


#endif  // SHA512_CLASS_CPP
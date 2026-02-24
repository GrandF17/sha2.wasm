#ifndef SHA512_CLASS_CPP
#define SHA512_CLASS_CPP


#include "core/sha2_512.hpp"


class SHA2_512_HASH {
private:
    using CTX = SHA2_512::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 128;
    static constexpr size_t digest_size = 64;

    inline void init() {
        SHA2_512::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA2_512::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA2_512::digest(ctx, out);
    };

    inline void destroy() {
        SHA2_512::destroy(ctx);
    };
};  // class SHA2_512_HASH


#endif  // SHA512_CLASS_CPP
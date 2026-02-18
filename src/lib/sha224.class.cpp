#ifndef SHA224_CLASS_CPP
#define SHA224_CLASS_CPP


#include "core/sha224.hpp"


class SHA224_HASH {
private:
    using CTX = SHA224::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 64;
    static constexpr size_t digest_size = 28;

    inline void init() {
        SHA224::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA224::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA224::digest(ctx, out);
    };

    inline void destroy() {
        SHA224::destroy(ctx);
    };
};  // class SHA224_HASH


#endif  // SHA224_CLASS_CPP
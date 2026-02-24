#ifndef SHA224_CLASS_CPP
#define SHA224_CLASS_CPP


#include "core/sha2_224.hpp"


class SHA2_224_HASH {
private:
    using CTX = SHA2_224::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 64;
    static constexpr size_t digest_size = 28;

    inline void init() {
        SHA2_224::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA2_224::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA2_224::digest(ctx, out);
    };

    inline void destroy() {
        SHA2_224::destroy(ctx);
    };
};  // class SHA2_224_HASH


#endif  // SHA224_CLASS_CPP
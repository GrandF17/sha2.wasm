#ifndef SHA256_CLASS_CPP
#define SHA256_CLASS_CPP


#include "core/sha2_256.hpp"


class SHA2_256_HASH {
private:
    using CTX = SHA2_256::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 64;
    static constexpr size_t digest_size = 32;

    inline void init() {
        SHA2_256::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA2_256::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA2_256::digest(ctx, out);
    };

    inline void destroy() {
        SHA2_256::destroy(ctx);
    };
};  // class SHA2_256_HASH


#endif  // SHA256_CLASS_CPP
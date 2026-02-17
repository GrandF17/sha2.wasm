#ifndef SHA256_CLASS_CPP
#define SHA256_CLASS_CPP


#include "core/sha256.hpp"


class SHA256_HASH {
private:
    using CTX = SHA256::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 64;
    static constexpr size_t digest_size = 32;

    inline void init() {
        SHA256::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA256::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA256::digest(ctx, out);
    };

    inline void destroy() {
        SHA256::destroy(ctx);
    };
};  // class SHA256


#endif  // SHA256_CLASS_CPP
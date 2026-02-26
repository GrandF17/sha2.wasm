#ifndef SHA2_384_CLASS_CPP
#define SHA2_384_CLASS_CPP


#include "core/sha2_384.hpp"


class SHA2_384_HASH {
private:
    using CTX = SHA2_384::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 128;
    static constexpr size_t digest_size = 48;

    inline void init() {
        SHA2_384::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA2_384::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA2_384::digest(ctx, out);
    };

    inline void destroy() {
        SHA2_384::destroy(ctx);
    };
};  // class SHA2_384_HASH


#endif  // SHA2_384_CLASS_CPP
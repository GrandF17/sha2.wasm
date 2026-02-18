#ifndef SHA384_CLASS_CPP
#define SHA384_CLASS_CPP


#include "core/sha384.hpp"


class SHA384_HASH {
private:
    using CTX = SHA384::CTX;
    CTX ctx;

public:
    static constexpr size_t block_size  = 128;
    static constexpr size_t digest_size = 48;

    inline void init() {
        SHA384::init(ctx);
    };

    inline void update(const uint8_t *message, size_t len) {
        SHA384::update(ctx, message, len);
    };

    inline void digest(uint8_t *out) {
        SHA384::digest(ctx, out);
    };

    inline void destroy() {
        SHA384::destroy(ctx);
    };
};  // class SHA384


#endif  // SHA384_CLASS_CPP
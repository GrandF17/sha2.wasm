#include "sha384.hpp"


extern "C" {
    SHA384::CTX *sha384_create() {
        auto *ctx = new SHA384::CTX();
        SHA384::init(*ctx);
        return ctx;
    };

    void sha384_update(
        SHA384::CTX *ctx,
        const uint8_t *message,
        size_t len
    ) {
        SHA384::update(*ctx, message, len);
    };
   
    void sha384_digest(
        SHA384::CTX *ctx,
        uint8_t *out
    ) {
        SHA384::digest(*ctx, out);
    };

    void sha384_destroy(SHA384::CTX *ctx) {
        SHA384::destroy(*ctx);
        delete ctx;
    };
};
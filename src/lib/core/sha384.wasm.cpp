#include "sha384.hpp"


extern "C" {
    SHA512::CTX *sha384_create() {
        auto *ctx = new SHA512::CTX();
        SHA384::init(*ctx);
        return ctx;
    };

    void sha384_update(
        SHA512::CTX *ctx,
        const uint8_t *message,
        size_t len
    ) {
        SHA384::update(*ctx, message, len);
    };
   
    void sha384_digest(
        SHA512::CTX *ctx,
        uint8_t *out
    ) {
        SHA384::digest(*ctx, out);
    };

    void sha384_destroy(SHA512::CTX *ctx) {
        SHA384::destroy(*ctx);
        delete ctx;
    };
};
#include "sha512.hpp"


extern "C" {
    SHA512::CTX *sha512_create() {
        auto *ctx = new SHA512::CTX();
        SHA512::init(*ctx);
        return ctx;
    };

    void sha512_update(
        SHA512::CTX *ctx,
        const uint8_t *message,
        size_t len
    ) {
        SHA512::update(*ctx, message, len);
    };
   
    void sha512_digest(
        SHA512::CTX *ctx,
        uint8_t *out
    ) {
        SHA512::digest(*ctx, out);
    };

    void sha512_destroy(SHA512::CTX *ctx) {
        SHA512::destroy(*ctx);
        delete ctx;
    };
};
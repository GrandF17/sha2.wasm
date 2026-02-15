#include "sha224.hpp"


extern "C" {
    SHA224::CTX *sha224_create() {
        auto *ctx = new SHA224::CTX();
        SHA224::init(*ctx);
        return ctx;
    };

    void sha224_update(
        SHA224::CTX *ctx,
        const uint8_t *message,
        size_t len
    ) {
        SHA224::update(*ctx, message, len);
    };
   
    void sha224_digest(
        SHA224::CTX *ctx,
        uint8_t *out
    ) {
        SHA224::digest(*ctx, out);
    };

    void sha224_destroy(SHA224::CTX *ctx) {
        SHA224::destroy(*ctx);
        delete ctx;
    };
};
#include "sha256.hpp"


extern "C" {
    SHA256::CTX *sha256_create() {
        auto *ctx = new SHA256::CTX();
        SHA256::init(*ctx);
        return ctx;
    };

    void sha256_update(
        SHA256::CTX *ctx,
        const uint8_t *message,
        size_t len
    ) {
        SHA256::update(*ctx, message, len);
    };
   
    void sha256_digest(
        SHA256::CTX *ctx,
        uint8_t *out
    ) {
        SHA256::digest(*ctx, out);
    };

    void sha256_destroy(SHA256::CTX *ctx) {
        SHA256::destroy(*ctx);
        delete ctx;
    };
};
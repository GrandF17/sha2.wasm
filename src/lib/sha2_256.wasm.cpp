#include <emscripten/emscripten.h>

#include "sha2_256.class.cpp"


extern "C" {
    EMSCRIPTEN_KEEPALIVE
    void sha2_256(const uint8_t *message, size_t len, uint8_t *out) {
        SHA2_256_HASH H;
        H.init();
        H.update(message, len);
        H.digest(out);
        H.destroy();
    };
};
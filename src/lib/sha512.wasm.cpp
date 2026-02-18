#include <emscripten/emscripten.h>

#include "sha512.class.cpp"


extern "C" {
    EMSCRIPTEN_KEEPALIVE
    void sha512(const uint8_t *message, size_t len, uint8_t *out) {
        SHA512_HASH H;
        H.init();
        H.update(message, len);
        H.digest(out);
        H.destroy();
    };
};
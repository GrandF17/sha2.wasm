#include <emscripten/emscripten.h>

#include "hmac.class.cpp"
#include "sha2_224.class.cpp"
#include "sha2_256.class.cpp"
#include "sha2_384.class.cpp"
#include "sha2_512.class.cpp"


extern "C" {
    /** HMAC for SHA2_224 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha2_224(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA2_224_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };

    /** HMAC for SHA2_256 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha2_256(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA2_256_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };

    /** HMAC for SHA2_384 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha2_384(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA2_384_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };

    /** HMAC for SHA2_512 */
    EMSCRIPTEN_KEEPALIVE
    void hmac_sha2_512(
        const uint8_t *message, size_t message_len,
        const uint8_t *key, size_t key_len,
        uint8_t *out
    ) {        
        HMAC<SHA2_512_HASH> hmac;
        hmac.init(key, key_len);
        hmac.update(message, message_len);
        hmac.digest(out);
        hmac.destroy();
    };
};